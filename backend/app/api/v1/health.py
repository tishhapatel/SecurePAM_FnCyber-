"""
Health check endpoints — no authentication required.

Provides service health for:
- Application
- Database
- Redis
- IdP (Keycloak)
- Vault
- Gateway (Guacamole)
"""

import time
from typing import List

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.deps import get_current_active_user, get_db
from app.core.logging import get_logger
from app.schemas.common import DetailedHealthCheck, HealthCheck, LivenessCheck, ReadinessCheck, ServiceHealth

router = APIRouter(tags=["health"])
logger = get_logger(__name__)


@router.get("/health", response_model=HealthCheck)
async def health_check():
    """Basic health check — returns app status."""
    return HealthCheck(
        status="healthy",
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        dev_mode=settings.DEV_MODE,
    )


@router.get("/health/live", response_model=LivenessCheck)
async def liveness_check():
    """
    Liveness probe — only confirms the application process can respond.
    Deliberately checks NO dependencies (DB/Redis/etc). A failing dependency
    should surface via /health/ready, not cause an orchestrator to restart
    an otherwise-healthy process.
    """
    return LivenessCheck(status="alive")


@router.get("/health/ready", response_model=ReadinessCheck)
async def readiness_check(response: Response, db: AsyncSession = Depends(get_db)):
    """
    Readiness probe — verifies the dependencies required to actually serve
    traffic (PostgreSQL, Redis). Returns 503 when not ready so load
    balancers / orchestrators can route around this instance.
    """
    checks: List[ServiceHealth] = [await _check_database(db), await _check_redis()]
    ready = all(c.status == "healthy" for c in checks)

    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return ReadinessCheck(status="ready" if ready else "not_ready", checks=checks)


@router.get("/health/detailed", response_model=DetailedHealthCheck)
async def detailed_health_check(
    db: AsyncSession = Depends(get_db),
    _: object = Depends(get_current_active_user),
):
    """Per-service status for signed-in users. Statuses: healthy, degraded,
    unhealthy, mock (a development stand-in is active), not_configured (the
    integration is not deployed). Only real failures degrade the overall status."""
    services: List[ServiceHealth] = []

    # Database
    db_health = await _check_database(db)
    services.append(db_health)

    # Redis
    redis_health = await _check_redis()
    services.append(redis_health)

    # IdP
    idp_health = await _check_idp()
    services.append(idp_health)

    # Vault
    vault_health = await _check_vault()
    services.append(vault_health)

    # Gateways
    services.extend(await _check_gateways(db))

    # Recording storage
    services.append(_check_recording_storage())

    # SIEM
    siem_health = _check_siem()
    services.append(siem_health)

    # Overall status
    unhealthy = any(s.status == "unhealthy" for s in services)
    degraded = any(s.status == "degraded" for s in services)

    overall = "healthy"
    if unhealthy:
        overall = "unhealthy"
    elif degraded:
        overall = "degraded"

    return DetailedHealthCheck(
        status=overall,
        version=settings.APP_VERSION,
        environment=settings.ENVIRONMENT,
        dev_mode=settings.DEV_MODE,
        services=services,
    )


def _log_unhealthy(service: str, exc: Exception) -> str:
    """Health endpoints are unauthenticated: log the real error server-side
    and return only a generic message (exception text can carry hostnames,
    usernames or driver internals)."""
    logger.warning("health_check_failed", service=service, error_type=type(exc).__name__, exc_info=True)
    return f"{service} unreachable"


async def _check_database(db: AsyncSession) -> ServiceHealth:
    """Check PostgreSQL connectivity."""
    try:
        start = time.monotonic()
        await db.execute(text("SELECT 1"))
        latency = (time.monotonic() - start) * 1000
        return ServiceHealth(
            service="database",
            status="healthy",
            latency_ms=round(latency, 2),
        )
    except Exception as e:
        return ServiceHealth(
            service="database",
            status="unhealthy",
            details=_log_unhealthy("database", e),
        )


async def _check_redis() -> ServiceHealth:
    """Check Redis connectivity."""
    try:
        import redis.asyncio as aioredis

        start = time.monotonic()
        r = aioredis.from_url(settings.REDIS_URL)
        await r.ping()
        await r.aclose()
        latency = (time.monotonic() - start) * 1000
        return ServiceHealth(
            service="redis",
            status="healthy",
            latency_ms=round(latency, 2),
        )
    except Exception as e:
        return ServiceHealth(
            service="redis",
            status="unhealthy",
            details=_log_unhealthy("redis", e),
        )


async def _check_idp() -> ServiceHealth:
    """DEV_MODE uses local development accounts; otherwise probe Keycloak's
    OIDC discovery document."""
    if settings.DEV_MODE:
        return ServiceHealth(
            service="identity_provider",
            status="mock",
            details="DEV_MODE: local development accounts; Keycloak not in use",
        )
    import httpx

    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=3, trust_env=False) as client:
            response = await client.get(f"{settings.KEYCLOAK_ISSUER_URL}/.well-known/openid-configuration")
        latency = round((time.monotonic() - start) * 1000, 2)
        if response.status_code == 200:
            return ServiceHealth(service="identity_provider", status="healthy", latency_ms=latency,
                                 details="Keycloak OIDC discovery reachable")
        return ServiceHealth(service="identity_provider", status="unhealthy", latency_ms=latency,
                             details=f"Keycloak discovery returned HTTP {response.status_code}")
    except httpx.HTTPError as exc:
        return ServiceHealth(service="identity_provider", status="unhealthy",
                             details=_log_unhealthy("identity_provider", exc))


async def _check_vault() -> ServiceHealth:
    """
    Check the configured secret provider. Reports reachability only: the
    detail strings come from ProviderHealth, which never includes the token
    or any secret value. The mock provider is healthy only in DEV_MODE —
    anywhere else it is reported degraded rather than passed off as real.
    """
    from app.secret_providers import get_secret_provider

    result = await get_secret_provider().health()
    if result.provider == "mock" and result.healthy and not settings.DEV_MODE:
        return ServiceHealth(service="vault", status="degraded", details="Mock secret provider active outside DEV_MODE")
    if result.provider == "mock":
        return ServiceHealth(service="vault", status="mock",
                             details="mock: in-memory development secrets; OpenBao not in use")
    return ServiceHealth(
        service="vault",
        status="healthy" if result.healthy else "unhealthy",
        latency_ms=result.latency_ms,
        details=f"{result.provider}: {result.detail}",
    )


async def _check_ssh_gateway(db: AsyncSession) -> ServiceHealth:
    """The SSH gateway runs inside the backend, so "healthy" must mean more
    than a configured path: the trusted host-key file has to parse and cover
    every enabled SSH target (anything uncovered is refused at connect time).
    Target reachability and credentials are only known when connecting."""
    import os

    import asyncssh
    from sqlalchemy import select

    from app.models.asset import Asset

    path = os.environ.get("SECUREPAM_KNOWN_HOSTS_PATH")
    if not path or not os.path.isfile(path):
        return ServiceHealth(service="gateway_ssh", status="not_configured",
                             details="No trusted host keys provisioned (SECUREPAM_KNOWN_HOSTS_PATH); SSH connections will be refused")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            known_hosts = asyncssh.import_known_hosts(handle.read())
    except Exception as exc:
        return ServiceHealth(service="gateway_ssh", status="unhealthy",
                             details=_log_unhealthy("gateway_ssh", exc))

    assets = (await db.execute(
        select(Asset).where(Asset.protocol == "SSH", Asset.enabled == True,  # noqa: E712
                            Asset.is_deleted == False)  # noqa: E712
    )).scalars().all()
    uncovered = [a.name for a in assets if not known_hosts.match(a.hostname, a.ip_address, a.port)[0]]
    if uncovered:
        return ServiceHealth(
            service="gateway_ssh", status="degraded",
            details=f"No trusted host key for {len(uncovered)} of {len(assets)} enabled SSH target(s): "
                    f"{', '.join(sorted(uncovered)[:5])}; connections to them are refused",
        )
    return ServiceHealth(
        service="gateway_ssh", status="healthy",
        details=f"Host keys verified for {len(assets)} enabled SSH target(s); target reachability is checked at connect time",
    )


async def _check_rdp_gateway() -> ServiceHealth:
    """Healthy only if guacd actually accepts a connection and recordings can be written."""
    from app.services.rdp_gateway import get_rdp_gateway, rdp_recording_writable

    if not settings.RDP_GATEWAY_ENABLED:
        return ServiceHealth(service="gateway_rdp", status="not_configured",
                             details="Guacamole (guacd) is not configured; RDP sessions cannot connect")
    gateway = get_rdp_gateway()
    start = time.monotonic()
    if not await gateway.available():
        return ServiceHealth(service="gateway_rdp", status="unhealthy",
                             details="guacd is configured but not reachable; RDP sessions cannot connect")
    latency = round((time.monotonic() - start) * 1000, 2)
    if not rdp_recording_writable():
        return ServiceHealth(service="gateway_rdp", status="degraded", latency_ms=latency,
                             details="guacd is reachable but RDP recording storage is not writable; "
                                     "sessions that require recording are refused")
    return ServiceHealth(service="gateway_rdp", status="healthy", latency_ms=latency,
                         details="guacd accepts connections and RDP recording storage is writable")


async def _check_gateways(db: AsyncSession) -> List[ServiceHealth]:
    """Report each session gateway by what is actually deployed."""
    return [
        await _check_ssh_gateway(db),
        await _check_rdp_gateway(),
        await _check_web_gateway(),
    ]


async def _check_web_gateway() -> ServiceHealth:
    """Isolated-browser gateway: a real, bounded probe of the isolation daemon (see probe_isolation_daemon)."""
    from app.services.browser_isolation import probe_isolation_daemon

    result = await probe_isolation_daemon()
    return ServiceHealth(service="gateway_web", status=result.status, latency_ms=result.latency_ms,
                         details=result.details)


def _check_recording_storage() -> ServiceHealth:
    from app.services.terminal_recorder import storage_writable

    if storage_writable():
        return ServiceHealth(service="recording_storage", status="healthy",
                             details="Recording storage writable")
    return ServiceHealth(service="recording_storage", status="unhealthy",
                         details="Recording storage is not writable; sessions that require recording will be refused")


def _check_siem() -> ServiceHealth:
    """Check SIEM status."""
    if settings.DEV_MODE or not settings.WAZUH_ENABLED:
        return ServiceHealth(
            service="siem",
            status="not_configured",
            details="No SIEM forwarding; events are kept in the SecurePAM audit log only",
        )
    return ServiceHealth(
        service="siem",
        status="degraded",
        details="Wazuh not yet configured",
    )
