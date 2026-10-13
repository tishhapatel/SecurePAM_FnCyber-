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
from app.core.deps import get_db
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
async def detailed_health_check(db: AsyncSession = Depends(get_db)):
    """Detailed health check with all service statuses."""
    services: List[ServiceHealth] = []

    # Database
    db_health = await _check_database(db)
    services.append(db_health)

    # Redis
    redis_health = await _check_redis()
    services.append(redis_health)

    # IdP
    idp_health = _check_idp()
    services.append(idp_health)

    # Vault
    vault_health = await _check_vault()
    services.append(vault_health)

    # Gateway
    gateway_health = _check_gateway()
    services.append(gateway_health)

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


def _check_idp() -> ServiceHealth:
    """Check IdP status."""
    if settings.DEV_MODE:
        return ServiceHealth(
            service="identity_provider",
            status="healthy",
            details="DEV_MODE: MockIdP active",
        )
    return ServiceHealth(
        service="identity_provider",
        status="degraded",
        details="Keycloak not yet configured",
    )


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
    return ServiceHealth(
        service="vault",
        status="healthy" if result.healthy else "unhealthy",
        latency_ms=result.latency_ms,
        details=f"{result.provider}: {result.detail}",
    )


def _check_gateway() -> ServiceHealth:
    """Check session gateway status."""
    if settings.DEV_MODE:
        return ServiceHealth(
            service="gateway",
            status="healthy",
            details="DEV_MODE: MockSessionProvider active",
        )
    return ServiceHealth(
        service="gateway",
        status="degraded",
        details="Guacamole not yet configured",
    )


def _check_siem() -> ServiceHealth:
    """Check SIEM status."""
    if settings.DEV_MODE or not settings.WAZUH_ENABLED:
        return ServiceHealth(
            service="siem",
            status="healthy",
            details="DEV_MODE: MockSIEM active",
        )
    return ServiceHealth(
        service="siem",
        status="degraded",
        details="Wazuh not yet configured",
    )
