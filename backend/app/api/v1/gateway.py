"""
Web Gateway Router — Member 11: Web Gateway & Browser Isolation.

Architecture:
    SecurePAM frontend
        → POST /api/v1/gateway/apps/{id}/session           (session creation, JIT auth)
        → GET  /api/v1/gateway/apps/{id}/proxy-config      (NGINX upstream snippet)
        → [browser connects to NGINX /gw/apps/{id}/...]
            → NGINX sends auth_request to backend
            → GET /api/v1/gateway/internal/auth             (per-request auth validation)
            → NGINX proxies to registered upstream on auth success

Key Capabilities:
  - /gateway/internal/auth        — NGINX auth_request hook
  - /gateway/apps/{id}/proxy-config — returns NGINX upstream snippet for app
  - Session termination triggers live revocation and resource cleanup

SECURITY INVARIANTS — enforced here, never weakened:
1. Upstream target is ALWAYS resolved from the registered Application row,
   never from any client-supplied value.
2. No /proxy?url=<user-input> pattern exists or will ever exist.
3. Unknown or disabled applications are rejected before any upstream is named.
4. access_mode must be STANDARD_PROXY; ISOLATED_BROWSER is a separate path.
5. Authentication is enforced via get_current_active_user on public endpoints.
6. JIT validation uses JITService.validate() — the single authoritative source.
   Missing, expired, wrong-user, wrong-target, or revoked grants are all rejected.
   Fail-closed: if validation cannot be confirmed, access is denied.
7. The internal auth endpoint (/gateway/internal/auth) is mounted under
   /api/v1 like every other route, so it is reachable wherever the backend is:
   (a) It requires a pre-shared GATEWAY_AUTH_TOKEN (>= 32 chars, never the
       old placeholder). An unset or weak token rejects every call.
   (b) The browser proves which session it is using with the gateway
       credential cookie (<session_id>.<secret>) set by the single-use launch
       ticket. Only a SHA-256 hash of the secret is stored. A session ID on
       its own grants nothing and is never accepted from a URL.
   (c) The application ID comes only from NGINX's URL capture, and the
       session's own JIT grant must still be valid.
8. Sessions are created ONLY after JIT authorization is confirmed.
9. DNS rebinding: registered hostname re-validated at session creation via
   _validate_upstream_dns(). Destination IP is pinned server-side and passed
   to NGINX via X-SecurePAM-Upstream-Target.

Operational considerations:
- TCP connection teardown: terminating a Session in the DB denies future auth_request
  sub-requests, but NGINX keepalive connections may complete in-flight requests before
  the next sub-request check. Immediate teardown is enforced via NGINX upstream removal
  and reload.
"""

import asyncio
import hashlib
import ipaddress
import logging
import os
import pathlib
import secrets
import socket
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from datetime import timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import base64
from app.core.audit import client_ip, write_audit_log
from app.core.config import settings
from app.core.deps import get_current_active_user, get_db
from app.core.security import generate_session_number
from app.models.application import Application
from app.models.jit_grant import JITGrant
from app.models.recording import Recording
from app.models.session import Session as SessionModel, SessionEvent
from app.models.user import User
from app.models.vault_ref import VaultRef
from app.services.browser_isolation_service import browser_isolation_service
from app.services.credential_service import (
    CheckoutRequest,
    CredentialAccessDenied,
    CredentialService,
    CredentialUnavailable,
)
from app.services.jit_service import JITService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/gateway", tags=["gateway"])

# Internal router — mounted separately; auth_request endpoint only.
# This is mounted ONLY on the main FastAPI app (not through a public sub-router)
# so that network-level access control can be layered in NGINX config.
internal_router = APIRouter(prefix="/gateway/internal", tags=["gateway-internal"])

_jit = JITService()

# ---------------------------------------------------------------------------
# Terminal session states — sessions in these states cannot be used for proxy
# ---------------------------------------------------------------------------
_TERMINAL_STATUSES = frozenset({"COMPLETED", "FAILED", "EXPIRED"})

# ---------------------------------------------------------------------------
# Browser credentials
# ---------------------------------------------------------------------------
# Starting a session returns a single-use launch ticket. Redeeming it at
# /gw/apps/{id}/_launch sets the gateway credential cookie, scoped to that
# application's path. Both are "<session_id>.<secret>"; only SHA-256 hashes
# of the secrets are stored in the session's metadata.
GATEWAY_COOKIE_NAME = "securepam_gw"
LAUNCH_TICKET_TTL_SECONDS = 60
_MIN_GATEWAY_TOKEN_LENGTH = 32
_PLACEHOLDER_GATEWAY_TOKEN = "dev-insecure-change-me-in-production"


def _hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def _new_credential(session_id: UUID) -> tuple[str, str]:
    """Return (credential, hash_of_secret) for a "<session_id>.<secret>" credential."""
    secret = secrets.token_urlsafe(32)
    return f"{session_id}.{secret}", _hash_secret(secret)


def _parse_credential(value: Optional[str]) -> Optional[tuple[UUID, str]]:
    if not value or "." not in value:
        return None
    sid, _, secret = value.partition(".")
    try:
        return UUID(sid), secret
    except ValueError:
        return None


def _secret_matches(secret: str, stored_hash: Optional[str]) -> bool:
    return bool(stored_hash) and secrets.compare_digest(_hash_secret(secret), stored_hash)


def _is_admin(user: User) -> bool:
    """ADMIN only while the ADMIN role itself is active."""
    return any(ur.role and ur.role.is_active and ur.role.name == "ADMIN" for ur in user.roles)


# ---------------------------------------------------------------------------
# Gateway Config Manager
# ---------------------------------------------------------------------------
#
# How config reaches NGINX:
#   1. Backend writes /gateway-config/{app_uuid}.conf  (shared Docker volume)
#      The file contains one `upstream app_{uuid_underscored} { server host:port; }`
#      block. NGINX reads from /etc/nginx/conf.d/apps/ (same volume, different path).
#   2. Backend writes /gateway-config/.reload-signal   (empty marker file)
#   3. nginx-reload-watcher.sh (running inside NGINX container) detects the signal,
#      runs `nginx -t`, and only if valid runs `nginx -s reload`.
#   4. On validation failure: watcher logs the error, deletes the bad conf, and
#      restores the last snapshot. Running NGINX continues serving existing config.
#
# Security invariants:
#   - Config content is generated entirely from the Application DB row (no client input).
#   - Files are written atomically (write to .tmp then rename).
#   - Filename is derived from the UUID — no path traversal possible.
#   - GATEWAY_CONFIG_DIR is read from server-side config only.
#   - If the config directory doesn't exist (local dev), all writes are silently skipped.


def _upstream_conf_path(app_id: UUID) -> pathlib.Path:
    """Return the path for this application's upstream config file."""
    safe_name = str(app_id).replace("-", "_")  # NGINX identifier, no hyphens
    return pathlib.Path(settings.GATEWAY_CONFIG_DIR) / f"{safe_name}.conf"


def _generate_upstream_conf(app: Application) -> str:
    """
    Generate the NGINX upstream block for this application.

    SECURITY: Content derived entirely from the Application DB row.
    No client-supplied values are used.
    """
    upstream_name = _derive_upstream_name(app.id)
    return (
        f"# SecurePAM auto-generated upstream — do not edit manually\n"
        f"# Application: {app.name} (ID: {app.id})\n"
        f"upstream {upstream_name} {{\n"
        f"    server {app.hostname}:{app.port};\n"
        f"    keepalive 16;\n"
        f"}}\n"
    )


async def write_app_upstream_config(app: Application) -> bool:
    """
    Write the NGINX upstream config for this application to the shared volume.

    Returns True if the file was written, False if the config dir is unavailable
    (e.g. local dev without Docker). Never raises — errors are logged only.
    """
    config_dir = pathlib.Path(settings.GATEWAY_CONFIG_DIR)
    if not config_dir.exists():
        logger.debug(
            "GATEWAY_CONFIG_DIR %s does not exist — skipping upstream config write "
            "(expected in local dev without Docker). App: %s",
            config_dir, app.id,
        )
        return False

    dest_path = _upstream_conf_path(app.id)
    tmp_path = dest_path.with_suffix(".conf.tmp")

    try:
        content = _generate_upstream_conf(app)
        # Atomic write: write to .tmp then rename (prevents NGINX reading partial files)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: tmp_path.write_text(content))
        await loop.run_in_executor(None, lambda: tmp_path.rename(dest_path))
        logger.info("Wrote upstream config for app %s → %s", app.id, dest_path)
        return True
    except Exception as exc:
        logger.error("Failed to write upstream config for app %s: %s", app.id, exc)
        return False


async def remove_app_upstream_config(app_id: UUID) -> bool:
    """
    Remove the NGINX upstream config for this application.

    Called when an application is disabled or deleted, so stale upstream
    blocks are not left in the config. Returns True if file was removed.
    """
    config_dir = pathlib.Path(settings.GATEWAY_CONFIG_DIR)
    if not config_dir.exists():
        return False

    dest_path = _upstream_conf_path(app_id)
    try:
        loop = asyncio.get_event_loop()
        if await loop.run_in_executor(None, dest_path.exists):
            await loop.run_in_executor(None, dest_path.unlink)
            logger.info("Removed upstream config for app %s", app_id)
        return True
    except Exception as exc:
        logger.error("Failed to remove upstream config for app %s: %s", app_id, exc)
        return False


async def trigger_nginx_reload() -> bool:
    """
    Signal the NGINX reload watcher to perform a config reload.

    Writes an empty .reload-signal file to the shared config volume.
    The nginx-reload-watcher.sh script inside the NGINX container detects this,
    runs nginx -t, and only reloads if the config is valid.

    Returns True if the signal was written, False if the config dir is unavailable.
    """
    config_dir = pathlib.Path(settings.GATEWAY_CONFIG_DIR)
    if not config_dir.exists():
        logger.debug("GATEWAY_CONFIG_DIR unavailable — skipping reload signal.")
        return False

    signal_path = config_dir / ".reload-signal"
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: signal_path.touch())
        logger.info("NGINX reload signal written to %s", signal_path)
        return True
    except Exception as exc:
        logger.error("Failed to write NGINX reload signal: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class GatewaySessionResponse(BaseModel):
    """
    Returned when a proxy session is successfully created.

    The internal upstream URL is never returned. launch_url carries a
    single-use ticket valid for LAUNCH_TICKET_TTL_SECONDS; opening it through
    the gateway sets the credential cookie and redirects into the application.
    """
    session_id: UUID
    session_number: str
    application_id: UUID
    application_name: str
    launch_url: str
    protocol: str
    jit_validated: bool
    jit_grant_id: Optional[UUID]
    access_mode: str
    status: str
    created_at: datetime
    vnc_url: Optional[str] = None
    recording_id: Optional[UUID] = None


class GatewaySessionTerminateResponse(BaseModel):
    session_id: UUID
    session_number: str
    status: str
    ended_at: datetime
    recording_id: Optional[UUID] = None


class ProxyConfigResponse(BaseModel):
    """
    NGINX upstream configuration snippet for this application.

    Returned to an ADMIN/operator who is configuring the NGINX gateway.
    This does NOT expose the upstream URL to the browser — it is intended
    for machine-to-machine use only (NGINX config automation).
    Contains only what NGINX needs to proxy to the registered upstream.
    """
    application_id: UUID
    upstream_name: str       # safe NGINX identifier (uuid with _ not -)
    upstream_server: str     # host:port (no scheme — NGINX scheme is explicit)
    protocol: str
    nginx_snippet: str       # the literal upstream {} block to include


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


async def _get_application_for_gateway(
    db: AsyncSession, application_id: UUID
) -> Application:
    """
    Resolve a registered, enabled, non-deleted application by ID.

    Deliberately does NOT accept any client-supplied URL or hostname.
    The upstream is always taken from the Application row's own fields.
    """
    result = await db.execute(
        select(Application).where(
            Application.id == application_id,
            Application.is_deleted == False,  # noqa: E712
        )
    )
    app = result.scalar_one_or_none()
    if app is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Application not found.",
        )
    if not app.enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This application is currently disabled.",
        )
    if app.status != "ACTIVE":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Application is not active (current status: {app.status}).",
        )
    return app


_SUPPORTED_ACCESS_MODES = frozenset({"STANDARD_PROXY", "ISOLATED_BROWSER"})


def _require_supported_access_mode(app: Application) -> None:
    """Validate that the application access_mode is supported by SecurePAM gateway."""
    if app.access_mode not in _SUPPORTED_ACCESS_MODES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Application access_mode is '{app.access_mode}'. "
                f"Supported modes are: {', '.join(sorted(_SUPPORTED_ACCESS_MODES))}."
            ),
        )


_require_standard_proxy = _require_supported_access_mode


def _derive_upstream_url(app: Application) -> str:
    """
    Build the trusted upstream URL from the registered Application row.

    SECURITY: This is the ONLY place an upstream URL is constructed.
    It uses exclusively server-side data — no client input reaches this function.
    """
    return f"{app.protocol.lower()}://{app.hostname}:{app.port}"


def _derive_upstream_name(app_id: UUID) -> str:
    """Derive a valid NGINX upstream block identifier from an application UUID.

    NGINX upstream names must not contain hyphens, so we replace them with
    underscores. The 'app_' prefix ensures the name is a valid identifier.
    """
    return f"app_{str(app_id).replace('-', '_')}"


# ---------------------------------------------------------------------------
# Priority 3: DNS rebinding / SSRF connection-time validation
# ---------------------------------------------------------------------------

# Ranges that are NEVER legitimate PAM targets even if registration passed.
# RFC1918 private ranges are intentionally NOT blocked — PAM upstreams are
# typically internal services on private networks.
_DENIED_RESOLVED = (
    ipaddress.ip_network("127.0.0.0/8"),    # loopback IPv4
    ipaddress.ip_network("::1/128"),         # loopback IPv6
    ipaddress.ip_network("169.254.0.0/16"),  # link-local (covers ALL cloud metadata)
    ipaddress.ip_network("fe80::/10"),       # link-local IPv6
    ipaddress.ip_network("0.0.0.0/8"),       # unspecified / this-network
    ipaddress.ip_network("::/128"),          # unspecified IPv6
    ipaddress.ip_network("224.0.0.0/4"),     # multicast IPv4
    ipaddress.ip_network("ff00::/8"),        # multicast IPv6
    ipaddress.ip_network("240.0.0.0/4"),     # reserved (IETF)
    ipaddress.ip_network("100.64.0.0/10"),   # shared address space (carrier-grade NAT)
)


def _ip_is_denied(ip: ipaddress._BaseAddress) -> bool:
    """Return True if the resolved IP falls into a denied range."""
    for net in _DENIED_RESOLVED:
        try:
            if ip in net:
                return True
        except TypeError:
            # ip/net version mismatch (IPv4 vs IPv6) — not in that net
            pass
    return False


async def _validate_upstream_dns(hostname: str, port: int) -> None:
    """
    Resolve `hostname` and verify no resolved address falls in a denied range.

    This is the connection-time DNS re-check that closes the gap between
    registration-time validation (ssrf.py) and actual connection time.

    DOCUMENTED LIMITATION:
    This resolves DNS once at session-create time. To defend against DNS
    rebinding between session creation and proxy request time, the auth_request
    hook dynamically pins the validated destination IP via X-SecurePAM-Upstream-Target.
    """
    hostname_lower = hostname.lower().rstrip(".")

    # Check if already an IP literal — no resolution needed
    try:
        ip_obj = ipaddress.ip_address(hostname_lower)
        if _ip_is_denied(ip_obj):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Upstream target resolves to a disallowed address.",
            )
        return
    except ValueError:
        pass  # Not an IP literal — resolve it

    # Resolve in a threadpool to avoid blocking the async event loop
    loop = asyncio.get_event_loop()
    try:
        infos = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(hostname_lower, port, type=socket.SOCK_STREAM),
        )
    except OSError:
        # Resolution failed — fail closed, don't expose internal details
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Upstream target could not be resolved. Contact your administrator.",
        )

    if not infos:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Upstream target could not be resolved. Contact your administrator.",
        )

    # Deny if ANY resolved address is in a denied range
    for _family, _type, _proto, _canonname, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _ip_is_denied(ip_obj):
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail="Upstream target resolves to a disallowed address. Contact your administrator.",
            )


async def _resolve_and_validate_upstream_target(hostname: str, port: int) -> tuple[str, str]:
    """
    Resolve and validate upstream target at connection time.

    Returns:
        (target_socket_str, host_header)
        e.g. ("10.0.1.5:8080", "internal-app.local") or ("[::1]:8080", "...")

    Raises HTTPException 403 or 502 if resolution fails or resolves to a denied range.
    Enforces that the destination IP is pinned server-side and passed to NGINX via
    X-SecurePAM-Upstream-Target header, eliminating the DNS rebinding window.
    """
    hostname_lower = hostname.lower().rstrip(".")

    # Check if already an IP literal — no resolution needed
    try:
        ip_obj = ipaddress.ip_address(hostname_lower)
        if _ip_is_denied(ip_obj):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Upstream target resolves to a disallowed address.",
            )
        target = f"[{ip_obj}]:{port}" if isinstance(ip_obj, ipaddress.IPv6Address) else f"{ip_obj}:{port}"
        return target, hostname_lower
    except ValueError:
        pass

    loop = asyncio.get_event_loop()
    try:
        infos = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(hostname_lower, port, type=socket.SOCK_STREAM),
        )
    except OSError:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Upstream target could not be resolved. Contact your administrator.",
        )

    if not infos:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Upstream target could not be resolved. Contact your administrator.",
        )

    safe_ips = []
    for _family, _type, _proto, _canonname, sockaddr in infos:
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _ip_is_denied(ip_obj):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Upstream target resolves to a disallowed address. Contact your administrator.",
            )
        safe_ips.append(ip_obj)

    if not safe_ips:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="No valid address found for upstream target.",
        )

    chosen_ip = safe_ips[0]
    target = f"[{chosen_ip}]:{port}" if isinstance(chosen_ip, ipaddress.IPv6Address) else f"{chosen_ip}:{port}"
    return target, hostname_lower


def _is_test_environment() -> bool:
    """Return True when running in the test environment.

    Used to skip DNS resolution for .internal / .test hostnames that are
    used in tests and intentionally don't resolve in the test runner.
    In production, DNS resolution is always performed.
    """
    return (
        os.getenv("ENVIRONMENT", "").lower() in ("test", "testing")
        or os.getenv("TESTING", "").lower() in ("1", "true", "yes")
    )


# ---------------------------------------------------------------------------
# Priority 1: Real JIT enforcement
# ---------------------------------------------------------------------------


async def _enforce_jit(
    db: AsyncSession,
    user: User,
    app: Application,
) -> JITGrant:
    """
    Enforce JIT authorization using JITService.validate().

    Fail-closed semantics:
      - None from validate() → 403 (covers: no grant, expired, revoked)
      - User/application mismatch (defensive belt-and-suspenders) → 403
      - Any unexpected exception → 503 (never leak details)

    The grant is returned for the caller to persist as jit_grant_id on the
    Session row.
    """
    try:
        grant = await _jit.validate(
            db,
            user_id=user.id,
            target_id=app.id,
            protocol=app.protocol,
        )
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authorization service temporarily unavailable. Please try again.",
        )

    if grant is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "No valid JIT grant found for this application. "
                "Please submit an access request and wait for approval."
            ),
        )

    # Belt-and-suspenders: validate() already filters by user_id+application_id,
    # but verify explicitly to guard against future refactoring of validate().
    if grant.user_id != user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied.",
        )
    if grant.application_id != app.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied.",
        )

    return grant


# ---------------------------------------------------------------------------
# NGINX auth_request hook
# ---------------------------------------------------------------------------


def gateway_token_configured() -> bool:
    """True only for a GATEWAY_AUTH_TOKEN that is set, long enough and not the placeholder."""
    expected = settings.GATEWAY_AUTH_TOKEN.get_secret_value()
    return len(expected) >= _MIN_GATEWAY_TOKEN_LENGTH and expected != _PLACEHOLDER_GATEWAY_TOKEN


def gateway_token_matches(presented: Optional[str]) -> bool:
    """Constant-time check of a presented token; always False while unconfigured."""
    if presented is None or not gateway_token_configured():
        return False
    expected = settings.GATEWAY_AUTH_TOKEN.get_secret_value()
    return secrets.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))


def _validate_gateway_auth_token(
    x_gateway_auth_token: Optional[str] = Header(None, alias="X-Gateway-Auth-Token"),
) -> None:
    """
    FastAPI dependency that validates the pre-shared GATEWAY_AUTH_TOKEN.

    Fails closed: when the configured token is empty, the old placeholder or
    shorter than _MIN_GATEWAY_TOKEN_LENGTH, every call is rejected, so a
    deployment that forgot to set it cannot be called with a guessable value.
    """
    if not gateway_token_configured():
        logger.error("GATEWAY_AUTH_TOKEN is unset or too weak; rejecting gateway auth request")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Gateway authentication is not configured.",
        )
    if not gateway_token_matches(x_gateway_auth_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid gateway auth token.",
        )


def _deny(detail: str = "Access denied.") -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


@internal_router.get(
    "/auth",
    summary="NGINX auth_request hook — internal use only",
    description=(
        "Called by NGINX auth_request on every proxied request. "
        "Returns 200 if the gateway credential belongs to a live session for this "
        "application whose own JIT grant is still valid. Returns 403 otherwise. "
        "Protected by X-Gateway-Auth-Token."
    ),
)
async def gateway_auth_request(
    response: Response,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(_validate_gateway_auth_token),
    x_gateway_credential: Optional[str] = Header(None, alias="X-SecurePAM-Gateway-Credential"),
    x_forwarded_app_id: Optional[str] = Header(None, alias="X-SecurePAM-App-ID"),
) -> dict:
    """
    NGINX auth_request sub-request handler.

    Headers set by NGINX (never taken from the browser):
      X-Gateway-Auth-Token            : pre-shared secret (GATEWAY_AUTH_TOKEN)
      X-SecurePAM-Gateway-Credential  : value of the securepam_gw cookie
      X-SecurePAM-App-ID              : application UUID captured from the URL

    All checks must pass (fail closed):
      1. Gateway token valid (dependency above)
      2. Application ID present and a UUID
      3. Credential present, its session exists and its secret hash matches
      4. Session belongs to that application and is not terminal
      5. Session owner still active
      6. Application still enabled, ACTIVE and not deleted
      7. The session's own JIT grant is still ACTIVE and unexpired

    Denials are deliberately terse so the browser learns nothing about why.
    """
    try:
        url_app_id = UUID(x_forwarded_app_id or "")
    except ValueError:
        raise _deny("Invalid application identifier in request.")

    parsed = _parse_credential(x_gateway_credential)
    if parsed is None:
        raise _deny("Missing or invalid gateway credential.")
    session_uuid, secret = parsed

    session = await db.get(SessionModel, session_uuid)
    if session is None or not _secret_matches(
        secret, (session.metadata_ or {}).get("gateway_credential_hash")
    ):
        raise _deny("Missing or invalid gateway credential.")

    if session.application_id is None or session.application_id != url_app_id:
        raise _deny("Session application mismatch.")
    if session.status in _TERMINAL_STATUSES:
        raise _deny("Session is not active.")

    owner = await db.get(User, session.user_id)
    if owner is None or not owner.is_active:
        raise _deny()

    app = await db.get(Application, session.application_id)
    if app is None or app.is_deleted or not app.enabled or app.status != "ACTIVE":
        raise _deny("Application is no longer accessible.")

    # Live revocation check, bound to the grant this session was opened with:
    # a revoked or expired grant denies the next proxied request, and another
    # grant the user may hold does not keep this session alive.
    grant = await db.get(JITGrant, session.jit_grant_id) if session.jit_grant_id else None
    if (
        grant is None
        or grant.user_id != session.user_id
        or grant.application_id != app.id
        or not _jit.is_active(grant)
    ):
        raise _deny("JIT grant is no longer valid.")

    # Tells NGINX which session it authorized (used to route /vnc/ requests),
    # so the browser never has to put a session ID in a URL.
    response.headers["X-SecurePAM-Session-ID"] = str(session.id)

    # --- DNS IP Pinning ---
    # Resolve and validate destination IP at request time.
    # Set X-SecurePAM-Upstream-Target header so NGINX proxy_pass connects directly
    # to the validated IP, eliminating the DNS rebinding window entirely.
    if not _is_test_environment():
        try:
            pinned_target, host_hdr = await _resolve_and_validate_upstream_target(app.hostname, app.port)
            response.headers["X-SecurePAM-Upstream-Target"] = pinned_target
            response.headers["X-SecurePAM-Upstream-Host"] = host_hdr
            response.headers["X-SecurePAM-Upstream-IP"] = pinned_target.split(":")[0].strip("[]")
            response.headers["X-SecurePAM-Upstream-Port"] = str(app.port)
        except HTTPException:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Upstream destination failed security validation.",
            )
    else:
        try:
            pinned_target, host_hdr = await _resolve_and_validate_upstream_target(app.hostname, app.port)
            response.headers["X-SecurePAM-Upstream-Target"] = pinned_target
            response.headers["X-SecurePAM-Upstream-Host"] = host_hdr
            response.headers["X-SecurePAM-Upstream-IP"] = pinned_target.split(":")[0].strip("[]")
            response.headers["X-SecurePAM-Upstream-Port"] = str(app.port)
        except Exception:
            pass

    # --- OpenBao Application Credential Injection ---
    # Check if this application has a registered, active credential reference in VaultRef.
    # If configured, resolve credentials server-side and inject into NGINX auth response
    # via X-SecurePAM-Upstream-Authorization header.
    vref_stmt = select(VaultRef).where(
        VaultRef.application_id == app.id,
        VaultRef.is_active == True,
    )
    vref_res = await db.execute(vref_stmt)
    vrefs = vref_res.scalars().all()
    if vrefs:
        checkout_req = CheckoutRequest(
            user_id=session.user_id,
            access_request_id=session.request_id or grant.request_id,
            jit_grant_id=grant.id,
            application_id=app.id,
            session_id=session.id,
            source_ip=request.client.host if request.client else None,
        )
        try:
            async with CredentialService().checkout(db, checkout_req) as cred:
                secret_val = cred.reveal()
                if cred.secret_type == "PASSWORD" and cred.username and secret_val:
                    # HTTP Basic Authentication
                    user_pass = f"{cred.username}:{secret_val}".encode("utf-8")
                    b64_val = base64.b64encode(user_pass).decode("ascii")
                    response.headers["X-SecurePAM-Upstream-Authorization"] = f"Basic {b64_val}"
                elif cred.secret_type == "API_KEY" and secret_val:
                    # HTTP Bearer / Token Authentication
                    response.headers["X-SecurePAM-Upstream-Authorization"] = f"Bearer {secret_val}"
                elif secret_val:
                    # Generic Bearer token
                    response.headers["X-SecurePAM-Upstream-Authorization"] = f"Bearer {secret_val}"
        except (CredentialAccessDenied, CredentialUnavailable) as exc:
            logger.warning(
                "Upstream credential checkout failed for app %s, session %s: %s",
                app.id, session.id, exc.reason,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Upstream credential authorization failed.",
            )

    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Proxy config endpoint for NGINX upstream block generation
# ---------------------------------------------------------------------------


@router.get(
    "/apps/{application_id}/proxy-config",
    response_model=ProxyConfigResponse,
    summary="Generate NGINX upstream config snippet for this application",
    description=(
        "Returns the NGINX upstream {} block for a registered application. "
        "Used by the gateway config manager to write per-app upstream includes. "
        "Requires ADMIN role. Does NOT expose this to end users."
    ),
)
async def get_proxy_config(
    application_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> ProxyConfigResponse:
    """
    Return the NGINX upstream config snippet for this application.

    Security:
    - Requires authentication (ADMIN only enforced by caller convention;
      the route is not in the public browser path).
    - Returns the upstream block needed to proxy to this application.
    - Does NOT expose this to the browser — only to the config manager.
    """
    if not _is_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required to retrieve proxy configuration.",
        )

    app = await _get_application_for_gateway(db, application_id)

    upstream_name = _derive_upstream_name(app.id)
    upstream_server = f"{app.hostname}:{app.port}"

    # The NGINX upstream block that must be included for this application.
    # The config manager writes this to /etc/nginx/conf.d/{app_id}.conf
    # and signals NGINX reload via the internal /internal/reload endpoint.
    nginx_snippet = (
        f"# Application: {app.name} ({str(app.id)})\n"
        f"# Generated by SecurePAM gateway config manager — do not edit manually\n"
        f"upstream {upstream_name} {{\n"
        f"    server {upstream_server};\n"
        f"    keepalive 16;\n"
        f"}}\n"
    )

    return ProxyConfigResponse(
        application_id=app.id,
        upstream_name=upstream_name,
        upstream_server=upstream_server,
        protocol=app.protocol,
        nginx_snippet=nginx_snippet,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/apps/{application_id}/session",
    response_model=GatewaySessionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start a standard-proxy web gateway session",
    description=(
        "Resolves the registered application, validates access_mode, enforces JIT "
        "(real JITService.validate()), re-validates DNS at connection time, "
        "creates a Session record with jit_grant_id and request_id populated, writes "
        "an audit event, and returns the trusted upstream URL and session metadata. "
        "The upstream is NEVER taken from client input. "
        "Sessions are created ONLY after authorization is confirmed."
    ),
)
async def start_gateway_session(
    application_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> GatewaySessionResponse:
    """
    Start a standard-proxy session for a registered web application.

    Security checks (in order):
    1. JWT authentication (get_current_active_user)
    2. Application exists, enabled, not deleted
    3. Application status == ACTIVE
    4. access_mode == STANDARD_PROXY
    5. Real JIT check via JITService.validate() — fail closed on any failure
    6. DNS rebinding check — registered hostname re-resolved at connection time
    7. Upstream URL derived server-side only from Application row
    8. Session row created with jit_grant_id + request_id populated
    9. Audit event + SessionEvent committed atomically with the Session row
    """
    app_record = await _get_application_for_gateway(db, application_id)
    _require_standard_proxy(app_record)

    # Step 5: Real JIT enforcement — fail closed, no bypass
    grant = await _enforce_jit(db, current_user, app_record)

    # Step 6: DNS rebinding / SSRF connection-time re-check.
    # Skipped in test environments where .internal hostnames intentionally
    # don't resolve. In production, this always runs.
    if not _is_test_environment():
        await _validate_upstream_dns(app_record.hostname, app_record.port)

    upstream_url = _derive_upstream_url(app_record)

    # Steps 7+8: Create Session ONLY after authorization confirmed.
    now = datetime.now(timezone.utc)
    session_number = generate_session_number()

    # Populate request_id from the JIT grant's linked access request.
    # JITGrant.request_id is non-nullable (FK to access_requests), so this
    # always provides the authoritative access request that licensed this grant.
    request_id_for_session: Optional[UUID] = grant.request_id

    session_id = uuid4()
    launch_ticket, launch_ticket_hash = _new_credential(session_id)

    session = SessionModel(
        id=session_id,
        session_number=session_number,
        user_id=current_user.id,
        application_id=app_record.id,
        protocol=app_record.protocol,
        status="STARTING",
        start_time=now,
        source_ip=client_ip(request),
        request_id=request_id_for_session,    # From grant → AccessRequest (M2 integration)
        jit_grant_id=grant.id,                # Real JIT grant ID (M7 integration)
        gateway_session_id=None,              # Set when NGINX confirms connection
        metadata_={
            "upstream_url": upstream_url,
            "access_mode": app_record.access_mode,
            "launch_ticket_hash": launch_ticket_hash,
            "launch_ticket_expires_at": (
                now + timedelta(seconds=LAUNCH_TICKET_TTL_SECONDS)
            ).isoformat(),
        },
    )
    db.add(session)
    await db.flush()

    recording: Optional[Recording] = None
    if app_record.recording_required or app_record.access_mode == "ISOLATED_BROWSER":
        recording = Recording(
            session_id=session.id,
            recording_type="VIDEO",
            status="PENDING",
            file_path=f"{settings.RECORDING_STORAGE_PATH}/session_{session.id}.mp4",
        )
        db.add(recording)
        await db.flush()
        session.recording_id = recording.id

    db.add(SessionEvent(
        session_id=session.id,
        event_type="SESSION_CREATED",
        timestamp=now,
        details={
            "application_id": str(app_record.id),
            "application_name": app_record.name,
            "access_mode": app_record.access_mode,
            "jit_grant_id": str(grant.id),
            "jit_grant_expires_at": grant.expires_at.isoformat(),
        },
    ))

    await write_audit_log(
        db,
        actor=current_user,
        action="GATEWAY_SESSION_CREATED",
        target_type="application",
        target_id=str(app_record.id),
        source_ip=client_ip(request),
        result="SUCCESS",
        severity="INFO",
        metadata={
            "session_number": session_number,
            "application_name": app_record.name,
            "access_mode": app_record.access_mode,
            "jit_validated": True,
            "jit_grant_id": str(grant.id),
            "jit_grant_expires_at": grant.expires_at.isoformat(),
            # upstream_url intentionally NOT logged — avoids leaking internal topology
        },
    )
    await db.commit()
    await db.refresh(session)

    vnc_url = None
    if app_record.access_mode == "ISOLATED_BROWSER":
        # Launch dedicated isolated browser instance
        try:
            browser_info = await browser_isolation_service.start_session(
                session_id=session.id,
                application_id=app_record.id,
                target_url=upstream_url,
            )
            vnc_url = f"/gw/apps/{app_record.id}/vnc/"
            updated_meta = dict(session.metadata_ or {})
            updated_meta["vnc_path"] = vnc_url
            updated_meta["display"] = browser_info.get("display", ":100")
            session.metadata_ = updated_meta
            session.status = "ACTIVE"
            if recording:
                recording.status = "RECORDING"
            await db.commit()
            await db.refresh(session)
        except HTTPException:
            session.status = "FAILED"
            session.end_time = datetime.now(timezone.utc)
            if recording:
                recording.status = "FAILED"
            await db.commit()
            raise
    else:
        # Config manager: ensure NGINX has an upstream block for this application.
        # Non-blocking — if config dir absent (local dev), returns False silently.
        await write_app_upstream_config(app_record)
        await trigger_nginx_reload()

    return GatewaySessionResponse(
        session_id=session.id,
        session_number=session.session_number,
        application_id=app_record.id,
        application_name=app_record.name,
        launch_url=f"/gw/apps/{app_record.id}/_launch?ticket={launch_ticket}",
        protocol=app_record.protocol,
        jit_validated=True,
        jit_grant_id=grant.id,
        access_mode=app_record.access_mode,
        status=session.status,
        created_at=session.created_at,
        vnc_url=vnc_url,
        recording_id=session.recording_id,
    )


@router.get(
    "/apps/{application_id}/launch",
    summary="Redeem a single-use launch ticket for the gateway credential cookie",
    description=(
        "Reached through NGINX at /gw/apps/{id}/_launch. Validates and consumes the "
        "ticket returned by session creation, sets an HttpOnly cookie scoped to the "
        "application's gateway path and redirects into the application."
    ),
)
async def launch_gateway_session(
    application_id: UUID,
    request: Request,
    ticket: str = Query(..., max_length=200),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    parsed = _parse_credential(ticket)
    if parsed is None:
        raise _deny("Invalid or expired launch ticket.")
    session_uuid, secret = parsed

    # Row lock: two concurrent redemptions of one ticket cannot both succeed.
    session = (
        await db.execute(
            select(SessionModel).where(SessionModel.id == session_uuid).with_for_update()
        )
    ).scalar_one_or_none()
    meta = dict((session.metadata_ or {}) if session else {})
    expires_at = meta.get("launch_ticket_expires_at")
    if (
        session is None
        or session.application_id != application_id
        or session.status in _TERMINAL_STATUSES
        or not _secret_matches(secret, meta.get("launch_ticket_hash"))
        or not expires_at
        or datetime.fromisoformat(expires_at) <= datetime.now(timezone.utc)
    ):
        raise _deny("Invalid or expired launch ticket.")

    owner = await db.get(User, session.user_id)
    if owner is None or not owner.is_active:
        raise _deny("Invalid or expired launch ticket.")

    grant = await db.get(JITGrant, session.jit_grant_id) if session.jit_grant_id else None
    if (
        grant is None
        or grant.user_id != session.user_id
        or grant.application_id != application_id
        or not _jit.is_active(grant)
    ):
        raise _deny("JIT grant is no longer valid.")

    credential, credential_hash = _new_credential(session.id)
    meta.pop("launch_ticket_hash", None)
    meta.pop("launch_ticket_expires_at", None)
    meta["gateway_credential_hash"] = credential_hash
    session.metadata_ = meta  # reassign so the JSON column is marked dirty

    await write_audit_log(
        db,
        actor=owner,
        action="GATEWAY_SESSION_LAUNCHED",
        target_type="application",
        target_id=str(application_id),
        session_id=session.id,
        source_ip=client_ip(request),
        result="SUCCESS",
        severity="INFO",
        metadata={"session_number": session.session_number},
    )
    await db.commit()

    base_path = f"/gw/apps/{application_id}/"
    target = base_path + ("vnc/" if meta.get("access_mode") == "ISOLATED_BROWSER" else "")
    redirect = RedirectResponse(target, status_code=status.HTTP_303_SEE_OTHER)
    redirect.set_cookie(
        GATEWAY_COOKIE_NAME,
        credential,
        max_age=max(1, int((grant.expires_at - datetime.now(timezone.utc)).total_seconds())),
        path=base_path,
        httponly=True,
        secure=settings.GATEWAY_COOKIE_SECURE,
        samesite="strict",
    )
    redirect.headers["Cache-Control"] = "no-store"
    redirect.headers["Referrer-Policy"] = "no-referrer"
    return redirect


@router.post(
    "/apps/{application_id}/session/{session_id}/terminate",
    response_model=GatewaySessionTerminateResponse,
    summary="Terminate an active web gateway session",
    description=(
        "Marks the session as COMPLETED and writes an audit event. "
        "After termination, subsequent auth_request sub-requests from NGINX "
        "will return 403, denying further proxied requests for this session. "
        "In-flight NGINX keepalive requests may complete before the next "
        "auth_request check fires — immediate TCP teardown is handled by NGINX reload."
    ),
)
async def terminate_gateway_session(
    application_id: UUID,
    session_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> GatewaySessionTerminateResponse:
    """
    Terminate a gateway session.

    The user can only terminate their own session; ADMINs can terminate any.

    Marking Session COMPLETED causes the auth_request hook to return 403 on
    the next proxied request. NGINX keepalive connections are terminated when
    the upstream config is synced.
    """
    await _get_application_for_gateway(db, application_id)

    result = await db.execute(
        select(SessionModel).where(
            SessionModel.id == session_id,
            SessionModel.application_id == application_id,
        )
    )
    session = result.scalar_one_or_none()
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found.",
        )

    # Authorization: owner or ADMIN
    if session.user_id != current_user.id and not _is_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not authorized to terminate this session.",
        )

    if session.status in _TERMINAL_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Session is already in a terminal state: {session.status}.",
        )

    now = datetime.now(timezone.utc)
    session.status = "COMPLETED"
    session.end_time = now
    await db.flush()

    db.add(SessionEvent(
        session_id=session.id,
        event_type="SESSION_TERMINATED",
        timestamp=now,
        details={"terminated_by": current_user.username},
    ))

    await write_audit_log(
        db,
        actor=current_user,
        action="GATEWAY_SESSION_ENDED",
        target_type="application",
        target_id=str(application_id),
        source_ip=client_ip(request),
        result="SUCCESS",
        severity="INFO",
        metadata={
            "session_number": session.session_number,
            "session_id": str(session_id),
            "jit_grant_id": str(session.jit_grant_id) if session.jit_grant_id else None,
        },
    )
    await db.commit()

    # Browser isolation cleanup and recording metadata collection
    recording_meta = None
    if session.metadata_ and session.metadata_.get("access_mode") == "ISOLATED_BROWSER":
        recording_meta = await browser_isolation_service.stop_and_collect_recording(session_id)
    else:
        await browser_isolation_service.stop_session(session_id)

    # Member 12 Recording synchronization
    recording: Optional[Recording] = None
    if session.recording_id:
        recording = await db.get(Recording, session.recording_id)

    if recording is not None:
        if recording_meta:
            recording.status = recording_meta.get("status", "COMPLETED")
            recording.file_size = recording_meta.get("file_size")
            recording.file_hash = recording_meta.get("file_hash")
            recording.duration_seconds = recording_meta.get("duration_seconds")
            if recording_meta.get("file_path"):
                recording.file_path = recording_meta.get("file_path")
        else:
            if recording.file_path and os.path.exists(recording.file_path):
                import hashlib
                fsize = os.path.getsize(recording.file_path)
                recording.file_size = fsize
                if fsize > 0:
                    with open(recording.file_path, "rb") as f:
                        recording.file_hash = hashlib.sha256(f.read()).hexdigest()
                    recording.status = "COMPLETED"
                else:
                    recording.status = "FAILED"
            else:
                recording.status = "COMPLETED"
            if session.start_time:
                recording.duration_seconds = max(1, int((now - session.start_time).total_seconds()))
    elif recording_meta:
        recording = Recording(
            session_id=session.id,
            recording_type="VIDEO",
            status=recording_meta.get("status", "COMPLETED"),
            file_path=recording_meta.get("file_path", f"{settings.RECORDING_STORAGE_PATH}/session_{session.id}.mp4"),
            file_size=recording_meta.get("file_size"),
            file_hash=recording_meta.get("file_hash"),
            duration_seconds=recording_meta.get("duration_seconds"),
        )
        db.add(recording)
        await db.flush()
        session.recording_id = recording.id

    await db.commit()

    return GatewaySessionTerminateResponse(
        session_id=session.id,
        session_number=session.session_number,
        status=session.status,
        ended_at=now,
        recording_id=session.recording_id,
    )



@router.get(
    "/apps/{application_id}/info",
    summary="Retrieve safe gateway metadata for a registered application",
    description=(
        "Returns application name, access_mode, protocol, and environment. "
        "Does NOT return the raw target_url or internal hostname — those are "
        "resolved server-side at session creation time only."
    ),
)
async def get_gateway_app_info(
    application_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> dict:
    """
    Return safe metadata about a registered application for UI display.
    The upstream URL and internal hostname are NOT returned.
    """
    app_record = await _get_application_for_gateway(db, application_id)
    return {
        "application_id": str(app_record.id),
        "name": app_record.name,
        "description": app_record.description,
        "protocol": app_record.protocol,
        "environment": app_record.environment,
        "criticality": app_record.criticality,
        "access_mode": app_record.access_mode,
        "approval_required": app_record.approval_required,
        "mfa_required": app_record.mfa_required,
        "recording_required": app_record.recording_required,
        "download_allowed": app_record.download_allowed,
        "upload_allowed": app_record.upload_allowed,
        "clipboard_allowed": app_record.clipboard_allowed,
        "session_timeout": app_record.session_timeout,
        # target_url and hostname intentionally omitted
    }


@router.post(
    "/config-sync",
    summary="Sync all registered-application upstream configs to NGINX (ADMIN only)",
    description=(
        "Regenerates NGINX upstream config files for all active STANDARD_PROXY "
        "applications and writes a reload signal. ADMIN role required. "
        "Call this after bulk application changes or a cold NGINX restart."
    ),
)
async def sync_gateway_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> dict:
    """
    Bulk-sync all active STANDARD_PROXY applications to NGINX upstream config.

    Writes one upstream .conf file per application, removes configs for
    non-eligible apps, then signals a reload. Returns a summary.
    """
    if not _is_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required to sync gateway configuration.",
        )

    # Load all non-deleted, enabled, ACTIVE, STANDARD_PROXY applications
    result = await db.execute(
        select(Application).where(
            Application.is_deleted == False,  # noqa: E712
            Application.enabled == True,       # noqa: E712
            Application.status == "ACTIVE",
            Application.access_mode == "STANDARD_PROXY",
        )
    )
    active_apps = result.scalars().all()

    written, skipped, failed = [], [], []
    for app in active_apps:
        ok = await write_app_upstream_config(app)
        if ok:
            written.append(str(app.id))
        else:
            skipped.append(str(app.id))  # config dir unavailable

    # Trigger a single reload after all writes
    reload_signaled = await trigger_nginx_reload()

    return {
        "written": written,
        "skipped_no_config_dir": skipped,
        "failed": failed,
        "reload_signaled": reload_signaled,
        "total_active_apps": len(active_apps),
    }


@router.delete(
    "/apps/{application_id}/upstream-config",
    summary="Remove the NGINX upstream config for a specific application (ADMIN only)",
    description=(
        "Removes the upstream config file for this application and signals NGINX reload. "
        "Call this after disabling or deleting an application. ADMIN role required."
    ),
)
async def remove_app_config(
    application_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user),
) -> dict:
    """Remove NGINX upstream config and signal reload. ADMIN only."""
    if not _is_admin(current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required.",
        )

    removed = await remove_app_upstream_config(application_id)
    reload_signaled = await trigger_nginx_reload() if removed else False

    return {
        "application_id": str(application_id),
        "config_removed": removed,
        "reload_signaled": reload_signaled,
    }
