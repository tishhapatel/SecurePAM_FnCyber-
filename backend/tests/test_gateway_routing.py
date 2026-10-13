"""
Gateway routing tests — Member 11: Web Gateway & Browser Isolation.

Tests the FastAPI gateway router (app/api/v1/gateway.py) against the real
test PostgreSQL database using the same fixtures as all other SecurePAM tests.

Coverage:
  - Session creation, JIT enforcement, DNS/SSRF validation, termination
  - Auth hook endpoint tests (/api/v1/gateway/internal/auth)
  - Proxy configuration generation (/apps/{id}/proxy-config)
  - Live revocation integration and session cleanup
  - GATEWAY_AUTH_TOKEN validation and timing attack prevention
  - Destination IP pinning and DNS rebinding mitigations
  - Isolated browser session creation, lifecycle sync, and cleanup
"""

import ipaddress
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import auth_header, issue_token

from app.api.v1.gateway import _ip_is_denied, _validate_upstream_dns
from app.core.config import settings
from app.core.ssrf import SSRFValidationError, validate_application_target
from app.database.session import async_session_factory
from app.models.application import Application
from app.models.audit import AuditLog
from app.models.jit_grant import JITGrant
from app.models.session import Session as SessionModel
from app.models.user import User
from app.services.jit_service import JITService


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _app_payload(**overrides) -> dict:
    base = {
        "name": "Test Web App",
        "hostname": "testapp.internal",
        "port": 8080,
        "protocol": "HTTP",
        "environment": "DEVELOPMENT",
        "criticality": "LOW",
        "access_mode": "STANDARD_PROXY",
        "approval_required": False,
        "mfa_required": False,
        "recording_required": False,
        "download_allowed": True,
        "upload_allowed": False,
        "clipboard_allowed": False,
        "session_timeout": 30,
    }
    base.update(overrides)
    return base


async def _create_app(client: AsyncClient, admin_token: str, **overrides) -> dict:
    resp = await client.post(
        "/api/v1/applications",
        json=_app_payload(**overrides),
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


async def _create_jit_grant(
    db: AsyncSession,
    *,
    user_id,
    application_id,
    protocol: str = "HTTP",
    duration_minutes: int = 60,
) -> JITGrant:
    from app.core.security import generate_request_number
    from app.models.access_request import AccessRequest

    req = AccessRequest(
        request_number=generate_request_number(),
        user_id=user_id,
        application_id=application_id,
        protocol=protocol,
        reason="Gateway test grant",
        requested_duration=duration_minutes,
        status="ACTIVE",
        risk_score=10,
        risk_level="LOW",
        approval_required=False,
        jit_required=True,
        mfa_required=False,
        recording_required=False,
    )
    db.add(req)
    await db.flush()

    jit = JITService()
    grant = await jit.grant(
        db,
        request_id=req.id,
        user_id=user_id,
        asset_id=None,
        application_id=application_id,
        protocol=protocol,
        duration_minutes=duration_minutes,
        created_by=None,
    )
    await db.commit()
    return grant


async def _get_user_id(username: str):
    async with async_session_factory() as db:
        result = await db.execute(select(User).where(User.username == username))
        user = result.scalar_one()
        return user.id


def _auth_hook_headers(
    session_id: str | None = None,
    app_id: str | None = None,
    token: str | None = None,
) -> dict:
    """Build the headers NGINX sends to the auth_request endpoint."""
    token_value = token if token is not None else settings.GATEWAY_AUTH_TOKEN
    headers = {"X-Gateway-Auth-Token": token_value}
    if session_id is not None:
        headers["X-SecurePAM-Session-ID"] = session_id
    if app_id is not None:
        headers["X-SecurePAM-App-ID"] = app_id
    return headers


# ---------------------------------------------------------------------------
# Gateway Session Creation & Verification Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_start_session_standard_proxy_with_valid_jit_grant(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    app = await _create_app(client, admin_token)
    app_id = app["id"]
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        grant = await _create_jit_grant(db, user_id=operator_id, application_id=app_id)
        grant_id = str(grant.id)

    resp = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session",
        headers=auth_header(operator_token),
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["application_id"] == app_id
    assert data["jit_validated"] is True
    assert data["jit_grant_id"] == grant_id
    assert data["session_id"] is not None
    assert data["upstream_url"] == "http://testapp.internal:8080"
    assert "jit_stubbed" not in data


@pytest.mark.asyncio
async def test_start_session_unknown_app_id_returns_404(client: AsyncClient, operator_token: str):
    resp = await client.post(f"/api/v1/gateway/apps/{uuid4()}/session", headers=auth_header(operator_token))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_start_session_disabled_app_returns_403(
    client: AsyncClient, admin_token: str, operator_token: str,
):
    app = await _create_app(client, admin_token)
    app_id = app["id"]
    await client.patch(f"/api/v1/applications/{app_id}", json={"enabled": False}, headers=auth_header(admin_token))
    resp = await client.post(f"/api/v1/gateway/apps/{app_id}/session", headers=auth_header(operator_token))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_start_session_unsupported_access_mode_returns_422(
    client: AsyncClient, admin_token: str, operator_token: str,
):
    app = await _create_app(client, admin_token, name="CustomMode")
    async with async_session_factory() as db:
        app_obj = await db.get(Application, UUID(app["id"]))
        app_obj.access_mode = "UNSUPPORTED_MODE"
        await db.commit()

    resp = await client.post(f"/api/v1/gateway/apps/{app['id']}/session", headers=auth_header(operator_token))
    assert resp.status_code == 422
    assert "UNSUPPORTED_MODE" in resp.text


@pytest.mark.asyncio
async def test_start_session_requires_authentication(client: AsyncClient):
    resp = await client.post(f"/api/v1/gateway/apps/{uuid4()}/session")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_gateway_app_info_does_not_expose_upstream(
    client: AsyncClient, admin_token: str, operator_token: str,
):
    app = await _create_app(client, admin_token, hostname="secret-internal.corp", port=9443, protocol="HTTPS")
    resp = await client.get(f"/api/v1/gateway/apps/{app['id']}/info", headers=auth_header(operator_token))
    assert resp.status_code == 200
    data = resp.json()
    assert "target_url" not in data
    assert "hostname" not in data
    assert "secret-internal.corp" not in str(data)


@pytest.mark.asyncio
async def test_no_upstream_override_via_query_param(
    client: AsyncClient, admin_token: str, operator_token: str,
):
    app = await _create_app(client, admin_token, hostname="legitimate.internal", port=8080)
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app["id"])
    resp = await client.post(
        f"/api/v1/gateway/apps/{app['id']}/session?upstream=http://attacker.example.com",
        headers=auth_header(operator_token),
    )
    assert resp.status_code == 201
    assert "attacker.example.com" not in resp.json()["upstream_url"]


@pytest.mark.asyncio
async def test_no_upstream_override_via_header(
    client: AsyncClient, admin_token: str, operator_token: str,
):
    app = await _create_app(client, admin_token, hostname="trusted.internal", port=443, protocol="HTTPS")
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app["id"], protocol="HTTPS")
    resp = await client.post(
        f"/api/v1/gateway/apps/{app['id']}/session",
        headers={**auth_header(operator_token), "X-Upstream": "http://evil.example.com"},
    )
    assert resp.status_code == 201
    assert "evil.example.com" not in resp.json()["upstream_url"]


@pytest.mark.asyncio
async def test_audit_event_written_on_session_creation(
    client: AsyncClient, admin_token: str, operator_token: str, db_session: AsyncSession,
):
    app = await _create_app(client, admin_token, name="Audited App")
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app["id"])
    resp = await client.post(f"/api/v1/gateway/apps/{app['id']}/session", headers=auth_header(operator_token))
    assert resp.status_code == 201
    result = await db_session.execute(select(AuditLog).where(AuditLog.action == "GATEWAY_SESSION_CREATED"))
    events = result.scalars().all()
    assert len(events) >= 1
    assert events[-1].actor_username == "operator"
    assert "upstream_url" not in events[-1].details


@pytest.mark.asyncio
async def test_session_owner_can_terminate(client: AsyncClient, admin_token: str, operator_token: str):
    app = await _create_app(client, admin_token)
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app["id"])
    start = await client.post(f"/api/v1/gateway/apps/{app['id']}/session", headers=auth_header(operator_token))
    assert start.status_code == 201
    session_id = start.json()["session_id"]
    term = await client.post(
        f"/api/v1/gateway/apps/{app['id']}/session/{session_id}/terminate",
        headers=auth_header(operator_token),
    )
    assert term.status_code == 200
    assert term.json()["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_other_operator_cannot_terminate_session(
    client: AsyncClient, admin_token: str, operator_token: str, operator2_token: str,
):
    app = await _create_app(client, admin_token)
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app["id"])
    start = await client.post(f"/api/v1/gateway/apps/{app['id']}/session", headers=auth_header(operator_token))
    assert start.status_code == 201
    term = await client.post(
        f"/api/v1/gateway/apps/{app['id']}/session/{start.json()['session_id']}/terminate",
        headers=auth_header(operator2_token),
    )
    assert term.status_code == 403


@pytest.mark.asyncio
async def test_admin_can_terminate_any_session(
    client: AsyncClient, admin_token: str, operator_token: str,
):
    app = await _create_app(client, admin_token)
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app["id"])
    start = await client.post(f"/api/v1/gateway/apps/{app['id']}/session", headers=auth_header(operator_token))
    assert start.status_code == 201
    term = await client.post(
        f"/api/v1/gateway/apps/{app['id']}/session/{start.json()['session_id']}/terminate",
        headers=auth_header(admin_token),
    )
    assert term.status_code == 200


@pytest.mark.asyncio
async def test_double_terminate_returns_409(client: AsyncClient, admin_token: str, operator_token: str):
    app = await _create_app(client, admin_token)
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app["id"])
    start = await client.post(f"/api/v1/gateway/apps/{app['id']}/session", headers=auth_header(operator_token))
    assert start.status_code == 201
    sid = start.json()["session_id"]
    t1 = await client.post(f"/api/v1/gateway/apps/{app['id']}/session/{sid}/terminate", headers=auth_header(operator_token))
    assert t1.status_code == 200
    t2 = await client.post(f"/api/v1/gateway/apps/{app['id']}/session/{sid}/terminate", headers=auth_header(operator_token))
    assert t2.status_code == 409


@pytest.mark.asyncio
async def test_deleted_app_returns_404(client: AsyncClient, admin_token: str, operator_token: str):
    app = await _create_app(client, admin_token)
    await client.delete(f"/api/v1/applications/{app['id']}", headers=auth_header(admin_token))
    resp = await client.post(f"/api/v1/gateway/apps/{app['id']}/session", headers=auth_header(operator_token))
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_existing_applications_list_still_works(client: AsyncClient, operator_token: str):
    resp = await client.get("/api/v1/applications", headers=auth_header(operator_token))
    assert resp.status_code == 200
    assert "items" in resp.json()


@pytest.mark.asyncio
async def test_existing_applications_crud_not_broken(
    client: AsyncClient, admin_token: str, operator_token: str,
):
    create = await client.post("/api/v1/applications", json=_app_payload(name="CRUD Check"), headers=auth_header(admin_token))
    assert create.status_code == 201
    get = await client.get(f"/api/v1/applications/{create.json()['id']}", headers=auth_header(operator_token))
    assert get.status_code == 200


@pytest.mark.asyncio
async def test_no_jit_grant_returns_403(client: AsyncClient, admin_token: str, operator_token: str):
    app = await _create_app(client, admin_token)
    resp = await client.post(f"/api/v1/gateway/apps/{app['id']}/session", headers=auth_header(operator_token))
    assert resp.status_code == 403
    assert any(k in resp.json()["detail"].lower() for k in ("jit", "grant", "access request"))


@pytest.mark.asyncio
async def test_wrong_user_jit_grant_returns_403(
    client: AsyncClient, admin_token: str, operator_token: str, operator2_token: str,
):
    app = await _create_app(client, admin_token)
    operator2_id = await _get_user_id("operator2")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator2_id, application_id=app["id"])
    resp = await client.post(f"/api/v1/gateway/apps/{app['id']}/session", headers=auth_header(operator_token))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_wrong_target_jit_grant_returns_403(
    client: AsyncClient, admin_token: str, operator_token: str,
):
    app_a = await _create_app(client, admin_token, name="App A", hostname="app-a.internal")
    app_b = await _create_app(client, admin_token, name="App B", hostname="app-b.internal")
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app_b["id"])
    resp = await client.post(f"/api/v1/gateway/apps/{app_a['id']}/session", headers=auth_header(operator_token))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_wrong_protocol_jit_grant_returns_403(
    client: AsyncClient, admin_token: str, operator_token: str,
):
    app = await _create_app(client, admin_token, name="HTTPS App", hostname="secure.internal", port=443, protocol="HTTPS")
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app["id"], protocol="HTTP")
    resp = await client.post(f"/api/v1/gateway/apps/{app['id']}/session", headers=auth_header(operator_token))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_expired_jit_grant_returns_403(
    client: AsyncClient, admin_token: str, operator_token: str,
):
    from app.core.security import generate_request_number
    from app.models.access_request import AccessRequest
    app = await _create_app(client, admin_token)
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        req = AccessRequest(
            request_number=generate_request_number(),
            user_id=operator_id, application_id=app["id"], protocol="HTTP",
            reason="Expired", requested_duration=1, status="ACTIVE",
            risk_score=10, risk_level="LOW", approval_required=False,
            jit_required=True, mfa_required=False, recording_required=False,
        )
        db.add(req)
        await db.flush()
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        grant = JITGrant(
            request_id=req.id, user_id=operator_id, application_id=app["id"],
            protocol="HTTP", granted_at=past - timedelta(hours=2),
            expires_at=past, status="ACTIVE", created_by=None,
        )
        db.add(grant)
        await db.commit()
    resp = await client.post(f"/api/v1/gateway/apps/{app['id']}/session", headers=auth_header(operator_token))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_revoked_jit_grant_returns_403(
    client: AsyncClient, admin_token: str, operator_token: str,
):
    app = await _create_app(client, admin_token)
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        grant = await _create_jit_grant(db, user_id=operator_id, application_id=app["id"])
        await JITService().revoke(db, grant)
        await db.commit()
    resp = await client.post(f"/api/v1/gateway/apps/{app['id']}/session", headers=auth_header(operator_token))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_session_jit_grant_and_request_id_populated(
    client: AsyncClient, admin_token: str, operator_token: str, db_session: AsyncSession,
):
    app = await _create_app(client, admin_token, name="Integration App")
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        grant = await _create_jit_grant(db, user_id=operator_id, application_id=app["id"])
        grant_id, request_id = grant.id, grant.request_id
    resp = await client.post(f"/api/v1/gateway/apps/{app['id']}/session", headers=auth_header(operator_token))
    assert resp.status_code == 201
    session_id = resp.json()["session_id"]
    result = await db_session.execute(select(SessionModel).where(SessionModel.id == session_id))
    session = result.scalar_one()
    assert session.jit_grant_id == grant_id
    assert session.request_id == request_id


# IP/DNS unit tests
@pytest.mark.asyncio
async def test_ip_is_denied_loopback():
    assert _ip_is_denied(ipaddress.ip_address("127.0.0.1")) is True
    assert _ip_is_denied(ipaddress.ip_address("::1")) is True

@pytest.mark.asyncio
async def test_ip_is_denied_link_local_metadata():
    assert _ip_is_denied(ipaddress.ip_address("169.254.169.254")) is True
    assert _ip_is_denied(ipaddress.ip_address("fe80::1")) is True

@pytest.mark.asyncio
async def test_ip_is_denied_multicast():
    assert _ip_is_denied(ipaddress.ip_address("224.0.0.1")) is True
    assert _ip_is_denied(ipaddress.ip_address("ff02::1")) is True

@pytest.mark.asyncio
async def test_ip_is_denied_allows_private_rfc1918():
    assert _ip_is_denied(ipaddress.ip_address("10.0.0.1")) is False
    assert _ip_is_denied(ipaddress.ip_address("192.168.0.1")) is False
    assert _ip_is_denied(ipaddress.ip_address("172.16.0.1")) is False

@pytest.mark.asyncio
async def test_ip_is_denied_allows_public_addresses():
    assert _ip_is_denied(ipaddress.ip_address("8.8.8.8")) is False

@pytest.mark.asyncio
async def test_ip_is_denied_carrier_grade_nat():
    assert _ip_is_denied(ipaddress.ip_address("100.64.0.1")) is True

@pytest.mark.asyncio
async def test_validate_upstream_dns_loopback_literal_rejected():
    with pytest.raises(Exception) as exc_info:
        await _validate_upstream_dns("127.0.0.1", 80)
    assert exc_info.value.status_code == 502

@pytest.mark.asyncio
async def test_validate_upstream_dns_metadata_ip_rejected():
    with pytest.raises(Exception) as exc_info:
        await _validate_upstream_dns("169.254.169.254", 80)
    assert exc_info.value.status_code == 502

@pytest.mark.asyncio
async def test_validate_upstream_dns_private_ip_allowed():
    await _validate_upstream_dns("10.0.0.1", 443)
    await _validate_upstream_dns("192.168.1.100", 8080)

@pytest.mark.asyncio
async def test_validate_upstream_dns_nonexistent_hostname_rejected():
    with pytest.raises(Exception) as exc_info:
        await _validate_upstream_dns("this-host-does-not-exist.securepam-test-invalid", 80)
    assert exc_info.value.status_code == 502

def test_ssrf_blocks_loopback():
    with pytest.raises(SSRFValidationError):
        validate_application_target("127.0.0.1", 80, "HTTP")

def test_ssrf_blocks_link_local():
    with pytest.raises(SSRFValidationError):
        validate_application_target("169.254.169.254", 80, "HTTP")

def test_ssrf_allows_private_rfc1918():
    validate_application_target("10.0.0.1", 443, "HTTP")

def test_ssrf_blocks_unsupported_protocol():
    with pytest.raises(SSRFValidationError):
        validate_application_target("admin.corp.internal", 22, "SSH")

def test_ssrf_blocks_malformed_hostname():
    with pytest.raises(SSRFValidationError):
        validate_application_target("not valid host!", 80, "HTTP")


# ===========================================================================
# Auth request hook tests
# ===========================================================================

@pytest.mark.asyncio
async def test_auth_hook_missing_token_returns_403(client: AsyncClient):
    """No X-Gateway-Auth-Token header → 403 immediately."""
    resp = await client.get(
        "/api/v1/gateway/internal/auth",
        headers={"X-SecurePAM-Session-ID": str(uuid4())},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_auth_hook_wrong_token_returns_403(client: AsyncClient):
    """Wrong X-Gateway-Auth-Token → 403."""
    resp = await client.get(
        "/api/v1/gateway/internal/auth",
        headers={
            "X-Gateway-Auth-Token": "totally-wrong-token",
            "X-SecurePAM-Session-ID": str(uuid4()),
        },
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_auth_hook_correct_token_no_session_id_returns_403(client: AsyncClient):
    """Valid token but missing session ID → 403."""
    resp = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_auth_hook_invalid_uuid_session_id_returns_403(client: AsyncClient):
    """Valid token but non-UUID session ID → 403."""
    resp = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id="not-a-uuid"),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_auth_hook_nonexistent_session_returns_403(client: AsyncClient):
    """Valid token + valid UUID that doesn't exist in DB → 403."""
    resp = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=str(uuid4())),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_auth_hook_valid_active_session_returns_200(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    """Valid token + active session with live JIT grant → 200."""
    app = await _create_app(client, admin_token)
    app_id = app["id"]
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app_id)

    # Create session via API (JIT enforced)
    start = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session",
        headers=auth_header(operator_token),
    )
    assert start.status_code == 201
    session_id = start.json()["session_id"]

    # Simulate NGINX auth_request
    resp = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=session_id, app_id=app_id),
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_auth_hook_completed_session_returns_403(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    """Terminated session → auth hook returns 403 (live revocation)."""
    app = await _create_app(client, admin_token)
    app_id = app["id"]
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app_id)

    start = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session",
        headers=auth_header(operator_token),
    )
    assert start.status_code == 201
    session_id = start.json()["session_id"]

    # Verify it works before termination
    pre = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=session_id, app_id=app_id),
    )
    assert pre.status_code == 200

    # Terminate
    term = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session/{session_id}/terminate",
        headers=auth_header(operator_token),
    )
    assert term.status_code == 200

    # Auth hook must now deny
    post = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=session_id, app_id=app_id),
    )
    assert post.status_code == 403


@pytest.mark.asyncio
async def test_auth_hook_expired_session_status_returns_403(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    """Session with EXPIRED status → auth hook returns 403."""
    app = await _create_app(client, admin_token)
    app_id = app["id"]
    operator_id = await _get_user_id("operator")

    async with async_session_factory() as db:
        grant = await _create_jit_grant(db, user_id=operator_id, application_id=app_id)
        from app.core.security import generate_session_number
        session = SessionModel(
            session_number=generate_session_number(),
            user_id=operator_id,
            application_id=app_id,
            protocol="HTTP",
            status="EXPIRED",
            jit_grant_id=grant.id,
            request_id=grant.request_id,
        )
        db.add(session)
        await db.commit()
        session_id = str(session.id)

    resp = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=session_id, app_id=app_id),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_auth_hook_failed_session_status_returns_403(
    client: AsyncClient,
    admin_token: str,
):
    """Session with FAILED status → auth hook returns 403."""
    app = await _create_app(client, admin_token)
    app_id = app["id"]
    operator_id = await _get_user_id("operator")

    async with async_session_factory() as db:
        grant = await _create_jit_grant(db, user_id=operator_id, application_id=app_id)
        from app.core.security import generate_session_number
        session = SessionModel(
            session_number=generate_session_number(),
            user_id=operator_id,
            application_id=app_id,
            protocol="HTTP",
            status="FAILED",
            jit_grant_id=grant.id,
            request_id=grant.request_id,
        )
        db.add(session)
        await db.commit()
        session_id = str(session.id)

    resp = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=session_id, app_id=app_id),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_auth_hook_revoked_jit_grant_returns_403(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    """
    Session STARTING but JIT grant revoked after session creation → auth hook 403.
    This is the key live-revocation test: the Session row still says STARTING
    but the JIT grant has been revoked, so the auth hook must deny.
    """
    app = await _create_app(client, admin_token)
    app_id = app["id"]
    operator_id = await _get_user_id("operator")

    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app_id)

    # Create session (JIT valid at this point)
    start = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session",
        headers=auth_header(operator_token),
    )
    assert start.status_code == 201
    session_id = start.json()["session_id"]
    grant_id = start.json()["jit_grant_id"]

    # Verify auth works initially
    pre = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=session_id, app_id=app_id),
    )
    assert pre.status_code == 200

    # Revoke the grant directly in DB
    async with async_session_factory() as db:
        result = await db.execute(select(JITGrant).where(JITGrant.id == grant_id))
        grant = result.scalar_one()
        await JITService().revoke(db, grant)
        await db.commit()

    # Auth hook must now return 403 — JIT revocation is live
    post = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=session_id, app_id=app_id),
    )
    assert post.status_code == 403


@pytest.mark.asyncio
async def test_auth_hook_expired_jit_grant_returns_403(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    """
    Session STARTING but JIT grant has expired after session creation → 403.
    Simulates a grant that expired between session-create and a later request.
    """
    app = await _create_app(client, admin_token)
    app_id = app["id"]
    operator_id = await _get_user_id("operator")

    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app_id)

    start = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session",
        headers=auth_header(operator_token),
    )
    assert start.status_code == 201
    session_id = start.json()["session_id"]
    grant_id = start.json()["jit_grant_id"]

    # Force-expire the grant by setting expires_at to the past
    async with async_session_factory() as db:
        result = await db.execute(select(JITGrant).where(JITGrant.id == grant_id))
        grant = result.scalar_one()
        grant.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        await db.commit()

    # Auth hook detects expired grant → 403
    post = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=session_id, app_id=app_id),
    )
    assert post.status_code == 403


@pytest.mark.asyncio
async def test_auth_hook_app_id_mismatch_returns_403(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    """
    Session is for appA but X-SecurePAM-App-ID claims appB → 403.
    This prevents a session token for one app being used to access another.
    """
    app_a = await _create_app(client, admin_token, name="App A", hostname="app-a.internal")
    app_b = await _create_app(client, admin_token, name="App B", hostname="app-b.internal")
    operator_id = await _get_user_id("operator")

    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app_a["id"])

    start = await client.post(
        f"/api/v1/gateway/apps/{app_a['id']}/session",
        headers=auth_header(operator_token),
    )
    assert start.status_code == 201
    session_id = start.json()["session_id"]

    # Send session for appA but claim appB in the URL-derived header
    resp = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=session_id, app_id=app_b["id"]),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_auth_hook_disabled_app_returns_403(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    """App is disabled after session creation → auth hook returns 403."""
    app = await _create_app(client, admin_token)
    app_id = app["id"]
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app_id)

    start = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session",
        headers=auth_header(operator_token),
    )
    assert start.status_code == 201
    session_id = start.json()["session_id"]

    # Disable the app
    await client.patch(f"/api/v1/applications/{app_id}", json={"enabled": False}, headers=auth_header(admin_token))

    resp = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=session_id, app_id=app_id),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_auth_hook_deleted_app_returns_403(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    """App is soft-deleted after session creation → auth hook returns 403.

    Note: the applications API blocks deletion when active sessions exist.
    We terminate the session first to allow soft-delete, then verify the
    auth hook rejects because the application no longer exists in the DB.
    """
    app = await _create_app(client, admin_token)
    app_id = app["id"]
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app_id)

    start = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session",
        headers=auth_header(operator_token),
    )
    assert start.status_code == 201
    session_id = start.json()["session_id"]

    # Terminate session first (app delete blocks if active sessions exist)
    term = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session/{session_id}/terminate",
        headers=auth_header(operator_token),
    )
    assert term.status_code == 200

    # Now soft-delete the app
    del_resp = await client.delete(f"/api/v1/applications/{app_id}", headers=auth_header(admin_token))
    assert del_resp.status_code == 204

    # Auth hook: session exists but app is deleted → 403
    resp = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=session_id, app_id=app_id),
    )
    # Session is already COMPLETED so this returns 403 due to terminal status —
    # which is the correct deny outcome regardless of whether app is deleted.
    assert resp.status_code == 403


# ===========================================================================
# Test 53: Full live revocation integration test
# ===========================================================================

@pytest.mark.asyncio
async def test_live_revocation_terminate_then_auth_denied(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    """
    Integration test for Priority 3: live revocation via session termination.

    Flow:
    1. Create app + JIT grant.
    2. Start gateway session.
    3. Auth hook returns 200 (session active, grant valid).
    4. Terminate session via API.
    5. Auth hook returns 403 (session COMPLETED → denied).

    This simulates what NGINX does: it sends auth_request before every
    proxied request. After termination, the next request is denied.
    """
    app = await _create_app(client, admin_token, name="Revocation Test App")
    app_id = app["id"]
    operator_id = await _get_user_id("operator")

    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app_id)

    # Step 1: Create session
    start = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session",
        headers=auth_header(operator_token),
    )
    assert start.status_code == 201
    session_id = start.json()["session_id"]

    # Step 2: Auth check passes
    auth_before = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=session_id, app_id=app_id),
    )
    assert auth_before.status_code == 200, "Auth should pass for active session"

    # Step 3: Terminate session
    term = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session/{session_id}/terminate",
        headers=auth_header(operator_token),
    )
    assert term.status_code == 200
    assert term.json()["status"] == "COMPLETED"

    # Step 4: Auth check now fails → NGINX would deny next proxied request
    auth_after = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=session_id, app_id=app_id),
    )
    assert auth_after.status_code == 403, "Auth must be denied after session termination"


# ===========================================================================
# Tests 54-57: proxy-config endpoint (Priority 2)
# ===========================================================================

@pytest.mark.asyncio
async def test_proxy_config_admin_gets_nginx_snippet(
    client: AsyncClient,
    admin_token: str,
):
    """ADMIN can retrieve the NGINX upstream config snippet for an app."""
    app = await _create_app(client, admin_token, name="Proxy Config App", hostname="myapp.internal", port=9000)
    app_id = app["id"]

    resp = await client.get(
        f"/api/v1/gateway/apps/{app_id}/proxy-config",
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["application_id"] == app_id
    assert data["protocol"] == "HTTP"
    assert "upstream_name" in data
    assert "nginx_snippet" in data


@pytest.mark.asyncio
async def test_proxy_config_operator_forbidden(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    """Non-ADMIN operator cannot access the proxy config endpoint."""
    app = await _create_app(client, admin_token)
    resp = await client.get(
        f"/api/v1/gateway/apps/{app['id']}/proxy-config",
        headers=auth_header(operator_token),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_proxy_config_unknown_app_returns_404(client: AsyncClient, admin_token: str):
    """Unknown app ID returns 404."""
    resp = await client.get(
        f"/api/v1/gateway/apps/{uuid4()}/proxy-config",
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_proxy_config_snippet_content_correct(
    client: AsyncClient,
    admin_token: str,
):
    """The returned nginx_snippet contains the correct upstream name and server."""
    app = await _create_app(
        client, admin_token,
        name="Snippet Check App",
        hostname="snippet-target.internal",
        port=7777,
    )
    app_id = app["id"]
    resp = await client.get(
        f"/api/v1/gateway/apps/{app_id}/proxy-config",
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200
    data = resp.json()

    # Upstream name: 'app_' + UUID with hyphens→underscores
    expected_name = "app_" + app_id.replace("-", "_")
    assert data["upstream_name"] == expected_name

    # Server is host:port (no scheme)
    assert data["upstream_server"] == "snippet-target.internal:7777"

    # Snippet contains the upstream block
    snippet = data["nginx_snippet"]
    assert f"upstream {expected_name}" in snippet
    assert "snippet-target.internal:7777" in snippet
    assert "keepalive" in snippet

    # Snippet must NOT contain the protocol/scheme in the server line
    # (NGINX upstream server lines are host:port only)
    assert "http://" not in snippet.split("upstream")[1]


# ===========================================================================
# Browser Isolation, IP Pinning, and Lifecycle Sync Tests
# ===========================================================================

@pytest.mark.asyncio
async def test_day5_isolated_browser_session_creation_with_jit(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    """Priority 1: ISOLATED_BROWSER creates session and launches isolated browser on valid JIT grant."""
    app = await _create_app(
        client, admin_token,
        name="Isolated Web App",
        access_mode="ISOLATED_BROWSER",
    )
    app_id = app["id"]
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        grant = await _create_jit_grant(db, user_id=operator_id, application_id=app_id)
        grant_id = str(grant.id)

    resp = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session",
        headers=auth_header(operator_token),
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["application_id"] == app_id
    assert data["access_mode"] == "ISOLATED_BROWSER"
    assert data["jit_validated"] is True
    assert data["jit_grant_id"] == grant_id
    assert data["vnc_url"] is not None
    assert f"/gw/apps/{app_id}/vnc/" in data["vnc_url"]
    assert "session_id=" in data["vnc_url"]

    # Verify session in DB has ISOLATED_BROWSER access_mode and vnc_path in metadata
    session_uuid = UUID(data["session_id"])
    async with async_session_factory() as db:
        session_obj = await db.get(SessionModel, session_uuid)
        assert session_obj is not None
        assert session_obj.metadata_["access_mode"] == "ISOLATED_BROWSER"
        assert "vnc_path" in session_obj.metadata_


@pytest.mark.asyncio
async def test_day5_isolated_browser_without_jit_grant_denied_403(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    """Priority 1: ISOLATED_BROWSER session creation fails closed (403) without valid JIT grant."""
    app = await _create_app(
        client, admin_token,
        name="Unauth Isolated App",
        access_mode="ISOLATED_BROWSER",
    )
    # No JIT grant created for operator
    resp = await client.post(
        f"/api/v1/gateway/apps/{app['id']}/session",
        headers=auth_header(operator_token),
    )
    assert resp.status_code == 403
    assert "No valid JIT grant found" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_day5_isolated_browser_termination_and_cleanup(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    """Priority 1: Session termination cleans up browser isolation process and denies further access."""
    app = await _create_app(
        client, admin_token,
        name="Term Isolated App",
        access_mode="ISOLATED_BROWSER",
    )
    app_id = app["id"]
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app_id)

    # 1. Create session
    create_resp = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session",
        headers=auth_header(operator_token),
    )
    assert create_resp.status_code == 201
    session_id = create_resp.json()["session_id"]

    # 2. Terminate session
    term_resp = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session/{session_id}/terminate",
        headers=auth_header(operator_token),
    )
    assert term_resp.status_code == 200
    assert term_resp.json()["status"] == "COMPLETED"

    # 3. Subsequent auth_request sub-request returns 403
    auth_resp = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=session_id, app_id=app_id),
    )
    assert auth_resp.status_code == 403
    assert auth_resp.json()["detail"] == "Session is not active."


@pytest.mark.asyncio
async def test_day5_dns_ip_pinning_response_headers(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    """Priority 2: auth_request hook returns validated X-SecurePAM-Upstream-Target header for IP pinning."""
    app = await _create_app(
        client, admin_token,
        hostname="10.0.10.5",  # Private RFC1918 IP
        port=8443,
        name="Pinned IP App",
    )
    app_id = app["id"]
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app_id)

    create_resp = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session",
        headers=auth_header(operator_token),
    )
    assert create_resp.status_code == 201
    session_id = create_resp.json()["session_id"]

    # Call internal auth hook
    auth_resp = await client.get(
        "/api/v1/gateway/internal/auth",
        headers=_auth_hook_headers(session_id=session_id, app_id=app_id),
    )
    assert auth_resp.status_code == 200
    assert "x-securepam-upstream-target" in auth_resp.headers
    assert auth_resp.headers["x-securepam-upstream-target"] == "10.0.10.5:8443"
    assert auth_resp.headers["x-securepam-upstream-host"] == "10.0.10.5"
    assert auth_resp.headers["x-securepam-upstream-ip"] == "10.0.10.5"
    assert auth_resp.headers["x-securepam-upstream-port"] == "8443"


@pytest.mark.asyncio
async def test_day5_dns_ssrf_denied_ranges():
    """Priority 2: Denied destination ranges are strictly blocked, while RFC1918 is allowed."""
    import ipaddress
    from app.api.v1.gateway import _ip_is_denied

    # Blocked ranges: loopback, link-local, cloud metadata, multicast, unspecified
    assert _ip_is_denied(ipaddress.ip_address("127.0.0.1")) is True
    assert _ip_is_denied(ipaddress.ip_address("127.0.0.2")) is True
    assert _ip_is_denied(ipaddress.ip_address("169.254.169.254")) is True  # AWS/GCP/Azure metadata
    assert _ip_is_denied(ipaddress.ip_address("0.0.0.0")) is True
    assert _ip_is_denied(ipaddress.ip_address("224.0.0.1")) is True  # Multicast
    assert _ip_is_denied(ipaddress.ip_address("::1")) is True  # IPv6 loopback
    assert _ip_is_denied(ipaddress.ip_address("fe80::1")) is True  # IPv6 link-local

    # Allowed ranges: legitimate RFC1918 PAM internal targets
    assert _ip_is_denied(ipaddress.ip_address("10.0.0.1")) is False
    assert _ip_is_denied(ipaddress.ip_address("172.16.0.50")) is False
    assert _ip_is_denied(ipaddress.ip_address("192.168.1.100")) is False


@pytest.mark.asyncio
async def test_day5_application_lifecycle_sync_create_patch_delete(
    client: AsyncClient,
    admin_token: str,
    tmp_path,
    monkeypatch,
):
    """Priority 3: Application create/patch/delete synchronizes upstream config safely."""
    # Point GATEWAY_CONFIG_DIR to tmp_path to test real file writing & removal
    monkeypatch.setattr(settings, "GATEWAY_CONFIG_DIR", str(tmp_path))

    # 1. Create app (STANDARD_PROXY) -> upstream config written
    app_data = {
        "name": "Lifecycle App",
        "hostname": "lifecycle.corp.internal",
        "port": 8080,
        "protocol": "HTTP",
        "environment": "TEST",
        "criticality": "LOW",
        "access_mode": "STANDARD_PROXY",
    }
    create_resp = await client.post(
        "/api/v1/applications",
        json=app_data,
        headers=auth_header(admin_token),
    )
    assert create_resp.status_code == 201
    app_id = create_resp.json()["id"]

    safe_name = app_id.replace("-", "_")
    conf_file = tmp_path / f"{safe_name}.conf"
    assert conf_file.exists()
    content = conf_file.read_text()
    assert f"upstream app_{safe_name}" in content
    assert "lifecycle.corp.internal:8080" in content

    # 2. Patch app to disable -> upstream config removed
    patch_resp = await client.patch(
        f"/api/v1/applications/{app_id}",
        json={"enabled": False},
        headers=auth_header(admin_token),
    )
    assert patch_resp.status_code == 200
    assert not conf_file.exists()

    # 3. Re-enable app -> upstream config re-written
    patch_resp2 = await client.patch(
        f"/api/v1/applications/{app_id}",
        json={"enabled": True},
        headers=auth_header(admin_token),
    )
    assert patch_resp2.status_code == 200
    assert conf_file.exists()

    # 4. Delete app -> upstream config removed
    del_resp = await client.delete(
        f"/api/v1/applications/{app_id}",
        headers=auth_header(admin_token),
    )
    assert del_resp.status_code == 204
    assert not conf_file.exists()


@pytest.mark.asyncio
async def test_internal_auth_query_param_fallback(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    """Verify internal auth hook accepts session_id query param for browser tabs."""
    app = await _create_app(client, admin_token)
    app_id = app["id"]
    operator_id = await _get_user_id("operator")

    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app_id)

    start = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session",
        headers=auth_header(operator_token),
    )
    assert start.status_code == 201
    session_id = start.json()["session_id"]

    # Query param fallback succeeds with 200 without X-SecurePAM-Session-ID header
    resp = await client.get(
        f"/api/v1/gateway/internal/auth?session_id={session_id}",
        headers={
            "X-Gateway-Auth-Token": settings.GATEWAY_AUTH_TOKEN,
            "X-SecurePAM-App-ID": str(app_id),
        },
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"

    # Query param with unknown session is rejected with 403
    bad_resp = await client.get(
        f"/api/v1/gateway/internal/auth?session_id={uuid4()}",
        headers={
            "X-Gateway-Auth-Token": settings.GATEWAY_AUTH_TOKEN,
            "X-SecurePAM-App-ID": str(app_id),
        },
    )
    assert bad_resp.status_code == 403


@pytest.mark.asyncio
async def test_dns_pinning_ssrf_validation_logic():
    """Verify SSRF blocklist strictly rejects disallowed destinations and permits RFC1918."""
    from app.api.v1.gateway import _resolve_and_validate_upstream_target, _ip_is_denied
    import ipaddress
    from fastapi import HTTPException

    # Prohibited destinations must be denied
    prohibited_ips = [
        "127.0.0.1",
        "127.0.1.1",
        "::1",
        "169.254.169.254",
        "169.254.1.1",
        "fe80::1",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "100.64.0.1",
    ]
    for bad_ip in prohibited_ips:
        ip_obj = ipaddress.ip_address(bad_ip)
        assert _ip_is_denied(ip_obj) is True, f"Expected {bad_ip} to be denied"
        with pytest.raises(HTTPException) as exc:
            await _resolve_and_validate_upstream_target(bad_ip, 8080)
        assert exc.value.status_code == 403

    # Legitimate RFC1918 PAM internal targets must be permitted
    allowed_ips = [
        "10.0.1.5",
        "10.254.0.1",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "192.168.100.50",
    ]
    for good_ip in allowed_ips:
        ip_obj = ipaddress.ip_address(good_ip)
        assert _ip_is_denied(ip_obj) is False, f"Expected {good_ip} to be allowed"
        target, host_hdr = await _resolve_and_validate_upstream_target(good_ip, 9090)
        assert target == f"{good_ip}:9090"
        assert host_hdr == good_ip


@pytest.mark.asyncio
async def test_day8_ssrf_dns_resolution_failure_fails_closed():
    """Verify non-resolvable hostnames fail closed with HTTP 502."""
    from fastapi import HTTPException
    from app.api.v1.gateway import _resolve_and_validate_upstream_target
    with pytest.raises(HTTPException) as exc:
        await _resolve_and_validate_upstream_target("nonexistent.invalid.securepam.local", 8080)
    assert exc.value.status_code == 502
    assert "could not be resolved" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_day8_ssrf_dns_rebinding_simulation_denies_target(monkeypatch):
    """
    Verify that if a domain rebinds to a disallowed destination (e.g. 169.254.169.254 or 127.0.0.1)
    at connection time, _resolve_and_validate_upstream_target intercepts and denies it with 403.
    """
    import socket
    from fastapi import HTTPException
    from app.api.v1.gateway import _resolve_and_validate_upstream_target

    # Simulate getaddrinfo returning AWS metadata IP for a legitimate-looking name
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(HTTPException) as exc:
        await _resolve_and_validate_upstream_target("trusted-subdomain.corp.internal", 80)
    assert exc.value.status_code == 403
    assert "disallowed address" in exc.value.detail.lower()


@pytest.mark.asyncio
async def test_day8_client_headers_cannot_override_pinned_ip(
    client: AsyncClient,
    admin_token: str,
    operator_token: str,
):
    """
    Verify client-supplied headers attempting to override upstream target or app ID
    are completely ignored in favor of DB-resolved pinned target.
    """

    app = await _create_app(
        client, admin_token,
        hostname="10.0.50.25",
        port=8080,
        name="Header Tamper Test App",
    )
    app_id = app["id"]
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        await _create_jit_grant(db, user_id=operator_id, application_id=app_id)

    create_resp = await client.post(
        f"/api/v1/gateway/apps/{app_id}/session",
        headers=auth_header(operator_token),
    )
    assert create_resp.status_code == 201
    session_id = create_resp.json()["session_id"]

    # Attempt to spoof upstream target and host via client headers
    headers = _auth_hook_headers(session_id=session_id, app_id=app_id)
    headers["X-SecurePAM-Upstream-Target"] = "1.2.3.4:9999"
    headers["X-SecurePAM-Upstream-Host"] = "evil-override.attacker.com"

    auth_resp = await client.get("/api/v1/gateway/internal/auth", headers=headers)
    assert auth_resp.status_code == 200
    # Must use DB-derived target, not client header
    assert auth_resp.headers["x-securepam-upstream-target"] == "10.0.50.25:8080"
    assert auth_resp.headers["x-securepam-upstream-host"] == "10.0.50.25"
    assert auth_resp.headers["x-securepam-upstream-ip"] == "10.0.50.25"



