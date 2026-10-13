"""
Web gateway security regressions:

- GATEWAY_AUTH_TOKEN has no usable default; unset, placeholder or short
  tokens reject every auth_request call.
- Proxied access needs the launch-issued credential cookie; the launch
  ticket is single-use, short-lived and bound to its application.
- A session stays bound to the JIT grant it was opened with.
- Responses never disclose the internal upstream.
- Gateway admin endpoints ignore deactivated ADMIN roles.
"""

from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from httpx import AsyncClient
from pydantic import SecretStr
from sqlalchemy import select

from tests.conftest import auth_header
from tests.test_gateway_routing import (
    GATEWAY_TOKEN,
    _auth_hook_headers,
    _create_app,
    _create_jit_grant,
    _get_user_id,
    _launch,
)

from app.api.v1.gateway import GATEWAY_COOKIE_NAME
from app.core.config import Settings, SettingsError, settings
from app.database.session import async_session_factory
from app.models.jit_grant import JITGrant
from app.models.role import Role
from app.models.session import Session as SessionModel
from app.models.user import User
from app.services.jit_service import JITService

AUTH = "/api/v1/gateway/internal/auth"


@pytest.fixture(autouse=True)
def _gateway_token(monkeypatch):
    monkeypatch.setattr(settings, "GATEWAY_AUTH_TOKEN", SecretStr(GATEWAY_TOKEN))


async def _started_session(client, admin_token, operator_token, **app_overrides):
    app = await _create_app(client, admin_token, **app_overrides)
    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        grant = await _create_jit_grant(db, user_id=operator_id, application_id=app["id"])
    start = await client.post(
        f"/api/v1/gateway/apps/{app['id']}/session", headers=auth_header(operator_token)
    )
    assert start.status_code == 201, start.text
    return app["id"], start.json(), grant


def _ticket(start: dict) -> str:
    return start["launch_url"].split("ticket=", 1)[1]


# --- gateway token ------------------------------------------------------------

def test_gateway_token_has_no_default():
    assert Settings(_env_file=None).GATEWAY_AUTH_TOKEN.get_secret_value() == ""


@pytest.mark.parametrize("configured", ["", "dev-insecure-change-me-in-production", "s" * 31])
@pytest.mark.asyncio
async def test_unset_or_weak_gateway_token_rejects_everything(
    client: AsyncClient, admin_token, operator_token, monkeypatch, configured
):
    app_id, start, _ = await _started_session(client, admin_token, operator_token)
    credential = await _launch(client, start)
    monkeypatch.setattr(settings, "GATEWAY_AUTH_TOKEN", SecretStr(configured))

    resp = await client.get(AUTH, headers={
        "X-Gateway-Auth-Token": configured,
        "X-SecurePAM-Gateway-Credential": credential,
        "X-SecurePAM-App-ID": app_id,
    })
    assert resp.status_code == 403
    assert "x-securepam-upstream-authorization" not in resp.headers


def test_gateway_token_not_in_settings_repr():
    s = Settings(_env_file=None, GATEWAY_AUTH_TOKEN="q" * 40)
    assert "q" * 40 not in repr(s) and "q" * 40 not in str(s.model_dump())


def test_production_rejects_insecure_gateway_cookie():
    with pytest.raises(SettingsError, match="GATEWAY_COOKIE_SECURE"):
        Settings(
            _env_file=None, ENVIRONMENT="production", DEV_MODE=False, SECRET_KEY="x" * 48,
            SECRET_PROVIDER="openbao", OPENBAO_ADDR="https://bao:8200", OPENBAO_TOKEN="t",
            GATEWAY_COOKIE_SECURE=False,
        )


# --- launch ticket and cookie ---------------------------------------------------

@pytest.mark.asyncio
async def test_launch_sets_scoped_httponly_cookie_and_redirects(
    client: AsyncClient, admin_token, operator_token
):
    app_id, start, _ = await _started_session(client, admin_token, operator_token)
    resp = await client.get(f"/api/v1/gateway/apps/{app_id}/launch", params={"ticket": _ticket(start)})
    assert resp.status_code == 303
    assert resp.headers["location"] == f"/gw/apps/{app_id}/"
    assert resp.headers["cache-control"] == "no-store"
    cookie = resp.headers["set-cookie"]
    for attribute in ("HttpOnly", "Secure", "SameSite=strict", f"Path=/gw/apps/{app_id}/"):
        assert attribute.lower() in cookie.lower(), cookie
    assert resp.cookies[GATEWAY_COOKIE_NAME] != _ticket(start)


@pytest.mark.asyncio
async def test_launch_ticket_is_single_use(client: AsyncClient, admin_token, operator_token):
    app_id, start, _ = await _started_session(client, admin_token, operator_token)
    url = f"/api/v1/gateway/apps/{app_id}/launch"
    assert (await client.get(url, params={"ticket": _ticket(start)})).status_code == 303
    assert (await client.get(url, params={"ticket": _ticket(start)})).status_code == 403


@pytest.mark.asyncio
async def test_launch_ticket_expires(client: AsyncClient, admin_token, operator_token):
    app_id, start, _ = await _started_session(client, admin_token, operator_token)
    async with async_session_factory() as db:
        session = await db.get(SessionModel, UUID(start["session_id"]))
        meta = dict(session.metadata_)
        meta["launch_ticket_expires_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        session.metadata_ = meta
        await db.commit()
    resp = await client.get(f"/api/v1/gateway/apps/{app_id}/launch", params={"ticket": _ticket(start)})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_launch_ticket_bound_to_its_application(client: AsyncClient, admin_token, operator_token):
    _, start, _ = await _started_session(client, admin_token, operator_token)
    other = await _create_app(client, admin_token, name="Other App", hostname="other.internal")
    resp = await client.get(f"/api/v1/gateway/apps/{other['id']}/launch", params={"ticket": _ticket(start)})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_forged_or_session_id_only_tickets_rejected(client: AsyncClient, admin_token, operator_token):
    app_id, start, _ = await _started_session(client, admin_token, operator_token)
    url = f"/api/v1/gateway/apps/{app_id}/launch"
    for ticket in (start["session_id"], f"{start['session_id']}.forged", "garbage"):
        assert (await client.get(url, params={"ticket": ticket})).status_code == 403


@pytest.mark.asyncio
async def test_credential_secret_is_stored_only_as_hash(client: AsyncClient, admin_token, operator_token):
    _, start, _ = await _started_session(client, admin_token, operator_token)
    credential = await _launch(client, start)
    secret = credential.split(".", 1)[1]
    async with async_session_factory() as db:
        session = await db.get(SessionModel, UUID(start["session_id"]))
    assert secret not in str(session.metadata_)
    assert "launch_ticket_hash" not in session.metadata_


@pytest.mark.asyncio
async def test_credential_cannot_be_used_for_another_application(
    client: AsyncClient, admin_token, operator_token
):
    _, start, _ = await _started_session(client, admin_token, operator_token)
    await _launch(client, start)
    other = await _create_app(client, admin_token, name="Other App", hostname="other.internal")
    resp = await client.get(AUTH, headers=_auth_hook_headers(session_id=start["session_id"], app_id=other["id"]))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_missing_app_id_is_rejected(client: AsyncClient, admin_token, operator_token):
    _, start, _ = await _started_session(client, admin_token, operator_token)
    await _launch(client, start)
    resp = await client.get(AUTH, headers=_auth_hook_headers(session_id=start["session_id"]))
    assert resp.status_code == 403


# --- grant binding and owner state ---------------------------------------------

@pytest.mark.asyncio
async def test_new_grant_does_not_revive_session_after_its_grant_is_revoked(
    client: AsyncClient, admin_token, operator_token
):
    app_id, start, grant = await _started_session(client, admin_token, operator_token)
    await _launch(client, start)
    headers = _auth_hook_headers(session_id=start["session_id"], app_id=app_id)
    assert (await client.get(AUTH, headers=headers)).status_code == 200

    operator_id = await _get_user_id("operator")
    async with async_session_factory() as db:
        # Flip only the grant (JITService.revoke would also end the session,
        # which is a different check). The session's own grant is now dead
        # while the user holds a fresh, valid grant for the same application.
        (await db.get(JITGrant, grant.id)).status = "REVOKED"
        await db.commit()
        await _create_jit_grant(db, user_id=operator_id, application_id=app_id)
        assert await JITService().validate(db, user_id=operator_id, target_id=UUID(app_id), protocol="HTTP")

    assert (await client.get(AUTH, headers=headers)).status_code == 403


@pytest.mark.asyncio
async def test_deactivated_owner_is_denied(client: AsyncClient, admin_token, operator_token):
    app_id, start, _ = await _started_session(client, admin_token, operator_token)
    await _launch(client, start)
    headers = _auth_hook_headers(session_id=start["session_id"], app_id=app_id)
    async with async_session_factory() as db:
        user = (await db.execute(select(User).where(User.username == "operator"))).scalar_one()
        user.is_active = False
        await db.commit()
    try:
        assert (await client.get(AUTH, headers=headers)).status_code == 403
    finally:
        async with async_session_factory() as db:
            user = (await db.execute(select(User).where(User.username == "operator"))).scalar_one()
            user.is_active = True
            await db.commit()


# --- disclosure and admin checks ------------------------------------------------

@pytest.mark.asyncio
async def test_session_response_never_contains_upstream(client: AsyncClient, admin_token, operator_token):
    _, start, _ = await _started_session(
        client, admin_token, operator_token, hostname="secret-upstream.internal"
    )
    assert "upstream_url" not in start
    assert "secret-upstream.internal" not in str(start)


@pytest.mark.asyncio
async def test_inactive_admin_role_cannot_use_gateway_admin_endpoints(client: AsyncClient, admin_token):
    app = await _create_app(client, admin_token)
    async with async_session_factory() as db:
        role = (await db.execute(select(Role).where(Role.name == "ADMIN"))).scalar_one()
        role.is_active = False
        await db.commit()
    try:
        for method, url in (
            ("GET", f"/api/v1/gateway/apps/{app['id']}/proxy-config"),
            ("POST", "/api/v1/gateway/config-sync"),
            ("DELETE", f"/api/v1/gateway/apps/{app['id']}/upstream-config"),
        ):
            resp = await client.request(method, url, headers=auth_header(admin_token))
            assert resp.status_code == 403, (url, resp.status_code)
    finally:
        async with async_session_factory() as db:
            role = (await db.execute(select(Role).where(Role.name == "ADMIN"))).scalar_one()
            role.is_active = True
            await db.commit()
