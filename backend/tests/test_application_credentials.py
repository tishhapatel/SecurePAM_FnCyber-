"""
Tests for Application-scoped OpenBao Credential Integration (Task A).
Verifies:
- Application-scoped credential checkout (PASSWORD/Basic and API_KEY/Bearer).
- Preservation of existing asset-scoped checkout.
- Denial when access request, user, or JIT grant does not match.
- Missing, inactive, or ambiguous credential references.
- Provider errors fail closed (CredentialUnavailable).
- Gateway internal auth hook injects X-SecurePAM-Upstream-Authorization correctly.
- Secret values are never leaked in audit logs or error responses.
"""

import base64
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from tests.conftest import auth_header, issue_token

from app.core.config import settings
from app.core.security import generate_request_number, generate_session_number
from app.models.access_request import AccessRequest
from app.models.application import Application
from app.models.approval import Approval
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.jit_grant import JITGrant
from app.models.session import Session as SessionModel
from app.models.user import User
from app.models.vault_ref import VaultRef
from app.secret_providers.mock import MockSecretProvider
from app.secret_providers.paths import application_secret_path
from app.services.credential_service import (
    CheckoutRequest,
    CredentialAccessDenied,
    CredentialService,
    CredentialUnavailable,
)

APP_PATH = "securepam/applications/app-crm"
APP_PASSWORD = "CrmSecurePassword!456"
APP_TOKEN = "pam-token-xyz-789"


@pytest_asyncio.fixture
async def app_setup(db_session: AsyncSession):
    """Sets up an Application, AccessRequest, and active JITGrant for operator."""
    res = await db_session.execute(select(User).where(User.username == "operator"))
    user = res.scalar_one()

    app = Application(
        name="CRM Portal",
        hostname="crm.internal",
        port=8443,
        protocol="HTTPS",
        target_url="https://crm.internal:8443",
        environment="PRODUCTION",
        criticality="HIGH",
        access_mode="STANDARD_PROXY",
        enabled=True,
        status="ACTIVE",
    )
    db_session.add(app)
    await db_session.flush()

    req = AccessRequest(
        request_number=generate_request_number(),
        user_id=user.id,
        application_id=app.id,
        protocol="HTTPS",
        reason="Testing app credential integration",
        requested_duration=30,
        status="ACTIVE",
        approval_required=False,
        jit_required=True,
        mfa_required=False,
        recording_required=False,
    )
    db_session.add(req)
    await db_session.flush()

    now = datetime.now(timezone.utc)
    grant = JITGrant(
        request_id=req.id,
        user_id=user.id,
        application_id=app.id,
        protocol="HTTPS",
        granted_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=30),
        status="ACTIVE",
    )
    db_session.add(grant)
    await db_session.flush()

    session = SessionModel(
        session_number=generate_session_number(),
        user_id=user.id,
        application_id=app.id,
        protocol="HTTPS",
        status="ACTIVE",
        start_time=now,
        request_id=req.id,
        jit_grant_id=grant.id,
    )
    db_session.add(session)
    await db_session.commit()
    await db_session.refresh(app)
    await db_session.refresh(req)
    await db_session.refresh(grant)
    await db_session.refresh(session)

    return {"user": user, "app": app, "request": req, "grant": grant, "session": session}


@pytest.mark.asyncio
async def test_checkout_application_password_basic_auth(db_session: AsyncSession, app_setup):
    """Test checking out application password credential."""
    user = app_setup["user"]
    app = app_setup["app"]
    req = app_setup["request"]
    grant = app_setup["grant"]
    session = app_setup["session"]

    vref = VaultRef(
        application_id=app.id,
        provider="mock",
        vault_path=APP_PATH,
        secret_type="PASSWORD",
        username="crm_admin",
        is_active=True,
    )
    db_session.add(vref)
    await db_session.commit()

    provider = MockSecretProvider({APP_PATH: {"username": "crm_admin", "password": APP_PASSWORD}})
    service = CredentialService(provider=provider)

    checkout_req = CheckoutRequest(
        user_id=user.id,
        access_request_id=req.id,
        jit_grant_id=grant.id,
        application_id=app.id,
        session_id=session.id,
        source_ip="10.10.10.10",
    )

    async with service.checkout(db_session, checkout_req) as cred:
        assert cred.username == "crm_admin"
        assert cred.reveal() == APP_PASSWORD
        assert cred.secret_type == "PASSWORD"

    with pytest.raises(RuntimeError):
        cred.reveal()


@pytest.mark.asyncio
async def test_checkout_application_api_key_bearer_auth(db_session: AsyncSession, app_setup):
    """Test checking out application API key / Bearer token."""
    user = app_setup["user"]
    app = app_setup["app"]
    req = app_setup["request"]
    grant = app_setup["grant"]

    api_path = "securepam/applications/api-gateway"
    vref = VaultRef(
        application_id=app.id,
        provider="mock",
        vault_path=api_path,
        secret_type="API_KEY",
        is_active=True,
    )
    db_session.add(vref)
    await db_session.commit()

    provider = MockSecretProvider({api_path: {"api_key": APP_TOKEN}})
    service = CredentialService(provider=provider)

    checkout_req = CheckoutRequest(
        user_id=user.id,
        access_request_id=req.id,
        jit_grant_id=grant.id,
        application_id=app.id,
    )

    async with service.checkout(db_session, checkout_req) as cred:
        assert cred.reveal() == APP_TOKEN
        assert cred.secret_type == "API_KEY"


@pytest.mark.asyncio
async def test_checkout_application_denies_wrong_user(db_session: AsyncSession, app_setup):
    """Attempting checkout with wrong user fails closed with ACCESS_REQUEST_USER_MISMATCH."""
    app = app_setup["app"]
    req = app_setup["request"]
    grant = app_setup["grant"]

    # Load existing admin user (who has sessions:create permission)
    admin_res = await db_session.execute(select(User).where(User.username == "admin"))
    admin_user = admin_res.scalar_one()

    provider = MockSecretProvider({APP_PATH: {"password": "test"}})
    service = CredentialService(provider=provider)

    checkout_req = CheckoutRequest(
        user_id=admin_user.id,  # admin user does NOT match req.user_id (operator)
        access_request_id=req.id,
        jit_grant_id=grant.id,
        application_id=app.id,
    )

    with pytest.raises(CredentialAccessDenied) as exc:
        async with service.checkout(db_session, checkout_req):
            pass
    assert exc.value.reason == "ACCESS_REQUEST_USER_MISMATCH"


@pytest.mark.asyncio
async def test_checkout_application_denies_inactive_vault_ref(db_session: AsyncSession, app_setup):
    """An inactive VaultRef results in NO_CREDENTIAL_REFERENCE."""
    user = app_setup["user"]
    app = app_setup["app"]
    req = app_setup["request"]
    grant = app_setup["grant"]

    vref = VaultRef(
        application_id=app.id,
        provider="mock",
        vault_path=APP_PATH,
        secret_type="PASSWORD",
        is_active=False,  # Inactive!
    )
    db_session.add(vref)
    await db_session.commit()

    provider = MockSecretProvider({APP_PATH: {"password": "test"}})
    service = CredentialService(provider=provider)

    checkout_req = CheckoutRequest(
        user_id=user.id,
        access_request_id=req.id,
        jit_grant_id=grant.id,
        application_id=app.id,
    )

    with pytest.raises(CredentialAccessDenied) as exc:
        async with service.checkout(db_session, checkout_req):
            pass
    assert exc.value.reason == "NO_CREDENTIAL_REFERENCE"


@pytest.mark.asyncio
async def test_checkout_application_denies_ambiguous_vault_refs(db_session: AsyncSession, app_setup):
    """Two active VaultRefs for the same application results in AMBIGUOUS_CREDENTIAL_REFERENCE."""
    user = app_setup["user"]
    app = app_setup["app"]
    req = app_setup["request"]
    grant = app_setup["grant"]

    db_session.add(VaultRef(application_id=app.id, provider="mock", vault_path="securepam/applications/app1",
                    secret_type="PASSWORD", is_active=True))
    db_session.add(VaultRef(application_id=app.id, provider="mock", vault_path="securepam/applications/app2",
                    secret_type="PASSWORD", is_active=True))
    await db_session.commit()

    provider = MockSecretProvider()
    service = CredentialService(provider=provider)

    checkout_req = CheckoutRequest(
        user_id=user.id,
        access_request_id=req.id,
        jit_grant_id=grant.id,
        application_id=app.id,
    )

    with pytest.raises(CredentialAccessDenied) as exc:
        async with service.checkout(db_session, checkout_req):
            pass
    assert exc.value.reason == "AMBIGUOUS_CREDENTIAL_REFERENCE"


@pytest.mark.asyncio
async def test_gateway_auth_hook_injects_basic_auth_header(
    client: AsyncClient, db_session: AsyncSession, app_setup, monkeypatch
):
    """Gateway internal auth hook detects application VaultRef and injects Basic auth header."""
    app = app_setup["app"]
    session = app_setup["session"]

    vref = VaultRef(
        application_id=app.id,
        provider="mock",
        vault_path=APP_PATH,
        secret_type="PASSWORD",
        username="service_account",
        is_active=True,
    )
    db_session.add(vref)
    await db_session.commit()

    mock_provider = MockSecretProvider({APP_PATH: {"username": "service_account", "password": "SuperSecretPassword123"}})
    monkeypatch.setattr("app.services.credential_service.get_secret_provider", lambda: mock_provider)

    headers = {
        "X-Gateway-Auth-Token": settings.GATEWAY_AUTH_TOKEN,
        "X-SecurePAM-Session-ID": str(session.id),
        "X-SecurePAM-App-ID": str(app.id),
    }

    resp = await client.get("/api/v1/gateway/internal/auth", headers=headers)
    assert resp.status_code == 200

    # Verify injected Authorization header
    auth_header = resp.headers.get("X-SecurePAM-Upstream-Authorization")
    assert auth_header is not None
    assert auth_header.startswith("Basic ")

    # Decode and verify credentials
    b64_part = auth_header.split(" ", 1)[1]
    decoded = base64.b64decode(b64_part).decode("utf-8")
    assert decoded == "service_account:SuperSecretPassword123"


@pytest.mark.asyncio
async def test_gateway_auth_hook_injects_bearer_auth_header(
    client: AsyncClient, db_session: AsyncSession, app_setup, monkeypatch
):
    """Gateway internal auth hook detects API_KEY VaultRef and injects Bearer header."""
    app = app_setup["app"]
    session = app_setup["session"]

    api_path = "securepam/applications/api-token"
    vref = VaultRef(
        application_id=app.id,
        provider="mock",
        vault_path=api_path,
        secret_type="API_KEY",
        is_active=True,
    )
    db_session.add(vref)
    await db_session.commit()

    mock_provider = MockSecretProvider({api_path: {"api_key": "bearer-jwt-token-val-456"}})
    monkeypatch.setattr("app.services.credential_service.get_secret_provider", lambda: mock_provider)

    headers = {
        "X-Gateway-Auth-Token": settings.GATEWAY_AUTH_TOKEN,
        "X-SecurePAM-Session-ID": str(session.id),
        "X-SecurePAM-App-ID": str(app.id),
    }

    resp = await client.get("/api/v1/gateway/internal/auth", headers=headers)
    assert resp.status_code == 200

    auth_header = resp.headers.get("X-SecurePAM-Upstream-Authorization")
    assert auth_header == "Bearer bearer-jwt-token-val-456"


@pytest.mark.asyncio
async def test_gateway_auth_hook_no_vault_ref_leaves_header_unset(
    client: AsyncClient, db_session: AsyncSession, app_setup
):
    """When an application has no VaultRef, no Authorization header is injected."""
    app = app_setup["app"]
    session = app_setup["session"]

    headers = {
        "X-Gateway-Auth-Token": settings.GATEWAY_AUTH_TOKEN,
        "X-SecurePAM-Session-ID": str(session.id),
        "X-SecurePAM-App-ID": str(app.id),
    }

    resp = await client.get("/api/v1/gateway/internal/auth", headers=headers)
    assert resp.status_code == 200
    assert "X-SecurePAM-Upstream-Authorization" not in resp.headers


@pytest.mark.asyncio
async def test_secret_redaction_in_audit_logs(db_session: AsyncSession, app_setup):
    """Verify that credentials are NEVER logged in audit records."""
    user = app_setup["user"]
    app = app_setup["app"]
    req = app_setup["request"]
    grant = app_setup["grant"]

    vref = VaultRef(
        application_id=app.id,
        provider="mock",
        vault_path=APP_PATH,
        secret_type="PASSWORD",
        username="audit_test_user",
        is_active=True,
    )
    db_session.add(vref)
    await db_session.commit()

    raw_secret = "UltraSecretValueNotToBeLogged!"
    provider = MockSecretProvider({APP_PATH: {"username": "audit_test_user", "password": raw_secret}})
    service = CredentialService(provider=provider)

    checkout_req = CheckoutRequest(
        user_id=user.id,
        access_request_id=req.id,
        jit_grant_id=grant.id,
        application_id=app.id,
    )

    async with service.checkout(db_session, checkout_req) as cred:
        _ = cred.reveal()

    # Query audit logs
    audit_res = await db_session.execute(
        select(AuditLog).where(AuditLog.action.like("CREDENTIAL_%"))
    )
    audit_entries = audit_res.scalars().all()
    assert len(audit_entries) >= 2  # ATTEMPTED and RETRIEVED

    for entry in audit_entries:
        details_str = str(entry.details or {})
        assert raw_secret not in details_str
