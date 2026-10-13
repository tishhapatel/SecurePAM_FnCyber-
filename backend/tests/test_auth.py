"""
Authentication: dev login, /me, invalid credentials, unauthorized access,
and the core trust boundary between IdP identity and local RBAC.
"""
from unittest.mock import patch
from sqlalchemy import select
from app.auth.oidc_provider import OIDCProviderUnavailableError
from app.models.user import User
from httpx import AsyncClient

from tests.conftest import auth_header, issue_token


async def test_login_success_returns_tokens(client: AsyncClient):
    resp = await client.post(
        "/api/v1/auth/login", json={"username": "operator", "password": "operator123"}
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["token_type"] == "bearer"


async def test_login_wrong_password_returns_401_with_consistent_envelope(client: AsyncClient):
    resp = await client.post(
        "/api/v1/auth/login", json={"username": "operator", "password": "not-the-password"}
    )
    assert resp.status_code == 401
    body = resp.json()
    assert body["detail"] == "Invalid username or password"
    assert "error_code" in body  # consistent envelope, even though null here


async def test_login_unknown_username_returns_401(client: AsyncClient):
    resp = await client.post(
        "/api/v1/auth/login", json={"username": "no-such-user", "password": "x"}
    )
    assert resp.status_code == 401


async def test_login_missing_fields_returns_422_validation_error(client: AsyncClient):
    resp = await client.post("/api/v1/auth/login", json={})
    assert resp.status_code == 422
    body = resp.json()
    assert body["error_code"] == "VALIDATION_ERROR"
    fields = {tuple(e["loc"]) for e in body["errors"]}
    assert ("body", "username") in fields
    assert ("body", "password") in fields


async def test_me_requires_authentication(client: AsyncClient):
    resp = await client.get("/api/v1/auth/me")
    assert resp.status_code == 401
    assert resp.json()["detail"] == "Authentication required"


async def test_me_rejects_garbage_token(client: AsyncClient):
    resp = await client.get("/api/v1/auth/me", headers=auth_header("not-a-real-jwt"))
    assert resp.status_code == 401


async def test_me_returns_profile_and_permissions(client: AsyncClient, admin_token: str):
    resp = await client.get("/api/v1/auth/me", headers=auth_header(admin_token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == "admin"
    assert "ADMIN" in body["roles"]
    assert "assets:read" in body["permissions"]


async def test_token_claimed_roles_are_not_trusted(client: AsyncClient):
    """
    Core security property from the auth architecture (app/auth/base.py):
    TokenIdentity.token_roles is informational ONLY. Authorization always
    comes from the local RBAC tables, never from what a token claims.

    Here we mint a token for the 'operator' user but forge ADMIN into its
    token_roles claim. /me must still report OPERATOR — proving the forged
    claim was never consulted.
    """
    forged_token = issue_token("operator", roles=["ADMIN"])
    resp = await client.get("/api/v1/auth/me", headers=auth_header(forged_token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["roles"] == ["OPERATOR"]
    assert "users:delete" not in body["permissions"]


async def test_login_disabled_outside_dev_mode(client: AsyncClient, monkeypatch):
    from app.api.v1 import auth as auth_module

    monkeypatch.setattr(auth_module.settings, "DEV_MODE", False)
    resp = await client.post(
        "/api/v1/auth/login", json={"username": "operator", "password": "operator123"}
    )
    assert resp.status_code == 403



async def test_keycloak_outage_returns_503(client: AsyncClient, monkeypatch):
    """A Keycloak signing-key outage should return 503, not 401."""
    from app.auth import get_token_validator
    from app.auth.oidc_provider import OIDCTokenValidator

    monkeypatch.setattr(
        "app.core.deps.get_token_validator",
        lambda: OIDCTokenValidator(),
    )

    with patch.object(
        OIDCTokenValidator,
        "validate",
        side_effect=OIDCProviderUnavailableError("Keycloak unavailable"),
    ):
        resp = await client.get(
            "/api/v1/auth/me",
            headers=auth_header("any-token"),
        )

    assert resp.status_code == 503
    assert resp.json()["detail"] == "Identity provider temporarily unavailable"


async def test_keycloak_identity_uses_external_id(
    client: AsyncClient,
    db_session,
    monkeypatch,
):
    """Keycloak's sub claim should match User.external_id, not username."""
    from app.auth import TokenIdentity
    from app.auth.oidc_provider import OIDCTokenValidator

    # Ensure the dependency uses the Keycloak identity lookup path.
    monkeypatch.setattr("app.core.deps.settings.DEV_MODE", False)
    monkeypatch.setattr(
        "app.core.deps.get_token_validator",
        lambda: OIDCTokenValidator(),
    )

    user = await db_session.scalar(
        select(User).where(User.username == "operator")
    )
    assert user is not None
    user.external_id = "keycloak-sub-123"
    await db_session.commit()

    with patch.object(
        OIDCTokenValidator,
        "validate",
        return_value=TokenIdentity(
            subject="keycloak-sub-123",
            email=user.email,
            name=user.full_name,
            token_roles=["ADMIN"],
        ),
    ):
        resp = await client.get(
            "/api/v1/auth/me",
            headers=auth_header("mock-keycloak-token"),
        )

    assert resp.status_code == 200
    assert resp.json()["username"] == "operator"
    # The token's ADMIN claim must not grant local ADMIN privileges.
    assert "ADMIN" not in resp.json()["roles"]


async def test_me_excludes_inactive_role_and_permissions(
    client: AsyncClient,
    admin_token: str,
    db_session,
):
    from sqlalchemy import select
    from app.models.role import Role

    role = await db_session.scalar(
        select(Role).where(Role.name == "ADMIN")
    )
    assert role is not None

    original_active = role.is_active
    try:
        role.is_active = False
        await db_session.commit()

        resp = await client.get(
            "/api/v1/auth/me",
            headers=auth_header(admin_token),
        )

        assert resp.status_code == 200
        body = resp.json()
        assert "ADMIN" not in body["roles"]
        assert "users:delete" not in body["permissions"]
    finally:
        role.is_active = original_active
        await db_session.commit()

async def test_keycloak_identity_rejects_inactive_user(
    client: AsyncClient,
    db_session,
    monkeypatch,
):
    from app.auth import TokenIdentity
    from app.auth.oidc_provider import OIDCTokenValidator

    monkeypatch.setattr("app.core.deps.settings.DEV_MODE", False)
    monkeypatch.setattr(
        "app.core.deps.get_token_validator",
        lambda: OIDCTokenValidator(),
    )

    user = await db_session.scalar(
        select(User).where(User.username == "operator")
    )
    assert user is not None

    user.external_id = "inactive-keycloak-sub"
    user.is_active = False
    await db_session.commit()

    with patch.object(
        OIDCTokenValidator,
        "validate",
        return_value=TokenIdentity(
            subject="inactive-keycloak-sub",
            email=user.email,
            name=user.full_name,
            token_roles=[],
        ),
    ):
        response = await client.get(
            "/api/v1/auth/me",
            headers=auth_header("inactive-keycloak-token"),
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "User not found or inactive"


async def test_keycloak_identity_rejects_deleted_user(
    client: AsyncClient,
    db_session,
    monkeypatch,
):
    from app.auth import TokenIdentity
    from app.auth.oidc_provider import OIDCTokenValidator

    monkeypatch.setattr("app.core.deps.settings.DEV_MODE", False)
    monkeypatch.setattr(
        "app.core.deps.get_token_validator",
        lambda: OIDCTokenValidator(),
    )

    user = await db_session.scalar(
        select(User).where(User.username == "operator")
    )
    assert user is not None

    user.external_id = "deleted-keycloak-sub"
    user.is_deleted = True
    await db_session.commit()

    with patch.object(
        OIDCTokenValidator,
        "validate",
        return_value=TokenIdentity(
            subject="deleted-keycloak-sub",
            email=user.email,
            name=user.full_name,
            token_roles=[],
        ),
    ):
        response = await client.get(
            "/api/v1/auth/me",
            headers=auth_header("deleted-keycloak-token"),
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "User not found or inactive"


async def test_unknown_keycloak_subject_is_not_auto_provisioned(
    client: AsyncClient,
    db_session,
    monkeypatch,
):
    from app.auth import TokenIdentity
    from app.models.user import User
    from app.auth.oidc_provider import OIDCTokenValidator

    monkeypatch.setattr("app.core.deps.settings.DEV_MODE", False)
    monkeypatch.setattr(
        "app.core.deps.get_token_validator",
        lambda: OIDCTokenValidator(),
    )

    with patch.object(
        OIDCTokenValidator,
        "validate",
        return_value=TokenIdentity(
            subject="unknown-keycloak-subject",
            email="unknown@example.test",
            name="Unknown User",
            token_roles=["ADMIN"],
        ),
    ):
        response = await client.get(
            "/api/v1/auth/me",
            headers=auth_header("unknown-keycloak-token"),
        )

    assert response.status_code == 401
    assert response.json()["detail"] == "User not found or inactive"

    user = await db_session.scalar(
        select(User).where(
            User.external_id == "unknown-keycloak-subject"
        )
    )
    assert user is None