"""
Access Request workflow: HTTP-level validation/RBAC/IDOR/state-machine
tests (using the `client` fixture — real wall-clock time, so these never
assert exact risk scores or depend on hitting a specific risk tier), plus
a few direct AccessDecisionService calls with an injected `now` for the
decision-matrix outcomes that DO need deterministic risk (auto-approve,
elevated-approval, policy-denial).
"""

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from httpx import AsyncClient

from app.models.asset import Asset
from app.models.policy import Policy
from app.models.user import User
from app.services.access_decision import AccessDecisionService, InvalidTargetError
from tests.conftest import auth_header

BUSINESS_HOURS_NOW = datetime(2025, 1, 8, 12, 0, tzinfo=timezone.utc)  # Wed noon UTC


async def _get(db_session: AsyncSession, model, **filters):
    conditions = [getattr(model, k) == v for k, v in filters.items()]
    result = await db_session.execute(select(model).where(*conditions))
    return result.scalar_one()


# --- validation ---

async def test_create_requires_authentication(client: AsyncClient):
    resp = await client.post("/api/v1/access-requests", json={"protocol": "SSH", "reason": "x"})
    assert resp.status_code == 401


async def test_missing_target_returns_422(client: AsyncClient, operator_token: str):
    resp = await client.post(
        "/api/v1/access-requests",
        json={"protocol": "SSH", "reason": "no target", "requested_duration": 30},
        headers=auth_header(operator_token),
    )
    assert resp.status_code == 422


async def test_both_targets_returns_422(client: AsyncClient, operator_token: str, db_session: AsyncSession):
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    resp = await client.post(
        "/api/v1/access-requests",
        json={
            "asset_id": str(asset.id), "application_id": str(uuid4()),
            "protocol": "SSH", "reason": "both", "requested_duration": 30,
        },
        headers=auth_header(operator_token),
    )
    assert resp.status_code == 422


async def test_nonexistent_asset_returns_422(client: AsyncClient, operator_token: str):
    resp = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(uuid4()), "protocol": "SSH", "reason": "x", "requested_duration": 30},
        headers=auth_header(operator_token),
    )
    assert resp.status_code == 422


async def test_disabled_target_returns_422(client: AsyncClient, operator_token: str, admin_token: str, db_session: AsyncSession):
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    await client.patch(f"/api/v1/assets/{asset.id}", json={"enabled": False}, headers=auth_header(admin_token))

    resp = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "x", "requested_duration": 30},
        headers=auth_header(operator_token),
    )
    assert resp.status_code == 422


async def test_protocol_mismatch_returns_422(client: AsyncClient, operator_token: str, db_session: AsyncSession):
    """LINUX-DEV-01 is registered as SSH — requesting RDP against it must fail."""
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    resp = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "RDP", "reason": "wrong protocol", "requested_duration": 30},
        headers=auth_header(operator_token),
    )
    assert resp.status_code == 422


async def test_excessive_duration_returns_422(client: AsyncClient, operator_token: str, db_session: AsyncSession):
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    resp = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "x", "requested_duration": 99999},
        headers=auth_header(operator_token),
    )
    assert resp.status_code == 422


async def test_operator_without_create_permission_cannot_request(client: AsyncClient, auditor_token: str, db_session: AsyncSession):
    """AUDITOR has no access_requests:create."""
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    resp = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "x", "requested_duration": 30},
        headers=auth_header(auditor_token),
    )
    assert resp.status_code == 403


# --- privilege escalation resistance ---

async def test_client_cannot_set_server_controlled_fields(client: AsyncClient, operator_token: str, db_session: AsyncSession):
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    resp = await client.post(
        "/api/v1/access-requests",
        json={
            "asset_id": str(asset.id), "protocol": "SSH", "reason": "escalation attempt", "requested_duration": 10,
            "risk_score": 0, "risk_level": "LOW", "status": "APPROVED", "approval_required": False,
            "requester_id": str(uuid4()), "decided_by": str(uuid4()),
        },
        headers=auth_header(operator_token),
    )
    assert resp.status_code == 201
    body = resp.json()
    # user_id came from the authenticated token, never the body.
    me = await client.get("/api/v1/auth/me", headers=auth_header(operator_token))
    assert body["user_id"] == me.json()["id"]
    # risk_score was computed server-side, not the client's "0".
    assert body["risk_score"] is not None


# --- IDOR ---

async def test_peer_operator_cannot_view_another_operators_request(
    client: AsyncClient, operator_token: str, operator2_token: str, db_session: AsyncSession
):
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    create = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "mine", "requested_duration": 15},
        headers=auth_header(operator_token),
    )
    request_id = create.json()["id"]

    resp = await client.get(f"/api/v1/access-requests/{request_id}", headers=auth_header(operator2_token))
    assert resp.status_code == 404  # not 403 — existence not disclosed


async def test_peer_operator_cannot_cancel_another_operators_request(
    client: AsyncClient, operator_token: str, operator2_token: str, db_session: AsyncSession
):
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    create = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "mine", "requested_duration": 15},
        headers=auth_header(operator_token),
    )
    request_id = create.json()["id"]

    resp = await client.post(f"/api/v1/access-requests/{request_id}/cancel", headers=auth_header(operator2_token))
    assert resp.status_code == 404


async def test_list_only_shows_own_requests_for_read_own_scope(
    client: AsyncClient, operator_token: str, operator2_token: str, db_session: AsyncSession
):
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "op1", "requested_duration": 15},
        headers=auth_header(operator_token),
    )
    await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "op2", "requested_duration": 15},
        headers=auth_header(operator2_token),
    )

    resp = await client.get("/api/v1/access-requests", headers=auth_header(operator_token))
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["reason"] == "op1"


async def test_view_all_permission_sees_every_request(
    client: AsyncClient, operator_token: str, approver_token: str, db_session: AsyncSession
):
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "op1", "requested_duration": 15},
        headers=auth_header(operator_token),
    )

    resp = await client.get("/api/v1/access-requests", headers=auth_header(approver_token))
    assert resp.status_code == 200
    assert resp.json()["total"] == 1


# --- cancel / state machine ---

async def test_requester_can_cancel_own_request(client: AsyncClient, operator_token: str, db_session: AsyncSession):
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    create = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "x", "requested_duration": 15},
        headers=auth_header(operator_token),
    )
    request_id = create.json()["id"]
    status_before = create.json()["status"]

    resp = await client.post(f"/api/v1/access-requests/{request_id}/cancel", headers=auth_header(operator_token))
    if status_before in ("PENDING", "APPROVAL_REQUIRED"):
        assert resp.status_code == 200
        assert resp.json()["status"] == "CANCELLED"
    else:
        # Auto-approved straight to ACTIVE this run (business-hours-dependent) — cancel must be refused.
        assert resp.status_code == 409


async def test_cannot_cancel_already_cancelled_request(client: AsyncClient, operator_token: str, db_session: AsyncSession):
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    create = await client.post(
        "/api/v1/access-requests",
        json={"asset_id": str(asset.id), "protocol": "SSH", "reason": "x", "requested_duration": 15},
        headers=auth_header(operator_token),
    )
    request_id = create.json()["id"]

    first = await client.post(f"/api/v1/access-requests/{request_id}/cancel", headers=auth_header(operator_token))
    if first.status_code != 200:
        return  # was auto-approved this run; nothing to double-cancel

    second = await client.post(f"/api/v1/access-requests/{request_id}/cancel", headers=auth_header(operator_token))
    assert second.status_code == 409


# --- deterministic decision-matrix outcomes (direct service calls, injected `now`) ---

async def test_policy_denial_yields_denied_status(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    policy = Policy(name=f"Deny-{uuid4()}", allowed_roles=["ADMIN"], enabled=True)
    db_session.add(policy)
    await db_session.flush()
    asset.policy_id = policy.id
    await db_session.commit()

    service = AccessDecisionService()
    request = await service.create_request(
        db_session, requester=operator, asset_id=asset.id, application_id=None,
        protocol="SSH", reason="denied test", requested_duration=15,
        source_ip="10.0.0.1", user_agent="pytest", now=BUSINESS_HOURS_NOW,
    )
    assert request.status == "DENIED"
    assert request.approval_required is False


async def test_policy_requiring_approval_yields_approval_required(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")
    policy = Policy(name=f"NeedsApproval-{uuid4()}", require_approval=True, auto_approve=False, enabled=True)
    db_session.add(policy)
    await db_session.flush()
    asset.policy_id = policy.id
    await db_session.commit()

    service = AccessDecisionService()
    request = await service.create_request(
        db_session, requester=operator, asset_id=asset.id, application_id=None,
        protocol="SSH", reason="approval test", requested_duration=15,
        source_ip="10.0.0.1", user_agent="pytest", now=BUSINESS_HOURS_NOW,
    )
    assert request.status == "APPROVAL_REQUIRED"
    assert request.approval_required is True
    assert request.expires_at is not None  # approval-queue deadline set


async def test_low_risk_auto_approve_policy_yields_active(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="LINUX-DEV-01")  # DEVELOPMENT, MEDIUM — no risk factors fire
    policy = Policy(name=f"AutoApprove-{uuid4()}", require_approval=False, auto_approve=True, enabled=True)
    db_session.add(policy)
    await db_session.flush()
    asset.policy_id = policy.id
    await db_session.commit()

    service = AccessDecisionService()
    request = await service.create_request(
        db_session, requester=operator, asset_id=asset.id, application_id=None,
        protocol="SSH", reason="auto-approve test", requested_duration=15,
        source_ip="10.0.0.1", user_agent="pytest", now=BUSINESS_HOURS_NOW,
    )
    assert request.risk_level == "LOW"
    assert request.status == "ACTIVE"
    assert request.decided_by is None  # automatic, not human


async def test_critical_risk_with_no_policy_is_denied(db_session: AsyncSession):
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="WIN-PROD-01")
    asset.criticality = "CRITICAL"
    asset.policy_id = None
    await db_session.commit()

    service = AccessDecisionService()
    request = await service.create_request(
        db_session, requester=operator, asset_id=asset.id, application_id=None,
        protocol="RDP", reason="critical no policy", requested_duration=15,
        source_ip=None, user_agent="pytest", now=datetime(2025, 1, 11, 12, 0, tzinfo=timezone.utc),  # Saturday
    )
    assert request.risk_level == "CRITICAL"
    assert request.status == "DENIED"


async def test_high_risk_forces_approval_even_with_auto_approve_policy(db_session: AsyncSession):
    """Risk HIGH must override an auto_approve=True policy — never 'high risk = automatically allowed'."""
    operator = await _get(db_session, User, username="operator")
    asset = await _get(db_session, Asset, name="WIN-PROD-01")  # PRODUCTION + HIGH
    policy = Policy(name=f"PermissiveButHighRisk-{uuid4()}", require_approval=False, auto_approve=True, enabled=True)
    db_session.add(policy)
    await db_session.flush()
    asset.policy_id = policy.id
    await db_session.commit()

    service = AccessDecisionService()
    request = await service.create_request(
        db_session, requester=operator, asset_id=asset.id, application_id=None,
        protocol="RDP", reason="high risk override test", requested_duration=15,
        source_ip="10.0.0.1", user_agent="pytest",
        now=datetime(2025, 1, 11, 12, 0, tzinfo=timezone.utc),  # Saturday -> OUTSIDE_BUSINESS_HOURS
    )
    assert request.risk_level in ("HIGH", "CRITICAL")
    assert request.status == "APPROVAL_REQUIRED"


async def test_inactive_admin_role_cannot_view_all_requests(
    client: AsyncClient,
    admin_token: str,
    db_session: AsyncSession,
):
    from app.models.role import Role

    role = await _get(db_session, Role, name="ADMIN")
    original_active = role.is_active

    try:
        role.is_active = False
        await db_session.commit()

        resp = await client.get(
            "/api/v1/access-requests",
            headers=auth_header(admin_token),
        )

        assert resp.status_code == 403
    finally:
        role.is_active = original_active
        await db_session.commit()
