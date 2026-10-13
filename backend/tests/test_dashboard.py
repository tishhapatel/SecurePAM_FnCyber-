"""Dashboard summary/activity endpoints â€” real DB-backed counts, never fake numbers."""

from httpx import AsyncClient
from sqlalchemy import select
from app.core.security import generate_request_number, generate_session_number
from app.models.access_request import AccessRequest
from app.models.asset import Asset
from app.models.recording import Recording
from app.models.session import Session
from app.models.user import User
from tests.conftest import auth_header


async def test_dashboard_summary_requires_authentication(client: AsyncClient):
    resp = await client.get("/api/v1/dashboard/summary")
    assert resp.status_code == 401


async def test_dashboard_summary_reflects_seeded_assets(client: AsyncClient, admin_token: str):
    resp = await client.get("/api/v1/dashboard/summary", headers=auth_header(admin_token))
    assert resp.status_code == 200
    body = resp.json()
    # Seed data creates exactly 5 assets (WIN-PROD-01, WIN-DEV-01,
    # LINUX-PROD-01, LINUX-DEV-01, LINUX-STAGING-01) â€” see app/main.py.
    assert body["registered_assets"] == 5
    assert body["active_sessions"] == 0
    assert body["pending_requests"] == 0
    assert isinstance(body["recording_storage_mb"], float)


async def test_dashboard_counts_requests_awaiting_approval(
    client: AsyncClient,
    admin_token: str,
    db_session,
):
    user = (
        await db_session.execute(
            select(User).where(User.username == "admin")
        )
    ).scalar_one()

    asset = (
        await db_session.execute(
            select(Asset).where(Asset.name == "LINUX-DEV-01")
        )
    ).scalar_one()

    request = AccessRequest(
        request_number=generate_request_number(),
        user_id=user.id,
        asset_id=asset.id,
        protocol="SSH",
        reason="Dashboard approval-count regression test",
        requested_duration=30,
        status="APPROVAL_REQUIRED",
        approval_required=True,
        jit_required=False,
        mfa_required=False,
        recording_required=True,
    )
    db_session.add(request)
    await db_session.commit()

    response = await client.get(
        "/api/v1/dashboard/summary",
        headers=auth_header(admin_token),
    )

    assert response.status_code == 200
    assert response.json()["pending_requests"] == 1


async def test_dashboard_activity_requires_authentication(client: AsyncClient):
    resp = await client.get("/api/v1/dashboard/activity")
    assert resp.status_code == 401


async def test_dashboard_activity_returns_a_list(client: AsyncClient, operator_token: str):
    resp = await client.get("/api/v1/dashboard/activity", headers=auth_header(operator_token))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


async def test_dashboard_activity_rejects_limit_above_maximum(
    client: AsyncClient,
    admin_token: str,
):
    response = await client.get(
        "/api/v1/dashboard/activity",
        params={"limit": 999},
        headers=auth_header(admin_token),
    )

    assert response.status_code == 422


async def _create_recording(
    db_session,
    *,
    user_id,
    asset_id,
    file_size,
    status="COMPLETED",
):
    """Create a valid session and its recording for dashboard tests."""
    request = AccessRequest(
        request_number=generate_request_number(),
        user_id=user_id,
        asset_id=asset_id,
        protocol="SSH",
        reason="Dashboard recording-storage test",
        requested_duration=30,
        status="ACTIVE",
        approval_required=False,
        jit_required=False,
        mfa_required=False,
        recording_required=True,
    )
    db_session.add(request)
    await db_session.flush()

    session = Session(
        session_number=generate_session_number(),
        user_id=user_id,
        asset_id=asset_id,
        protocol="SSH",
        status="COMPLETED",
        request_id=request.id,
    )
    db_session.add(session)
    await db_session.flush()

    recording = Recording(
        session_id=session.id,
        recording_type="TERMINAL",
        status=status,
        file_size=file_size,
    )
    db_session.add(recording)
    await db_session.flush()
    return recording


async def test_dashboard_storage_sums_non_deleted_recordings(
    client: AsyncClient,
    admin_token: str,
    db_session,
):
    

    user = (
        await db_session.execute(select(User).where(User.username == "admin"))
    ).scalar_one()
    asset = (
        await db_session.execute(select(Asset).where(Asset.name == "LINUX-DEV-01"))
    ).scalar_one()

    await _create_recording(
        db_session, user_id=user.id, asset_id=asset.id, file_size=1024 * 1024
    )
    await _create_recording(
        db_session, user_id=user.id, asset_id=asset.id, file_size=2 * 1024 * 1024
    )
    await _create_recording(
        db_session,
        user_id=user.id,
        asset_id=asset.id,
        file_size=50 * 1024 * 1024,
        status="DELETED",
    )
    await db_session.commit()

    response = await client.get(
        "/api/v1/dashboard/summary", headers=auth_header(admin_token)
    )

    assert response.status_code == 200
    assert response.json()["recording_storage_mb"] == 3.0


async def test_dashboard_storage_is_zero_without_recordings(
    client: AsyncClient,
    admin_token: str,
):
    response = await client.get(
        "/api/v1/dashboard/summary", headers=auth_header(admin_token)
    )

    assert response.status_code == 200
    assert response.json()["recording_storage_mb"] == 0.0


async def test_dashboard_activity_rejects_invalid_limit(
    client: AsyncClient,
    admin_token: str,
):
    for limit in (0, -1, 51):
        response = await client.get(
            "/api/v1/dashboard/activity",
            params={"limit": limit},
            headers=auth_header(admin_token),
        )
        assert response.status_code == 422
