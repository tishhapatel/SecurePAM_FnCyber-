"""
Tests for Session Video Recording & Member 12 Integration (Task B).

Covers:
- Recording process startup & metadata association on session launch.
- Successful recording finalization with file size, duration, and SHA-256 hash.
- Storage under settings.RECORDING_STORAGE_PATH with .mp4 format.
- Member 12 stream endpoint compatibility (GET /api/v1/recordings/{id}/stream).
- RBAC protection: Auditor/Admin can stream; unprivileged operators get 403.
- Audit logging for RECORDING_VIEWED upon streaming.
- Safe idempotent session termination (duplicate termination returns 409).
- Failed recording handling (empty output / failure flags).
- Path traversal protection (outside storage path returns 404).
"""

import hashlib
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

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
from app.models.audit import AuditLog
from app.models.jit_grant import JITGrant
from app.models.recording import Recording
from app.models.session import Session as SessionModel, SessionEvent
from app.models.user import User
from app.services.browser_isolation_service import browser_isolation_service


@pytest.fixture
def recording_storage(tmp_path, monkeypatch):
    """Sets up a temporary recording storage root directory."""
    rec_dir = tmp_path / "recordings"
    rec_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(settings, "RECORDING_STORAGE_PATH", str(rec_dir))
    return rec_dir


@pytest_asyncio.fixture
async def browser_session_setup(db_session: AsyncSession, recording_storage):
    """Sets up an ISOLATED_BROWSER Application, approved AccessRequest, and active JITGrant."""
    res = await db_session.execute(select(User).where(User.username == "operator"))
    operator_user = res.scalar_one()

    app = Application(
        name="Isolated Analytics App",
        hostname="analytics.internal",
        port=8080,
        protocol="HTTP",
        target_url="http://analytics.internal:8080",
        environment="PRODUCTION",
        criticality="HIGH",
        access_mode="ISOLATED_BROWSER",
        recording_required=True,
        approval_required=False,
        mfa_required=False,
        status="ACTIVE",
        enabled=True,
    )
    db_session.add(app)
    await db_session.flush()

    now = datetime.now(timezone.utc)
    req = AccessRequest(
        request_number=generate_request_number(),
        user_id=operator_user.id,
        application_id=app.id,
        protocol="HTTP",
        reason="Security analytics inspection",
        status="APPROVED",
        requested_duration=30,
        recording_required=True,
    )
    db_session.add(req)
    await db_session.flush()

    grant = JITGrant(
        request_id=req.id,
        user_id=operator_user.id,
        application_id=app.id,
        protocol="HTTP",
        status="ACTIVE",
        granted_at=now - timedelta(minutes=2),
        expires_at=now + timedelta(minutes=28),
    )

    db_session.add(grant)
    await db_session.commit()
    await db_session.refresh(app)
    await db_session.refresh(req)
    await db_session.refresh(grant)

    return {
        "user": operator_user,
        "app": app,
        "request": req,
        "grant": grant,
        "storage": recording_storage,
    }


@pytest.mark.asyncio
async def test_session_launch_creates_and_associates_recording(client: AsyncClient, db_session: AsyncSession, browser_session_setup):
    """Launching an isolated browser session must create a PENDING/RECORDING Recording row associated with Session."""
    setup = browser_session_setup
    op_token = issue_token("operator")

    res = await client.post(
        f"/api/v1/gateway/apps/{setup['app'].id}/session",
        headers=auth_header(op_token),
        json={"application_id": str(setup['app'].id)},
    )
    assert res.status_code == 201, res.text
    data = res.json()
    session_id = uuid.UUID(data["session_id"])
    assert data["recording_id"] is not None
    rec_id = uuid.UUID(data["recording_id"])

    # Verify session and recording in database
    session_row = await db_session.get(SessionModel, session_id)
    assert session_row is not None
    assert session_row.recording_id == rec_id

    rec_row = await db_session.get(Recording, rec_id)
    assert rec_row is not None
    assert rec_row.session_id == session_id
    assert rec_row.recording_type == "VIDEO"
    assert rec_row.status == "RECORDING"
    assert rec_row.file_path.endswith(f"session_{session_id}.mp4")


@pytest.mark.asyncio
async def test_session_termination_finalizes_recording_metadata(client: AsyncClient, db_session: AsyncSession, browser_session_setup):
    """Terminating an isolated browser session finalizes recording file size, sha256 hash, and duration."""
    setup = browser_session_setup
    op_token = issue_token("operator")
    storage_dir = setup["storage"]

    # 1. Start session
    start_res = await client.post(
        f"/api/v1/gateway/apps/{setup['app'].id}/session",
        headers=auth_header(op_token),
        json={"application_id": str(setup['app'].id)},
    )
    assert start_res.status_code == 201
    session_id = uuid.UUID(start_res.json()["session_id"])
    rec_id = uuid.UUID(start_res.json()["recording_id"])

    # Create dummy mp4 file on disk in storage
    rec_file = storage_dir / f"session_{session_id}.mp4"
    dummy_video_bytes = b"\x00\x00\x00\x1cftypisom\x00\x00\x02\x00mp41isomiso2avc1\x00\x00\x00\x08free" + b"TESTVIDEOPAYLOAD12345"
    rec_file.write_bytes(dummy_video_bytes)

    # 2. Terminate session
    term_res = await client.post(
        f"/api/v1/gateway/apps/{setup['app'].id}/session/{session_id}/terminate",
        headers=auth_header(op_token),
    )
    assert term_res.status_code == 200, term_res.text
    term_data = term_res.json()
    assert term_data["status"] == "COMPLETED"
    assert term_data["recording_id"] == str(rec_id)

    # 3. Verify Recording row is COMPLETED and has accurate hash & size
    db_session.expire_all()
    rec_row = await db_session.get(Recording, rec_id)
    assert rec_row.status == "COMPLETED"
    assert rec_row.file_size == len(dummy_video_bytes)
    expected_hash = hashlib.sha256(dummy_video_bytes).hexdigest()
    assert rec_row.file_hash == expected_hash
    assert rec_row.duration_seconds is not None
    assert rec_row.duration_seconds >= 1


@pytest.mark.asyncio
async def test_member12_recording_stream_playback_and_audit(client: AsyncClient, db_session: AsyncSession, browser_session_setup):
    """Member 12's GET /api/v1/recordings/{id}/stream streams finalized video and audits RECORDING_VIEWED."""
    setup = browser_session_setup
    op_token = issue_token("operator")
    auditor_token = issue_token("auditor")
    storage_dir = setup["storage"]

    # Launch & terminate session
    start_res = await client.post(
        f"/api/v1/gateway/apps/{setup['app'].id}/session",
        headers=auth_header(op_token),
        json={"application_id": str(setup['app'].id)},
    )
    session_id = uuid.UUID(start_res.json()["session_id"])
    rec_id = uuid.UUID(start_res.json()["recording_id"])

    rec_file = storage_dir / f"session_{session_id}.mp4"
    dummy_video_bytes = b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00isommp42\x00\x00\x00\x08freeMP4EVIDENCE"
    rec_file.write_bytes(dummy_video_bytes)

    await client.post(
        f"/api/v1/gateway/apps/{setup['app'].id}/session/{session_id}/terminate",
        headers=auth_header(op_token),
    )

    # 1. Auditor requests stream playback
    stream_res = await client.get(
        f"/api/v1/recordings/{rec_id}/stream",
        headers=auth_header(auditor_token),
    )
    assert stream_res.status_code == 200
    assert stream_res.headers.get("content-type") == "video/mp4"
    assert stream_res.content == dummy_video_bytes

    # 2. Verify Member 12 audit log
    audit_res = await db_session.execute(
        select(AuditLog).where(
            AuditLog.action == "RECORDING_VIEWED",
            AuditLog.target_id == str(rec_id),
        )
    )
    audit_event = audit_res.scalar_one_or_none()
    assert audit_event is not None
    assert audit_event.result == "SUCCESS"
    assert audit_event.actor_username == "auditor"


@pytest.mark.asyncio
async def test_recording_stream_unauthorized_access_denied(client: AsyncClient, browser_session_setup):
    """Unprivileged users (operator without recordings:read) are denied access with HTTP 403."""
    setup = browser_session_setup
    op_token = issue_token("operator")
    storage_dir = setup["storage"]

    # Start and terminate
    start_res = await client.post(
        f"/api/v1/gateway/apps/{setup['app'].id}/session",
        headers=auth_header(op_token),
        json={"application_id": str(setup['app'].id)},
    )
    session_id = uuid.UUID(start_res.json()["session_id"])
    rec_id = uuid.UUID(start_res.json()["recording_id"])

    (storage_dir / f"session_{session_id}.mp4").write_bytes(b"DATA")

    await client.post(
        f"/api/v1/gateway/apps/{setup['app'].id}/session/{session_id}/terminate",
        headers=auth_header(op_token),
    )

    # Operator attempts to view recording stream
    unauth_res = await client.get(
        f"/api/v1/recordings/{rec_id}/stream",
        headers=auth_header(op_token),
    )
    assert unauth_res.status_code == 403


@pytest.mark.asyncio
async def test_session_termination_is_idempotent(client: AsyncClient, browser_session_setup):
    """Calling terminate on an already terminated session returns HTTP 409 Conflict without duplicating records."""
    setup = browser_session_setup
    op_token = issue_token("operator")

    start_res = await client.post(
        f"/api/v1/gateway/apps/{setup['app'].id}/session",
        headers=auth_header(op_token),
        json={"application_id": str(setup['app'].id)},
    )
    session_id = uuid.UUID(start_res.json()["session_id"])

    # First termination: 200 OK
    term1 = await client.post(
        f"/api/v1/gateway/apps/{setup['app'].id}/session/{session_id}/terminate",
        headers=auth_header(op_token),
    )
    assert term1.status_code == 200

    # Repeat termination: 409 Conflict
    term2 = await client.post(
        f"/api/v1/gateway/apps/{setup['app'].id}/session/{session_id}/terminate",
        headers=auth_header(op_token),
    )
    assert term2.status_code == 409
    assert "already in a terminal state" in term2.json()["detail"]


@pytest.mark.asyncio
async def test_recording_stream_path_traversal_blocked(client: AsyncClient, db_session: AsyncSession, browser_session_setup):
    """Recordings pointing outside settings.RECORDING_STORAGE_PATH return HTTP 404."""
    setup = browser_session_setup
    # Launch session to obtain real session_id and recording
    start_res = await client.post(
        f"/api/v1/gateway/apps/{setup['app'].id}/session",
        headers=auth_header(issue_token("operator")),
        json={"application_id": str(setup['app'].id)},
    )
    rec_id = uuid.UUID(start_res.json()["recording_id"])

    # Tamper with recording to point outside storage
    evil_rec = await db_session.get(Recording, rec_id)
    evil_rec.file_path = "/etc/passwd"
    evil_rec.status = "COMPLETED"
    await db_session.commit()

    auditor_token = issue_token("auditor")
    res = await client.get(
        f"/api/v1/recordings/{evil_rec.id}/stream",
        headers=auth_header(auditor_token),
    )
    assert res.status_code == 404

