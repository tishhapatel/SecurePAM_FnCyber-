"""
Security regression tests for the M9/M12 audit, session and recording
endpoints: authentication, RBAC per role, object-level authorization
(IDOR -> 404), termination rules, RDP launch going through JIT +
CredentialService (never returning a credential), and recording streaming
(confined to RECORDING_STORAGE_PATH, audited).
"""

import uuid
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.api.v1.sessions import get_credential_service
from app.core.config import settings
from app.main import app
from app.models.access_request import AccessRequest
from app.models.asset import Asset
from app.models.audit import AuditLog
from app.models.jit_grant import JITGrant
from app.models.recording import Recording
from app.models.session import Session
from app.models.user import User
from app.models.vault_ref import VaultRef
from app.secret_providers import MockSecretProvider
from app.services.credential_service import CredentialService
from tests.conftest import auth_header
from tests.test_credential_service import _scenario

RDP_PATH = "securepam/assets/win-dev-01"
CANARY = "RDP-PW-CANARY-not-real"
NIL = "00000000-0000-0000-0000-000000000000"


async def _user(db, username) -> User:
    return (await db.execute(select(User).where(User.username == username))).scalar_one()


async def _asset(db, name) -> Asset:
    return (await db.execute(select(Asset).where(Asset.name == name))).scalar_one()


async def _actions(db, action) -> list[AuditLog]:
    return (await db.execute(select(AuditLog).where(AuditLog.action == action))).scalars().all()


async def _make_session(db, username="operator", status="ACTIVE", with_recording=False) -> Session:
    """A session row for list/detail/terminate tests, bound to a real request."""
    user = await _user(db, username)
    asset = await _asset(db, "WIN-DEV-01")
    req = await _scenario(db, username=username, asset_name="WIN-DEV-01", protocol="RDP", with_ref=False)
    s = Session(session_number=f"SES-{uuid.uuid4().hex[:6].upper()}", user_id=user.id, asset_id=asset.id,
                request_id=req.access_request_id, jit_grant_id=req.jit_grant_id, protocol="RDP", status=status)
    db.add(s)
    await db.flush()
    if with_recording:
        rec = Recording(session_id=s.id, recording_type="VIDEO", status="RECORDING", file_path="/nowhere/x")
        db.add(rec)
        await db.flush()
        s.recording_id = rec.id
    await db.commit()
    return s


@pytest.fixture
def provider():
    """Route the launch endpoint's CredentialService to a fake provider."""
    p = MockSecretProvider({RDP_PATH: {"username": "svc-rdp", "password": CANARY}})
    app.dependency_overrides[get_credential_service] = lambda: CredentialService(provider=p)
    yield p
    app.dependency_overrides.pop(get_credential_service, None)


# --- authentication ---------------------------------------------------------

@pytest.mark.parametrize(
    "method, path",
    [
        ("GET", "/api/v1/audit/"),
        ("GET", "/api/v1/sessions/"),
        ("GET", f"/api/v1/sessions/{NIL}"),
        ("POST", f"/api/v1/sessions/{NIL}/terminate"),
        ("POST", "/api/v1/sessions/rdp/launch"),
        ("GET", "/api/v1/recordings/"),
        ("GET", f"/api/v1/recordings/{NIL}/stream"),
    ],
)
async def test_unauthenticated_requests_rejected(client, method, path):
    r = await client.request(method, path, json={"request_id": NIL, "asset_id": NIL} if method == "POST" else None)
    assert r.status_code == 401


async def test_unauthenticated_audit_read_returns_no_data(client, db_session):
    await _make_session(db_session)
    r = await client.get("/api/v1/audit/")
    assert r.status_code == 401 and "event_id" not in r.text


async def test_audit_pagination_and_sorting(
    client, db_session, auditor_token
):
    now = datetime.now(timezone.utc)
    db_session.add_all([
        AuditLog(
            event_id="EVT-PAGE-001",
            timestamp=now - timedelta(minutes=3),
            actor_username="operator",
            action="LOGIN_SUCCESS",
            result="SUCCESS",
            severity="INFO",
        ),
        AuditLog(
            event_id="EVT-PAGE-002",
            timestamp=now - timedelta(minutes=2),
            actor_username="operator",
            action="ACCESS_DENIED",
            result="DENIED",
            severity="HIGH",
        ),
        AuditLog(
            event_id="EVT-PAGE-003",
            timestamp=now - timedelta(minutes=1),
            actor_username="admin",
            action="LOGIN_SUCCESS",
            result="SUCCESS",
            severity="INFO",
        ),
    ])
    await db_session.commit()

    r = await client.get(
        "/api/v1/audit/?page=1&page_size=2&sort_by=timestamp&sort_order=asc",
        headers=auth_header(auditor_token),
    )

    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3
    assert body["page"] == 1
    assert body["page_size"] == 2
    assert body["pages"] == 2
    assert len(body["items"]) == 2
    assert body["items"][0]["event_id"] == "EVT-PAGE-001"
    assert body["items"][1]["event_id"] == "EVT-PAGE-002"


async def test_audit_action_and_severity_filters(
    client, db_session, auditor_token
):
    now = datetime.now(timezone.utc)
    db_session.add_all([
        AuditLog(
            event_id="EVT-FILTER-001",
            timestamp=now - timedelta(minutes=2),
            actor_username="operator",
            action="LOGIN_SUCCESS",
            result="SUCCESS",
            severity="INFO",
        ),
        AuditLog(
            event_id="EVT-FILTER-002",
            timestamp=now - timedelta(minutes=1),
            actor_username="operator",
            action="ACCESS_DENIED",
            result="DENIED",
            severity="HIGH",
        ),
    ])
    await db_session.commit()

    r = await client.get(
        "/api/v1/audit/?action=access_denied&severity=high",
        headers=auth_header(auditor_token),
    )

    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 1
    assert len(body["items"]) == 1
    assert body["items"][0]["event_id"] == "EVT-FILTER-002"
    assert body["items"][0]["action"] == "ACCESS_DENIED"
    assert body["items"][0]["severity"] == "HIGH"


# --- role-based access ------------------------------------------------------

@pytest.mark.parametrize(
    "token_fixture, path, expected",
    [
        ("operator_token", "/api/v1/audit/", 403),
        ("approver_token", "/api/v1/audit/", 403),
        ("auditor_token", "/api/v1/audit/", 200),
        ("admin_token", "/api/v1/audit/", 200),
        ("approver_token", "/api/v1/sessions/", 403),
        ("operator_token", "/api/v1/sessions/", 200),
        ("auditor_token", "/api/v1/sessions/", 200),
        ("operator_token", "/api/v1/recordings/", 403),
        ("approver_token", "/api/v1/recordings/", 403),
        ("auditor_token", "/api/v1/recordings/", 200),
        ("admin_token", "/api/v1/recordings/", 200),
    ],
)
async def test_role_matrix(client, request, token_fixture, path, expected):
    r = await client.get(path, headers=auth_header(request.getfixturevalue(token_fixture)))
    assert r.status_code == expected


async def test_denial_is_audited(client, db_session, operator_token):
    assert (await client.get("/api/v1/audit/", headers=auth_header(operator_token))).status_code == 403
    denied = await _actions(db_session, "ACCESS_DENIED")
    assert any(d.details["required_permission"] == "audit:read" for d in denied)


async def test_approver_cannot_launch_or_terminate(client, db_session, approver_token):
    s = await _make_session(db_session)
    h = auth_header(approver_token)
    assert (await client.post(f"/api/v1/sessions/{s.id}/terminate", headers=h)).status_code == 403
    r = await client.post("/api/v1/sessions/rdp/launch", headers=h, json={"request_id": str(s.request_id), "asset_id": str(s.asset_id)})
    assert r.status_code == 403


# --- object-level authorization (IDOR) --------------------------------------


async def test_own_scope_lists_only_own_sessions(
    client, db_session, operator_token, operator2_token
):
    mine = await _make_session(db_session, "operator")
    theirs = await _make_session(db_session, "operator2")

    r = await client.get(
        "/api/v1/sessions/",
        headers=auth_header(operator_token),
    )
    assert r.status_code == 200
    assert [s["id"] for s in r.json()["items"]] == [str(mine.id)]

    r = await client.get(
        "/api/v1/sessions/",
        headers=auth_header(operator2_token),
    )
    assert r.status_code == 200
    assert [s["id"] for s in r.json()["items"]] == [str(theirs.id)]


async def test_view_all_scope_lists_everyone(
    client, db_session, auditor_token, operator2_token
):
    await _make_session(db_session, "operator")
    await _make_session(db_session, "operator2")

    r = await client.get(
        "/api/v1/sessions/",
        headers=auth_header(auditor_token),
    )
    assert r.status_code == 200
    assert len(r.json()["items"]) == 2
    assert r.json()["total"] == 2


async def test_sessions_pagination_returns_page_metadata(
    client, db_session, auditor_token
):
    await _make_session(db_session, status="ACTIVE")
    await _make_session(db_session, status="COMPLETED")
    await _make_session(db_session, status="FAILED")

    r = await client.get(
        "/api/v1/sessions/?page=1&page_size=2",
        headers=auth_header(auditor_token),
    )

    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 2
    assert body["total"] == 3
    assert body["page"] == 1
    assert body["page_size"] == 2
    assert body["pages"] == 2


async def test_sessions_sorting_and_status_filter(
    client, db_session, auditor_token
):
    await _make_session(db_session, status="ACTIVE")
    await _make_session(db_session, status="COMPLETED")
    await _make_session(db_session, status="ACTIVE")

    r = await client.get(
        "/api/v1/sessions/?status=ACTIVE&sort_by=session_number&sort_order=asc",
        headers=auth_header(auditor_token),
    )

    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2
    assert all(item["status"] == "ACTIVE" for item in body["items"])
    session_numbers = [item["session_number"] for item in body["items"]]
    assert session_numbers == sorted(session_numbers)


async def test_peer_session_detail_is_404(client, db_session, operator2_token):
    s = await _make_session(db_session, "operator")
    r = await client.get(f"/api/v1/sessions/{s.id}", headers=auth_header(operator2_token))
    assert r.status_code == 404


async def test_owner_and_auditor_can_view_session(client, db_session, operator_token, auditor_token):
    s = await _make_session(db_session, "operator")
    for token in (operator_token, auditor_token):
        assert (await client.get(f"/api/v1/sessions/{s.id}", headers=auth_header(token))).status_code == 200


async def test_status_filter_validated(client, operator_token):
    r = await client.get("/api/v1/sessions/?status=nope", headers=auth_header(operator_token))
    assert r.status_code == 422


# --- termination ------------------------------------------------------------

async def test_owner_terminates_own_session(client, db_session, operator_token):
    s = await _make_session(db_session, with_recording=True)
    r = await client.post(f"/api/v1/sessions/{s.id}/terminate", headers=auth_header(operator_token))
    assert r.status_code == 200

    await db_session.refresh(s)
    assert s.status == "COMPLETED" and s.end_time is not None
    rec = await db_session.get(Recording, s.recording_id)
    await db_session.refresh(rec)
    assert rec.status == "COMPLETED"
    (audit,) = await _actions(db_session, "SESSION_TERMINATED")
    assert audit.actor_username == "operator" and audit.session_id == s.id

    again = await client.post(f"/api/v1/sessions/{s.id}/terminate", headers=auth_header(operator_token))
    assert again.status_code == 409


async def test_peer_cannot_terminate_session(client, db_session, operator2_token):
    s = await _make_session(db_session, "operator")
    r = await client.post(f"/api/v1/sessions/{s.id}/terminate", headers=auth_header(operator2_token))
    assert r.status_code == 404
    await db_session.refresh(s)
    assert s.status == "ACTIVE"


async def test_auditor_can_view_but_not_terminate(client, db_session, auditor_token):
    s = await _make_session(db_session, "operator")
    r = await client.post(f"/api/v1/sessions/{s.id}/terminate", headers=auth_header(auditor_token))
    assert r.status_code == 403
    await db_session.refresh(s)
    assert s.status == "ACTIVE"


async def test_admin_terminates_any_session(client, db_session, admin_token):
    s = await _make_session(db_session, "operator")
    r = await client.post(f"/api/v1/sessions/{s.id}/terminate", headers=auth_header(admin_token))
    assert r.status_code == 200
    (audit,) = await _actions(db_session, "SESSION_TERMINATED")
    assert audit.actor_username == "admin" and audit.details == {"by_owner": False}


# --- RDP launch -------------------------------------------------------------

async def _rdp_ready(db, **kw):
    return await _scenario(db, asset_name=kw.pop("asset_name", "WIN-DEV-01"), protocol="RDP",
                           ref_path=RDP_PATH, **kw)


def _launch_body(req):
    return {"request_id": str(req.access_request_id), "asset_id": str(req.asset_id)}


async def test_launch_success_uses_jit_and_credential_service(client, db_session, operator_token, provider):
    req = await _rdp_ready(db_session)
    r = await client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token), json=_launch_body(req))
    assert r.status_code == 201, r.text
    body = r.json()

    assert CANARY not in r.text and "svc-rdp" not in r.text
    assert "recording_path" not in r.text and "file_path" not in r.text
    assert body["connection"] == {"protocol": "rdp", "hostname": "win-dev-01.internal", "port": 3389}
    assert provider.reads == [RDP_PATH]

    s = await db_session.get(Session, uuid.UUID(body["session_id"]))
    assert s.user_id == req.user_id  # the real caller, not a random UUID
    assert s.jit_grant_id == req.jit_grant_id
    assert s.status == "ACTIVE" and s.start_time is not None

    (started,) = await _actions(db_session, "SESSION_STARTED")
    assert started.actor_username == "operator" and started.session_id == s.id
    (retrieved,) = await _actions(db_session, "CREDENTIAL_RETRIEVED")
    assert retrieved.session_id == s.id
    for row in (await db_session.execute(select(AuditLog))).scalars().all():
        assert CANARY not in repr(row.details)


async def test_launch_creates_recording_when_required(client, db_session, operator_token, provider):
    req = await _rdp_ready(db_session)
    asset = await db_session.get(Asset, req.asset_id)
    asset.recording_required = True
    await db_session.commit()

    r = await client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token), json=_launch_body(req))
    assert r.status_code == 201
    rec = await db_session.get(Recording, uuid.UUID(r.json()["recording_id"]))
    assert rec.status == "RECORDING"
    assert rec.file_path.startswith(settings.RECORDING_STORAGE_PATH)


@pytest.mark.parametrize("grant_status", ["REVOKED", "EXPIRED"])
async def test_launch_without_live_grant_denied(client, db_session, operator_token, provider, grant_status):
    req = await _rdp_ready(db_session, grant_status=grant_status)
    r = await client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token), json=_launch_body(req))
    assert r.status_code == 403
    assert (await db_session.execute(select(Session))).scalars().all() == []
    assert provider.reads == []
    (denied,) = await _actions(db_session, "SESSION_LAUNCH_DENIED")
    assert denied.details["reason"] == "NO_VALID_JIT_GRANT"


async def test_launch_with_lapsed_grant_denied_and_grant_expired(client, db_session, operator_token, provider):
    req = await _rdp_ready(db_session, expires_in_minutes=-1)
    r = await client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token), json=_launch_body(req))
    assert r.status_code == 403
    grant = await db_session.get(JITGrant, req.jit_grant_id)
    await db_session.refresh(grant)
    assert grant.status == "EXPIRED"


async def test_launch_with_another_users_request_is_404(client, db_session, operator2_token, provider):
    req = await _rdp_ready(db_session)  # owned by operator
    r = await client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator2_token), json=_launch_body(req))
    assert r.status_code == 404
    assert provider.reads == []


async def test_launch_request_for_other_target_rejected(client, db_session, operator_token, provider):
    req = await _rdp_ready(db_session)
    other = await _asset(db_session, "WIN-PROD-01")
    r = await client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token),
                          json={"request_id": str(req.access_request_id), "asset_id": str(other.id)})
    assert r.status_code == 422


async def test_launch_non_rdp_target_rejected(client, db_session, operator_token, provider):
    req = await _scenario(db_session)  # SSH on LINUX-DEV-01
    r = await client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token), json=_launch_body(req))
    assert r.status_code == 422


async def test_launch_disabled_target_denied(client, db_session, operator_token, provider):
    req = await _rdp_ready(db_session)
    asset = await db_session.get(Asset, req.asset_id)
    asset.enabled = False
    await db_session.commit()
    r = await client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token), json=_launch_body(req))
    assert r.status_code == 403
    assert provider.reads == []


async def test_launch_inactive_request_denied(client, db_session, operator_token, provider):
    req = await _rdp_ready(db_session, request_status="CANCELLED")
    r = await client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token), json=_launch_body(req))
    assert r.status_code == 403


async def test_launch_unknown_asset_404(client, db_session, operator_token, provider):
    req = await _rdp_ready(db_session)
    r = await client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token),
                          json={"request_id": str(req.access_request_id), "asset_id": NIL})
    assert r.status_code == 404


async def test_launch_rejects_client_supplied_identity(client, db_session, operator_token, provider):
    req = await _rdp_ready(db_session)
    peer = await _user(db_session, "admin")
    r = await client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token),
                          json={**_launch_body(req), "user_id": str(peer.id)})
    assert r.status_code == 422


async def test_launch_without_credential_reference_fails_closed(client, db_session, operator_token, provider):
    req = await _rdp_ready(db_session, with_ref=False)
    r = await client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token), json=_launch_body(req))
    assert r.status_code == 403
    (s,) = (await db_session.execute(select(Session))).scalars().all()
    assert s.status == "FAILED"
    (failed,) = await _actions(db_session, "SESSION_LAUNCH_FAILED")
    assert failed.details["reason"] == "NO_CREDENTIAL_REFERENCE"
    assert await _actions(db_session, "SESSION_STARTED") == []


async def test_launch_provider_unavailable_fails_closed(client, db_session, operator_token, provider):
    provider.available = False
    req = await _rdp_ready(db_session)
    r = await client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token), json=_launch_body(req))
    assert r.status_code == 503
    assert CANARY not in r.text
    (s,) = (await db_session.execute(select(Session))).scalars().all()
    assert s.status == "FAILED"
    assert await _actions(db_session, "SESSION_STARTED") == []


async def test_recordings_pagination_returns_page_metadata(
    client, db_session, auditor_token
):
    await _make_session(db_session, with_recording=True)
    await _make_session(db_session, with_recording=True)
    await _make_session(db_session, with_recording=True)

    r = await client.get(
        "/api/v1/recordings/?page=1&page_size=2",
        headers=auth_header(auditor_token),
    )

    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 2
    assert body["total"] == 3
    assert body["page"] == 1
    assert body["page_size"] == 2
    assert body["pages"] == 2


async def test_recordings_sort_by_type(
    client, db_session, auditor_token
):
    session = await _make_session(db_session)
    db_session.add_all([
        Recording(
            session_id=session.id,
            recording_type="VIDEO",
            status="COMPLETED",
        ),
        Recording(
            session_id=session.id,
            recording_type="TERMINAL",
            status="COMPLETED",
        ),
    ])
    await db_session.commit()

    r = await client.get(
        "/api/v1/recordings/?sort_by=recording_type&sort_order=asc",
        headers=auth_header(auditor_token),
    )

    assert r.status_code == 200
    body = r.json()
    types = [item["recording_type"] for item in body["items"]]
    assert types == sorted(types)
    assert body["total"] == 2

# --- recording streaming ----------------------------------------------------

@pytest.fixture
def storage(tmp_path, monkeypatch):
    root = tmp_path / "recordings"
    root.mkdir()
    monkeypatch.setattr(settings, "RECORDING_STORAGE_PATH", str(root))
    return root


async def _recording(db, file_path, status="COMPLETED") -> Recording:
    s = await _make_session(db)
    rec = Recording(session_id=s.id, recording_type="VIDEO", status=status, file_path=file_path)
    db.add(rec)
    await db.commit()
    return rec


async def test_auditor_streams_recording_and_view_is_audited(client, db_session, storage, auditor_token):
    (storage / "session_a.mp4").write_bytes(b"\x00\x00\x00\x18ftypmp42fake")
    rec = await _recording(db_session, str(storage / "session_a"))
    r = await client.get(f"/api/v1/recordings/{rec.id}/stream", headers=auth_header(auditor_token))
    assert r.status_code == 200 and r.content.endswith(b"fake")
    (viewed,) = await _actions(db_session, "RECORDING_VIEWED")
    assert viewed.actor_username == "auditor" and viewed.target_id == str(rec.id)


@pytest.mark.parametrize("token_fixture", ["operator_token", "approver_token"])
async def test_non_auditors_cannot_stream(client, db_session, storage, request, token_fixture):
    (storage / "session_b").write_bytes(b"x")
    rec = await _recording(db_session, str(storage / "session_b"))
    r = await client.get(f"/api/v1/recordings/{rec.id}/stream", headers=auth_header(request.getfixturevalue(token_fixture)))
    assert r.status_code == 403


async def test_recording_owner_without_permission_cannot_stream(client, db_session, storage, operator_token):
    """Owning the session does not grant access to its evidence recording."""
    (storage / "own").write_bytes(b"x")
    rec = await _recording(db_session, str(storage / "own"))
    r = await client.get(f"/api/v1/recordings/{rec.id}/stream", headers=auth_header(operator_token))
    assert r.status_code == 403


@pytest.mark.parametrize("make_path", [
    lambda root, outside: str(outside),
    lambda root, outside: f"{root}/../{outside.name}",
    lambda root, outside: str(root / "link"),
])
async def test_paths_outside_storage_are_not_served(client, db_session, storage, tmp_path, auditor_token, make_path):
    outside = tmp_path / "secret.txt"
    outside.write_text("not a recording")
    (storage / "link").symlink_to(outside)
    rec = await _recording(db_session, make_path(storage, outside))
    r = await client.get(f"/api/v1/recordings/{rec.id}/stream", headers=auth_header(auditor_token))
    assert r.status_code == 404
    assert "not a recording" not in r.text


async def test_deleted_or_missing_recordings_404(client, db_session, storage, auditor_token):
    (storage / "gone").write_bytes(b"x")
    deleted = await _recording(db_session, str(storage / "gone"), status="DELETED")
    missing = await _recording(db_session, str(storage / "never-written"))
    for rec_id in (deleted.id, missing.id, NIL):
        r = await client.get(f"/api/v1/recordings/{rec_id}/stream", headers=auth_header(auditor_token))
        assert r.status_code == 404
