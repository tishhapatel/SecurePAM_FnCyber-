"""RDP gateway: the WebSocket path against a fake guacd that speaks the Guacamole handshake."""

import asyncio
import hashlib
import json
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.api.v1.sessions import get_credential_service
from app.core.config import settings
from app.database.session import async_session_factory
from app.main import app
from app.models.asset import Asset
from app.models.jit_grant import JITGrant
from app.models.recording import Recording
from app.models.session import Session
from app.secret_providers import MockSecretProvider
from app.services.credential_service import CredentialService
from app.services.guacamole import InstructionParser, encode, looks_like_recording, recording_duration_seconds
from app.services.rdp_gateway import GuacdRdpGateway, get_rdp_gateway
from tests.conftest import auth_header
from tests.test_session_endpoints import (  # noqa: F401  (fixtures and helpers)
    RDP_PATH, _actions, _launch_body, _rdp_ready, _rdp_recording_root,
)

CANARY = "RDP-GW-CANARY-not-real"
CLIP_CANARY = "Q0xJUC1DQU5BUlktbm90LXJlYWw="  # base64 "CLIP-CANARY-not-real": must never reach guacd or the audit log
ARGS = ["VERSION_1_5_0", "hostname", "port", "username", "password", "domain", "security", "ignore-cert",
        "resize-method", "disable-audio", "recording-path", "recording-name", "create-recording-path",
        "recording-include-keys", "timezone",
        "disable-copy", "disable-paste", "enable-drive", "disable-download", "disable-upload",
        "enable-printing", "enable-sftp", "client-name"]


class FakeGuacd:
    """Speaks guacd's side of the handshake, then behaves per `scenario`."""

    def __init__(self, scenario="ok"):
        self.scenario, self.port = scenario, None
        self.connect_params, self.received, self.closed = {}, [], threading.Event()
        self.select_seen = None
        self._ready, self._loop = threading.Event(), None

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()
        assert self._ready.wait(5)
        return self.port

    def stop(self):
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)

    def _run(self):
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        server = self._loop.run_until_complete(asyncio.start_server(self._handle, "127.0.0.1", 0))
        self.port = server.sockets[0].getsockname()[1]
        self._ready.set()
        self._loop.run_forever()

    async def _read_instruction(self, reader, parser):
        while True:
            data = await reader.read(65536)
            if not data:
                return None
            out = parser.feed(data.decode())
            if out:
                return out

    async def _handle(self, reader, writer):
        parser = InstructionParser()
        pending = await self._read_instruction(reader, parser)
        self.select_seen = pending[0]
        writer.write(encode("args", *ARGS).encode())
        await writer.drain()
        seen, collected = [], []
        while not any(i[0] == "connect" for i in collected):
            batch = await self._read_instruction(reader, parser)
            if batch is None:
                return
            collected += batch
        connect = next(i for i in collected if i[0] == "connect")
        self.connect_params = dict(zip(ARGS, connect[1:]))
        self.handshake_opcodes = [i[0] for i in collected]
        rec_dir = Path(self.recording_root) / Path(self.connect_params["recording-path"]).name \
            if self.connect_params.get("recording-path") else None
        if self.scenario == "auth_error":
            # Like real guacd: `ready` first, then the upstream error; its recording holds only the error.
            if rec_dir is not None:
                rec_dir.mkdir(parents=True, exist_ok=True)
                (rec_dir / "recording").write_text(encode("error", "Authentication failure", "769"))
            writer.write((encode("ready", "$guacd-connection-1") + encode("error", "Authentication failure", "769")).encode())
            await writer.drain()
            writer.close()
            return
        if rec_dir is not None and self.scenario != "no_recording_file":
            rec_dir.mkdir(parents=True, exist_ok=True)
            (rec_dir / "recording").write_text(encode("size", "0", "1280", "800") + encode("sync", "1000", "0"))
        writer.write(encode("ready", "$guacd-connection-1").encode())
        await writer.drain()
        if self.scenario == "never_syncs":
            await asyncio.sleep(60)
            return
        writer.write((encode("size", "0", "1280", "800") + encode("sync", "1500", "1")).encode())
        await writer.drain()
        if self.scenario == "remote_logoff":
            # Like Windows signing the RDP session out: guacd reports it and closes.
            await asyncio.sleep(0.5)
            writer.write(encode("disconnect").encode())
            await writer.drain()
            await asyncio.sleep(0.3)
            writer.close()
            self.closed.set()
            return
        while True:
            batch = await self._read_instruction(reader, parser)
            if batch is None:
                break
            self.received += [i[0] for i in batch]
            if any(i[0] == "disconnect" for i in batch):
                break
        # Like real guacd: the recording is flushed and closed *after* the client asks to disconnect,
        # later than any "size is stable" heuristic would wait, and the socket closes only afterwards.
        await asyncio.sleep(1.5)
        if rec_dir is not None and (rec_dir / "recording").exists():
            with open(rec_dir / "recording", "a") as handle:
                handle.write(encode("sync", "4500", "9"))
        writer.close()
        self.closed.set()


@pytest.fixture
def provider():
    p = MockSecretProvider({RDP_PATH: {"username": "LAB\\svc-rdp", "password": CANARY}})
    app.dependency_overrides[get_credential_service] = lambda: CredentialService(provider=p)
    yield p
    app.dependency_overrides.pop(get_credential_service, None)


@pytest.fixture
def guacd(tmp_path):
    made = []

    def make(scenario="ok"):
        fake = FakeGuacd(scenario)
        fake.recording_root = settings.RDP_RECORDING_PATH
        port = fake.start()
        gateway = GuacdRdpGateway("127.0.0.1", port)
        app.dependency_overrides[get_rdp_gateway] = lambda: gateway
        made.append(fake)
        return fake, gateway

    yield make
    app.dependency_overrides.pop(get_rdp_gateway, None)
    for fake in made:
        fake.stop()


async def _launch(db, token, *, recording=True):
    req = await _rdp_ready(db)
    asset = await db.get(Asset, req.asset_id)
    asset.recording_required = recording
    asset.ip_address = "192.168.117.154"
    await db.commit()
    client = TestClient(app)
    r = client.post("/api/v1/sessions/rdp/launch", headers=auth_header(token), json=_launch_body(req))
    assert r.status_code == 201, r.text
    return client, req, r.json()


def _auth(ticket, **extra):
    return json.dumps({"type": "auth", "ticket": ticket, "width": 1024, "height": 768, "dpi": 96, **extra})


async def _wait(predicate, seconds=10):
    end = time.time() + seconds
    while time.time() < end:
        if await predicate():
            return True
        await asyncio.sleep(0.2)
    return False


async def _row(model, pk):
    async with async_session_factory() as db:
        return await db.get(model, pk)


# --- protocol unit tests -----------------------------------------------------------------

def test_instruction_parser_handles_partial_and_multibyte():
    p = InstructionParser()
    assert p.feed("4.args,13.VERSION_1_5_0,2.é") == []
    assert p.feed("x;") == [["args", "VERSION_1_5_0", "éx"]]
    assert encode("size", "1", "2") == "4.size,1.1,1.2;"


def test_recording_inspection():
    assert looks_like_recording(b"4.size,1.0,4.1280,3.800;")
    assert not looks_like_recording(b"\x00\x01garbage")
    assert recording_duration_seconds(b"4.sync,4.1000;", b"4.sync,4.4500;") == 4


# --- launch + connect ----------------------------------------------------------------------

async def test_full_session_credentials_stay_server_side_and_recording_is_finalized(
    db_session, operator_token, admin_token, provider, guacd
):
    fake, gateway = guacd()
    client, req, launched = await _launch(db_session, operator_token)
    sid = launched["session_id"]
    assert CANARY not in json.dumps(launched)

    with client.websocket_connect(launched["ws_url"]) as ws:
        ws.send_text(_auth(launched["ticket"]))
        first = ws.receive_text()
        assert "ready" not in first  # handshake chatter is never relayed as a desktop frame
        data = first
        while "4.sync" not in data:  # frame boundaries are not part of the contract
            data += ws.receive_text()
        assert data.startswith("4.size")  # desktop frames only
        assert CANARY not in first

        # ACTIVE only now; recording only now.
        session = await _row(Session, launched["session_id"])
        assert session.status == "ACTIVE" and session.start_time is not None
        assert session.gateway_session_id == "$guacd-connection-1"
        rec = await _row(Recording, launched["recording_id"])
        assert rec.status == "RECORDING"

        # Browser input is relayed; anything outside the allowlist (e.g. a second connect) is dropped.
        ws.send_text(encode("mouse", "10", "20", "1", "0") + encode("key", "65", "1") + encode("connect", "x")
                     + encode("get", "0", "stream")
                     # A paste into the remote desktop: default deny, so the whole clipboard stream is dropped.
                     + encode("clipboard", "7", "text/plain") + encode("blob", "7", CLIP_CANARY) + encode("end", "7"))
        await _wait(lambda: asyncio.sleep(0, result="mouse" in fake.received))

        gw_conn = gateway.get_live_connection(session.id)
        assert gw_conn is not None

        term = client.post(f"/api/v1/sessions/{sid}/terminate", headers=auth_header(admin_token),
                           json={"reason": "test"})
        assert term.status_code == 200, term.text
        body = term.json()["result"]
        assert body["gateway"] == "closed" and body["recording"] == "COMPLETED" and body["grant_revoked"] is True

    assert fake.closed.wait(5), "guacd's TCP connection was not closed"
    # What guacd was told: the registered target, the account split into domain/user, secret only here.
    p = fake.connect_params
    assert p["hostname"] == "192.168.117.154" and p["port"] == "3389"
    assert (p["username"], p["domain"], p["password"]) == ("svc-rdp", "LAB", CANARY)
    assert p["security"] == "nla" and p["recording-include-keys"] == "false" and p["create-recording-path"] == "true"
    assert p["recording-path"] == f"{settings.GUACD_RECORDING_PATH}/{sid}" and p["recording-name"] == "recording"
    assert fake.handshake_opcodes[:4] == ["size", "audio", "video", "image"]
    assert "mouse" in fake.received and "key" in fake.received and "disconnect" in fake.received
    assert "connect" not in fake.received and "get" not in fake.received
    # Default deny: guacd was told so explicitly, and no clipboard stream reached it.
    assert (p["disable-copy"], p["disable-paste"]) == ("true", "true")
    assert (p["enable-drive"], p["disable-download"], p["disable-upload"]) == ("false", "true", "true")
    assert (p["enable-printing"], p["enable-sftp"]) == ("false", "false")
    assert "clipboard" not in fake.received and "blob" not in fake.received and "end" not in fake.received
    # Correlation: the SecurePAM session number is the RDP client name Windows is told about.
    assert p["client-name"] == (await _row(Session, launched["session_id"])).session_number

    session = await _row(Session, launched["session_id"])
    assert session.status == "TERMINATED"
    rec = await _row(Recording, launched["recording_id"])
    artifact = Path(settings.RDP_RECORDING_PATH) / sid / "recording"
    assert rec.status == "COMPLETED"
    assert rec.file_hash == hashlib.sha256(artifact.read_bytes()).hexdigest() and rec.file_size == artifact.stat().st_size
    assert rec.duration_seconds >= 4 and rec.metadata_["format"] == "guacamole"
    # The late flush guacd does after `disconnect` is inside the hashed artifact (the hash above matches).
    assert artifact.read_text().rstrip().endswith(encode("sync", "4500", "9"))
    grant = await _row(JITGrant, req.jit_grant_id)
    assert grant.status == "REVOKED"
    actions = {a.action for a in (await db_session.execute(
        select(__import__("app.models.audit", fromlist=["AuditLog"]).AuditLog))).scalars().all()}
    assert {"SESSION_STARTED", "RECORDING_STARTED", "RECORDING_COMPLETED", "SESSION_TERMINATED", "JIT_REVOKED"} <= actions
    for row in (await db_session.execute(select(__import__("app.models.audit", fromlist=["AuditLog"]).AuditLog))).scalars():
        assert CANARY not in repr(row.details) and CLIP_CANARY not in repr(row.details)
    (started,) = await _actions(db_session, "SESSION_STARTED")
    assert started.details["controls"] == {"clipboard": False, "file_transfer": False}
    (clip,) = await _actions(db_session, "RDP_CLIPBOARD_ACTIVITY")   # counts only; never the content
    assert clip.details["clipboard_policy"] == "blocked" and clip.details["browser_to_remote_transfers"] == 1
    assert clip.details["blocked_at_gateway"] == 1 and clip.details["content_captured"] is False


async def test_recording_must_exist_before_any_frame_is_shown(db_session, operator_token, provider, guacd, monkeypatch):
    import app.api.v1.rdp_sessions as module
    real_wait = module.wait_for_recording_file
    monkeypatch.setattr(module, "wait_for_recording_file", lambda sid, timeout=5.0: real_wait(sid, 0.6))
    fake, _ = guacd("no_recording_file")
    client, _, launched = await _launch(db_session, operator_token)
    with client.websocket_connect(launched["ws_url"]) as ws:
        ws.send_text(_auth(launched["ticket"]))
        frame = ws.receive_text()
        assert frame.startswith("5.error") and "sync" not in frame  # refused, no desktop shown
    assert (await _row(Session, launched["session_id"])).status == "FAILED"
    rec = await _row(Recording, launched["recording_id"])
    assert rec.status == "FAILED" and rec.file_hash is None
    assert await _actions(db_session, "SESSION_STARTED") == []


async def test_windows_authentication_failure_is_reported_not_faked(db_session, operator_token, provider, guacd):
    guacd("auth_error")
    client, _, launched = await _launch(db_session, operator_token)
    with client.websocket_connect(launched["ws_url"]) as ws:
        ws.send_text(_auth(launched["ticket"]))
        assert ws.receive_text().startswith("5.error")
    session = await _row(Session, launched["session_id"])
    assert session.status == "FAILED" and session.start_time is None
    assert (await _row(Recording, launched["recording_id"])).status == "FAILED"
    assert await _actions(db_session, "SESSION_STARTED") == []
    (failed,) = await _actions(db_session, "SESSION_LAUNCH_FAILED")
    assert failed.details["reason"] == "TARGET_AUTH_FAILED"  # the audit trail says why
    (rec_failed,) = await _actions(db_session, "RECORDING_FAILED")
    assert rec_failed.details["reason"] == "RECORDING_NO_FRAMES"  # an error-only file is not a recording


async def test_ticket_is_single_use_and_required(db_session, operator_token, provider, guacd):
    guacd()
    client, _, launched = await _launch(db_session, operator_token)
    with client.websocket_connect(launched["ws_url"]) as ws:
        ws.send_text(json.dumps({"type": "auth"}))
        assert "ticket" in ws.receive_text().lower()
    with client.websocket_connect(launched["ws_url"]) as ws:
        ws.send_text(_auth("not-the-ticket"))
        assert ws.receive_text().startswith("5.error")
    assert (await _row(Session, launched["session_id"])).status == "STARTING"  # no connection was made


async def test_ticket_in_url_is_not_accepted(db_session, operator_token, provider, guacd):
    guacd()
    client, _, launched = await _launch(db_session, operator_token)
    with client.websocket_connect(f"{launched['ws_url']}?ticket={launched['ticket']}") as ws:
        ws.send_text(json.dumps({"type": "auth"}))
        assert ws.receive_text().startswith("5.error")


async def test_revoked_grant_closes_the_real_connection_and_blocks_reconnect(
    db_session, operator_token, admin_token, provider, guacd
):
    fake, _ = guacd()
    client, req, launched = await _launch(db_session, operator_token)
    with client.websocket_connect(launched["ws_url"]) as ws:
        ws.send_text(_auth(launched["ticket"]))
        ws.receive_text()
        r = client.post(f"/api/v1/jit-grants/{req.jit_grant_id}/revoke", headers=auth_header(admin_token))
        assert r.status_code == 200
        assert fake.closed.wait(6), "revoking the grant left guacd's connection open"
    session = await _row(Session, launched["session_id"])
    assert session.status in ("EXPIRED", "COMPLETED", "TERMINATED")
    again = client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token), json=_launch_body(req))
    assert again.status_code == 403


async def test_unreachable_guacd_fails_the_launch_honestly(db_session, operator_token, provider):
    gateway = GuacdRdpGateway("127.0.0.1", 9)  # nothing listens
    app.dependency_overrides[get_rdp_gateway] = lambda: gateway
    try:
        req = await _rdp_ready(db_session)
        client = TestClient(app)
        r = client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token), json=_launch_body(req))
        assert r.status_code == 503
        assert (await db_session.execute(select(Session))).scalars().all() == []
    finally:
        app.dependency_overrides.pop(get_rdp_gateway, None)


async def test_session_limit_applies_to_rdp(db_session, operator_token, provider, guacd):
    guacd()
    client, _, _ = await _launch(db_session, operator_token)
    second = await _rdp_ready(db_session, with_ref=False)
    assert client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token),
                       json=_launch_body(second)).status_code == 201
    third = await _rdp_ready(db_session, with_ref=False)
    r = client.post("/api/v1/sessions/rdp/launch", headers=auth_header(operator_token), json=_launch_body(third))
    assert r.status_code == 409 and "limit" in r.json()["detail"].lower()


# --- playback API ------------------------------------------------------------------------

async def _rdp_recording(db, content=None):
    from tests.test_session_endpoints import _make_session
    s = await _make_session(db)
    path = Path(settings.RDP_RECORDING_PATH) / str(s.id) / "recording"
    path.parent.mkdir(parents=True)
    data = content or (encode("size", "0", "1280", "800") + encode("sync", "1000", "0")).encode()
    path.write_bytes(data)
    rec = Recording(session_id=s.id, recording_type="VIDEO", status="COMPLETED", file_path=str(path),
                    file_hash=hashlib.sha256(data).hexdigest(), file_size=len(data), metadata_={"format": "guacamole"})
    db.add(rec)
    await db.commit()
    return rec, path


async def test_rdp_recording_is_served_verified_and_access_controlled(client, db_session, auditor_token, operator_token):
    rec, path = await _rdp_recording(db_session)
    items = (await client.get("/api/v1/recordings/", headers=auth_header(auditor_token))).json()["items"]
    assert items[0]["format"] == "guacamole" and items[0]["integrity"] == "verified"
    assert str(path) not in json.dumps(items)
    r = await client.get(f"/api/v1/recordings/{rec.id}/stream", headers=auth_header(auditor_token))
    assert r.status_code == 200 and r.headers["content-type"].startswith("application/x-guacamole-recording")
    assert r.headers["x-recording-sha256"] == rec.file_hash and r.content == path.read_bytes()
    assert (await client.get(f"/api/v1/recordings/{rec.id}/stream", headers=auth_header(operator_token))).status_code == 403
    assert "RECORDING_VIEWED" in {a.action for a in await _actions(db_session, "RECORDING_VIEWED")}


async def test_tampered_rdp_recording_is_refused(client, db_session, auditor_token):
    rec, path = await _rdp_recording(db_session)
    path.write_bytes(path.read_bytes() + b"4.sync,4.9999;")
    r = await client.get(f"/api/v1/recordings/{rec.id}/stream", headers=auth_header(auditor_token))
    assert r.status_code == 409
    assert (await client.get("/api/v1/recordings/", headers=auth_header(auditor_token))).json()["items"][0]["integrity"] == "mismatch"


async def test_rdp_recording_has_no_command_transcript_without_windows_telemetry(client, db_session, auditor_token):
    rec, _ = await _rdp_recording(db_session)
    body = (await client.get(f"/api/v1/recordings/{rec.id}/transcript", headers=auth_header(auditor_token))).json()
    assert body["available"] is False and "4688" in body["reason"]


@pytest.mark.parametrize("content, reason", [
    (b"", "RECORDING_EMPTY"),
    (b"\x00\x01 not a recording", "RECORDING_CORRUPT"),
    (b"5.error,45.Authentication failure (invalid credentials?),3.769;", "RECORDING_NO_FRAMES"),
])
async def test_unusable_artifacts_are_failed_never_completed(db_session, content, reason):
    """Captured from a real failed login: guacd leaves a file holding only an error instruction."""
    from app.services.rdp_recording import finalize_rdp_recording
    from tests.test_session_endpoints import _make_session, _user
    s = await _make_session(db_session)
    path = Path(settings.RDP_RECORDING_PATH) / str(s.id) / "recording"
    path.parent.mkdir(parents=True)
    path.write_bytes(content)
    rec = Recording(session_id=s.id, recording_type="VIDEO", status="RECORDING", file_path=str(path))
    db_session.add(rec)
    await db_session.commit()
    operator = await _user(db_session, "operator")
    assert await finalize_rdp_recording(rec.id, s.id, operator.id, settle_seconds=0) == "FAILED"
    row = await _row(Recording, rec.id)
    assert row.status == "FAILED" and row.file_hash is None
    (failed,) = await _actions(db_session, "RECORDING_FAILED")
    assert failed.details["reason"] == reason


async def test_missing_artifact_is_failed(db_session):
    from app.services.rdp_recording import finalize_rdp_recording
    from tests.test_session_endpoints import _make_session, _user
    s = await _make_session(db_session)
    rec = Recording(session_id=s.id, recording_type="VIDEO", status="RECORDING", file_path="/nowhere")
    db_session.add(rec)
    await db_session.commit()
    operator = await _user(db_session, "operator")
    assert await finalize_rdp_recording(rec.id, s.id, operator.id, settle_seconds=0) == "FAILED"
    (failed,) = await _actions(db_session, "RECORDING_FAILED")
    assert failed.details["reason"] == "RECORDING_ARTIFACT_MISSING"



async def test_session_ended_by_windows_is_recorded_as_such(db_session, operator_token, provider, guacd):
    """Captured live: Windows signed the RDP session out ("Manually logged off"). That must read as a
    remote disconnect in the audit trail, never as a termination nobody performed."""
    guacd("remote_logoff")
    client, _, launched = await _launch(db_session, operator_token)
    with client.websocket_connect(launched["ws_url"]) as ws:
        ws.send_text(_auth(launched["ticket"]))
        data = ws.receive_text()
        while "disconnect" not in data:
            data += ws.receive_text()
    assert await _wait(lambda: _row(Session, launched["session_id"]))
    for _ in range(50):
        session = await _row(Session, launched["session_id"])
        if session.status != "ACTIVE":
            break
        await asyncio.sleep(0.2)
    assert session.status == "COMPLETED"
    for _ in range(50):
        ended = await _actions(db_session, "SESSION_ENDED")
        if ended:
            break
        await asyncio.sleep(0.2)
    (ended,) = ended
    assert ended.details["reason"] == "REMOTE_DISCONNECTED" and ended.result == "SUCCESS"
    assert await _actions(db_session, "SESSION_TERMINATED") == []



@pytest.mark.parametrize("content", [
    encode("error", "Authentication failure (invalid credentials?)", "769").encode(),  # captured from a real failed login
    encode("size", "0", "1280", "800").encode(),                                         # display set up, nothing drawn
])
async def test_valid_hash_and_nonzero_size_do_not_make_a_recording_usable(client, db_session, auditor_token, content):
    """Regression: a COMPLETED row with a correct SHA-256 over a non-empty file must still not be presented
    or served as a playable screen recording unless it actually contains display frames."""
    rec, path = await _rdp_recording(db_session, content)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == rec.file_hash and rec.file_size > 0
    items = (await client.get("/api/v1/recordings/", headers=auth_header(auditor_token))).json()["items"]
    assert items[0]["integrity"] == "no_display_data"
    r = await client.get(f"/api/v1/recordings/{rec.id}/stream", headers=auth_header(auditor_token))
    assert r.status_code == 409 and "no display data" in r.json()["detail"]
