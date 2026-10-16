"""
RDP session WebSocket: the browser's end of a Guacamole session.

The browser never talks to guacd or to Guacamole's web application. It redeems
a one-time ticket (first frame, never the URL) on this SecurePAM WebSocket;
the backend re-validates everything server-side, checks out the credential
from the secret store, opens a TCP connection to guacd, hands it the target
and credential, and relays Guacamole instructions both ways.

Guarantees:
  * the credential, OpenBao token and any gateway credential never reach the browser;
  * the target is the registered asset bound to the session, never client-supplied;
  * required recording must exist (guacd has created its file) before any desktop
    frame is forwarded, otherwise the session is refused;
  * ACTIVE only after guacd has produced a real display update (first `sync`);
  * a monitor re-reads session, grant, request, user and asset every second and
    closes guacd's connection (and so the RDP connection) when any of them stops
    authorizing the session — termination, expiry, revocation, deactivation;
  * the recording is finalized from what is on disk (see rdp_recording.py).
"""

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, status

from app.api.v1.sessions import get_credential_service
from app.api.v1.ssh_sessions import _close_session_in_db
from app.core.audit import write_audit_log
from app.core.config import settings
from app.database.session import async_session_factory
from app.models.access_request import AccessRequest
from app.models.asset import Asset
from app.models.jit_grant import JITGrant
from app.models.policy import Policy
from app.models.recording import Recording
from app.models.session import Session, SessionEvent
from app.models.user import User
from app.services.credential_errors import failure_message
from app.services.credential_service import CheckoutRequest, CredentialAccessDenied, CredentialService, CredentialUnavailable
from app.services.guacamole import GuacamoleError, InstructionParser, connect_guacd, encode, handshake
from app.services.jit_service import JITService
from app.services.rdp_controls import ClipboardGate, audit_summary, channel_params, client_name, resolve_controls
from app.services.rdp_gateway import GuacdRdpGateway, LiveRDPConnection, get_rdp_gateway, rdp_recording_writable
from app.services.rdp_recording import RECORDING_NAME, finalize_rdp_recording, wait_for_recording_file
from app.services.ssh_ticket import SSHTicketInvalidError, SSHTicketService, SSHTicketStorageError, get_ssh_ticket_service
from anyio import CancelScope

router = APIRouter(prefix="/sessions", tags=["RDP Sessions"])
logger = logging.getLogger("securepam.rdp")
_jit = JITService()

# What a browser may send to guacd once connected: input, clipboard and display negotiation only.
CLIENT_OPCODES = {"key", "mouse", "touch", "size", "clipboard", "blob", "end", "ack", "sync", "nop"}
MAX_CLIENT_FRAME = 256 * 1024
FIRST_FRAME_TIMEOUT = 5.0
FIRST_SYNC_TIMEOUT = 30.0

# guacd/Guacamole status codes that tell us why the upstream connection failed.
_AUTH_STATUS = {"769", "771"}
_UNREACHABLE_STATUS = {"515", "516", "519", "520", "521"}


def _error_frame(message: str, code: str = "512") -> str:
    return encode("error", message, code)


def _classify_guacd_error(exc: GuacamoleError) -> str:
    text = str(exc)
    if exc.code == "GUACD_UNREACHABLE":
        return "GATEWAY_UNAVAILABLE"
    if exc.code in ("GUACD_TIMEOUT", "GUACD_CLOSED"):
        return "TARGET_UNREACHABLE"
    return "GATEWAY_ERROR" if not text else "GATEWAY_ERROR"


async def _authorization_problem(
    session_id, user_id, asset_id, request_id, grant_id
) -> Optional[tuple[str, str, str]]:
    """None while the session is still authorized, else (final status, reason, message for the user)."""
    async with async_session_factory() as db:
        s = await db.get(Session, session_id)
        if s is None or s.status not in ("STARTING", "ACTIVE"):
            return "COMPLETED", "SESSION_TERMINATED", "Session was terminated."
        g = await db.get(JITGrant, grant_id) if grant_id else None
        ar = await db.get(AccessRequest, request_id)
        if g is None or g.status != "ACTIVE" or g.revoked_at is not None or ar is None or ar.status != "ACTIVE":
            return "EXPIRED", "JIT_GRANT_REVOKED", "Access authorization has been revoked."
        if g.expires_at <= datetime.now(timezone.utc):
            return "EXPIRED", "JIT_GRANT_EXPIRED", "The just-in-time grant has expired."
        u = await db.get(User, user_id)
        a = await db.get(Asset, asset_id)
        if u is None or not u.is_active or u.is_deleted or a is None or not a.enabled or a.status != "ACTIVE" or a.is_deleted:
            return "FAILED", "AUTHORIZATION_REVOKED", "User or target is no longer active."
    return None


def _split_account(username: str) -> tuple[str, str]:
    """`DOMAIN\\user` or `user@domain` -> (user, domain); plain names have no domain."""
    if "\\" in username:
        domain, _, user = username.partition("\\")
        return user, domain
    if "@" in username:
        user, _, domain = username.partition("@")
        return user, domain
    return username, ""


@router.websocket("/rdp/{session_id}/ws")
async def rdp_websocket(
    websocket: WebSocket,
    session_id: uuid.UUID,
    ticket_service: SSHTicketService = Depends(get_ssh_ticket_service),
    gateway=Depends(get_rdp_gateway),
    credentials: CredentialService = Depends(get_credential_service),
):
    await websocket.accept()

    async def refuse(reason: str, code: str = "512") -> None:
        try:
            await websocket.send_text(_error_frame(failure_message(reason), code))
        except Exception:
            pass
        try:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason=reason[:100])
        except Exception:
            pass

    # 1. First frame: ticket and display size. Never from the URL.
    ticket, size = None, (1280, 800, 96)
    try:
        parsed = json.loads(await asyncio.wait_for(websocket.receive_text(), FIRST_FRAME_TIMEOUT))
        if isinstance(parsed, dict) and parsed.get("type") == "auth":
            ticket = parsed.get("ticket")
            clamp = lambda v, lo, hi, d: v if isinstance(v, int) and lo <= v <= hi else d  # noqa: E731
            size = (clamp(parsed.get("width"), 320, 4096, 1280), clamp(parsed.get("height"), 240, 2160, 800),
                    clamp(parsed.get("dpi"), 48, 384, 96))
    except (asyncio.TimeoutError, WebSocketDisconnect, json.JSONDecodeError, ValueError):
        pass
    if not ticket or not isinstance(ticket, str):
        await refuse("TICKET_REQUIRED")
        return
    if not isinstance(gateway, GuacdRdpGateway):
        await refuse("GATEWAY_UNAVAILABLE")
        return

    # 2. Authoritative validation, ticket consumption, credential, recording prerequisites.
    async with async_session_factory() as db:
        session = await db.get(Session, session_id)
        if session is None or session.protocol != "RDP" or session.status != "STARTING":
            await refuse("SESSION_NOT_CONNECTABLE")
            return
        try:
            await ticket_service.consume_ticket(
                ticket=ticket, expected_session_id=session.id, expected_user_id=session.user_id,
                expected_asset_id=session.asset_id)
        except SSHTicketInvalidError:
            await refuse("TICKET_INVALID")
            return
        except SSHTicketStorageError:
            await refuse("TICKET_UNAVAILABLE")
            return
        if gateway.get_live_connection(session.id) is not None:
            await refuse("SESSION_NOT_CONNECTABLE")
            return
        user = await db.get(User, session.user_id)
        asset = await db.get(Asset, session.asset_id)
        access_request = await db.get(AccessRequest, session.request_id)
        if user is None or not user.is_active or user.is_deleted:
            await refuse("AUTHORIZATION_REVOKED")
            return
        if asset is None or not asset.enabled or asset.status != "ACTIVE" or asset.is_deleted or asset.protocol != "RDP":
            await refuse("ASSET_DISABLED")
            return
        if access_request is None or access_request.status != "ACTIVE":
            await refuse("ACCESS_REQUEST_NOT_ACTIVE")
            return
        recording_required = bool(asset.recording_required or access_request.recording_required)
        if recording_required and (session.recording_id is None or not rdp_recording_writable()):
            await refuse("RECORDING_START_FAILED")
            return
        grant = await _jit.live_grant(
            db, await db.get(JITGrant, session.jit_grant_id) if session.jit_grant_id else None,
            user_id=user.id, target_id=asset.id, protocol="RDP")
        if grant is None:
            await refuse("JIT_GRANT_INVALID")
            return
        ids = dict(user_id=user.id, asset_id=asset.id, request_id=access_request.id, grant_id=grant.id)
        session_number, recording_id = session.session_number, session.recording_id
        target_host, target_port = (asset.ip_address or asset.hostname), asset.port
        controls = resolve_controls(await db.get(Policy, asset.policy_id) if asset.policy_id else None)
        checkout = CheckoutRequest(
            user_id=user.id, access_request_id=access_request.id, jit_grant_id=grant.id, asset_id=asset.id,
            session_id=session.id, source_ip=websocket.client.host if websocket.client else None)
        try:
            async with credentials.checkout(db, checkout) as credential:
                account, domain = _split_account(credential.username)
                params = {
                    "hostname": target_host, "port": str(target_port), "username": account, "password": credential.reveal(),
                    "domain": domain, "security": settings.RDP_SECURITY, "ignore-cert": "true" if settings.RDP_IGNORE_CERT else "false",
                    "resize-method": "display-update", "disable-audio": "true", "timezone": "UTC",
                    **channel_params(controls), "client-name": client_name(session_number),
                }
        except (CredentialAccessDenied, CredentialUnavailable) as exc:
            await _close_session_in_db(session_id, status_val="FAILED", reason=exc.reason)
            await refuse(exc.reason)
            return
        if recording_id:
            from app.services.rdp_recording import session_recording_dir
            params.update({
                "recording-path": f"{settings.GUACD_RECORDING_PATH}/{session.id}", "recording-name": RECORDING_NAME,
                "create-recording-path": "true",
                # Keystrokes would capture passwords typed into the remote desktop.
                "recording-include-keys": "false",
            })

    # 3. Connect to guacd and hand it the target. The credential lives only in `params`.
    stream = None
    failure: Optional[str] = None
    try:
        stream = await connect_guacd(gateway.host, gateway.port)
        guac_id = await handshake(stream, protocol="rdp", params=params, width=size[0], height=size[1], dpi=size[2])
    except GuacamoleError as exc:
        failure = _classify_guacd_error(exc)
        logger.warning("rdp_connect_failed session=%s reason=%s code=%s", session_id, failure, exc.code)
    finally:
        params.clear()
    if failure is not None or stream is None:
        if stream:
            await stream.close()
        await _fail_session(session_id, recording_id, user.id, failure or "GATEWAY_ERROR")
        await refuse(failure or "GATEWAY_ERROR")
        return

    live = LiveRDPConnection(session_id=session_id, stream=stream, guacd_connection_id=guac_id)
    gateway.register(live)
    gate = ClipboardGate(controls.clipboard)
    final_status, final_reason = "COMPLETED", "SESSION_TERMINATED"
    activated = False
    recording_failure: Optional[str] = None
    tasks: list = []
    try:
        # 4. Recording must exist before any desktop frame is shown.
        if recording_id and not await wait_for_recording_file(session_id, 5.0):
            recording_failure = "RECORDING_START_FAILED"
            final_status, final_reason = "FAILED", "RECORDING_START_FAILED"
            await websocket.send_text(_error_frame(failure_message("RECORDING_START_FAILED"), "512"))
            return

        # 5. ACTIVE only on the first real display update; hold frames until then.
        # Instructions guacd sent in the same chunk as `ready` were parsed during the handshake: inspect
        # them exactly like later ones, so an immediate upstream error is classified correctly.
        early = stream.take_pending()
        held: list = []
        seen_sync = False
        deadline = asyncio.get_event_loop().time() + FIRST_SYNC_TIMEOUT
        next_batch = (("".join(encode(*i) for i in early), early) if early else None)
        while not seen_sync:
            if next_batch is not None:
                text, instructions = next_batch
                next_batch = None
            else:
                remaining = deadline - asyncio.get_event_loop().time()
                try:
                    if remaining <= 0:
                        raise asyncio.TimeoutError
                    text, instructions = await stream.read_chunk(remaining)
                except (asyncio.TimeoutError, GuacamoleError):
                    final_status, final_reason = "FAILED", "TARGET_UNREACHABLE"
                    await websocket.send_text(_error_frame(failure_message("TARGET_UNREACHABLE"), "519"))
                    return
            held.append(text)
            for ins in instructions:
                if ins and ins[0] == "error":
                    code = ins[2] if len(ins) > 2 else ""
                    final_status = "FAILED"
                    final_reason = "TARGET_AUTH_FAILED" if code in _AUTH_STATUS else (
                        "TARGET_UNREACHABLE" if code in _UNREACHABLE_STATUS else "GATEWAY_ERROR")
                    await websocket.send_text(_error_frame(failure_message(final_reason), code or "512"))
                    return
                if ins and ins[0] == "disconnect":
                    final_status, final_reason = "FAILED", "TARGET_UNREACHABLE"
                    return
                if ins and ins[0] == "sync":
                    seen_sync = True

        now = datetime.now(timezone.utc)
        async with async_session_factory() as db:
            s = await db.get(Session, session_id)
            actor = await db.get(User, ids["user_id"])
            if s is None or s.status != "STARTING":
                return  # terminated while connecting
            s.status, s.start_time, s.gateway_session_id = "ACTIVE", now, guac_id
            activated = True
            if recording_id:
                rec = await db.get(Recording, recording_id)
                if rec:
                    rec.status = "RECORDING"
                    await write_audit_log(db, actor=actor, action="RECORDING_STARTED", target_type="recording",
                                          target_id=str(rec.id), session_id=session_id, result="SUCCESS",
                                          severity="INFO", metadata={"format": "guacamole", "captures": "screen,mouse"})
            db.add(SessionEvent(session_id=session_id, event_type="SESSION_STARTED", timestamp=now,
                                details={"protocol": "RDP"}))
            await write_audit_log(
                db, actor=actor, action="SESSION_STARTED", target_type="asset", target_id=str(ids["asset_id"]),
                request_id=ids["request_id"], session_id=session_id,
                source_ip=websocket.client.host if websocket.client else None, result="SUCCESS", severity="INFO",
                metadata={"protocol": "RDP", "session_number": session_number, "recording": recording_id is not None,
                          "controls": audit_summary(controls)})
            await db.commit()
        for chunk in held:
            await websocket.send_text(chunk)

        # 6. Relay + monitor.
        async def guacd_to_browser():
            nonlocal final_status, final_reason
            try:
                while True:
                    text, instructions = await stream.read_chunk()
                    for ins in instructions:
                        gate.server_instruction(ins)
                    await websocket.send_text(text)
                    if any(i and i[0] in ("disconnect", "error") for i in instructions):
                        final_reason = "REMOTE_DISCONNECTED"  # e.g. Windows signed the session out
                        return
            except GuacamoleError:
                final_reason = "REMOTE_DISCONNECTED"  # guacd closed the connection
                return
            except (WebSocketDisconnect, asyncio.CancelledError):
                return
            except Exception as exc:
                logger.warning("rdp relay error session=%s %s", session_id, type(exc).__name__)

        async def browser_to_guacd():
            nonlocal final_reason
            parser = InstructionParser()
            try:
                while True:
                    text = await websocket.receive_text()
                    if len(text) > MAX_CLIENT_FRAME:
                        continue
                    for ins in parser.feed(text):
                        if ins and ins[0] in CLIENT_OPCODES and gate.client_instruction(ins):
                            stream.send(*ins)
                    await stream.writer.drain()
            except WebSocketDisconnect:
                final_reason = "BROWSER_DISCONNECTED"
                return
            except (GuacamoleError, asyncio.CancelledError, ConnectionError):
                return
            except Exception as exc:
                logger.warning("rdp input error session=%s %s", session_id, type(exc).__name__)

        async def monitor():
            nonlocal final_status, final_reason
            consecutive = 0
            try:
                while True:
                    try:
                        problem = await _authorization_problem(session_id, **ids)
                        consecutive = 0
                    except Exception:
                        consecutive += 1
                        problem = ("FAILED", "AUTH_REVALIDATION_FAILED", "Authorization could not be verified.") \
                            if consecutive >= 2 else None
                    if problem:
                        final_status, final_reason, message = problem
                        try:
                            await websocket.send_text(_error_frame(message, "521"))
                        except Exception:
                            pass
                        return
                    await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                return

        tasks = [asyncio.create_task(guacd_to_browser()), asyncio.create_task(browser_to_guacd()),
                 asyncio.create_task(monitor())]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    except Exception as exc:
        final_status, final_reason = "FAILED", f"ERROR: {type(exc).__name__}"
        logger.error("rdp session %s failed: %s", session_id, type(exc).__name__)
    finally:
        with CancelScope(shield=True):
            for t in tasks:
                if not t.done():
                    t.cancel()
            if tasks:  # the relay must have let go of the guacd socket before we wait on it
                await asyncio.gather(*tasks, return_exceptions=True)
            try:
                await gateway.close_connection(session_id)  # drops the TCP link: guacd ends the RDP connection
            except Exception as exc:
                logger.warning("rdp close failed session=%s %s", session_id, type(exc).__name__)
            if recording_id:
                try:
                    await finalize_rdp_recording(recording_id, session_id, ids["user_id"], failure_reason=recording_failure)
                except Exception as exc:
                    logger.error("rdp recording finalize failed session=%s %s", session_id, type(exc).__name__)
            await _close_session_in_db(session_id, status_val=final_status, reason=final_reason)
            clip = gate.summary()
            if clip is not None:
                try:
                    async with async_session_factory() as db:
                        await write_audit_log(
                            db, actor=await db.get(User, ids["user_id"]), action="RDP_CLIPBOARD_ACTIVITY",
                            target_type="session", target_id=str(session_id), request_id=ids["request_id"],
                            session_id=session_id, result="SUCCESS", severity="INFO" if gate.allowed else "MEDIUM",
                            metadata={"protocol": "RDP", **clip})
                        await db.commit()
                except Exception as exc:
                    logger.error("rdp clipboard audit failed session=%s %s", session_id, type(exc).__name__)
            if activated:
                # How the connected session ended, unless an administrator/owner termination (which audits
                # itself as SESSION_TERMINATED) owns that record.
                try:
                    async with async_session_factory() as db:
                        row = await db.get(Session, session_id)
                        if row is not None and row.status not in ("TERMINATING", "TERMINATED"):
                            await write_audit_log(
                                db, actor=await db.get(User, ids["user_id"]), action="SESSION_ENDED",
                                target_type="session", target_id=str(session_id), request_id=ids["request_id"],
                                session_id=session_id, result="SUCCESS" if row.status == "COMPLETED" else "FAILURE",
                                severity="INFO" if row.status == "COMPLETED" else "MEDIUM",
                                metadata={"reason": final_reason, "status": row.status, "protocol": "RDP"})
                            await db.commit()
                except Exception as exc:
                    logger.error("rdp end audit failed session=%s %s", session_id, type(exc).__name__)
            if final_status == "FAILED" and not activated:
                # Failed after the handshake but before any desktop: say why in the audit trail.
                try:
                    async with async_session_factory() as db:
                        await write_audit_log(
                            db, actor=await db.get(User, ids["user_id"]), action="SESSION_LAUNCH_FAILED",
                            target_type="asset", target_id=str(ids["asset_id"]), request_id=ids["request_id"],
                            session_id=session_id, result="FAILURE", severity="HIGH",
                            metadata={"reason": final_reason, "protocol": "RDP"})
                        await db.commit()
                except Exception as exc:
                    logger.error("rdp failure audit failed session=%s %s", session_id, type(exc).__name__)
            try:
                await websocket.close(code=status.WS_1000_NORMAL_CLOSURE)
            except Exception:
                pass


async def _fail_session(session_id, recording_id, user_id, reason: str) -> None:
    """The connection never came up: FAILED, with the recording failed too (nothing was captured)."""
    if recording_id:
        await finalize_rdp_recording(recording_id, session_id, user_id, failure_reason="RECORDING_NOT_STARTED",
                                     settle_seconds=0)
    await _close_session_in_db(session_id, status_val="FAILED", reason=reason)
    async with async_session_factory() as db:
        user = await db.get(User, user_id)
        await write_audit_log(db, actor=user, action="SESSION_LAUNCH_FAILED", target_type="session",
                              target_id=str(session_id), session_id=session_id, result="FAILURE", severity="HIGH",
                              metadata={"reason": reason, "protocol": "RDP"})
        await db.commit()
