"""
Isolated-browser gateway: the backend's side of infrastructure/browser-isolation.

The daemon (in its own hardened container) runs one Xvfb + Chromium + x11vnc + egress proxy per
session, locked to the registered application. This module:

  * talks to the daemon's loopback management API (bearer token read from a 0600 file);
  * keeps the per-session VNC password in process memory only (never DB, logs or the browser);
  * terminates the VNC security handshake itself, so the browser's noVNC client gets an already
    authenticated stream and never learns the password;
  * filters what the browser may send to the VNC server (input and display negotiation only;
    clipboard only when the application allows it);
  * reaps sessions that never connect or are ended before connecting, so no browser is left running.
"""

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Dict, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger("securepam.web")

UNCONNECTED_TTL = 120.0  # seconds a prepared session may wait for its browser before it is reaped


class IsolationError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass
class LiveWebSession:
    session_id: object
    vnc_port: int
    vnc_password: str = field(repr=False)
    clipboard_allowed: bool = False
    created: float = field(default_factory=time.monotonic)
    attached: bool = False          # a browser WebSocket currently owns the relay
    violations_seen: int = 0


def _token() -> str:
    path = settings.BROWSER_ISOLATION_TOKEN_FILE
    if not path:
        raise IsolationError("ISOLATION_NOT_CONFIGURED")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError as exc:
        raise IsolationError("ISOLATION_NOT_CONFIGURED") from exc


@dataclass(frozen=True)
class IsolationProbe:
    status: str                 # healthy | degraded | unhealthy | not_configured
    details: str
    latency_ms: Optional[float] = None


_PROBE_SLOW_SECONDS = 1.0       # reachable but slow: launches would be sluggish -> degraded
_PROBE_HTTP_TIMEOUT = httpx.Timeout(1.5, connect=1.0)
_PROBE_TOTAL_BUDGET = 4.0       # hard ceiling for the whole probe: a health check must never hang
_NO_SUCH_SESSION = "00000000-0000-0000-0000-000000000000"


async def probe_isolation_daemon() -> IsolationProbe:
    """Real, bounded probe of the isolation daemon. Returns generic text only: no token, path, URL or
    exception detail is placed in the result (health responses are readable by operators and logs).

    1. Disabled by configuration -> not_configured (nothing to probe).
    2. Gateway token unreadable/empty -> unhealthy: a launch cannot authenticate.
    3. GET /health (unauthenticated) unreachable / not ok -> unhealthy.
    4. GET /sessions/<unused id> with the bearer token: 404 means the token is accepted (read-only, nothing is
       created); 401 -> unhealthy (launches would be rejected); anything else -> degraded.
    5. Slow answers -> degraded. Otherwise healthy.
    """
    if not settings.BROWSER_ISOLATION_ENABLED:
        return IsolationProbe("not_configured", "Isolated browsing is disabled (BROWSER_ISOLATION_ENABLED=false)")
    try:
        token = _token()
    except IsolationError:
        return IsolationProbe("unhealthy", "Isolation gateway token is not configured or not readable")
    if not token:
        return IsolationProbe("unhealthy", "Isolation gateway token file is empty")

    started = time.monotonic()

    async def run() -> IsolationProbe:
        async with httpx.AsyncClient(base_url=settings.BROWSER_ISOLATION_URL, timeout=_PROBE_HTTP_TIMEOUT,
                                     trust_env=False, follow_redirects=False) as client:
            health = await client.get("/health")
            elapsed = round((time.monotonic() - started) * 1000, 1)
            if health.status_code != 200:
                return IsolationProbe("unhealthy", f"Isolation daemon health returned HTTP {health.status_code}", elapsed)
            try:
                body = health.json()
            except ValueError:
                body = {}
            if body.get("ok") is not True:
                return IsolationProbe("unhealthy", "Isolation daemon reports it is not ready", elapsed)
            sessions = body.get("sessions")
            active = f"{sessions} active browser session(s)" if isinstance(sessions, int) and sessions >= 0 else "session count unavailable"
            auth = await client.get(f"/sessions/{_NO_SUCH_SESSION}", headers={"Authorization": f"Bearer {token}"})
            elapsed = round((time.monotonic() - started) * 1000, 1)
            if auth.status_code == 401:
                return IsolationProbe("unhealthy", "Isolation daemon rejects the gateway token; launches would fail", elapsed)
            if auth.status_code != 404:
                return IsolationProbe("degraded", f"Isolation daemon answered an authenticated probe with HTTP {auth.status_code}", elapsed)
            note = "; sessions that require recording are refused (recording is not implemented)"
            if elapsed / 1000 > _PROBE_SLOW_SECONDS:
                return IsolationProbe("degraded", f"Isolation daemon reachable and authenticated but slow ({elapsed:.0f} ms); {active}" + note, elapsed)
            return IsolationProbe("healthy", f"Isolation daemon reachable and accepts the gateway token; {active}" + note, elapsed)

    try:
        return await asyncio.wait_for(run(), _PROBE_TOTAL_BUDGET)
    except asyncio.TimeoutError:
        return IsolationProbe("unhealthy", "Isolation daemon did not answer in time")
    except httpx.HTTPError:
        return IsolationProbe("unhealthy", "Isolation daemon is unreachable")


class BrowserIsolationGateway:
    is_deployed = True

    def __init__(self) -> None:
        self._live: Dict[object, LiveWebSession] = {}

    # -- daemon API ---------------------------------------------------------------------------
    async def _call(self, method: str, path: str, json: Optional[dict] = None, timeout: float = 60.0):
        async with httpx.AsyncClient(base_url=settings.BROWSER_ISOLATION_URL, timeout=timeout, trust_env=False) as c:
            return await c.request(method, path, json=json, headers={"Authorization": f"Bearer {_token()}"})

    async def available(self) -> bool:
        try:
            async with httpx.AsyncClient(base_url=settings.BROWSER_ISOLATION_URL, timeout=2, trust_env=False) as c:
                ok = (await c.get("/health")).status_code == 200
            return ok and bool(settings.BROWSER_ISOLATION_TOKEN_FILE)
        except httpx.HTTPError:
            return False

    async def launch(self, *, session_id, scheme: str, host: str, port: int, path: str, tls_pin: Optional[str],
                     clipboard_allowed: bool, ttl_seconds: int) -> LiveWebSession:
        password = secrets.token_hex(4)  # 8 chars: the VNC password length; loopback-only, per session
        try:
            r = await self._call("POST", "/sessions", json={
                "session_id": str(session_id), "scheme": scheme, "host": host, "port": port, "path": path,
                "tls_pin": tls_pin, "clipboard_allowed": clipboard_allowed, "ttl_seconds": ttl_seconds,
                "vnc_password": password})
        except httpx.HTTPError as exc:
            raise IsolationError("ISOLATION_UNAVAILABLE") from exc
        if r.status_code != 201:
            code = (r.json() or {}).get("error", "LAUNCH_FAILED") if r.headers.get("content-type", "").startswith("application/json") else "LAUNCH_FAILED"
            raise IsolationError(code if code in ("TLS_VALIDATION_FAILED", "DESTINATION_BLOCKED") else "LAUNCH_FAILED")
        live = LiveWebSession(session_id, int(r.json()["vnc_port"]), password, clipboard_allowed)
        self._live[session_id] = live
        return live

    async def wait_ready(self, session_id, timeout: float = 45.0) -> dict:
        deadline = time.monotonic() + timeout
        state: dict = {}
        while time.monotonic() < deadline:
            state = await self.status(session_id)
            if state.get("state") in ("READY", "FAILED", "ENDED"):
                return state
            await asyncio.sleep(1)
        return {**state, "state": "FAILED", "failure": state.get("failure") or "NOT_READY_IN_TIME"}

    async def status(self, session_id) -> dict:
        try:
            r = await self._call("GET", f"/sessions/{session_id}", timeout=5)
            return r.json()
        except (httpx.HTTPError, ValueError):
            return {"state": "UNKNOWN"}

    async def stop(self, session_id) -> dict:
        """Kill the session's processes and delete its profile. Returns {"cleaned": bool, ...}."""
        self._live.pop(session_id, None)
        try:
            return (await self._call("DELETE", f"/sessions/{session_id}", timeout=15)).json()
        except (httpx.HTTPError, ValueError):
            return {"cleaned": False, "leftover": ["daemon unreachable"]}

    # -- registry (same shape as the SSH/RDP gateways, so termination treats all alike) ----------
    def get_live_connection(self, session_id) -> Optional[LiveWebSession]:
        return self._live.get(session_id)

    async def close_connection(self, session_id) -> None:
        await self.stop(session_id)


_gateway: Optional[BrowserIsolationGateway] = None


class _Disabled:
    is_deployed = False

    async def available(self) -> bool:
        return False

    def get_live_connection(self, session_id):
        return None


def get_browser_isolation_gateway():
    global _gateway
    if not settings.BROWSER_ISOLATION_ENABLED:
        return _Disabled()
    if _gateway is None:
        _gateway = BrowserIsolationGateway()
    return _gateway


# -- VNC (RFB 3.8) handshake helpers ---------------------------------------------------------------

def vnc_auth_response(challenge: bytes, password: str) -> bytes:
    """RFB "VNC Authentication": DES-ECB of the 16-byte challenge with the password (8 bytes, zero
    padded) whose every byte is bit-reversed. DES == TripleDES with an 8-byte (single) key."""
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
    from cryptography.hazmat.primitives.ciphers import Cipher, modes

    key = password.encode("latin-1")[:8].ljust(8, b"\0")
    key = bytes(int(f"{b:08b}"[::-1], 2) for b in key)
    enc = Cipher(TripleDES(key * 3), modes.ECB()).encryptor()  # K1=K2=K3: exactly single DES
    return enc.update(challenge) + enc.finalize()


async def server_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, password: str) -> None:
    """Authenticate to x11vnc. Leaves the stream right before ClientInit."""
    version = await asyncio.wait_for(reader.readexactly(12), 10)
    if not version.startswith(b"RFB "):
        raise IsolationError("VNC_PROTOCOL_ERROR")
    writer.write(b"RFB 003.008\n")
    count = (await reader.readexactly(1))[0]
    if count == 0:
        raise IsolationError("VNC_REFUSED")
    types = await reader.readexactly(count)
    if 2 not in types:
        raise IsolationError("VNC_NO_PASSWORD_AUTH")  # never accept a server offering only "None"
    writer.write(b"\x02")
    challenge = await reader.readexactly(16)
    writer.write(vnc_auth_response(challenge, password))
    await writer.drain()
    if await reader.readexactly(4) != b"\0\0\0\0":
        raise IsolationError("VNC_AUTH_FAILED")


class ClientMessageFilter:
    """Parses the browser->server RFB stream (after the handshake) and passes only allowed messages:
    SetPixelFormat, SetEncodings, FramebufferUpdateRequest, KeyEvent, PointerEvent and, when the
    application allows it, ClientCutText. Anything else fails closed."""

    FIXED = {0: 20, 3: 10, 4: 8, 5: 6}
    # Encodings the browser may request. SetEncodings is rewritten to this list, so x11vnc never
    # enables an extension whose client messages this filter refuses (fence, continuous updates,
    # QEMU key events, xvp, SetDesktopSize, extended mouse buttons) or the extended clipboard.
    ALLOWED_ENCODINGS = frozenset(
        {0, 1, 2, 5, 6, 7, 16, 21, -260}            # Raw CopyRect RRE Hextile Zlib Tight ZRLE JPEG TightPNG
        | set(range(-32, -22)) | set(range(-256, -246))  # quality / compression levels
        | {-223, -224, -239, -307, 0x574D5664}      # DesktopSize LastRect Cursor DesktopName VMwareCursor
    )

    def __init__(self, clipboard_allowed: bool) -> None:
        self.clipboard_allowed = clipboard_allowed
        self.buf = b""
        self.init_pending = True  # ClientInit: one byte, first thing after security

    def feed(self, data: bytes) -> bytes:
        self.buf += data
        out = bytearray()
        if self.init_pending and self.buf:
            out += b"\x00"  # ClientInit: force exclusive (shared=0) whatever the browser asked for
            self.buf = self.buf[1:]
            self.init_pending = False
        while self.buf:
            kind = self.buf[0]
            if kind in self.FIXED:
                size = self.FIXED[kind]
            elif kind == 2:
                if len(self.buf) < 4:
                    break
                size = 4 + 4 * int.from_bytes(self.buf[2:4], "big")
            elif kind == 6:
                if len(self.buf) < 8:
                    break
                # Signed: a negative length is the extended-clipboard form (still clipboard data).
                size = 8 + abs(int.from_bytes(self.buf[4:8], "big", signed=True))
                if size > 1 << 20:
                    raise IsolationError("VNC_MESSAGE_TOO_LARGE")
            else:
                raise IsolationError("VNC_MESSAGE_NOT_ALLOWED")
            if len(self.buf) < size:
                break
            message, self.buf = self.buf[:size], self.buf[size:]
            if kind == 6 and not self.clipboard_allowed:
                continue  # clipboard paste into the isolated browser is not permitted for this app
            if kind == 2:
                message = self._allowed_encodings(message)
            out += message
        return bytes(out)

    def _allowed_encodings(self, message: bytes) -> bytes:
        requested = [int.from_bytes(message[i:i + 4], "big", signed=True) for i in range(4, len(message), 4)]
        kept = [e for e in requested if e in self.ALLOWED_ENCODINGS] or [0]  # Raw is always valid
        return (b"\x02\x00" + len(kept).to_bytes(2, "big")
                + b"".join(e.to_bytes(4, "big", signed=True) for e in kept))
