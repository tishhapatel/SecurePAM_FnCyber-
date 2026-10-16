"""Isolated-browser gateway health: a real, bounded probe with accurate states and no secret in the output."""
import asyncio

import httpx
import pytest

from app.core.config import settings
from app.services import browser_isolation as bi

SECRET = "ISOLATION-TOKEN-CANARY-not-real"
NO_SESSION = "/sessions/00000000-0000-0000-0000-000000000000"


@pytest.fixture
def token_file(tmp_path, monkeypatch):
    f = tmp_path / "isolation_token"
    f.write_text(SECRET + "\n")
    f.chmod(0o600)
    monkeypatch.setattr(settings, "BROWSER_ISOLATION_ENABLED", True)
    monkeypatch.setattr(settings, "BROWSER_ISOLATION_TOKEN_FILE", str(f))
    return f


def daemon(monkeypatch, handler):
    """Route the probe's HTTP client to an in-process fake daemon."""
    real = httpx.AsyncClient

    def factory(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real(*args, **kwargs)

    monkeypatch.setattr(bi.httpx, "AsyncClient", factory)


def ok_daemon(health=None, auth_status=404):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.method, request.url.path, request.headers.get("authorization")))
        if request.url.path == "/health":
            return httpx.Response(200, json=health if health is not None else {"ok": True, "sessions": 2})
        if request.url.path == NO_SESSION:
            return httpx.Response(auth_status, json={"state": "ENDED"})
        return httpx.Response(500)

    handler.seen = seen
    return handler


def assert_no_secret(probe):
    assert SECRET not in probe.details and SECRET not in repr(probe)
    assert "127.0.0.1" not in probe.details and "token_file" not in probe.details.lower()


async def test_disabled_is_not_configured_and_does_not_probe(monkeypatch):
    monkeypatch.setattr(settings, "BROWSER_ISOLATION_ENABLED", False)
    daemon(monkeypatch, lambda r: pytest.fail("a disabled gateway must not be probed"))
    probe = await bi.probe_isolation_daemon()
    assert probe.status == "not_configured" and "disabled" in probe.details


@pytest.mark.parametrize("content", [None, "", "  \n"])
async def test_missing_or_empty_token_is_unhealthy(tmp_path, monkeypatch, content):
    monkeypatch.setattr(settings, "BROWSER_ISOLATION_ENABLED", True)
    if content is None:
        monkeypatch.setattr(settings, "BROWSER_ISOLATION_TOKEN_FILE", None)
    else:
        f = tmp_path / "t"; f.write_text(content)
        monkeypatch.setattr(settings, "BROWSER_ISOLATION_TOKEN_FILE", str(f))
    daemon(monkeypatch, lambda r: pytest.fail("no token, no probe"))
    probe = await bi.probe_isolation_daemon()
    assert probe.status == "unhealthy" and str(tmp_path) not in probe.details


async def test_healthy_reports_session_count_and_uses_a_read_only_authenticated_probe(token_file, monkeypatch):
    handler = ok_daemon()
    daemon(monkeypatch, handler)
    probe = await bi.probe_isolation_daemon()
    assert probe.status == "healthy" and "2 active browser session(s)" in probe.details
    assert "recording" in probe.details and probe.latency_ms is not None
    assert [(m, p) for m, p, _ in handler.seen] == [("GET", "/health"), ("GET", NO_SESSION)]   # nothing created
    assert handler.seen[0][2] is None and handler.seen[1][2] == f"Bearer {SECRET}"            # token only on the auth probe
    assert_no_secret(probe)


async def test_rejected_token_is_unhealthy_not_degraded(token_file, monkeypatch):
    daemon(monkeypatch, ok_daemon(auth_status=401))
    probe = await bi.probe_isolation_daemon()
    assert probe.status == "unhealthy" and "rejects the gateway token" in probe.details
    assert_no_secret(probe)


async def test_unexpected_authenticated_answer_is_degraded(token_file, monkeypatch):
    daemon(monkeypatch, ok_daemon(auth_status=500))
    probe = await bi.probe_isolation_daemon()
    assert probe.status == "degraded" and "HTTP 500" in probe.details


@pytest.mark.parametrize("response", [httpx.Response(503, json={}), httpx.Response(200, json={"ok": False}),
                                       httpx.Response(200, content=b"not json")])
async def test_daemon_not_ready_is_unhealthy(token_file, monkeypatch, response):
    daemon(monkeypatch, lambda r: response)
    probe = await bi.probe_isolation_daemon()
    assert probe.status == "unhealthy"


async def test_unreachable_daemon_is_unhealthy_without_leaking_the_address(token_file, monkeypatch):
    def refuse(request):
        raise httpx.ConnectError("connection refused to http://127.0.0.1:6090")
    daemon(monkeypatch, refuse)
    probe = await bi.probe_isolation_daemon()
    assert probe.status == "unhealthy" and "unreachable" in probe.details
    assert_no_secret(probe)


async def test_slow_daemon_is_degraded(token_file, monkeypatch):
    monkeypatch.setattr(bi, "_PROBE_SLOW_SECONDS", -1.0)   # any answer counts as slow
    daemon(monkeypatch, ok_daemon())
    probe = await bi.probe_isolation_daemon()
    assert probe.status == "degraded" and "slow" in probe.details


async def test_a_hung_daemon_cannot_hang_the_health_check(token_file, monkeypatch):
    async def hang(request):
        await asyncio.sleep(30)
    daemon(monkeypatch, hang)
    monkeypatch.setattr(bi, "_PROBE_TOTAL_BUDGET", 0.3)
    loop = asyncio.get_event_loop()
    start = loop.time()
    probe = await bi.probe_isolation_daemon()
    assert loop.time() - start < 2.0
    assert probe.status == "unhealthy" and "did not answer in time" in probe.details
