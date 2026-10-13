"""
Unit tests for Browser Isolation Daemon and Service — Member 11.
"""

import importlib.util
import json
import os
import shutil
import sys
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest

# Dynamically import the browser-isolation daemon server module
server_path = Path(__file__).resolve().parents[2] / "gateway" / "browser-isolation" / "server.py"
spec = importlib.util.spec_from_file_location("browser_isolation_server", str(server_path))
bi_server = importlib.util.module_from_spec(spec)
sys.modules["browser_isolation_server"] = bi_server
spec.loader.exec_module(bi_server)

from app.services.browser_isolation_service import BrowserIsolationService


class DummyRequest:
    def __init__(self, method: str, path: str, headers: dict = None, body: bytes = b""):
        self.method = method
        self.path = path
        self.headers = headers or {}
        self.body = body

    def makefile(self, *args, **kwargs):
        return BytesIO(self.body)


def invoke_handler(method: str, path: str, headers: dict = None, body: dict = None):
    body_bytes = json.dumps(body).encode("utf-8") if body else b""
    hdr_dict = dict(headers or {})
    if body_bytes:
        hdr_dict["Content-Length"] = str(len(body_bytes))

    # Mock BaseHTTPRequestHandler
    handler = bi_server.BrowserIsolationHandler.__new__(bi_server.BrowserIsolationHandler)
    handler.path = path
    handler.command = method
    handler.headers = hdr_dict
    handler.rfile = BytesIO(body_bytes)
    handler.wfile = BytesIO()

    handler._sent_status = None
    handler._sent_headers = {}

    def send_response(status_code):
        handler._sent_status = status_code

    def send_header(k, v):
        handler._sent_headers[k] = v

    def end_headers():
        pass

    handler.send_response = send_response
    handler.send_header = send_header
    handler.end_headers = end_headers

    if method == "GET":
        handler.do_GET()
    elif method == "POST":
        handler.do_POST()

    handler.wfile.seek(0)
    raw_response = handler.wfile.read()
    response_data = None
    if "application/json" in handler._sent_headers.get("Content-Type", ""):
        try:
            response_data = json.loads(raw_response.decode("utf-8"))
        except Exception:
            pass
    return handler._sent_status, handler._sent_headers, response_data, raw_response


def test_daemon_health_endpoint():
    status, _, data, _ = invoke_handler("GET", "/health")
    assert status == 200
    assert data["status"] == "healthy"
    assert data["service"] == "securepam-browser-isolation"


def test_daemon_launch_without_auth_token_rejected_403():
    status, _, data, _ = invoke_handler(
        "POST", "/sessions/launch",
        headers={},
        body={"session_id": str(uuid4()), "application_id": str(uuid4()), "target_url": "http://example.com"},
    )
    assert status == 403
    assert "Invalid or missing gateway auth token" in data["detail"]


def test_daemon_launch_invalid_uuid_rejected_422():
    status, _, data, _ = invoke_handler(
        "POST", "/sessions/launch",
        headers={"X-Gateway-Auth-Token": bi_server.AUTH_TOKEN},
        body={"session_id": "not-a-valid-uuid", "application_id": str(uuid4()), "target_url": "http://example.com"},
    )
    assert status == 422
    assert "Invalid session_id" in data["detail"]


def test_daemon_launch_invalid_url_rejected_422():
    status, _, data, _ = invoke_handler(
        "POST", "/sessions/launch",
        headers={"X-Gateway-Auth-Token": bi_server.AUTH_TOKEN},
        body={"session_id": str(uuid4()), "application_id": str(uuid4()), "target_url": "ftp://malicious.org"},
    )
    assert status == 422
    assert "must be an HTTP/HTTPS URL" in data["detail"]


def test_daemon_launch_success_and_lifecycle():
    s_id = str(uuid4())
    a_id = str(uuid4())
    target = "https://internal-app.local:8443/console"

    # 1. Launch session
    status, _, data, _ = invoke_handler(
        "POST", "/sessions/launch",
        headers={"X-Gateway-Auth-Token": bi_server.AUTH_TOKEN},
        body={"session_id": s_id, "application_id": a_id, "target_url": target},
    )
    assert status == 200
    assert data["status"] == "RUNNING"
    assert data["session_id"] == s_id
    assert data["application_id"] == a_id
    assert f"/vnc/{s_id}" in data["vnc_path"]

    # 2. Query status
    status, _, status_data, _ = invoke_handler(
        "GET", f"/sessions/{s_id}/status",
        headers={"X-Gateway-Auth-Token": bi_server.AUTH_TOKEN},
    )
    assert status == 200
    assert status_data["target_url"] == target

    # 3. Access VNC viewer HTML
    status, hdrs, _, raw = invoke_handler(
        "GET", f"/vnc/{s_id}",
    )
    assert status == 200
    assert "text/html" in hdrs.get("Content-Type", "")
    html = raw.decode("utf-8")
    assert "SecurePAM Browser Isolation" in html
    assert target in html

    # 4. Terminate session
    status, _, term_data, _ = invoke_handler(
        "POST", f"/sessions/{s_id}/terminate",
        headers={"X-Gateway-Auth-Token": bi_server.AUTH_TOKEN},
    )
    assert status == 200
    assert term_data["status"] == "TERMINATED"

    # 5. Subsequent status query returns 404
    status, _, _, _ = invoke_handler(
        "GET", f"/sessions/{s_id}/status",
        headers={"X-Gateway-Auth-Token": bi_server.AUTH_TOKEN},
    )
    assert status == 404


@pytest.mark.asyncio
async def test_browser_isolation_service_unit():
    service = BrowserIsolationService(base_url="http://mock-browser-isolation:6080")
    s_id = uuid4()
    a_id = uuid4()
    target = "http://target.corp:8080"

    # Start session in mock/test mode
    data = await service.start_session(session_id=s_id, application_id=a_id, target_url=target)
    assert data["session_id"] == str(s_id)
    assert data["status"] == "RUNNING"

    status_data = await service.get_session_status(session_id=s_id)
    assert status_data is not None
    assert status_data["session_id"] == str(s_id)

    # Stop session
    assert await service.stop_session(session_id=s_id) is True
    assert await service.get_session_status(session_id=s_id) is None


def test_cross_session_and_cross_application_isolation():
    """
    Test that distinct sessions receive isolated displays, ports, and profiles,
    and cross-application/cross-session tampering is blocked.
    """
    s1_id = str(uuid4())
    s2_id = str(uuid4())
    app_a = str(uuid4())
    app_b = str(uuid4())

    # Launch session 1 for app A
    status, _, data1, _ = invoke_handler(
        "POST", "/sessions/launch",
        headers={"X-Gateway-Auth-Token": bi_server.AUTH_TOKEN},
        body={"session_id": s1_id, "application_id": app_a, "target_url": "http://app-a.internal:8080"},
    )
    assert status == 200
    display1 = data1["display"]

    # Launch session 2 for app B
    status, _, data2, _ = invoke_handler(
        "POST", "/sessions/launch",
        headers={"X-Gateway-Auth-Token": bi_server.AUTH_TOKEN},
        body={"session_id": s2_id, "application_id": app_b, "target_url": "http://app-b.internal:9000"},
    )
    assert status == 200
    display2 = data2["display"]

    # Invariant: Distinct displays and ports
    assert display1 != display2
    assert data1["rfb_port"] != data2["rfb_port"]

    # Authorized access to session 1 via app A succeeds
    status, _, _, raw1 = invoke_handler("GET", f"/vnc/{app_a}?session_id={s1_id}")
    assert status == 200
    assert "http://app-a.internal:8080" in raw1.decode("utf-8")

    # Unauthorized cross-app access: session 1 with app B path is rejected
    status, _, err, _ = invoke_handler("GET", f"/vnc/{app_b}?session_id={s1_id}")
    assert status == 403
    assert "Session does not belong to the requested application" in err["detail"]

    # Terminate session 1
    status, _, _, _ = invoke_handler(
        "POST", f"/sessions/{s1_id}/terminate",
        headers={"X-Gateway-Auth-Token": bi_server.AUTH_TOKEN},
    )
    assert status == 200

    # Session 1 is now inaccessible
    status, _, _, _ = invoke_handler("GET", f"/vnc/{app_a}?session_id={s1_id}")
    assert status == 404

    # Session 2 remains fully active and unaffected
    status, _, s2_status, _ = invoke_handler(
        "GET", f"/sessions/{s2_id}/status",
        headers={"X-Gateway-Auth-Token": bi_server.AUTH_TOKEN},
    )
    assert status == 200
    assert s2_status["status"] == "RUNNING"

    # Terminate session 2
    invoke_handler(
        "POST", f"/sessions/{s2_id}/terminate",
        headers={"X-Gateway-Auth-Token": bi_server.AUTH_TOKEN},
    )
