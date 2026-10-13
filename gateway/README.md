# SecurePAM Web Gateway & Browser Isolation

**Team Member:** Member 11 — Web Gateway & Browser Isolation  
**Target Branch:** `feature/web-gateway`  
**Core Technologies:** NGINX 1.27, FastAPI (Python 3.13), Chromium, Xvfb, x11vnc, websockify, noVNC, FFmpeg 6.1.1, Docker Compose

---

## 1. Overview & Architecture

The SecurePAM Web Gateway provides secure, audited, and isolated HTTP/HTTPS access to internal web applications. It supports two distinct access modes defined in the Application registry (`Application.access_mode`):

1. **`STANDARD_PROXY` Mode**: An NGINX reverse proxy terminating client TLS/HTTP and routing strictly to registered, enabled internal web applications with destination IP pinning, centralized JIT authorization, and OpenBao credential injection.
2. **`ISOLATED_BROWSER` Mode**: An isolated containerized browser session running Chromium inside an Xvfb virtual frame buffer, streamed to the user's browser via WebSocket / noVNC, and recorded frame-by-frame via FFmpeg.

### End-to-End Architecture

```
User Browser (Authenticated via JWT)
  │
  │ 1. POST /api/v1/gateway/apps/{id}/session
  ▼
FastAPI Backend (Port 8000)
  │ 2. Authenticate user & verify roles (app/core/deps.py)
  │ 3. Resolve Application from registry (app/models/application.py)
  │ 4. Validate JIT authorization grant (JITService.validate())
  │ 5. Perform connection-time DNS & SSRF validation
  │ 6. Create Session record (Session.status = "STARTING")
  │ 7. Trigger dynamic upstream config sync OR launch isolated browser
  ▼
NGINX Gateway (Port 7000 / Custom GATEWAY_PORT)
  │
  ├─► STANDARD_PROXY Route: /gw/apps/{application_uuid}/...
  │     │ a. auth_request sub-request to /api/v1/gateway/internal/auth
  │     │ b. Backend validates session, active JIT grant, and pins destination IP
  │     │ c. Backend checks out application credentials from OpenBao (VaultRef)
  │     │ d. NGINX receives pinned IP via X-SecurePAM-Upstream-Target
  │     │ e. NGINX injects Authorization header from X-SecurePAM-Upstream-Authorization
  │     │ f. NGINX proxies directly to validated IP:port (closing DNS rebinding window)
  │     ▼
  │   Target Internal Web Application
  │
  └─► ISOLATED_BROWSER Route: /gw/apps/{application_uuid}/vnc/...
        │ a. auth_request validates session ownership & active JIT grant
        │ b. Upgraded WebSocket stream connects to Browser Isolation Daemon
        ▼
      Browser Isolation Daemon (Port 6080)
        ├─ Dedicated Xvfb display (:100+)
        ├─ Dedicated user profile dir (/tmp/browser_sessions/{session_id})
        ├─ Kiosk Chromium locked strictly to server-derived target URL
        ├─ websockify / x11vnc RFB WebSocket bridge
        └─ FFmpeg screen recorder writing to /data/recordings/session_{session_id}.mp4
```

---

## 2. Team Component Ownership & Boundaries

To avoid duplicate logic, Member 11 integrates with shared control-plane services across team members:

| Module / Area | Owner | Member 11 Scope & Integration Boundary |
|---|---|---|
| **Application Registry** | **Member 4** | Member 11 reads `Application` records (`hostname`, `port`, `protocol`, `access_mode`, `enabled`). Member 11 hooks upstream configuration generation on app create/update/delete. |
| **JIT Access Control** | **Member 7** | Member 11 invokes `JITService().validate()` as the single authoritative source. Member 11 does **not** implement duplicate approval or grant issuance logic. |
| **Credential Checkout** | **Member 8** | Member 11 extended `CredentialService.checkout()` with `application_id` to retrieve application credentials from OpenBao (`VaultRef`) and inject Basic/Bearer headers in NGINX. Member 11 does **not** manage vault storage engines. |
| **Sessions & Video Recording** | **Member 12** | Member 11 creates web gateway `Session` records, executes display recording via FFmpeg, and synchronizes finalized metadata (size, hash, duration) into Member 12's `recordings` table. Member 12 owns unified session listing and the playback streaming API (`GET /api/v1/recordings/{id}/stream`). |
| **Audit Logging** | **Member 13** | Member 11 emits standard audit events (`GATEWAY_SESSION_CREATED`, `GATEWAY_SESSION_ENDED`, `CREDENTIAL_CHECKED_OUT`) via `write_audit_log()`. |

---

## 3. Security Invariants

These invariants are enforced by code and verified by tests. They must **never** be weakened:

1. **Zero Open Proxy:** No `/proxy?url=<user-input>` endpoint exists. Upstream URLs are derived strictly server-side from registered `Application` database records.
2. **Per-Request JIT Authorization:** Every proxied request passes through NGINX `auth_request` (`GET /api/v1/gateway/internal/auth`). If a JIT grant lapses, expires, or is revoked, access is denied immediately with HTTP 403.
3. **SSRF Defense & IP Pinning:** Loopback, link-local, cloud metadata (`169.254.0.0/16`), unspecified, and multicast destinations are strictly denied. Destination IP is resolved and pinned server-side at connection time, passed via `X-SecurePAM-Upstream-Target`, and NGINX connects directly to the validated IP to prevent DNS rebinding.
4. **Client Header Sanitization:** Client-supplied `Authorization`, `X-Real-IP`, and `X-Forwarded-*` headers are stripped or authoritatively set by NGINX.
5. **Secret Masking:** Application credentials checked out from OpenBao are injected into upstream headers by NGINX; raw secrets are never returned in HTTP responses, logged in audit records, or exposed in error messages.
6. **Isolated Browser Sandboxing:** Chromium runs with an isolated profile directory per session, preventing cross-session cookie or local storage leakage. Terminating a session cleans up all child processes and deletes profile data.
7. **Control Plane Protection:** Internal control ports (NGINX `8081` and browser isolation `6080`) bind to `127.0.0.1` on the host and require a pre-shared `GATEWAY_AUTH_TOKEN`.
8. **Production Fail-Closed Validation:** When `ENVIRONMENT=production`, `validate_security_settings()` rejects default or short (<32 character) `GATEWAY_AUTH_TOKEN` values.

---

## 4. Prerequisites & Environment Configuration

### Prerequisites
- Docker Engine 24+ and Docker Compose v2.
- Python 3.13 virtual environment (`backend/.venv`).
- PostgreSQL 16 and Redis 7 (running via `docker compose up -d postgres redis`).

### Environment Variables
Configure the following in `backend/.env` (refer to `.env.example`):

```bash
# Gateway authentication secret: required, >= 32 characters of A-Z a-z 0-9 _ -.
# No default. While unset, NGINX and browser isolation refuse to start and the
# backend's auth hook rejects every request.
# Generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
GATEWAY_AUTH_TOKEN=

# Shared config directory for NGINX upstream blocks (mounted in docker-compose)
GATEWAY_CONFIG_DIR=/gateway-config

# NGINX internal control URL (used by backend to trigger config reloads)
GATEWAY_NGINX_CONTROL_URL=http://securepam-nginx-gateway:8081

# Browser Isolation Daemon URL
GATEWAY_BROWSER_ISOLATION_URL=http://browser-isolation:6080
BROWSER_ISOLATION_ENABLED=true

# Storage directory for FFmpeg screen recordings
RECORDING_STORAGE_PATH=/data/recordings

# Public Gateway Port override (Recommended on macOS to avoid AirPlay port 7000 conflict)
GATEWAY_PORT=17000
```

> [!WARNING]
> **macOS Port 7000 Conflict:** On macOS Monterey and later, Apple's AirPlay Receiver (`ControlCenter`) listens on port 7000 by default. To prevent `bind: address already in use` errors, set `GATEWAY_PORT=17000` in `.env` or pass it when running Docker Compose.

---

## 5. Local Setup & Running

### Starting Gateway Services
Start the backend, database, and the gateway profile containers:

```bash
# 1. Start core dependencies
docker compose up -d postgres redis

# 2. Start gateway profile (NGINX + Browser Isolation)
GATEWAY_PORT=17000 docker compose --profile gateway up -d
```

### Verifying Service Health

```bash
# Check running containers
docker compose --profile gateway ps

# Verify NGINX syntax and runtime configuration
docker exec securepam-nginx-gateway nginx -t

# Test NGINX health proxy route
curl -i http://localhost:17000/gw/test-health
# Expected: HTTP/1.1 200 OK {"status":"healthy", ...}
```

---

## 6. Core API Contracts

### A. Create Gateway Session
- **Endpoint:** `POST /api/v1/gateway/apps/{application_id}/session`
- **Headers:** `Authorization: Bearer <jwt_token>`
- **Response (201 Created):**
  ```json
  {
    "session_id": "c1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c",
    "session_number": "SES-20261013-0001",
    "application_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "application_name": "Internal Admin Portal",
    "launch_url": "/gw/apps/f47ac10b-58cc-4372-a567-0e02b2c3d479/_launch?ticket=c1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c.<single-use secret>",
    "protocol": "HTTP",
    "jit_validated": true,
    "jit_grant_id": "e8f1b2c3-d4e5-6f7a-8b9c-0d1e2f3a4b5c",
    "access_mode": "STANDARD_PROXY",
    "status": "STARTING",
    "created_at": "2026-10-13T07:00:00Z",
    "vnc_url": null,
    "recording_id": "a9b8c7d6-e5f4-3a2b-1c0d-9e8f7a6b5c4d"
  }
  ```
  The internal upstream URL is never returned. Open `launch_url` through the
  gateway within 60 seconds: the ticket is single-use, and redeeming it sets an
  HttpOnly, `SameSite=Strict` cookie (`securepam_gw`) scoped to
  `/gw/apps/{application_id}/`, then redirects into the application (or to
  `/vnc/` for `ISOLATED_BROWSER`, whose `vnc_url` is `/gw/apps/{application_id}/vnc/`).
  A session ID by itself grants nothing.

### A2. Launch (via NGINX only)
- **Gateway path:** `GET /gw/apps/{application_id}/_launch?ticket=...` → backend
  `GET /api/v1/gateway/apps/{application_id}/launch`. Not access-logged by NGINX.
- **Response:** `303 See Other` with `Set-Cookie: securepam_gw=...`, or `403`
  for an unknown, reused, expired or other-application ticket.

### B. Terminate Gateway Session
- **Endpoint:** `POST /api/v1/gateway/apps/{application_id}/session/{session_id}/terminate`
- **Headers:** `Authorization: Bearer <jwt_token>`
- **Response (200 OK):**
  ```json
  {
    "session_id": "c1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c",
    "status": "COMPLETED",
    "terminated_at": "2026-10-13T07:15:00Z",
    "recording_id": "a9b8c7d6-e5f4-3a2b-1c0d-9e8f7a6b5c4d"
  }
  ```

### C. Internal Auth Request Hook (NGINX sub-request)
- **Endpoint:** `GET /api/v1/gateway/internal/auth`
- **Headers:**
  - `X-Gateway-Auth-Token`: pre-shared secret
  - `X-SecurePAM-Gateway-Credential`: value of the `securepam_gw` cookie (set by NGINX from the cookie only)
  - `X-SecurePAM-App-ID`: application UUID from the URL (required)
- **Checks:** credential secret matches the stored hash, session belongs to that
  application and is live, owner is active, application is enabled, and the
  session's own JIT grant is still active.
- **Response:**
  - `HTTP 200 OK`: authorized. Emits `X-SecurePAM-Session-ID` (for NGINX's `/vnc/` routing), `X-SecurePAM-Upstream-Target: <ip>:<port>`, `X-SecurePAM-Upstream-Host: <host>`, and `X-SecurePAM-Upstream-Authorization: Basic/Bearer <token>`.
  - `HTTP 403 Forbidden`: unauthorized, expired, revoked, mismatched, or SSRF-denied.

---

## 7. Verification & Testing

### Running Member 11 Test Suites
Execute the full Member 11 test suite from `backend/`:

```bash
cd backend

# 1. Gateway routing, SSRF, IP pinning, and auth hook tests (68 tests)
.venv/bin/pytest tests/test_gateway_routing.py

# 2. Browser isolation daemon and service unit tests (7 tests)
.venv/bin/pytest tests/test_browser_isolation.py

# 3. OpenBao application credentials checkout & injection tests (9 tests)
.venv/bin/pytest tests/test_application_credentials.py

# 4. FFmpeg screen recording & Member 12 streaming tests (6 tests)
.venv/bin/pytest tests/test_session_recording.py

# 5. Production configuration hardening tests (4 tests)
.venv/bin/pytest tests/test_production_config.py

# Combined Member 11 suite (94 tests)
.venv/bin/pytest \
  tests/test_gateway_routing.py \
  tests/test_browser_isolation.py \
  tests/test_application_credentials.py \
  tests/test_session_recording.py \
  tests/test_production_config.py
```

### Running Cross-Member Regression Tests
Verify that Member 11 changes did not break adjacent modules (139 tests):

```bash
.venv/bin/pytest \
  tests/test_migrations.py \
  tests/test_security_hardening.py \
  tests/test_credential_service.py \
  tests/test_session_endpoints.py \
  tests/test_applications.py
```

---

## 8. Detailed Documentation Links

For component-specific configurations, internals, and troubleshooting, consult:
- **[NGINX Gateway Detailed Guide](nginx/README.md):** Configuration templates, upstream dynamic includes, reload watcher, header transformations, and reverse proxy troubleshooting.
- **[Browser Isolation & Recording Guide](browser-isolation/README.md):** Chromium sandboxing, Xvfb display management, websockify noVNC streaming, FFmpeg display grab, and Firecracker microVM migration blueprint.
