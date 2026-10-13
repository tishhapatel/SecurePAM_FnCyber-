# SecurePAM Browser Isolation & Session Recording Guide

**Component:** Isolated Browser Execution & Screen Capture Daemon  
**Container:** `securepam-browser-isolation`  
**Base Image:** `alpine:3.20`  
**Source Code:** [server.py](server.py)  
**Dockerfile:** [Dockerfile](Dockerfile)

---

## 1. Overview & Architecture

The SecurePAM Browser Isolation Daemon provides container-level sandboxing for web application sessions flagged as `ISOLATED_BROWSER` in the application registry.

### Core Capabilities:
1. **Sandboxed Browser Session:** Launches a dedicated Chromium browser inside an Xvfb virtual frame buffer for each authorized user session.
2. **Strict Destination Locking:** Chromium starts in kiosk mode pointing strictly to the server-side authorized application URL; the user has no URL bar, navigation bar, or capability to navigate to arbitrary external sites.
3. **Multi-Session Profile Isolation:** Each session receives a distinct Chromium profile and cache directory (`/tmp/browser_sessions/{session_id}`). Cookies, localStorage, credentials, and cache are strictly isolated between concurrent sessions.
4. **WebSocket noVNC Streaming:** Streams display updates to the user's browser via x11vnc and websockify.
5. **Frame-by-Frame Screen Recording:** Records display activity via FFmpeg and synchronizes video metadata with Member 12's `recordings` subsystem.

```
Client Browser
      │
      ▼
NGINX Gateway (/gw/apps/{app_id}/vnc/?session_id={session_id})
      │ (auth_request validates active session + JIT grant)
      ▼
Browser Isolation Daemon (Port 6080)
      │
      ├── Process Group Manager
      │     ├─ Xvfb (:100+)               ── Virtual framebuffer (1280x800x24)
      │     ├─ Chromium (--kiosk)         ── Locked to registered target_url
      │     │                                Isolated user-data-dir: /tmp/browser_sessions/{id}
      │     ├─ x11vnc (:100 -> :5900+)    ── VNC server bound to local display
      │     └─ websockify (:6080 -> :5900)── RFB over WebSocket bridge
      │
      └── Screen Recording Subsystem
            └─ FFmpeg (x11grab :100.0)    ── Records to /data/recordings/session_{id}.mp4
```

---

## 2. Daemon Management API (Port 6080)

All management endpoints require the header `X-Gateway-Auth-Token: <token>` (or `Authorization: Bearer <token>`) matching `settings.GATEWAY_AUTH_TOKEN`.

### A. Launch Session (`POST /sessions/launch`)
- **Payload:**
  ```json
  {
    "session_id": "c1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c",
    "application_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "target_url": "http://internal-app.local:8080/dashboard"
  }
  ```
- **Lifecycle Actions:**
  1. Validates that `session_id` is a clean UUID (blocking path traversal).
  2. Allocates a unique display number (`:100`, `:101`, etc.).
  3. Spawns `Xvfb :display -screen 0 1280x800x24`.
  4. Launches `ffmpeg -y -f x11grab -draw_mouse 1 -video_size 1280x800 -framerate 15 -i :display.0 -c:v libx264 -pix_fmt yuv420p -preset ultrafast -crf 28 /data/recordings/session_{session_id}.mp4`.
  5. Launches Chromium kiosk pointing strictly to `target_url`:
     ```bash
     chromium --no-sandbox --kiosk --no-first-run --no-default-browser-check \
              --disable-extensions --disable-popup-blocking \
              --user-data-dir=/tmp/browser_sessions/{session_id} \
              --window-size=1280,800 "target_url"
     ```
  6. Spawns `x11vnc -display :display -forever -shared -nopw -rfbport <port>`.
  7. Spawns `websockify --web /usr/share/novnc 6080 localhost:<rfbport>`.
- **Response (200 OK):**
  ```json
  {
    "status": "RUNNING",
    "session_id": "c1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c",
    "display": ":100",
    "vnc_path": "/gw/apps/f47ac10b-58cc-4372-a567-0e02b2c3d479/vnc/?session_id=c1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c"
  }
  ```

### B. Terminate Session (`POST /sessions/{session_id}/terminate`)
- **Lifecycle Actions:**
  1. Sends `SIGINT` to FFmpeg process and waits up to 3.0 seconds for clean MP4 `moov` atom trailer write. If unclosed, terminates with `SIGTERM`.
  2. Verifies output file existence, calculates file size, duration, and SHA-256 hash.
  3. Sends `SIGTERM` to `chromium`, `x11vnc`, `websockify`, and `Xvfb`.
  4. Recursively deletes `/tmp/browser_sessions/{session_id}`.
  5. Removes session from the in-memory `ACTIVE_SESSIONS` registry.
- **Response (200 OK):**
  ```json
  {
    "status": "TERMINATED",
    "session_id": "c1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c",
    "recording": {
      "status": "COMPLETED",
      "file_path": "/data/recordings/session_c1a2b3c4-d5e6-7f8a-9b0c-1d2e3f4a5b6c.mp4",
      "file_size": 245892,
      "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "duration_seconds": 45
    }
  }
  ```

### C. Session Status (`GET /sessions/{session_id}/status`)
- Returns liveness details, display number, and start timestamp.

### D. Health Check (`GET /health`)
- Unauthenticated liveness check returning `{"status": "ok"}`. Used by Docker Compose healthcheck.

---

## 3. Screen Recording & Member 12 Integration

Screen recording is tightly integrated with Member 12's session audit and video playback services:

1. **Shared Volume Mount:** The shared Docker volume `recording_data` is mounted at `/data/recordings` in both `securepam-browser-isolation` and `securepam-backend`.
2. **Database Record Lifecycle:**
   - **On Session Launch:** Backend creates a `Recording` row with `status="PENDING"`, `recording_type="VIDEO"`, and `file_path="/data/recordings/session_{session_id}.mp4"`.
   - **On Session Active:** Status transitions to `RECORDING`.
   - **On Session Termination:** Backend updates the `Recording` row with `status="COMPLETED"`, `file_size`, `file_hash`, and `duration_seconds`.
3. **Playback Streaming API (Member 12):**
   - Playback endpoint: `GET /api/v1/recordings/{id}/stream`.
   - Enforces RBAC (`recordings:read` permission required).
   - Validates paths against traversal attacks (only files inside `RECORDING_STORAGE_PATH` are served).
   - Records an audit log entry (`RECORDING_VIEWED`) on playback access.

---

## 4. PoC Process Isolation vs. Production Hypervisor Isolation

### What IS Isolated in this PoC:
- **Process Trees:** Each session executes under a distinct process tree with its own X11 display.
- **Filesystem / Profile:** Dedicated `/tmp/browser_sessions/{session_id}` user profile directory per session, cleaned up on exit.
- **Network Routing:** Display stream is multiplexed over distinct RFB ports and gated by NGINX `auth_request`.
- **Target URL:** User cannot navigate to arbitrary domains outside the pre-authorized target application.

### Outstanding Infrastructure Limitation (Why Firecracker is Blocked):
- **Environmental Constraint:** Standard macOS ARM64 development hosts running Docker Desktop lack access to nested `/dev/kvm` hardware virtualization.
- **Classification:** Marked **`BLOCKED (INFRASTRUCTURE DEPENDENCY)`** for bare-metal Linux.

### Production Architecture Plan (Linux Bare-Metal Host):
For release in high-security multi-tenant production environments:
1. **Target Infrastructure:** Deploy on bare-metal Linux (kernel 5.10+) with `/dev/kvm` hardware virtualization (e.g. AWS `c5.metal` or `c6g.metal`).
2. **MicroVM Per Session:** Replace container process launching with Firecracker microVMs:
   - Ephemeral microVM boots in ~120ms with ~5MB RAM baseline.
   - Read-only base rootfs with copy-on-write `tmpfs` overlay destroyed upon exit.
   - Ephemeral `tap` network device per VM with strict egress iptables (allowing access strictly to target application IP).
   - Video recording output streamed back to the host via `virtio-vsock`.

---

## 5. Troubleshooting & Diagnostics

### Issue 1: Black Screen or VNC Disconnect
- **Symptom:** noVNC connects but displays a black screen or immediately drops.
- **Check:**
  1. Verify Chromium started successfully:
     ```bash
     docker exec securepam-browser-isolation ps aux | grep -E "chromium|Xvfb"
     ```
  2. Verify that the target web application is reachable from inside the container:
     ```bash
     docker exec securepam-browser-isolation curl -I http://target-app:8080
     ```

### Issue 2: Zero-Byte or Corrupted MP4 Files
- **Symptom:** Finalized recording has `file_size: 0` or fails to play.
- **Cause:** FFmpeg was killed forcefully (`SIGKILL`) before writing the MP4 `moov` atom trailer.
- **Check:** Ensure the daemon's graceful `SIGINT` flush (3.0s grace period) in `server.py` executed cleanly without timeout expiration.

### Issue 3: Permission Denied on `/data/recordings`
- **Symptom:** FFmpeg logs `Permission denied` when opening output file.
- **Check:** Verify volume permissions:
  ```bash
  docker exec securepam-browser-isolation ls -ld /data/recordings
  ```
  Ensure the directory is writable by the container's runtime user.
