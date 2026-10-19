# SecurePAM — Implementation Action Plan & Engineering Task Backlog

Generated from the evidence-based project audit on 19 October 2026.

---

## Priority 0 (P0) — Critical Infrastructure & Execution Blockers

- [ ] **TASK-01: Local PostgreSQL & Redis Infrastructure for Windows Development**
  - **Goal:** Enable local execution of the backend FastAPI application and the 52 backend integration test suites.
  - **Action Required:**
    1. Install Docker Desktop for Windows or install native Windows services for PostgreSQL 16 and Redis 7.
    2. Create dedicated database instances: `securepam` (development) and `securepam_test` (automated test runner).
    3. Verify connection strings in `.env`:
       ```env
       DATABASE_URL=postgresql+asyncpg://securepam:securepam_dev_password@localhost:5432/securepam
       REDIS_URL=redis://localhost:6379/0
       ```
  - **Affected Files:** `docker-compose.yml`, `backend/tests/conftest.py`.

- [ ] **TASK-02: Backend Integration Test Suite Execution & Baseline Validation**
  - **Goal:** Execute and record passing baseline across all 52 backend test files.
  - **Action Required:**
    1. Activate Python virtual environment.
    2. Run `pytest -v` from `backend/`.
    3. Document any failing tests or database race conditions.
  - **Affected Files:** `backend/tests/*.py`.

---

## Priority 1 (P1) — Core Feature Gaps & Protocol Enhancements

- [ ] **TASK-03: Implement Isolated Browser Screen Recording**
  - **Goal:** Allow browser isolation sessions that require session recording to proceed safely instead of returning HTTP 400 `RECORDING_UNAVAILABLE`.
  - **Action Required:**
    1. Update `infrastructure/browser-isolation/daemon.py` to launch an FFmpeg subprocess capturing `:display` to an `.mp4` / `.webm` container.
    2. On session termination, compute SHA-256 digest and move the recording file to `~/securepam-data/recordings/web/<session_id>/`.
    3. Update `backend/app/api/v1/web_sessions.py:112` to allow recording-required sessions.
  - **Affected Files:** `infrastructure/browser-isolation/daemon.py`, `backend/app/api/v1/web_sessions.py`.

- [ ] **TASK-04: Enforce RDP TLS Host Certificate Validation**
  - **Goal:** Eliminate `RDP_IGNORE_CERT=true` in production to prevent MITM attacks against RDP gateways.
  - **Action Required:**
    1. Update Guacamole connection parameters in `backend/app/services/guacamole.py` to enforce certificate thumbprint pinning or CA trust validation.
    2. Make certificate verification mandatory when `ENVIRONMENT=production`.
  - **Affected Files:** `backend/app/core/config.py`, `backend/app/services/guacamole.py`.

- [ ] **TASK-05: Reconcile Decoupled Policy Engine**
  - **Goal:** Unify the two distinct policy evaluators (`policy-engine/` package vs `backend/app/policies/evaluator.py`).
  - **Action Required:**
    1. Either package and install `securepam-member5-policy-engine` into `backend/requirements.txt` and replace `backend/app/policies/evaluator.py` with the package import;
    2. Or remove the decoupled `policy-engine/` folder and consolidate all 101 tests into `backend/tests/test_policy_engine.py`.
  - **Affected Files:** `policy-engine/`, `backend/app/policies/evaluator.py`, `backend/requirements.txt`.

---

## Priority 2 (P2) — Security Hardening, Lints & Tooling

- [ ] **TASK-06: Fix Frontend Linting & Resolve Vulnerable Packages**
  - **Goal:** Restore `npm run lint` functionality and resolve critical prototype pollution advisories.
  - **Action Required:**
    1. Add `eslint` and plugins to `frontend/package.json`:
       ```bash
       npm install --save-dev eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin
       ```
    2. Run `npm audit fix` to address vulnerability alerts.
  - **Affected Files:** `frontend/package.json`, `frontend/package-lock.json`.

- [ ] **TASK-07: Configure Persistent SIEM Event Sink and Keycloak MFA Sync**
  - **Goal:** Enable continuous security telemetry export for Wazuh and active brute-force MFA detection.
  - **Action Required:**
    1. Set `SIEM_EVENT_LOG_PATH=/data/logs/securepam-siem.json` in `.env`.
    2. Enable `KEYCLOAK_MFA_SYNC_ENABLED=true` when running with Keycloak.
  - **Affected Files:** `backend/app/core/config.py`, `docker-compose.yml`.

- [ ] **TASK-08: Fix Python Static Analysis Cleanliness Warnings**
  - **Goal:** Clean up Flake8 warnings.
  - **Action Required:**
    1. Remove unused `nonlocal final_status` in `backend/app/api/v1/rdp_sessions.py:320`.
    2. Remove unused `ticket_data` in `backend/app/api/v1/ssh_sessions.py:605`.
  - **Affected Files:** `backend/app/api/v1/rdp_sessions.py`, `backend/app/api/v1/ssh_sessions.py`.

---

## Priority 3 (P3) — Cleanliness, Scripts & Polish

- [ ] **TASK-09: Remove Unused Frontend Placeholder Component**
  - **Goal:** Eliminate dead code.
  - **Action Required:** Delete `frontend/src/pages/ComingSoon.tsx`.
  - **Affected Files:** `frontend/src/pages/ComingSoon.tsx`.

- [ ] **TASK-10: Create Windows-Native Startup & Status Automation**
  - **Goal:** Enable Windows users to start and check platform health without bash/macOS requirements.
  - **Action Required:**
    1. Author `scripts/start-securepam.ps1` and `scripts/status-securepam.ps1`.
  - **Affected Files:** `scripts/start-securepam.ps1`, `scripts/status-securepam.ps1`.
