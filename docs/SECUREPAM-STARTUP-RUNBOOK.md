# SecurePAM startup and status runbook

Two commands, from the project root (`~/Documents/SecurePAM`):

```bash
./scripts/start-securepam.sh      # start whatever is not running, then print the status table
./scripts/status-securepam.sh     # read-only health report (changes nothing)
```

Useful options: `start-securepam.sh --dry-run` (print exactly what would be started, change nothing),
`--no-unseal-prompt` (never offer the interactive OpenBao unseal), `status-securepam.sh --no-color`.
Both are written for macOS system bash 3.2 on Apple Silicon. The status script exits `0` only when every managed
component is healthy.

**First time on a new boot or after changes: run `./scripts/start-securepam.sh --dry-run` first.** On a healthy system
it plans nothing; on a cold start it lists the exact order of actions.

## What "healthy" means here

A component is `healthy` only when it gives a real answer, never because a port is open:

| Component | Check |
|---|---|
| Docker engine | `docker info` returns a server version |
| PostgreSQL / Redis (Homebrew) | `pg_isready` accepts connections on 5432 / Redis answers `PONG` on 6379 |
| OpenBao staging | `https://127.0.0.1:18210/v1/sys/seal-status`, verified against `~/.securepam/openbao/tls/ca.crt`: initialized and **not sealed** |
| Keycloak (+ its DB container) | container running and healthy, and `http://localhost:8080/realms/securepam` returns HTTP 200 |
| Guacamole DB / guacd / Guacamole | DB container healthy; guacd healthy and accepting on 4822; `http://127.0.0.1:8081/guacamole/` returns 200 |
| Browser isolation | container running and the daemon's `GET /health` (port 6090) reports `ok: true` |
| Backends 8001 / 8002 | the listener is *this project's* uvicorn on that port, `GET /health/ready` returns `ready` with database and Redis healthy, and `/api/v1/auth/config` reports the expected mode (8001 `dev_mode=true`, 8002 `dev_mode=false`) |
| Frontends 3001 / 3002 | the listener is *this project's* vite on that port, the app page loads (`id="root"`), and its `VITE_API_URL` points at 8001 / 8002 respectively |

States: `healthy`, `stopped`, `sealed` (OpenBao running but needs unseal shares), `degraded` (running but failing a real
check, or a port conflict), `unknown` (cannot tell, e.g. a container that does not exist).

## The two application pairs (verified launch commands)

Both run from the project root, load `backend/.env` through the application's own settings, and log to
`~/.securepam/`. There were no launch scripts before; these commands mirror the processes that were verified running.

| Pair | Process | Command | Inline environment (non-secret) |
|---|---|---|---|
| 8001 / 3001 (dev login) | backend | `backend/.venv/bin/python backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8001 --app-dir backend` | `SECRET_PROVIDER=openbao`, `OPENBAO_ADDR=https://127.0.0.1:18210`, `OPENBAO_CA_CERT=~/.securepam/openbao/tls/ca.crt`, `OPENBAO_TOKEN_FILE` / `OPENBAO_WRITER_TOKEN_FILE` = `~/.securepam/openbao/tokens/staging-reader-token` / `staging-writer-token`, `REDIS_URL=redis://127.0.0.1:6379/0`, recording and RDP paths under `~/securepam-data`, `SECUREPAM_KNOWN_HOSTS_PATH=~/securepam-data/ssh/known_hosts`, `GUACD_HOST/PORT`, `GUACAMOLE_URL`, browser-isolation settings, `KEYCLOAK_INTERNAL_URL`, CORS for 3001 |
| | frontend | `npm run dev -- --port 3001 --strictPort` in `frontend/` | `VITE_API_URL=http://localhost:8001` |
| 8002 / 3002 (Keycloak MFA) | backend | same command with `--port 8002` | as above, plus `DEV_MODE=false`, `KEYCLOAK_URL=http://localhost:8080`; **OpenBao = `http://127.0.0.1:18200` with `~/.securepam/openbao-app-token` / `openbao-writer-token`** (see "Known caveats"); CORS for 3002 |
| | frontend | `npm run dev -- --port 3002 --strictPort` in `frontend/` | `VITE_API_URL=http://localhost:8002` |

`node`/`npm` come from `~/Library/pnpm` (the scripts put it on `PATH`). Database and Keycloak client settings come from
`backend/.env`, which the scripts never read, print or change.

## Startup order and what is touched

1. **Preflight (read-only):** macOS/arch, not root, required files exist (venv, `node_modules`, `.env`, token files, CA,
   known_hosts, recording dir), and ports 8001/8002/3001/3002 are free or owned by this project. If a port is held by
   anything else the run stops before changing anything and the process is **not** killed.
2. **Docker Desktop:** launched with `open -a Docker` only if the engine is down; waits up to 4 minutes.
3. **Homebrew services:** `postgresql@16` and `redis`, started with `brew services start` only if Homebrew says they are
   stopped. A service that Homebrew says is started but is not answering is reported, never restarted.
4. **Existing Docker containers, `docker start` only:**
   `securepam-keycloak-postgres`, `guacamole-guac-postgres-1`, `guacamole-guacd-1`, `browser-isolation-browser-isolation-1`,
   then `securepam-keycloak` and `guacamole-guacamole-1` once their databases are healthy. Keycloak and its DB have restart
   policy `no`, so after a Docker or Mac restart they always need this step; the other four come back by themselves
   (`unless-stopped`). A container that does not exist is an error: the scripts never create, recreate, rebuild or remove one.
5. **OpenBao:** the existing LaunchAgent `local.securepam.openbao` (`~/Library/LaunchAgents/…plist`) is loaded
   (`launchctl bootstrap`) or started (`launchctl kickstart`, no `-k`) only if it is not running. See "OpenBao is sealed".
6. **Backends, then frontends**, each only if its port is free; waits for the real health check.
7. **Status table** (the same code as `status-securepam.sh`).

Never touched: healthy services, `.env` files, ports, configuration, migrations/init/provisioning, git, packages,
permissions, anything on ports **3000/8000** (a different project), and the earlier Docker trial stack
(`securepam-backend`, `securepam-frontend`, `securepam-postgres`, `securepam-redis`, `securepam-guacd`,
`securepam-guacamole`, `securepam-openbao`, `securepam-openbao-init`), which the two host application pairs do not use.

## After a Mac restart: what comes back by itself

| Comes back automatically | Needs `start-securepam.sh` |
|---|---|
| Homebrew PostgreSQL and Redis (launchd) | Docker Desktop launch (if not set to start at login) |
| OpenBao LaunchAgent, **but sealed** | Keycloak DB + Keycloak containers (restart policy `no`) |
| Guacamole stack and browser-isolation containers (once Docker is up) | OpenBao **unseal** (your shares) |
| | The four application processes (3001, 8001, 3002, 8002) |

## OpenBao is sealed

After every restart OpenBao starts sealed and SecurePAM fails closed for credential retrieval until it is unsealed.
Staging is a Shamir seal with **3 shares, threshold 2**; only you hold the shares (never store them in this repo, on this
disk beside the data, or in a snapshot folder).

When the start script finds it sealed and is running in a terminal it asks `Enter unseal shares now? [y/N]` and then runs
the OpenBao CLI's own `bao operator unseal`, which prompts with hidden input. The script never sees, stores or logs a share.
To do it yourself (or after `--no-unseal-prompt` / a non-interactive run):

```bash
export BAO_ADDR=https://127.0.0.1:18210 BAO_CACERT=$HOME/.securepam/openbao/tls/ca.crt
bao operator unseal      # hidden prompt - repeat with a DIFFERENT share until Sealed is false
bao status
```

If OpenBao reports **not initialized**, the start script stops. Do not initialize: that would mean its storage was lost.
Use `~/.securepam/openbao/RUNBOOK.md` and the Raft snapshot in `~/securepam-backups/`.

## Port conflicts

If something other than this project's backend/frontend owns 8001, 8002, 3001 or 3002, the script prints the pid and
command and exits without killing anything. Free the port yourself (or stop that process on purpose), then re-run.

## Logs

`~/.securepam/backend-8001.log`, `backend-8002.log`, `frontend-3001.log`, `frontend-3002.log`; OpenBao:
`~/.securepam/openbao/logs/openbao.log`; containers: `docker logs <name>`.

## Known caveats and unknowns

- **Backend 8002 uses the OpenBao dev instance on `127.0.0.1:18200`** (in-memory, started by hand with `bao server -dev`,
  with the old token files). That instance is not managed by these scripts and does not survive a reboot, so after a restart
  8002's credential retrieval is unavailable (its login through Keycloak is unaffected). The start script reproduces 8002's
  existing configuration unchanged. Moving 8002 to the staging OpenBao is a configuration change for you to decide; the status
  table shows the dev instance's state on its own row.
- The application launch commands were reconstructed from the verified running processes and saved launch records
  (`~/securepam-backups/pre-activation-*/addendum-config/launch/`); no earlier script existed. Anything exported in your
  shell is inherited by the processes the script starts (as it was when they were started by hand).
- The scripts assume the project at `~/Documents/SecurePAM`, Homebrew formulas `postgresql@16` and `redis`, and the container
  names above. A missing file or container stops the run with a message; nothing is created.
- Keycloak can take about a minute to answer after its container starts; the script waits up to 150 s.
- The dev login (3001) is for the local demo only. The status check for 8001 expects `dev_mode=true` and for 8002 `dev_mode=false`;
  a mismatch is reported as `degraded`.
- Not covered: backups (see `~/securepam-backups/pre-activation-*/RESTORE.md` and `RESTORE-ADDENDUM.md`), stopping services,
  rebuilding images, and migrations.

## Quick troubleshooting

| Status row | Meaning / next step |
|---|---|
| OpenBao `sealed` | Unseal as above. |
| OpenBao `stopped` | `launchctl print gui/$(id -u)/local.securepam.openbao`; check `~/.securepam/openbao/logs/openbao.log`. |
| Keycloak `degraded` right after start | Still starting; re-run `status-securepam.sh` in a minute. |
| Backend `degraded` with `PORT CONFLICT` | Another process owns the port; the scripts will not kill it. |
| Backend `degraded` with `/health/ready=…` | A dependency (database/Redis) is failing; check PostgreSQL/Redis rows and the backend log. |
| Frontend `degraded` with a `VITE_API_URL` mismatch | The frontend was started by hand against a different API; it was left as is. |
| Any container `unknown` | The container does not exist; it must be recreated deliberately (compose files under `infrastructure/` and the root `docker-compose*.yml`), not by these scripts. |
