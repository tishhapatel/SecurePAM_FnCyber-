#!/bin/bash
# start-securepam.sh - bring the existing SecurePAM environment up, idempotently and without side effects
# beyond starting things that are STOPPED.
#
#   ./scripts/start-securepam.sh                 start whatever is not running, then print the status table
#   ./scripts/start-securepam.sh --dry-run       change nothing; print exactly what would be started
#   ./scripts/start-securepam.sh --no-unseal-prompt   never offer to unseal OpenBao interactively
#
# What it does (in order): preflight -> Docker Desktop (only if the engine is down) -> Homebrew PostgreSQL/Redis
# (only if stopped) -> existing Docker containers (docker start only) -> OpenBao LaunchAgent + guided unseal ->
# backends 8001/8002 -> frontends 3001/3002 -> status table.
#
# What it never does: recreate/remove/rebuild containers, docker compose, prune, kill any process, restart a
# healthy service, touch .env files/ports/configuration, run migrations/init/provisioning, install anything, use
# git, or touch ports 3000/8000 (another project). OpenBao unseal shares are typed at the bao CLI's own hidden
# prompt; this script never sees, stores or logs them.
#
# Every state change goes through act() so --dry-run is exact. Written for macOS system bash 3.2.

set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=status-securepam.sh
. "$SCRIPT_DIR/status-securepam.sh"      # health-check functions; running it sourced prints nothing

SP_DRY=0
SP_NO_UNSEAL=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) SP_DRY=1;;
    --no-unseal-prompt) SP_NO_UNSEAL=1;;
    -h|--help) sed -n '2,19p' "${BASH_SOURCE[0]}"; exit 0;;
    *) echo "unknown option: $arg (see --help)" >&2; exit 2;;
  esac
done

LOG_DIR="$HOME/.securepam"
LOCK_DIR="${TMPDIR:-/tmp}/securepam-start.lock"
LOCK_MINE=0

# --- output ------------------------------------------------------------------------------------------------
c() { if [ "$SP_COLOR" = 1 ]; then printf '\033[%sm%s\033[0m' "$1" "$2"; else printf '%s' "$2"; fi; }
info() { printf '  %s %s\n' "$(c 90 '..')" "$*"; }
ok()   { printf '  %s %s\n' "$(c 32 'OK')" "$*"; }
warn() { printf '  %s %s\n' "$(c 33 '!!')" "$*"; }
step() { printf '\n%s\n' "$(c 1 "== $*")"; }
fail() { printf '  %s %s\n' "$(c 31 'XX')" "$*" >&2; exit 1; }

cleanup() { if [ "$LOCK_MINE" = 1 ]; then rm -f "$LOCK_DIR/pid"; rmdir "$LOCK_DIR" 2>/dev/null || true; fi; }
trap cleanup EXIT
trap 'echo; echo "interrupted - nothing was killed; services already started keep running"; exit 130' INT TERM

# The ONLY way this script changes anything.
act() { local desc="$1"; shift
  if [ "$SP_DRY" = 1 ]; then info "[dry-run] would: $desc"; return 0; fi
  info "$desc"; "$@"; }

wait_until() { # <label> <seconds> <check fn + args>; success when CHK_STATE=healthy
  local label="$1" secs="$2" i=0; shift 2
  [ "$SP_DRY" = 1 ] && return 0
  while [ "$i" -lt "$secs" ]; do
    "$@"; [ "$CHK_STATE" = healthy ] && return 0
    sleep 2; i=$((i+2))
  done
  warn "$label did not become healthy within ${secs}s: $CHK_DETAIL"; return 1
}

# --- lock (a temporary resource created and removed by this script only) -------------------------------------
acquire_lock() {
  [ "$SP_DRY" = 1 ] && return 0
  if mkdir "$LOCK_DIR" 2>/dev/null; then echo $$ > "$LOCK_DIR/pid"; LOCK_MINE=1; return 0; fi
  local old; old="$(cat "$LOCK_DIR/pid" 2>/dev/null)"
  if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then fail "another start-securepam.sh is already running (pid $old)"; fi
  rm -f "$LOCK_DIR/pid"; rmdir "$LOCK_DIR" 2>/dev/null || true       # stale lock from a crashed earlier run
  mkdir "$LOCK_DIR" 2>/dev/null || fail "could not take the start lock at $LOCK_DIR"
  echo $$ > "$LOCK_DIR/pid"; LOCK_MINE=1
}

# --- 0. preflight (read-only) ----------------------------------------------------------------------------------
preflight() {
  step "Preflight"
  [ "$(uname -s)" = Darwin ] || fail "this tooling is for macOS (found $(uname -s))"
  [ "$(uname -m)" = arm64 ] || warn "not Apple Silicon ($(uname -m)); the verified setup is arm64"
  [ "$(id -u)" -ne 0 ] || fail "do not run as root"
  local missing="" f
  for f in "$SP_ROOT/backend/.venv/bin/python" "$SP_ROOT/backend/.venv/bin/uvicorn" "$SP_ROOT/backend/.env" \
           "$SP_ROOT/frontend/node_modules/.bin/vite" "$SP_ROOT/infrastructure/browser-isolation/.isolation_token" \
           "$SP_OB_CA" "$SP_OB_DIR/tokens/staging-reader-token" "$SP_OB_DIR/tokens/staging-writer-token" \
           "$HOME/.securepam/openbao-app-token" "$HOME/.securepam/openbao-writer-token" \
           "$HOME/securepam-data/ssh/known_hosts" "$HOME/securepam-data/recordings/rdp" "$LOG_DIR"; do
    [ -e "$f" ] || missing="$missing
    ~${f#$HOME}"
  done
  command -v npm >/dev/null 2>&1 || missing="$missing
    npm (not on PATH: looked in ~/Library/pnpm, /opt/homebrew/bin, /usr/local/bin)"
  command -v brew >/dev/null 2>&1 || missing="$missing
    brew"
  [ -z "$missing" ] || fail "required files are missing (nothing is created or changed):$missing"
  ok "macOS $(sw_vers -productVersion 2>/dev/null) $(uname -m); launch files, venv, node_modules and token files present"
  # Port ownership BEFORE starting anything: an unexpected owner aborts the whole run untouched.
  local p pid
  for p in 8001 8002; do pid="$(port_pid $p)"
    [ -z "$pid" ] || owner_is_backend "$pid" "$p" || fail "PORT CONFLICT on $p: pid $pid ($(pid_cmd "$pid")) is not this project's backend. Not killing it. Free the port, then re-run."
  done
  for p in 3001 3002; do pid="$(port_pid $p)"
    [ -z "$pid" ] || owner_is_frontend "$pid" "$p" || fail "PORT CONFLICT on $p: pid $pid ($(pid_cmd "$pid")) is not this project's frontend. Not killing it. Free the port, then re-run."
  done
  ok "ports 8001/8002/3001/3002 are free or owned by this project (3000/8000 belong to another project and are never touched)"
}

# --- 1. Docker Desktop -----------------------------------------------------------------------------------------
phase_docker() {
  step "Docker"
  chk_docker
  if [ "$CHK_STATE" = healthy ]; then ok "engine already running ($CHK_DETAIL)"; return; fi
  [ -d /Applications/Docker.app ] || fail "Docker engine is down and /Applications/Docker.app is not installed"
  act "launch Docker Desktop and wait for the engine (up to 4 min)" open -a Docker
  wait_until "Docker engine" 240 chk_docker || fail "Docker engine did not come up; open Docker Desktop manually and re-run"
  [ "$SP_DRY" = 1 ] || ok "engine ready ($CHK_DETAIL)"
}

# --- 2. Homebrew PostgreSQL / Redis ------------------------------------------------------------------------------
brew_start() { brew services start "$1" >/dev/null; }
ensure_brew() { # <formula> <check fn> <label>
  local formula="$1" check="$2" label="$3" st
  "$check"
  if [ "$CHK_STATE" = healthy ]; then ok "$label already running"; return; fi
  brew_refresh; st="$(brew_status "$formula")"
  case "$st" in
    none|stopped) act "start Homebrew service $formula" brew_start "$formula"
                  wait_until "$label" 60 "$check" && { [ "$SP_DRY" = 1 ] || ok "$label is up"; } || fail "$label did not become healthy; see: brew services info $formula";;
    started)      warn "$label: brew says '$formula' is started but it is not answering - NOT restarting it (check its log)";;
    *)            fail "$label: unexpected Homebrew state '$st' for '$formula'";;
  esac
}
phase_brew() { step "PostgreSQL and Redis (Homebrew)"
  ensure_brew "$SP_BREW_PG" chk_postgres "PostgreSQL"
  ensure_brew "$SP_BREW_REDIS" chk_redis "Redis"
}

# --- 3. existing Docker containers (docker start only) -----------------------------------------------------------
docker_start() { docker start "$1" >/dev/null; }
start_if_stopped() { # <container>
  local name="$1"; chk_container "$name"
  case "$CHK_STATE" in
    healthy)  ok "$name already running";;
    stopped)  act "docker start $name" docker_start "$name" || fail "could not start $name";;
    degraded) warn "$name is running but not fully healthy ($CHK_DETAIL) - not touching it";;
    unknown)  fail "container '$name' does not exist. This tooling never creates containers (see docs/SECUREPAM-STARTUP-RUNBOOK.md).";;
  esac
}
phase_containers() {
  step "Docker containers (existing ones only)"
  chk_docker
  if [ "$CHK_STATE" != healthy ]; then
    if [ "$SP_DRY" = 1 ]; then info "[dry-run] Docker is down: the container steps below would run after the engine is up"; return; fi
    fail "Docker engine is not running"
  fi
  # independent ones first, then those that need a healthy database
  start_if_stopped securepam-keycloak-postgres
  start_if_stopped guacamole-guac-postgres-1
  start_if_stopped guacamole-guacd-1
  start_if_stopped browser-isolation-browser-isolation-1
  wait_until "Keycloak DB" 90 chk_keycloak_db || true
  start_if_stopped securepam-keycloak
  wait_until "Guacamole DB" 90 chk_guac_db || true
  start_if_stopped guacamole-guacamole-1
  [ "$SP_DRY" = 1 ] && return
  info "waiting for each service to actually answer (Keycloak can take about a minute)"
  wait_until "guacd"              60  chk_guacd      && ok "guacd answers on 4822"        || true
  wait_until "Guacamole"          90  chk_guacamole  && ok "Guacamole web app answers"    || true
  wait_until "Browser isolation"  45  chk_isolation  && ok "isolation daemon /health ok"  || true
  wait_until "Keycloak"          150  chk_keycloak   && ok "Keycloak realm 'securepam' answers" || true
}

# --- 4. OpenBao (existing LaunchAgent; never initialized by this script) -----------------------------------------
unseal_openbao() {
  info "OpenBao is SEALED. It needs $OB_T of $OB_N unseal shares; only you hold them."
  info "Shares are typed at the bao CLI's own hidden prompt - this script never sees, stores or logs them."
  if [ "$SP_DRY" = 1 ]; then info "[dry-run] would offer the interactive unseal here"; return 0; fi
  if [ ! -t 0 ] || [ ! -t 1 ] || [ "$SP_NO_UNSEAL" = 1 ]; then
    warn "not unsealing from this run. When ready, in a terminal:"
    info "  export BAO_ADDR=$SP_OB_URL BAO_CACERT=\$HOME/.securepam/openbao/tls/ca.crt"
    info "  bao operator unseal      # hidden prompt - run it $OB_T times with DIFFERENT shares"
    return 1
  fi
  local ans attempts=0
  printf '  Enter unseal shares now? [y/N] '; read -r ans
  case "$ans" in y|Y|yes|YES) ;; *) warn "skipped - OpenBao stays sealed; credential retrieval will fail closed until it is unsealed"; return 1;; esac
  while [ "$attempts" -lt $((OB_T + 2)) ]; do
    BAO_ADDR="$SP_OB_URL" BAO_CACERT="$SP_OB_CA" bao operator unseal || warn "that share was not accepted"
    attempts=$((attempts+1)); chk_openbao
    [ "$CHK_STATE" = sealed ] || break
    info "still sealed ($OB_PROGRESS/$OB_T shares accepted)"
  done
  [ "$CHK_STATE" = healthy ] && { ok "OpenBao is unsealed"; return 0; }
  warn "OpenBao is still not unsealed ($CHK_STATE: $CHK_DETAIL)"; return 1
}
phase_openbao() {
  step "OpenBao staging (LaunchAgent $SP_OB_LABEL)"
  chk_openbao
  if [ "$CHK_STATE" = stopped ]; then
    [ -f "$SP_OB_PLIST" ] || fail "LaunchAgent plist is missing ($SP_OB_PLIST). Not inventing a configuration - see ~/.securepam/openbao/RUNBOOK.md"
    case "$OB_AGENT" in
      not-loaded) act "load the existing LaunchAgent (launchctl bootstrap)" launchctl bootstrap "gui/$(id -u)" "$SP_OB_PLIST";;
      *)          act "start the existing LaunchAgent (launchctl kickstart, no -k)" launchctl kickstart "gui/$(id -u)/$SP_OB_LABEL";;
    esac
    if [ "$SP_DRY" = 0 ]; then
      local i=0; while [ "$i" -lt 60 ]; do chk_openbao; [ "$CHK_STATE" != stopped ] && break; sleep 2; i=$((i+2)); done
    fi
  fi
  [ "$SP_DRY" = 1 ] && [ "$CHK_STATE" = stopped ] && return
  if [ "$CHK_STATE" = degraded ] && [ "$OB_INIT" = False ]; then
    fail "OpenBao reports it is NOT INITIALIZED. This could mean its storage was lost - stopping. Do not initialize; see ~/.securepam/openbao/RUNBOOK.md and the Raft snapshot backups."
  fi
  case "$CHK_STATE" in
    healthy) ok "OpenBao is unsealed and answering over verified TLS";;
    sealed)  unseal_openbao || true;;
    *)       warn "OpenBao: $CHK_STATE - $CHK_DETAIL";;
  esac
}

# --- 5. applications -----------------------------------------------------------------------------------------------
# Launch commands mirror the processes that were verified running (see docs/SECUREPAM-STARTUP-RUNBOOK.md).
launch_backend_8001() {
  ( cd "$SP_ROOT" && env \
      SECRET_PROVIDER=openbao OPENBAO_ADDR="$SP_OB_URL" OPENBAO_CA_CERT="$SP_OB_CA" \
      OPENBAO_TOKEN_FILE="$SP_OB_DIR/tokens/staging-reader-token" OPENBAO_WRITER_TOKEN_FILE="$SP_OB_DIR/tokens/staging-writer-token" \
      SECUREPAM_KNOWN_HOSTS_PATH="$HOME/securepam-data/ssh/known_hosts" \
      RECORDING_STORAGE_PATH="$HOME/securepam-data/recordings" RDP_RECORDING_PATH="$HOME/securepam-data/recordings/rdp" \
      RDP_GATEWAY_ENABLED=true GUACD_HOST=127.0.0.1 GUACD_PORT=4822 REDIS_URL=redis://127.0.0.1:6379/0 \
      GUACAMOLE_URL=http://127.0.0.1:8081/guacamole \
      BROWSER_ISOLATION_ENABLED=true BROWSER_ISOLATION_TOKEN_FILE="$SP_ROOT/infrastructure/browser-isolation/.isolation_token" \
      KEYCLOAK_INTERNAL_URL=http://127.0.0.1:8080 \
      BACKEND_CORS_ORIGINS='["http://localhost:3001","http://127.0.0.1:3001"]' \
      nohup backend/.venv/bin/python backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8001 --app-dir backend \
      </dev/null >>"$LOG_DIR/backend-8001.log" 2>&1 & )
}
launch_backend_8002() { # exactly as it has been running (note: OpenBao = the user-run dev instance on 18200)
  ( cd "$SP_ROOT" && env \
      DEV_MODE=false KEYCLOAK_URL=http://localhost:8080 KEYCLOAK_INTERNAL_URL=http://127.0.0.1:8080 \
      SECRET_PROVIDER=openbao OPENBAO_ADDR=http://127.0.0.1:18200 \
      OPENBAO_TOKEN_FILE="$HOME/.securepam/openbao-app-token" OPENBAO_WRITER_TOKEN_FILE="$HOME/.securepam/openbao-writer-token" \
      SECUREPAM_KNOWN_HOSTS_PATH="$HOME/securepam-data/ssh/known_hosts" \
      RECORDING_STORAGE_PATH="$HOME/securepam-data/recordings" RDP_RECORDING_PATH="$HOME/securepam-data/recordings/rdp" \
      RDP_GATEWAY_ENABLED=true GUACD_HOST=127.0.0.1 GUACD_PORT=4822 REDIS_URL=redis://127.0.0.1:6379/0 \
      GUACAMOLE_URL=http://127.0.0.1:8081/guacamole \
      BROWSER_ISOLATION_ENABLED=true BROWSER_ISOLATION_TOKEN_FILE="$SP_ROOT/infrastructure/browser-isolation/.isolation_token" \
      BACKEND_CORS_ORIGINS='["http://localhost:3002","http://127.0.0.1:3002"]' \
      nohup backend/.venv/bin/python backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8002 --app-dir backend \
      </dev/null >>"$LOG_DIR/backend-8002.log" 2>&1 & )
}
launch_frontend() { # <port> <backend url>
  ( cd "$SP_ROOT/frontend" && env VITE_API_URL="$2" nohup npm run dev -- --port "$1" --strictPort \
      </dev/null >>"$LOG_DIR/frontend-$1.log" 2>&1 & )
}

ensure_backend() { # <port> <expected dev_mode> <launcher fn>
  local port="$1" want="$2" launcher="$3" pid
  pid="$(port_pid "$port")"
  if [ -n "$pid" ]; then
    owner_is_backend "$pid" "$port" || fail "PORT CONFLICT on $port: pid $pid ($(pid_cmd "$pid")) is not this project's backend. Not killing it."
    chk_backend "$port" "$want"
    if [ "$CHK_STATE" = healthy ]; then ok "backend :$port already healthy"; return; fi
    warn "backend :$port is running but $CHK_STATE ($CHK_DETAIL) - waiting briefly, not restarting it"
    wait_until "backend :$port" 30 chk_backend "$port" "$want" && ok "backend :$port healthy" || true
    return
  fi
  act "start backend :$port (log: ~/.securepam/backend-$port.log)" "$launcher"
  wait_until "backend :$port" 90 chk_backend "$port" "$want" && { [ "$SP_DRY" = 1 ] || ok "backend :$port healthy"; } || warn "check ~/.securepam/backend-$port.log"
}
ensure_frontend() { # <port> <backend url>
  local port="$1" api="$2" pid
  pid="$(port_pid "$port")"
  if [ -n "$pid" ]; then
    owner_is_frontend "$pid" "$port" || fail "PORT CONFLICT on $port: pid $pid ($(pid_cmd "$pid")) is not this project's frontend. Not killing it."
    chk_frontend "$port" "$api"
    if [ "$CHK_STATE" = healthy ]; then ok "frontend :$port already healthy"; return; fi
    warn "frontend :$port is running but $CHK_STATE ($CHK_DETAIL) - not restarting it"; return
  fi
  act "start frontend :$port -> $api (log: ~/.securepam/frontend-$port.log)" launch_frontend "$port" "$api"
  wait_until "frontend :$port" 60 chk_frontend "$port" "$api" && { [ "$SP_DRY" = 1 ] || ok "frontend :$port healthy"; } || warn "check ~/.securepam/frontend-$port.log"
}
phase_apps() {
  step "Applications"
  ensure_backend 8001 true  launch_backend_8001
  ensure_frontend 3001 http://localhost:8001
  ensure_backend 8002 false launch_backend_8002
  ensure_frontend 3002 http://localhost:8002
}

# --- main ----------------------------------------------------------------------------------------------------------
main() {
  [ "$SP_DRY" = 1 ] && printf '%s\n' "$(c 33 'DRY RUN - nothing will be started, stopped or changed')"
  acquire_lock
  preflight
  phase_docker
  phase_brew
  phase_containers
  phase_openbao
  phase_apps
  step "Final status"
  sp_status_main
}

# Run only when executed (not when sourced, e.g. by tests).
if [ "${BASH_SOURCE[0]}" = "$0" ]; then main; exit $?; fi
