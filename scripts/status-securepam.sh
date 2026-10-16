#!/bin/bash
# status-securepam.sh - READ-ONLY health report for the whole SecurePAM environment.
#
#   ./scripts/status-securepam.sh [--no-color]
#
# Changes nothing: no start/stop/restart, no writes, no secrets read or printed. Every row is a real check
# (an HTTP/protocol answer or a container/launchd state), never "the port is open". States:
#   healthy | stopped | sealed | degraded | unknown        (exit 0 only if every managed row is healthy)
#
# This file is also sourced by start-securepam.sh so both use identical definitions of "healthy".
# Written for macOS system bash 3.2 (no associative arrays / bash-4 features).

SP_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PATH="$HOME/Library/pnpm:/opt/homebrew/bin:/usr/local/bin:/Applications/Docker.app/Contents/Resources/bin:/usr/bin:/bin:/usr/sbin:/sbin:$PATH"
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1

CURL=/usr/bin/curl
PY=/usr/bin/python3
LSOF=/usr/sbin/lsof

# --- verified facts about this installation (see docs/SECUREPAM-STARTUP-RUNBOOK.md) -------------------------
SP_OB_DIR="$HOME/.securepam/openbao"
SP_OB_URL="https://127.0.0.1:18210"
SP_OB_CA="$SP_OB_DIR/tls/ca.crt"
SP_OB_LABEL="local.securepam.openbao"
SP_OB_PLIST="$HOME/Library/LaunchAgents/$SP_OB_LABEL.plist"
SP_BREW_PG="postgresql@16"
SP_BREW_REDIS="redis"
# Managed containers, in dependency order (all pre-existing; this tooling never creates/removes containers).
SP_CONTAINERS="securepam-keycloak-postgres securepam-keycloak guacamole-guac-postgres-1 guacamole-guacd-1 guacamole-guacamole-1 browser-isolation-browser-isolation-1"
# Docker-migration stack from the earlier trial: not used by the two host application pairs, so not managed.
SP_UNMANAGED_CONTAINERS="securepam-backend securepam-frontend securepam-postgres securepam-redis securepam-guacd securepam-guacamole securepam-openbao securepam-openbao-init"

CHK_STATE=""
CHK_DETAIL=""

# ---------------------------------------------------------------------------------------------------------
sp_timeout() { local secs="$1"; shift; /usr/bin/perl -e 'alarm shift; exec @ARGV' "$secs" "$@"; }
http_code() { $CURL -s -o /dev/null -w '%{http_code}' --max-time "${2:-4}" "$1" 2>/dev/null || true; }
http_body() { $CURL -s --max-time "${2:-4}" "$1" 2>/dev/null || true; }
set_chk() { CHK_STATE="$1"; CHK_DETAIL="$2"; }
port_pid() { $LSOF -nP -iTCP:"$1" -sTCP:LISTEN -t 2>/dev/null | head -1; }
pid_cmd() { ps -o command= -p "$1" 2>/dev/null | cut -c1-110; }
pid_cwd() { $LSOF -a -p "$1" -d cwd -Fn 2>/dev/null | sed -n 's/^n//p' | head -1; }
pid_env() { ps eww -p "$1" 2>/dev/null | tr ' ' '\n' | grep "^$2=" | head -1 | cut -d= -f2-; }
json_field() { $PY -c 'import sys,json
try:
    d=json.load(sys.stdin)
    for k in sys.argv[1].split("."):
        d=d[k]
    print(d)
except Exception:
    pass' "$1" 2>/dev/null; }

# The listener on <port> is this repo's uvicorn / vite for that port (so we never mistake or touch a stranger).
owner_is_backend() { local pid="$1" port="$2" cmd cwd; cmd="$(pid_cmd "$pid") "; cwd="$(pid_cwd "$pid")"
  case "$cmd" in *uvicorn*app.main:app*" --port $port "*) [ "$cwd" = "$SP_ROOT" ];; *) return 1;; esac; }
owner_is_frontend() { local pid="$1" port="$2" cmd cwd; cmd="$(pid_cmd "$pid") "; cwd="$(pid_cwd "$pid")"
  case "$cmd" in *vite*" --port $port "*) [ "$cwd" = "$SP_ROOT/frontend" ];; *) return 1;; esac; }

# --- checks: each sets CHK_STATE / CHK_DETAIL ------------------------------------------------------------
chk_docker() {
  if ! command -v docker >/dev/null 2>&1; then set_chk unknown "docker CLI not found"; return; fi
  local v; v="$(sp_timeout 10 docker info --format '{{.ServerVersion}}' 2>/dev/null)"
  if [ -n "$v" ]; then set_chk healthy "engine $v"; else set_chk stopped "Docker daemon is not answering"; fi
}

# Container-level state only. Service-level answers (HTTP/protocol) are checked by the callers below.
chk_container() {
  local name="$1" raw st hl rp
  if ! command -v docker >/dev/null 2>&1; then set_chk unknown "docker CLI not found"; return; fi
  raw="$(sp_timeout 10 docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}-{{end}}|{{.HostConfig.RestartPolicy.Name}}' "$name" 2>/dev/null)"
  if [ -z "$raw" ]; then
    if [ -z "$(sp_timeout 10 docker info --format '{{.ServerVersion}}' 2>/dev/null)" ]; then set_chk stopped "Docker daemon is not running"
    else set_chk unknown "container '$name' not found"; fi
    return
  fi
  st="${raw%%|*}"; raw="${raw#*|}"; hl="${raw%%|*}"; rp="${raw#*|}"
  case "$st" in
    running)
      case "$hl" in
        -|healthy) set_chk healthy "container running$([ "$hl" = healthy ] && printf ', health ok'), restart=$rp";;
        starting)  set_chk degraded "container running, health check still starting";;
        *)         set_chk degraded "container running but health=$hl";;
      esac;;
    exited|created|dead) set_chk stopped "container $st (restart=$rp)";;
    paused|restarting)   set_chk degraded "container $st";;
    *)                   set_chk unknown "container state '$st'";;
  esac
}

SP_BREW_CACHE=""
brew_status() { # <formula> -> started|none|error|unknown
  [ -z "$SP_BREW_CACHE" ] && SP_BREW_CACHE="$(brew services list 2>/dev/null || true)"
  local s; s="$(printf '%s\n' "$SP_BREW_CACHE" | awk -v f="$1" '$1==f {print $2}')"
  echo "${s:-unknown}"
}
brew_refresh() { SP_BREW_CACHE=""; }

chk_postgres() {
  if pg_isready -q -h localhost -p 5432 2>/dev/null; then set_chk healthy "accepting connections on 5432 (brew: $(brew_status $SP_BREW_PG))"; return; fi
  case "$(brew_status $SP_BREW_PG)" in
    none|stopped) set_chk stopped "Homebrew service $SP_BREW_PG is stopped";;
    started)      set_chk degraded "Homebrew says $SP_BREW_PG is started but 5432 is not accepting connections";;
    *)            set_chk unknown "Homebrew service state: $(brew_status $SP_BREW_PG)";;
  esac
}

chk_redis() {
  if [ "$(redis-cli -h 127.0.0.1 -p 6379 ping 2>/dev/null)" = "PONG" ]; then set_chk healthy "PONG on 6379 (brew: $(brew_status $SP_BREW_REDIS))"; return; fi
  case "$(brew_status $SP_BREW_REDIS)" in
    none|stopped) set_chk stopped "Homebrew service $SP_BREW_REDIS is stopped";;
    started)      set_chk degraded "Homebrew says $SP_BREW_REDIS is started but 6379 does not answer PING";;
    *)            set_chk unknown "Homebrew service state: $(brew_status $SP_BREW_REDIS)";;
  esac
}

# Globals filled for start-securepam.sh
OB_AGENT=""; OB_INIT=""; OB_SEALED=""; OB_T=""; OB_N=""; OB_PROGRESS=""
ob_agent_state() { # running | loaded | not-loaded
  local out; out="$(launchctl print "gui/$(id -u)/$SP_OB_LABEL" 2>/dev/null)" || { echo not-loaded; return; }
  if printf '%s\n' "$out" | grep -q 'state = running'; then echo running; else echo loaded; fi
}
chk_openbao() {
  OB_AGENT="$(ob_agent_state)"; OB_INIT=""; OB_SEALED=""; OB_T=""; OB_N=""; OB_PROGRESS=""
  local body fields
  if [ ! -r "$SP_OB_CA" ]; then set_chk unknown "CA certificate not readable (~/.securepam/openbao/tls/ca.crt)"; return; fi
  body="$($CURL -s --max-time 4 --cacert "$SP_OB_CA" "$SP_OB_URL/v1/sys/seal-status" 2>/dev/null)"
  if [ -z "$body" ]; then
    if [ "$OB_AGENT" = running ]; then set_chk degraded "LaunchAgent running but the TLS API is not answering"
    else set_chk stopped "LaunchAgent $OB_AGENT; API not reachable"; fi
    return
  fi
  fields="$(printf '%s' "$body" | $PY -c 'import sys,json
d=json.load(sys.stdin)
print(d.get("initialized"),d.get("sealed"),d.get("t"),d.get("n"),d.get("progress"))' 2>/dev/null)"
  set -- $fields
  OB_INIT="$1"; OB_SEALED="$2"; OB_T="$3"; OB_N="$4"; OB_PROGRESS="$5"
  if [ -z "$OB_INIT" ]; then set_chk unknown "unexpected seal-status response"; return; fi
  if [ "$OB_INIT" != "True" ]; then set_chk degraded "NOT INITIALIZED - this tooling never initializes OpenBao"; return; fi
  if [ "$OB_SEALED" = "True" ]; then set_chk sealed "sealed: needs $OB_T of $OB_N unseal shares (entered $OB_PROGRESS/$OB_T)"; return; fi
  set_chk healthy "unsealed, TLS verified with the local CA, agent $OB_AGENT"
}

chk_openbao_dev() { # informational only (user-run, in-memory; backend 8002 is configured to use it)
  if [ "$(http_code http://127.0.0.1:18200/v1/sys/health 3)" = 200 ]; then set_chk healthy "dev instance answering (user-run, in-memory)"
  else set_chk stopped "not running (not managed; backend 8002 vault calls need it)"; fi
}

chk_backend() { # <port> <expected dev_mode: true|false>
  local port="$1" want="$2" pid body st detail cfg dm
  pid="$(port_pid "$port")"
  if [ -z "$pid" ]; then set_chk stopped "nothing listening on $port"; return; fi
  if ! owner_is_backend "$pid" "$port"; then set_chk degraded "PORT CONFLICT: held by pid $pid ($(pid_cmd "$pid"))"; return; fi
  body="$(http_body "http://127.0.0.1:$port/health/ready" 5)"
  if [ -z "$body" ]; then set_chk degraded "listening (pid $pid) but /health/ready does not answer"; return; fi
  st="$(printf '%s' "$body" | json_field status)"
  detail="$(printf '%s' "$body" | $PY -c 'import sys,json
d=json.load(sys.stdin); print(",".join("%s:%s"%(c["service"],c["status"]) for c in d.get("checks",[])))' 2>/dev/null)"
  if [ "$st" != "ready" ]; then set_chk degraded "/health/ready=$st ($detail)"; return; fi
  cfg="$(http_body "http://127.0.0.1:$port/api/v1/auth/config" 4)"
  dm="$(printf '%s' "$cfg" | json_field dev_mode)"
  if [ -z "$dm" ]; then set_chk degraded "ready, but /auth/config does not answer"; return; fi
  if [ "$(printf '%s' "$dm" | tr 'A-Z' 'a-z')" != "$want" ]; then set_chk degraded "ready, but dev_mode=$dm (expected $want)"; return; fi
  set_chk healthy "ready ($detail); dev_mode=$dm; pid $pid"
}

chk_frontend() { # <port> <expected backend URL>
  local port="$1" want="$2" pid html api
  pid="$(port_pid "$port")"
  if [ -z "$pid" ]; then set_chk stopped "nothing listening on $port"; return; fi
  if ! owner_is_frontend "$pid" "$port"; then set_chk degraded "PORT CONFLICT: held by pid $pid ($(pid_cmd "$pid"))"; return; fi
  html="$(http_body "http://127.0.0.1:$port/" 5)"
  case "$html" in *'id="root"'*) ;; *) set_chk degraded "listening (pid $pid) but the app page did not load"; return;; esac
  api="$(pid_env "$pid" VITE_API_URL)"
  if [ "$api" != "$want" ]; then set_chk degraded "page loads, but VITE_API_URL='${api:-unset}' (expected $want)"; return; fi
  set_chk healthy "app page loads; API -> $api; pid $pid"
}

chk_keycloak_db() { chk_container securepam-keycloak-postgres; }
chk_keycloak() {
  chk_container securepam-keycloak
  [ "$CHK_STATE" = healthy ] || return
  local code; code="$(http_code http://localhost:8080/realms/securepam 5)"
  if [ "$code" = 200 ]; then set_chk healthy "realm 'securepam' answers (HTTP 200)"
  else set_chk degraded "container running but realm URL returned HTTP ${code:-none} (still starting?)"; fi
}
chk_guac_db() { chk_container guacamole-guac-postgres-1; }
chk_guacd() {
  chk_container guacamole-guacd-1
  [ "$CHK_STATE" = healthy ] || return
  if nc -z -G 3 127.0.0.1 4822 >/dev/null 2>&1; then set_chk healthy "container healthy; accepts connections on 4822"
  else set_chk degraded "container healthy but 4822 refuses connections"; fi
}
chk_guacamole() {
  chk_container guacamole-guacamole-1
  [ "$CHK_STATE" = healthy ] || return
  local code; code="$(http_code http://127.0.0.1:8081/guacamole/ 5)"
  if [ "$code" = 200 ]; then set_chk healthy "web app answers (HTTP 200)"
  else set_chk degraded "container running but /guacamole/ returned HTTP ${code:-none}"; fi
}
chk_isolation() {
  chk_container browser-isolation-browser-isolation-1
  [ "$CHK_STATE" = healthy ] || return
  local body ok n; body="$(http_body http://127.0.0.1:6090/health 4)"
  ok="$(printf '%s' "$body" | json_field ok)"; n="$(printf '%s' "$body" | json_field sessions)"
  if [ "$ok" = "True" ]; then set_chk healthy "daemon /health ok; ${n:-?} active session(s)"
  else set_chk degraded "container running but daemon /health did not report ok"; fi
}

# --- report ------------------------------------------------------------------------------------------------
SP_COLOR=1; { [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; } || SP_COLOR=0
paint() { # <state> <text>
  if [ "$SP_COLOR" = 1 ]; then
    case "$1" in healthy) printf '\033[32m%s\033[0m' "$2";; stopped) printf '\033[31m%s\033[0m' "$2";;
      sealed) printf '\033[35m%s\033[0m' "$2";; degraded) printf '\033[33m%s\033[0m' "$2";; *) printf '\033[90m%s\033[0m' "$2";; esac
  else printf '%s' "$2"; fi
}
SP_BAD=0
row() { # <label> <managed 1|0> -> prints the last check
  local pad; pad="$(printf '%-34s' "$1")"
  printf '%s ' "$pad"; paint "$CHK_STATE" "$(printf '%-9s' "$CHK_STATE")"; printf ' %s\n' "$CHK_DETAIL"
  if [ "$2" = 1 ] && [ "$CHK_STATE" != healthy ]; then SP_BAD=$((SP_BAD+1)); fi
}

sp_status_main() {
  case "${1:-}" in --no-color) SP_COLOR=0;; -h|--help) sed -n '2,12p' "${BASH_SOURCE[0]}"; return 0;; esac
  SP_BAD=0; brew_refresh
  echo "SecurePAM status  $(date '+%Y-%m-%d %H:%M:%S')   ($(uname -sm))"
  echo "------------------------------------------------------------------------------------------------"
  echo "Infrastructure"
  chk_docker;       row "Docker engine" 1
  chk_postgres;     row "PostgreSQL (brew $SP_BREW_PG)" 1
  chk_redis;        row "Redis (brew $SP_BREW_REDIS)" 1
  chk_openbao;      row "OpenBao staging :18210 (TLS)" 1
  chk_keycloak_db;  row "Keycloak DB container" 1
  chk_keycloak;     row "Keycloak :8080" 1
  chk_guac_db;      row "Guacamole DB container" 1
  chk_guacd;        row "guacd :4822" 1
  chk_guacamole;    row "Guacamole :8081" 1
  chk_isolation;    row "Browser isolation :6090" 1
  echo "Applications"
  chk_backend 8001 true;   row "Backend  :8001 (dev login)" 1
  chk_frontend 3001 http://localhost:8001; row "Frontend :3001 -> 8001" 1
  chk_backend 8002 false;  row "Backend  :8002 (Keycloak MFA)" 1
  chk_frontend 3002 http://localhost:8002; row "Frontend :3002 -> 8002" 1
  echo "Informational (not managed by these scripts)"
  chk_openbao_dev;  row "OpenBao dev :18200 (8002 uses)" 0
  local n=0 c
  for c in $SP_UNMANAGED_CONTAINERS; do
    [ "$(sp_timeout 10 docker inspect --format '{{.State.Status}}' "$c" 2>/dev/null)" = running ] && n=$((n+1))
  done
  set_chk unknown "$n of 8 containers of the earlier Docker trial stack are running (left as they are)"; row "Docker trial stack" 0
  echo "------------------------------------------------------------------------------------------------"
  if [ "$SP_BAD" -eq 0 ]; then echo "All managed components are healthy."; return 0; fi
  echo "$SP_BAD managed component(s) not healthy.  Fix/start with: ./scripts/start-securepam.sh   (OpenBao 'sealed' needs your unseal shares)"
  return 1
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then sp_status_main "$@"; exit $?; fi
