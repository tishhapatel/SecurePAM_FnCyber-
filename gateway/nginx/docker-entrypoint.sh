#!/bin/sh
##############################################################################
# SecurePAM NGINX Gateway — Container Entrypoint
# Substitutes environment variables in the NGINX config template before start.
##############################################################################
set -e

# Set defaults if not provided in environment
export GATEWAY_BACKEND_HOST="${GATEWAY_BACKEND_HOST:-backend}"
export GATEWAY_BACKEND_PORT="${GATEWAY_BACKEND_PORT:-8000}"
export GATEWAY_TEST_UPSTREAM="${GATEWAY_TEST_UPSTREAM:-backend:8000}"
# No default: refuse to start with an unset, short or placeholder token,
# which the backend would reject anyway.
case "${GATEWAY_AUTH_TOKEN:-}" in
  ""|dev-insecure-change-me-in-production)
    echo "[entrypoint] GATEWAY_AUTH_TOKEN must be set (at least 32 characters)." >&2
    exit 1 ;;
esac
if [ "${#GATEWAY_AUTH_TOKEN}" -lt 32 ]; then
  echo "[entrypoint] GATEWAY_AUTH_TOKEN must be at least 32 characters." >&2
  exit 1
fi
case "$GATEWAY_AUTH_TOKEN" in
  *[!A-Za-z0-9_-]*)
    # It is substituted into a quoted nginx directive.
    echo "[entrypoint] GATEWAY_AUTH_TOKEN may contain only A-Z a-z 0-9 _ -" >&2
    exit 1 ;;
esac
export GATEWAY_AUTH_TOKEN
export GATEWAY_BROWSER_ISOLATION_HOST="${GATEWAY_BROWSER_ISOLATION_HOST:-browser-isolation}"
export GATEWAY_BROWSER_ISOLATION_PORT="${GATEWAY_BROWSER_ISOLATION_PORT:-6080}"

# Substitute environment variables in the NGINX config template.
# Only the listed variables are substituted — no shell injection risk
# from arbitrary env vars.
envsubst '${GATEWAY_BACKEND_HOST} ${GATEWAY_BACKEND_PORT} ${GATEWAY_TEST_UPSTREAM} ${GATEWAY_AUTH_TOKEN} ${GATEWAY_BROWSER_ISOLATION_HOST} ${GATEWAY_BROWSER_ISOLATION_PORT}' \
    < /etc/nginx/nginx.conf.template \
    > /etc/nginx/nginx.conf

# Create per-application upstream include directory if absent.
mkdir -p /etc/nginx/conf.d/apps
if [ ! -f /etc/nginx/conf.d/apps/.keep ]; then
    touch /etc/nginx/conf.d/apps/.keep
fi

# Validate the generated config before starting
nginx -t

# Start the reload watcher as a background daemon.
# It watches /etc/nginx/conf.d/apps/.reload-signal and triggers nginx -s reload
# only after nginx -t passes. Runs for the lifetime of the container.
/nginx-reload-watcher.sh &
WATCHER_PID=$!
echo "[entrypoint] Reload watcher started (PID ${WATCHER_PID})"

exec "$@"
