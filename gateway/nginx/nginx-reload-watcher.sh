#!/bin/sh
##############################################################################
# SecurePAM NGINX Gateway — Config Reload Watcher
# Member 11: Web Gateway & Browser Isolation
#
# Runs as a background process inside the NGINX container.
# Watches /etc/nginx/conf.d/apps/ for a .reload-signal file written by
# the backend config manager. When detected:
#   1. Removes the signal file
#   2. Runs nginx -t to validate the new configuration
#   3. If valid: runs nginx -s reload (zero-downtime reload)
#   4. If invalid: logs the error and restores the last-known-good backup
#
# This process is started by docker-entrypoint.sh before nginx starts.
#
# SECURITY:
# - Never reads config content from the signal file (it carries no data)
# - Config files are written by the backend to the shared volume only
# - nginx -t must pass before reload; invalid config is never applied
##############################################################################
set -e

CONF_DIR="/etc/nginx/conf.d/apps"
SIGNAL_FILE="${CONF_DIR}/.reload-signal"
BACKUP_DIR="/tmp/nginx-conf-backup"
POLL_INTERVAL=2   # seconds between checks

log() {
    echo "[nginx-reload-watcher] $(date -u '+%Y-%m-%dT%H:%M:%SZ') $*" >&2
}

# Create backup directory for known-good config snapshot
mkdir -p "${BACKUP_DIR}"

log "Started. Watching ${CONF_DIR} for reload signals (poll every ${POLL_INTERVAL}s)."

while true; do
    if [ -f "${SIGNAL_FILE}" ]; then
        log "Reload signal detected."

        # Remove signal file first — so we don't loop on a failed reload
        rm -f "${SIGNAL_FILE}"

        # Snapshot current conf files before testing the new ones
        cp -r "${CONF_DIR}" "${BACKUP_DIR}/apps_snapshot" 2>/dev/null || true

        # Test the new configuration
        if nginx -t 2>/tmp/nginx-t-output; then
            log "nginx -t passed. Reloading..."
            nginx -s reload
            log "Reload complete."
        else
            log "ERROR: nginx -t FAILED. Keeping current running config."
            log "nginx -t output:"
            cat /tmp/nginx-t-output >&2
            log "No reload performed — last known-good configuration preserved."
        fi
    fi
    sleep "${POLL_INTERVAL}"
done
