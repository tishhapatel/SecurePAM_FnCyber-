#!/bin/sh
set -e

# SecurePAM Browser Isolation Daemon Entrypoint
echo "Starting SecurePAM Browser Isolation service on port ${PORT:-6080}..."
mkdir -p /tmp/browser_sessions

exec "$@"
