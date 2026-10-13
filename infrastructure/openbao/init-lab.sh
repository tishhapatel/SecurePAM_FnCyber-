#!/bin/sh
# Bootstrap a lab OpenBao server. Idempotent.
# Uses the dev root token only inside this container. The application token
# is written to the openbao_runtime volume and is never printed.

set -eu

BAO_ADDR="${BAO_ADDR:-http://openbao:8200}"
export BAO_ADDR

if [ -z "${BAO_TOKEN:-}" ]; then
  echo "BAO_TOKEN is empty. Set OPENBAO_DEV_ROOT_TOKEN_ID for the lab bootstrap." >&2
  exit 1
fi

echo "Waiting for OpenBao at ${BAO_ADDR}..."
i=0
until bao status >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 60 ]; then
    echo "OpenBao did not become ready." >&2
    exit 1
  fi
  sleep 1
done

if bao secrets list -format=json | grep -q '"secret/"'; then
  echo "KV mount secret/ already present."
else
  bao secrets enable -path=secret kv-v2
fi

bao policy write securepam-read /openbao/policies/securepam-read.hcl

# Synthetic path matching CredentialService's server-derived convention.
# This is not a real credential. Written only once, so a rerun never
# overwrites a value someone has since put at this path.
if bao kv get secret/securepam/assets/test-linux-01 >/dev/null 2>&1; then
  echo "Sample secret already present; left unchanged."
else
  bao kv put secret/securepam/assets/test-linux-01 \
    username="fakeuser" \
    password="fake-only" \
    >/dev/null
fi

mkdir -p /openbao/runtime
chmod 711 /openbao/runtime
umask 077
tmp=/openbao/runtime/app-token.tmp
bao token create \
  -policy=securepam-read \
  -no-default-policy \
  -orphan \
  -ttl=24h \
  -display-name=securepam-backend \
  -field=token \
  > "$tmp"
# Lab volume only. The directory is traversable and the file is world-readable
# so the non-root backend user can load the token. The volume is not a host directory.
chmod 444 "$tmp"
# Atomic replace: the backend never reads a partially written token.
mv "$tmp" /openbao/runtime/app-token

echo "OpenBao lab configuration applied. Runtime token stored in the openbao_runtime volume."
