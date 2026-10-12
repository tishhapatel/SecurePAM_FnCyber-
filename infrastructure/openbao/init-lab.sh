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

bao policy write securepam-runtime /openbao/policies/securepam-runtime.hcl

# Synthetic path so the convention exists. This is not a real credential.
bao kv put secret/targets/lab-sample \
  username="lab-operator" \
  password="lab-only-not-a-real-credential" \
  >/dev/null

umask 077
bao token create \
  -policy=securepam-runtime \
  -no-default-policy \
  -orphan \
  -ttl=768h \
  -display-name=securepam-lab \
  -field=token \
  > /openbao/runtime/app-token

echo "OpenBao lab configuration applied. Runtime token stored in the openbao_runtime volume."
