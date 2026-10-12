# Least-privilege policy for the SecurePAM application identity (lab/dev).
#
# The backend reads exactly one kind of path: an asset credential at
#   <mount>/data/<OPENBAO_SECRET_PATH_PREFIX>/assets/<name>
# (see backend/app/secret_providers/paths.py). Read only — no write, no
# delete, no metadata/list (so the token cannot enumerate secrets), and
# no sys/ or auth/ paths.
#
# KV v2 stores data at secret/data/...; the CLI path
# secret/securepam/assets/<name> maps to secret/data/securepam/assets/<name>.

path "secret/data/securepam/assets/*" {
  capabilities = ["read"]
}
