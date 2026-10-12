# Least-privilege policy for the SecurePAM application identity.
# Lab/dev only. This policy can read target and application secrets.
# It cannot write secrets, list the whole mount, or use sys/admin paths.
#
# KV v2 stores data at secret/data/... and metadata at secret/metadata/...
# The CLI path secret/targets/<name> maps to secret/data/targets/<name>.

path "secret/data/targets/*" {
  capabilities = ["read"]
}

path "secret/data/applications/*" {
  capabilities = ["read"]
}

path "secret/metadata/targets/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/applications/*" {
  capabilities = ["read", "list"]
}
