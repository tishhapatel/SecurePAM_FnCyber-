# Least-privilege policy for the SecurePAM application identity.
# Matches the path convention on main: secret/data/securepam/assets/*
# Read only. No write, delete, or sys/admin capabilities.

path "secret/data/securepam/assets/*" {
  capabilities = ["read"]
}
