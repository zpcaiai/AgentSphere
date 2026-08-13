# Credential Proxy security model

The Proxy verifies signed single-use Execution Authorization, online Registry state, exact connector profile, workload credential scope, target profile, and input schema. Target secrets live only in `SecretLease`, are exposed only to a connector, zeroized on drop, and revoked on success/error/timeout. HTTP has fixed HTTPS targets with no redirect/private/metadata IPs; Git has high-level task-branch operations; SQL uses registered templates; industrial writes require allowlisted CAS fields.

