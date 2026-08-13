package agenttrust.common

import rego.v1

default allow := false

allow if {
  input.subject.tenant_id == input.resource.tenant_id
  input.tool.status == "ACTIVE"
  production_identity_ok
  not protected_control_plane_resource
}

production_identity_ok if { input.environment.deployment != "production" }
production_identity_ok if { input.subject.trust_level != "development" }

protected_control_plane_resource if {
  startswith(input.resource.locator, "policy:")
  not "control-admin" in input.subject.roles
}

decision := {
  "decision": "ALLOW",
  "reason_codes": ["COMMON_GUARDS_PASS"],
} if allow

decision := {
  "decision": "DENY",
  "reason_codes": ["COMMON_FAIL_CLOSED"],
} if not allow
