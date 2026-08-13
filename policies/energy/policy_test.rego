package agenttrust.energy_test

import data.agenttrust.energy
import rego.v1

base := {
  "intent":{"operation":"dispatch"},
  "subject":{"tenant_id":"tenant-1"},
  "resource":{"tenant_id":"tenant-1"},
  "asset":{"lifecycle":"ACTIVE","minimum_power_kw":-50,"maximum_power_kw":50},
  "arguments":{"power_kw":20,"resource_version":"v4"},
  "telemetry":{"resource_version":"v4","state_of_charge":0.55,"observed_at_ns":90,"alarm_active":false},
  "constraints":{"minimum_state_of_charge":0.2,"maximum_state_of_charge":0.9,"max_telemetry_age_ns":20},
  "forecast":{"digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","valid_until_ns":120},
  "approval":{"valid":true},
  "environment":{"mode":"SHADOW"}
}

test_valid_shadow_dispatch_allowed if { energy.dispatch_allowed with input as base with time.now_ns as 100 }
test_stale_telemetry_denied if { not energy.dispatch_allowed with input as base with time.now_ns as 200 }
test_cross_tenant_denied if { not energy.dispatch_allowed with input as object.union(base, {"resource":{"tenant_id":"tenant-2"}}) with time.now_ns as 100 }
test_out_of_bound_power_denied if { not energy.dispatch_allowed with input as object.union(base, {"arguments":{"power_kw":51,"resource_version":"v4"}}) with time.now_ns as 100 }
test_missing_approval_denied if { not energy.dispatch_allowed with input as object.union(base, {"approval":{"valid":false}}) with time.now_ns as 100 }
