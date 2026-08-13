package agenttrust.industrial_test

import data.agenttrust.industrial
import rego.v1

base := {"intent":{"operation":"commit_setpoint"},"environment":{"simulation":true},"approval":{"valid":false},"arguments":{"value":80,"resource_version":"v1","expected_current_value":70},"constraints":{"minimum":0,"maximum":80,"max_state_age_ns":100},"current_state":{"resource_version":"v1","value":70,"observed_at_ns":50,"alarm_active":false,"interlock_ok":true}}

test_boundary_80_allowed if { industrial.commit_allowed with input as base with time.now_ns as 100 }
test_boundary_80_1_denied if { not industrial.commit_allowed with input as object.union(base, {"arguments":{"value":80.1,"resource_version":"v1","expected_current_value":70}}) with time.now_ns as 100 }
test_stale_version_denied if { not industrial.commit_allowed with input as object.union(base, {"arguments":{"value":70,"resource_version":"v2","expected_current_value":70}}) with time.now_ns as 100 }

