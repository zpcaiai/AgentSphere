package agenttrust.energy

import rego.v1

default dispatch_allowed := false

telemetry_fresh if {
  input.telemetry.observed_at_ns <= time.now_ns()
  time.now_ns() - input.telemetry.observed_at_ns <= input.constraints.max_telemetry_age_ns
}

forecast_bound if {
  input.forecast.digest != ""
  input.forecast.valid_until_ns >= time.now_ns()
}

power_within_asset_bounds if {
  input.arguments.power_kw >= input.asset.minimum_power_kw
  input.arguments.power_kw <= input.asset.maximum_power_kw
}

state_of_charge_safe if {
  input.telemetry.state_of_charge >= input.constraints.minimum_state_of_charge
  input.telemetry.state_of_charge <= input.constraints.maximum_state_of_charge
}

dispatch_allowed if {
  input.intent.operation == "dispatch"
  input.resource.tenant_id == input.subject.tenant_id
  input.asset.lifecycle == "ACTIVE"
  input.arguments.resource_version == input.telemetry.resource_version
  telemetry_fresh
  forecast_bound
  power_within_asset_bounds
  state_of_charge_safe
  not input.telemetry.alarm_active
  input.approval.valid
  input.environment.mode in {"SHADOW", "SIMULATION", "PRODUCTION"}
}

fallback_required if {
  input.intent.operation == "dispatch"
  not dispatch_allowed
}

decision := {"decision": "ALLOW", "reason_codes": ["ENERGY_CONSTRAINTS_PASS"]} if dispatch_allowed

decision := {"decision": "DENY", "reason_codes": ["ENERGY_FAIL_CLOSED"], "fallback_required": true} if not dispatch_allowed
