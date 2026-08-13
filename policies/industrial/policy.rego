package agenttrust.industrial

import rego.v1

within_range if {
  input.arguments.value >= input.constraints.minimum
  input.arguments.value <= input.constraints.maximum
}

fresh_state if { time.now_ns() - input.current_state.observed_at_ns <= input.constraints.max_state_age_ns }

commit_allowed if {
  input.intent.operation == "commit_setpoint"
  simulation_or_approved
  input.current_state.resource_version == input.arguments.resource_version
  input.current_state.value == input.arguments.expected_current_value
  within_range
  fresh_state
  not input.current_state.alarm_active
  input.current_state.interlock_ok
}

simulation_or_approved if { input.environment.simulation }
simulation_or_approved if { input.approval.valid }
