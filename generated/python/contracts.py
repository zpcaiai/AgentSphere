# GENERATED from schemas/contract-model.json; source_sha256=90e36f317a4dedf3f38397c419c3975ca2d14dda60664af823301cb68633d097; run ./scripts/generate-contracts.sh

from dataclasses import dataclass
from enum import Enum

class TaskStatus(str, Enum):
    CREATED = 'CREATED'
    PLANNED = 'PLANNED'
    POLICY_CHECKED = 'POLICY_CHECKED'
    APPROVAL_PENDING = 'APPROVAL_PENDING'
    APPROVED = 'APPROVED'
    RUNNING = 'RUNNING'
    PAUSE_REQUESTED = 'PAUSE_REQUESTED'
    PAUSED = 'PAUSED'
    CANCEL_REQUESTED = 'CANCEL_REQUESTED'
    CANCELLING = 'CANCELLING'
    KILL_REQUESTED = 'KILL_REQUESTED'
    KILLED = 'KILLED'
    VERIFYING = 'VERIFYING'
    COMPLETED = 'COMPLETED'
    DENIED = 'DENIED'
    FAILED = 'FAILED'
    EVALUATION_FAILED = 'EVALUATION_FAILED'
    COMPENSATING = 'COMPENSATING'
    ROLLED_BACK = 'ROLLED_BACK'
    NEEDS_HUMAN = 'NEEDS_HUMAN'
    MANUAL_RECOVERY_REQUIRED = 'MANUAL_RECOVERY_REQUIRED'

class ExecutionStatus(str, Enum):
    PREPARED = 'PREPARED'
    RUNNING = 'RUNNING'
    SUCCEEDED = 'SUCCEEDED'
    FAILED = 'FAILED'
    TIMED_OUT = 'TIMED_OUT'
    CANCELLED = 'CANCELLED'
    KILLED = 'KILLED'
    COMPENSATING = 'COMPENSATING'
    COMPENSATED = 'COMPENSATED'
    COMPENSATION_FAILED = 'COMPENSATION_FAILED'
    UNKNOWN = 'UNKNOWN'

class RiskLevel(str, Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'

class EffectClass(str, Enum):
    PURE = 'PURE'
    IDEMPOTENT = 'IDEMPOTENT'
    COMPENSATABLE = 'COMPENSATABLE'
    IRREVERSIBLE = 'IRREVERSIBLE'

class Decision(str, Enum):
    ALLOW = 'ALLOW'
    DENY = 'DENY'
    REQUIRE_APPROVAL = 'REQUIRE_APPROVAL'
    PAUSE = 'PAUSE'
    KILL = 'KILL'

class DataClassification(str, Enum):
    PUBLIC = 'PUBLIC'
    INTERNAL = 'INTERNAL'
    CONFIDENTIAL = 'CONFIDENTIAL'
    RESTRICTED = 'RESTRICTED'
    REGULATED = 'REGULATED'

class EvaluationStatus(str, Enum):
    PASS = 'PASS'
    FAIL = 'FAIL'
    NEEDS_HUMAN = 'NEEDS_HUMAN'
    ROLLED_BACK = 'ROLLED_BACK'
    MANUAL_RECOVERY_REQUIRED = 'MANUAL_RECOVERY_REQUIRED'

@dataclass(frozen=True, slots=True)
class ToolRef:
    tool_id: str
    tool_version: str

@dataclass(frozen=True, slots=True)
class PlanStep:
    step_id: str
    sequence: int
    intent: str
    dependencies: list[str]
    tool: ToolRef | None
    resource_scope: list[str]
    risk: RiskLevel

@dataclass(frozen=True, slots=True)
class SignedGoal:
    schema_version: str
    goal_id: str
    normalized_goal: str
    goal_hash: str
    constraints: dict[str, str]
    approved_by: str
    signed_at: str
    signer_key_id: str
    signature: str

@dataclass(frozen=True, slots=True)
class PlanManifest:
    schema_version: str
    plan_id: str
    goal_hash: str
    plan_hash: str
    steps: list[PlanStep]
    max_scope: list[str]
    risk_budget: RiskLevel
    cost_budget_microunits: int
    valid_until: str

@dataclass(frozen=True, slots=True)
class DelegationEnvelope:
    schema_version: str
    parent_agent: str
    child_agent: str
    delegated_tools: list[ToolRef]
    delegated_resources: list[str]
    budget_ceiling_microunits: int
    expiry: str

@dataclass(frozen=True, slots=True)
class AuthorizationLease:
    schema_version: str
    lease_id: str
    task_id: str
    goal_hash: str
    plan_hash: str
    policy_snapshot: str
    allowed_tools: list[ToolRef]
    allowed_resources: list[str]
    revocation_epoch: int
    valid_until: str
