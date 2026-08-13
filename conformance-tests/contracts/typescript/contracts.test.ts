import type { AuthorizationLease, Decision } from "../../../generated/typescript/contracts";
const decision: Decision = "DENY";
const lease: AuthorizationLease = {schema_version:"v1",lease_id:"l",task_id:"t",goal_hash:"g",plan_hash:"p",policy_snapshot:"s",allowed_tools:[],allowed_resources:[],revocation_epoch:1,valid_until:"2026-01-01T00:00:00Z"};
if (decision !== "DENY" || lease.revocation_epoch !== 1) throw new Error("contract mismatch");

