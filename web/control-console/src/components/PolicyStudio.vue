<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { isRecord, isUuid, sha256Canonical } from "../control-state";
import type {
  PolicyAction, PolicyArtifactPage, PolicyArtifactType, PolicyCommand, PolicyOperation,
  PolicyPage, PolicyRule, PolicyActionReceipt,
} from "../enterprise-api-types";

const props = withDefaults(defineProps<{
  tenantId: string;
  requestedBy: string;
  approvalIds: string[];
  page?: PolicyPage | null;
  artifactPage?: PolicyArtifactPage | null;
  receipt?: PolicyActionReceipt | null;
  busy?: boolean;
  error?: string;
  locale?: "zh-CN" | "en-US";
}>(), { page: null, artifactPage: null, receipt: null, busy: false, error: "", locale: "zh-CN" });

const emit = defineEmits<{
  load: [string | null];
  loadArtifacts: [string, PolicyArtifactType];
  submit: [PolicyCommand];
}>();

const form = ref<HTMLFormElement>();
const operation = ref<PolicyOperation>("CREATE_DRAFT");
const policyId = ref("");
const expectedVersion = ref(0);
const sourceVersion = ref("1");
const defaultDecision = ref<"DENY" | "KILL" | "PAUSE" | "REQUIRE_APPROVAL">("DENY");
const rulesJson = ref(JSON.stringify([{ rule_id: "deny-unreviewed-write", subject_pattern: "*",
  tool_pattern: "tool:write", resource_pattern: "*", decision: "DENY", maximum_risk: "CRITICAL",
  reason_code: "POLICY_DENY_UNREVIEWED_WRITE" }], null, 2));
const baselineDigest = ref("0".repeat(64));
const actionsJson = ref(JSON.stringify([{ action_id: "simulation-1", agent_id: "agent:example",
  subject: "subject:example", tool: "tool:read", resource: "repo:example", risk: "LOW" }], null, 2));
const simulationId = ref("");
const reviewDigest = ref("");
const bundleDigest = ref("");
const impactDigest = ref("");
const reasonDigest = ref("");
const environment = ref<"DEV" | "STAGING" | "CANARY" | "PRODUCTION">("DEV");
const exceptionId = ref("");
const ownerSubject = ref("");
const exceptionScope = ref("");
const compensatingControls = ref("");
const exceptionApprovals = ref(props.approvalIds.join("\n"));
const expiresAt = ref(toLocalDateTime(new Date(Date.now() + 86_400_000)));
const localError = ref("");

const artifactTypes: PolicyArtifactType[] = ["SOURCES", "ANALYSES", "REVIEWS", "SIMULATIONS",
  "IMPACT_REPORTS", "PROMOTIONS", "EXCEPTIONS"];
const operations: PolicyOperation[] = ["CREATE_DRAFT", "VALIDATE", "SIMULATE", "SHADOW_EVALUATE",
  "IMPACT_ANALYZE", "APPROVE", "SIGN", "PROMOTE", "ROLLBACK", "DEPRECATE", "CREATE_EXCEPTION",
  "REVOKE_EXCEPTION"];
const labels = computed(() => props.locale === "en-US" ? {
  title: "Policy Studio", authority: "Authoritative lifecycle", command: "Governed lifecycle action",
  policy: "Policy ID", version: "Expected resource version", submit: "Admit canonical action",
  pending: "Durably admitted; execution and lifecycle completion remain pending.", empty: "No authoritative policies.",
  load: "Load policies", older: "Next page", artifacts: "Lifecycle artifacts", sod: "Separation of duties",
  exception: "Exception expiry and compensating controls", strong: "Every action requires current strong authentication.",
} : {
  title: "Policy Studio", authority: "权威生命周期", command: "受治理生命周期动作",
  policy: "Policy ID", version: "预期资源版本", submit: "提交 Canonical Action",
  pending: "已持久接收；执行与生命周期完成仍在等待中。", empty: "暂无权威 Policy。",
  load: "加载 Policy", older: "下一页", artifacts: "生命周期产物", sod: "职责分离",
  exception: "例外到期与补偿控制", strong: "每个动作都要求当前强认证。",
});
const artifactRows = computed(() => (props.artifactPage?.items ?? []).map(safeArtifactSummary));
const separation = computed(() => {
  if (props.artifactPage?.artifact_type !== "REVIEWS") return null;
  const reviewers = new Set(props.artifactPage.items.filter(isRecord)
    .map((item) => String(item.reviewer_subject ?? "")).filter(Boolean));
  const author = props.page?.items.find((item) => item.policy_id === props.artifactPage?.policy_id)?.author_subject;
  return { reviewers: reviewers.size, authorExcluded: author ? !reviewers.has(author) : false,
    signingReady: reviewers.size >= 2 && Boolean(author) && !reviewers.has(String(author)) };
});

onMounted(() => emit("load", null));

function selectPolicy(id: string, resourceVersion: number): void {
  policyId.value = id;
  expectedVersion.value = resourceVersion;
}

async function submit(): Promise<void> {
  localError.value = "";
  if (!form.value?.reportValidity() || !/^[A-Za-z0-9._:/-]{1,256}$/.test(policyId.value)
    || !Number.isSafeInteger(expectedVersion.value) || expectedVersion.value < 0) return;
  try {
    const commandId = crypto.randomUUID();
    const requestedAt = new Date().toISOString();
    let payload: PolicyCommand["payload"];
    switch (operation.value) {
      case "CREATE_DRAFT": {
        const rules = parseRules(rulesJson.value);
        const source = { schema_version: "agenttrust.policy-admin.v1" as const,
          source_id: policyId.value, tenant_id: props.tenantId, version: sourceVersion.value.trim(),
          rules, default_decision: defaultDecision.value, author: props.requestedBy,
          source_digest: "", created_at: requestedAt };
        source.source_digest = await sha256Canonical(source);
        payload = { source };
        break;
      }
      case "VALIDATE": case "SIGN": payload = {}; break;
      case "SIMULATE": case "SHADOW_EVALUATE":
        payload = { baseline_bundle_digest: requireDigest(baselineDigest.value),
          actions: parseActions(actionsJson.value, props.tenantId) };
        break;
      case "IMPACT_ANALYZE":
        if (!isUuid(simulationId.value)) throw new Error("CONTROL_POLICY_SIMULATION_ID_INVALID");
        payload = { simulation_id: simulationId.value };
        break;
      case "APPROVE": payload = { decision: "APPROVE", review_digest: requireDigest(reviewDigest.value) }; break;
      case "PROMOTE": payload = { bundle_digest: requireDigest(bundleDigest.value),
        impact_report_digest: requireDigest(impactDigest.value), environment: environment.value }; break;
      case "ROLLBACK": payload = { target_bundle_digest: requireDigest(bundleDigest.value),
        reason_digest: requireDigest(reasonDigest.value), environment: environment.value }; break;
      case "DEPRECATE": payload = { bundle_digest: requireDigest(bundleDigest.value),
        reason_digest: requireDigest(reasonDigest.value) }; break;
      case "CREATE_EXCEPTION": {
        const approvalIds = lines(exceptionApprovals.value, 64, 256);
        const expiry = new Date(expiresAt.value);
        if (!isUuid(exceptionId.value) || ownerSubject.value === props.requestedBy || approvalIds.length < 2
          || !approvalIds.every((item) => props.approvalIds.includes(item))
          || expiry.getTime() <= Date.now() || expiry.getTime() > Date.now() + 30 * 86_400_000) {
          throw new Error("CONTROL_POLICY_EXCEPTION_INVALID");
        }
        payload = { exception_id: exceptionId.value, owner_subject: ownerSubject.value.trim(),
          scope: lines(exceptionScope.value, 128, 2_048), reason_digest: requireDigest(reasonDigest.value),
          compensating_controls: lines(compensatingControls.value, 64, 256), approval_ids: approvalIds,
          expires_at: expiry.toISOString() };
        break;
      }
      case "REVOKE_EXCEPTION":
        if (!isUuid(exceptionId.value)) throw new Error("CONTROL_POLICY_EXCEPTION_INVALID");
        payload = { exception_id: exceptionId.value, reason_digest: requireDigest(reasonDigest.value) };
        break;
    }
    emit("submit", { schema_version: "agenttrust.policy-command.v1", tenant_id: props.tenantId,
      command_id: commandId, policy_id: policyId.value, operation: operation.value,
      expected_resource_version: expectedVersion.value, payload, requested_at: requestedAt });
  } catch (error) {
    localError.value = error instanceof Error && /^[A-Z][A-Z0-9_]{2,120}$/.test(error.message)
      ? error.message : "CONTROL_POLICY_COMMAND_INVALID";
  }
}

function parseRules(value: string): PolicyRule[] {
  const parsed: unknown = JSON.parse(value);
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 10_000) throw new Error("CONTROL_POLICY_RULES_INVALID");
  for (const rule of parsed) {
    if (!isRecord(rule) || JSON.stringify(Object.keys(rule).sort()) !== JSON.stringify([
      "decision", "maximum_risk", "reason_code", "resource_pattern", "rule_id", "subject_pattern", "tool_pattern"])
      || !String(rule.rule_id).match(/^.{1,256}$/) || !["ALLOW", "DENY", "KILL", "PAUSE", "REQUIRE_APPROVAL"].includes(String(rule.decision))
      || !["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(String(rule.maximum_risk))
      || !/^[A-Z][A-Z0-9_]{2,127}$/.test(String(rule.reason_code))) throw new Error("CONTROL_POLICY_RULES_INVALID");
  }
  return parsed as PolicyRule[];
}

function parseActions(value: string, tenantId: string): PolicyAction[] {
  const parsed: unknown = JSON.parse(value);
  if (!Array.isArray(parsed) || parsed.length < 1 || parsed.length > 10_000) throw new Error("CONTROL_POLICY_ACTIONS_INVALID");
  return parsed.map((item) => {
    if (!isRecord(item) || JSON.stringify(Object.keys(item).sort()) !== JSON.stringify([
      "action_id", "agent_id", "resource", "risk", "subject", "tool"])
      || !["LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(String(item.risk))) throw new Error("CONTROL_POLICY_ACTIONS_INVALID");
    for (const key of ["action_id", "agent_id", "subject", "tool", "resource"] as const) {
      if (typeof item[key] !== "string" || !item[key] || item[key].length > (key === "resource" ? 2_048 : 1_024))
        throw new Error("CONTROL_POLICY_ACTIONS_INVALID");
    }
    return { ...item, tenant_id: tenantId } as PolicyAction;
  });
}

function lines(value: string, maximum: number, length: number): string[] {
  const result = [...new Set(value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean))].sort();
  if (result.length < 1 || result.length > maximum || result.some((item) => item.length > length))
    throw new Error("CONTROL_POLICY_BOUNDED_LIST_INVALID");
  return result;
}
function requireDigest(value: string): string {
  if (!/^[a-f0-9]{64}$/.test(value)) throw new Error("CONTROL_POLICY_DIGEST_INVALID");
  return value;
}
function safeArtifactSummary(value: unknown): { id: string; details: string[] } {
  if (!isRecord(value)) return { id: "INVALID", details: ["CONTROL_POLICY_ARTIFACT_INVALID"] };
  const id = String(value.source_id ?? value.review_id ?? value.simulation_id ?? value.impact_report_id
    ?? value.promotion_digest ?? value.exception_id ?? "artifact");
  const details = Object.entries(value).filter(([key, item]) => ["schema_version", "version", "revision", "valid",
    "decision", "run_kind", "evaluated_actions", "difference_count", "side_effect_count", "environment", "state",
    "source_digest", "review_digest", "impact_report_digest", "promotion_digest", "scope_digest", "reason_digest",
    "owner_subject", "expires_at", "revoked_at", "expired_at"].includes(key)
      && (typeof item === "string" || typeof item === "number" || typeof item === "boolean" || item === null))
    .slice(0, 16).map(([key, item]) => `${key}: ${String(item)}`);
  if (Array.isArray(value.compensating_controls)) details.push(`compensating_controls: ${value.compensating_controls.join(", ")}`);
  return { id: id.slice(0, 256), details };
}
function toLocalDateTime(value: Date): string {
  return new Date(value.getTime() - value.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
}
</script>

<template>
  <section aria-labelledby="policy-studio-title">
    <h2 id="policy-studio-title">{{ labels.title }}</h2>
    <p class="authority-note">{{ labels.strong }}</p>
    <p v-if="error || localError" role="alert">{{ error || localError }}</p>

    <section aria-labelledby="policy-authority-title">
      <h3 id="policy-authority-title">{{ labels.authority }}</h3>
      <button type="button" :disabled="busy" @click="emit('load', null)">{{ labels.load }}</button>
      <p v-if="!page?.items.length" role="status">{{ labels.empty }}</p>
      <table v-else>
        <thead><tr><th>Policy</th><th>State</th><th>Revision</th><th>Resource version</th><th>Active</th><th>Action</th></tr></thead>
        <tbody><tr v-for="item in page.items" :key="item.policy_id">
          <td><code>{{ item.policy_id }}</code></td><td>{{ item.lifecycle_state }}</td><td>{{ item.revision }}</td>
          <td>{{ item.resource_version }}</td><td>{{ item.active_environment ?? '—' }}</td>
          <td><button type="button" :disabled="busy" :aria-label="`Select ${item.policy_id}`"
            @click="selectPolicy(item.policy_id, item.resource_version)">Select</button></td>
        </tr></tbody>
      </table>
      <button v-if="page?.next_after_policy_id" type="button" :disabled="busy"
        @click="emit('load', page.next_after_policy_id)">{{ labels.older }}</button>
    </section>

    <section aria-labelledby="policy-artifacts-title">
      <h3 id="policy-artifacts-title">{{ labels.artifacts }}</h3>
      <div class="button-row">
        <button v-for="type in artifactTypes" :key="type" type="button" :disabled="busy || !policyId"
          @click="emit('loadArtifacts', policyId, type)">{{ type }}</button>
      </div>
      <p v-if="separation"><strong>{{ labels.sod }}:</strong> reviewers={{ separation.reviewers }},
        author_excluded={{ separation.authorExcluded }}, signing_ready={{ separation.signingReady }}</p>
      <article v-for="item in artifactRows" :key="item.id" class="artifact-card">
        <h4><code>{{ item.id }}</code></h4><ul><li v-for="detail in item.details" :key="detail">{{ detail }}</li></ul>
      </article>
    </section>

    <form ref="form" class="admin-form" aria-labelledby="policy-command-title" @submit.prevent="submit">
      <h3 id="policy-command-title">{{ labels.command }}</h3>
      <label for="policy-id">{{ labels.policy }}</label>
      <input id="policy-id" v-model="policyId" required pattern="[A-Za-z0-9._:/-]{1,256}" maxlength="256" autocomplete="off">
      <label for="policy-operation">Operation</label>
      <select id="policy-operation" v-model="operation"><option v-for="item in operations" :key="item">{{ item }}</option></select>
      <label for="policy-resource-version">{{ labels.version }}</label>
      <input id="policy-resource-version" v-model.number="expectedVersion" required type="number" min="0" step="1">

      <fieldset v-if="operation === 'CREATE_DRAFT'"><legend>Immutable source revision</legend>
        <label>Version <input v-model="sourceVersion" required maxlength="128"></label>
        <label>Default decision <select v-model="defaultDecision"><option>DENY</option><option>KILL</option><option>PAUSE</option><option>REQUIRE_APPROVAL</option></select></label>
        <label>Rules JSON <textarea v-model="rulesJson" required maxlength="900000" rows="12" spellcheck="false" /></label>
      </fieldset>
      <fieldset v-else-if="operation === 'SIMULATE' || operation === 'SHADOW_EVALUATE'"><legend>Side-effect-free corpus</legend>
        <label>Baseline bundle digest <input v-model="baselineDigest" required pattern="[a-f0-9]{64}" maxlength="64"></label>
        <label>Bounded actions JSON <textarea v-model="actionsJson" required maxlength="900000" rows="10" spellcheck="false" /></label>
      </fieldset>
      <fieldset v-else-if="operation === 'IMPACT_ANALYZE'"><legend>Impact input</legend>
        <label>Simulation UUID <input v-model="simulationId" required pattern="[0-9a-f-]{36}" maxlength="36"></label>
      </fieldset>
      <fieldset v-else-if="operation === 'APPROVE'"><legend>Independent review</legend>
        <label>Review digest <input v-model="reviewDigest" required pattern="[a-f0-9]{64}" maxlength="64"></label>
      </fieldset>
      <fieldset v-else-if="['PROMOTE','ROLLBACK','DEPRECATE'].includes(operation)"><legend>Signed bundle reference</legend>
        <label>Bundle digest <input v-model="bundleDigest" required pattern="[a-f0-9]{64}" maxlength="64"></label>
        <label v-if="operation === 'PROMOTE'">Impact report digest <input v-model="impactDigest" required pattern="[a-f0-9]{64}" maxlength="64"></label>
        <label v-else>Reason digest <input v-model="reasonDigest" required pattern="[a-f0-9]{64}" maxlength="64"></label>
        <label v-if="operation !== 'DEPRECATE'">Environment <select v-model="environment"><option>DEV</option><option>STAGING</option><option>CANARY</option><option>PRODUCTION</option></select></label>
      </fieldset>
      <fieldset v-else-if="operation === 'CREATE_EXCEPTION'"><legend>{{ labels.exception }}</legend>
        <label>Exception UUID <input v-model="exceptionId" required pattern="[0-9a-f-]{36}" maxlength="36"></label>
        <label>Owner subject <input v-model="ownerSubject" required pattern="[A-Za-z0-9._:/@-]{1,256}" maxlength="256"></label>
        <label>Scope, one per line <textarea v-model="exceptionScope" required maxlength="262144" /></label>
        <label>Reason digest <input v-model="reasonDigest" required pattern="[a-f0-9]{64}" maxlength="64"></label>
        <label>Compensating controls, one per line <textarea v-model="compensatingControls" required maxlength="16384" /></label>
        <label>Approval IDs, one per line <textarea v-model="exceptionApprovals" required maxlength="16384" /></label>
        <label>Expires within 30 days <input v-model="expiresAt" required type="datetime-local"></label>
      </fieldset>
      <fieldset v-else-if="operation === 'REVOKE_EXCEPTION'"><legend>Revoke exception</legend>
        <label>Exception UUID <input v-model="exceptionId" required pattern="[0-9a-f-]{36}" maxlength="36"></label>
        <label>Reason digest <input v-model="reasonDigest" required pattern="[a-f0-9]{64}" maxlength="64"></label>
      </fieldset>
      <p v-else>{{ operation }} uses an exact empty payload; authority preconditions still apply.</p>
      <button type="submit" :disabled="busy">{{ labels.submit }}</button>
    </form>

    <aside v-if="receipt" aria-live="polite" class="action-receipt">
      <h3>Policy action {{ receipt.action_id }}</h3><p>{{ labels.pending }}</p>
      <p>Task: <code>{{ receipt.task_id }}</code></p>
      <p>Ledger evidence: <code>{{ receipt.ledger_evidence_ref }}</code></p>
    </aside>
  </section>
</template>
