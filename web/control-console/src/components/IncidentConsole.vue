<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { incidentPayloadTemplate, incidentResource, INCIDENT_OPERATIONS,
  prepareIncidentPayload } from "../incident-command";
import { isUuid } from "../control-state";
import type { Incident, IncidentActionReceipt, IncidentCommand, IncidentOperation,
  IncidentPage } from "../enterprise-api-types";

const props = withDefaults(defineProps<{
  tenantId: string;
  requestedBy: string;
  approvalIds: string[];
  page?: IncidentPage | null;
  detail?: Incident | null;
  receipt?: IncidentActionReceipt | null;
  busy?: boolean;
  error?: string;
  locale?: "zh-CN" | "en-US";
}>(), { page: null, detail: null, receipt: null, busy: false, error: "", locale: "zh-CN" });

const emit = defineEmits<{
  load: [string | null];
  loadDetail: [string];
  submit: [IncidentCommand];
}>();

const form = ref<HTMLFormElement>();
const operation = ref<IncidentOperation>("TRIAGE");
const incidentId = ref("");
const releaseId = ref("");
const taskId = ref("");
const expectedVersion = ref(1);
const payloadJson = ref("");
const localError = ref("");
const releaseOperations = new Set<IncidentOperation>([
  "EVALUATE_RELEASE", "START_CANARY", "RECORD_CANARY", "ROLLBACK_RELEASE",
]);
const labels = computed(() => props.locale === "en-US" ? {
  title: "Incident, replay, and release console", authority: "Authoritative incident timeline",
  load: "Load incidents", empty: "No authoritative incidents.", next: "Next page",
  action: "Governed incident or release action", submit: "Admit canonical incident action",
  pending: "Durably admitted; execution, remediation, release, and rollback state remain pending.",
  boundary: "Logical replay has no resources. Sandbox replay uses test-only credentials. Live replay and release actions require fresh leases and independent approvals.",
} : {
  title: "事件、回放与发布控制台", authority: "权威事件时间线", load: "加载事件",
  empty: "暂无权威事件。", next: "下一页", action: "受治理事件或发布动作",
  submit: "提交 Canonical Incident Action",
  pending: "已持久接收；执行、修复、发布与回滚状态仍在等待中。",
  boundary: "逻辑回放不接触资源；沙箱回放只能使用 test-only 凭据；真实回放和发布动作要求新租约与独立审批。",
});
const selectedTimeline = computed(() => props.detail?.timeline ?? []);
const selectedEvidence = computed(() => props.detail?.evidence_refs ?? []);
const requiresTwoApprovals = computed(() => releaseOperations.has(operation.value)
  || operation.value === "PLAN_REPLAY" && /"mode"\s*:\s*"LIVE"/.test(payloadJson.value)
  || operation.value === "COMPLETE_REPLAY" && /"mode"\s*:\s*"LIVE"/.test(payloadJson.value));

watch(operation, (value) => {
  payloadJson.value = JSON.stringify(incidentPayloadTemplate(
    value, props.requestedBy, props.approvalIds.length), null, 2);
  localError.value = "";
}, { immediate: true });
onMounted(() => emit("load", null));

function selectIncident(item: Incident): void {
  incidentId.value = item.incident_id;
  taskId.value = item.task_id;
  expectedVersion.value = item.resource_version;
  emit("loadDetail", item.incident_id);
}

async function submit(): Promise<void> {
  localError.value = "";
  if (!form.value?.reportValidity() || !isUuid(taskId.value)
    || !Number.isSafeInteger(expectedVersion.value) || expectedVersion.value < 0) return;
  try {
    if (requiresTwoApprovals.value && props.approvalIds.length < 2) {
      throw new Error("CONTROL_INCIDENT_INDEPENDENT_APPROVAL_REQUIRED");
    }
    const parsed: unknown = JSON.parse(payloadJson.value);
    const payload = await prepareIncidentPayload(operation.value, parsed, props.approvalIds.length);
    emit("submit", { schema_version: "agenttrust.incident-command.v1", tenant_id: props.tenantId,
      command_id: crypto.randomUUID(), resource_id: incidentResource(operation.value,
        incidentId.value, releaseId.value), task_id: taskId.value, operation: operation.value,
      expected_resource_version: expectedVersion.value, requested_at: new Date().toISOString(),
      payload: payload as IncidentCommand["payload"] });
  } catch (error) {
    localError.value = error instanceof Error && /^[A-Z][A-Z0-9_]{2,120}$/.test(error.message)
      ? error.message : "CONTROL_INCIDENT_COMMAND_INVALID";
  }
}
</script>

<template>
  <section aria-labelledby="incident-console-title">
    <h2 id="incident-console-title">{{ labels.title }}</h2>
    <p class="authority-note">{{ labels.boundary }}</p>
    <p v-if="error || localError" role="alert">{{ error || localError }}</p>

    <section aria-labelledby="incident-authority-title">
      <h3 id="incident-authority-title">{{ labels.authority }}</h3>
      <button type="button" :disabled="busy" @click="emit('load', null)">{{ labels.load }}</button>
      <p v-if="!page?.items.length" role="status">{{ labels.empty }}</p>
      <div v-else class="table-scroll">
        <table>
          <thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Owner</th>
            <th>Resource version</th><th>Updated</th><th>Action</th></tr></thead>
          <tbody><tr v-for="item in page.items" :key="item.incident_id">
            <td><code>{{ item.incident_id }}</code><br>{{ item.safe_summary }}</td>
            <td>{{ item.severity }}</td><td>{{ item.status }}</td><td>{{ item.owner }}</td>
            <td>{{ item.resource_version }}</td><td>{{ item.updated_at }}</td>
            <td><button type="button" :disabled="busy" :aria-label="`Select incident ${item.incident_id}`"
              @click="selectIncident(item)">Select</button></td>
          </tr></tbody>
        </table>
      </div>
      <button v-if="page?.next_after_incident_id" type="button" :disabled="busy"
        @click="emit('load', page.next_after_incident_id)">{{ labels.next }}</button>
    </section>

    <section v-if="detail" aria-labelledby="incident-detail-title">
      <h3 id="incident-detail-title">Incident <code>{{ detail.incident_id }}</code></h3>
      <dl><dt>Status</dt><dd>{{ detail.status }}</dd><dt>Task</dt><dd><code>{{ detail.task_id }}</code></dd>
        <dt>Legal hold</dt><dd><code>{{ detail.legal_hold_id }}</code></dd>
        <dt>Scope</dt><dd>{{ detail.scope.join(', ') }}</dd></dl>
      <h4>Evidence</h4><ul><li v-for="item in selectedEvidence" :key="item"><code>{{ item }}</code></li></ul>
      <h4>Timeline</h4>
      <div class="table-scroll"><table><thead><tr><th>Sequence</th><th>Event</th><th>Transition</th>
        <th>Actor / reason</th><th>Authorization evidence</th><th>Occurred</th></tr></thead>
        <tbody><tr v-for="item in selectedTimeline" :key="item.event_id"><td>{{ item.sequence }}</td>
          <td>{{ item.event_type }}</td><td>{{ item.from_status ?? '—' }} → {{ item.to_status ?? '—' }}</td>
          <td>{{ item.actor_subject }}<br><code>{{ item.reason_code }}</code></td>
          <td><code>{{ item.authorization_evidence_ref }}</code><br><code>{{ item.authorization_evidence_digest }}</code></td>
          <td>{{ item.occurred_at }}</td></tr></tbody></table></div>
    </section>

    <form ref="form" class="admin-form" aria-labelledby="incident-action-title" @submit.prevent="submit">
      <h3 id="incident-action-title">{{ labels.action }}</h3>
      <label for="incident-operation">Operation
        <select id="incident-operation" v-model="operation"><option v-for="item in INCIDENT_OPERATIONS" :key="item">{{ item }}</option></select>
      </label>
      <label v-if="!releaseOperations.has(operation)" for="incident-id">Incident UUID
        <input id="incident-id" v-model="incidentId" required pattern="[0-9a-fA-F-]{36}" maxlength="36" autocomplete="off">
      </label>
      <label v-else for="incident-release-id">Release resource
        <input id="incident-release-id" v-model="releaseId" required pattern="[A-Za-z0-9][A-Za-z0-9._:/-]{0,1015}" maxlength="1016" autocomplete="off">
      </label>
      <label for="incident-task-id">Task UUID
        <input id="incident-task-id" v-model="taskId" required pattern="[0-9a-fA-F-]{36}" maxlength="36" autocomplete="off">
      </label>
      <label for="incident-resource-version">Expected resource version
        <input id="incident-resource-version" v-model.number="expectedVersion" required type="number" min="0" step="1">
      </label>
      <label for="incident-payload">Exact typed payload JSON
        <textarea id="incident-payload" v-model="payloadJson" required rows="18" maxlength="900000" spellcheck="false" />
      </label>
      <p v-if="requiresTwoApprovals" class="banner warning" role="note">
        {{ locale === 'en-US' ? `Independent approvals present: ${approvalIds.length}/2.` : `独立审批数量：${approvalIds.length}/2。` }}
      </p>
      <button type="submit" :disabled="busy">{{ labels.submit }}</button>
    </form>

    <aside v-if="receipt" class="action-receipt" aria-live="polite">
      <h3>Incident action <code>{{ receipt.action_id }}</code></h3><p>{{ labels.pending }}</p>
      <p>Task: <code>{{ receipt.task_id }}</code></p>
      <p>Ledger evidence: <code>{{ receipt.ledger_evidence_ref }}</code></p>
    </aside>
  </section>
</template>
