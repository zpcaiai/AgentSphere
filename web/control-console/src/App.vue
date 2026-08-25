<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import type { ApprovalIntent, AgUiEventEnvelope } from "../../shared/agui-client";
import { AgUiResumeClient, createEd25519Verifier } from "../../shared/agui-client";
import ControlConsole from "./ControlConsole.vue";
import { ControlApiClient, ControlApiError } from "./api-client";
import { approvalIdempotencyKey, buildAdminIntent, extractTaskAuthorityStatuses, isUuid,
  type EnterpriseDashboard, type TaskAuthorityStatus } from "./control-state";
import type {
  AgentInventoryItem,
  AuthorityPage,
  EnterpriseActionReceipt,
  GovernedWriteCommand,
  Incident,
  IncidentActionReceipt,
  IncidentCommand,
  IncidentPage,
  MarketplaceActionReceipt,
  MarketplaceCommand,
  PackPage,
  PolicyActionReceipt,
  PolicyArtifactPage,
  PolicyArtifactType,
  PolicyCommand,
  PolicyPage,
} from "./enterprise-api-types";

interface BootContext {
  tenantId: string;
  requestedBy: string;
  projectId: string | null;
  approvalIds: string[];
  approvalStrongAuth: boolean;
  csrfToken: string;
}

const context = ref<BootContext | null>(null);
const client = ref<ControlApiClient | null>(null);
const dashboard = ref<EnterpriseDashboard | null>(null);
const tasks = ref<TaskAuthorityStatus[]>([]);
const events = ref<AgUiEventEnvelope[]>([]);
const eventTaskId = ref("");
const agentPage = ref<AuthorityPage<AgentInventoryItem> | null>(null);
const policyPage = ref<PolicyPage | null>(null);
const policyArtifactPage = ref<PolicyArtifactPage | null>(null);
const policyReceipt = ref<PolicyActionReceipt | null>(null);
const incidentPage = ref<IncidentPage | null>(null);
const incidentDetail = ref<Incident | null>(null);
const incidentReceipt = ref<IncidentActionReceipt | null>(null);
const packPage = ref<PackPage | null>(null);
const packReceipt = ref<MarketplaceActionReceipt | null>(null);
const actionReceipt = ref<EnterpriseActionReceipt | null>(null);
const fatalError = ref("");
const moduleError = ref("");
const streamError = ref("");
const operationMessage = ref("");
const signInUrl = ref("");
const inFlight = ref(0);
const busy = computed(() => inFlight.value > 0);
const locale = ref<"zh-CN" | "en-US">(navigator.language.toLocaleLowerCase().startsWith("zh") ? "zh-CN" : "en-US");
let agUiClient: AgUiResumeClient | null = null;

onMounted(async () => {
  try {
    client.value = new ControlApiClient(import.meta.env.VITE_CONTROL_API_URL);
    signInUrl.value = client.value.signInUrl();
    const session = await client.value.session();
    if (!isUuid(session.tenant_id)) throw new Error("CONTROL_SESSION_INVALID");
    context.value = {
      tenantId: session.tenant_id,
      requestedBy: session.subject,
      // A multi-project session does not imply a safe default project scope.
      projectId: session.project_ids.length === 1 ? session.project_ids[0] ?? null : null,
      approvalIds: [...new Set(session.approval_ids)].sort(),
      approvalStrongAuth: session.strong_auth,
      csrfToken: session.csrf_token,
    };
    await loadDashboard();
  } catch (error) {
    fatalError.value = safeCode(error, "CONTROL_CONSOLE_BOOT_FAILED");
  }
});

onBeforeUnmount(() => {
  actionReceipt.value = null;
  events.value = [];
  agUiClient?.clear();
});

async function loadDashboard(): Promise<void> {
  if (!client.value || !context.value) throw new Error("CONTROL_CONSOLE_NOT_READY");
  await run(async () => {
    const authoritative = await client.value!.dashboard(context.value!.tenantId);
    const authoritativeTasks = extractTaskAuthorityStatuses(authoritative);
    dashboard.value = authoritative;
    tasks.value = authoritativeTasks;
    operationMessage.value = "";
  }, (code) => { fatalError.value = code; });
}

async function submitGoverned(command: GovernedWriteCommand): Promise<void> {
  if (!client.value || !context.value) return;
  moduleError.value = "";
  operationMessage.value = "";
  await run(async () => {
    const governed = await buildAdminIntent({
      tenant_id: context.value!.tenantId,
      project_id: context.value!.projectId,
      operation: command.kind,
      resource: command.resource,
      requested_by: context.value!.requestedBy,
      approval_ids: context.value!.approvalIds,
      reason: command.reason,
      csrf_token: context.value!.csrfToken,
      payload: command.payload,
    });
    switch (command.kind) {
      case "CREATE_TENANT": actionReceipt.value = await client.value!.createTenant(command.payload, governed); break;
      case "CREATE_ORGANIZATION": actionReceipt.value = await client.value!.createOrganization(command.payload, governed); break;
      case "CREATE_PROJECT": actionReceipt.value = await client.value!.createProject(command.payload, governed); break;
      case "CREATE_INTEGRATION": actionReceipt.value = await client.value!.createIntegration(command.payload, governed); break;
      case "CONSUME_QUOTA": actionReceipt.value = await client.value!.consumeQuota(command.payload, governed); break;
      case "RECORD_COST": actionReceipt.value = await client.value!.recordCost(command.payload, governed); break;
      case "ISSUE_API_KEY": actionReceipt.value = await client.value!.issueApiKey(command.payload, governed); break;
      case "REVOKE_API_KEY": actionReceipt.value = await client.value!.revokeApiKey(command.payload, governed); break;
      default:
        if (command.kind.startsWith("TASK_")) {
          await client.value!.submitTaskCommand(command.resource.slice("task:".length), command.payload, governed);
        } else {
          throw new Error("CONTROL_OPERATION_UNSUPPORTED");
        }
    }
    operationMessage.value = locale.value === "en-US"
      ? "Intent accepted for authoritative processing; this is not a success or authorization claim."
      : "意图已进入权威处理；这不代表动作成功或已获授权。";
  }, (code) => { moduleError.value = code; });
}

async function submitApproval(value: ApprovalIntent): Promise<void> {
  if (!client.value || !context.value) return;
  await run(async () => {
    const retryKey = await approvalIdempotencyKey(
      context.value!.tenantId,
      context.value!.requestedBy,
      value,
    );
    const receipt = await client.value!.submitApprovalIntent(
      context.value!.tenantId, value, context.value!.csrfToken, retryKey,
    );
    operationMessage.value = locale.value === "en-US"
      ? `Approval decision receipt verified (${receipt.case_status}); downstream action execution is not implied.`
      : `审批决定回执已验证（${receipt.case_status}）；这不代表下游动作已经执行。`;
    await refreshDashboardWithoutBusyReset();
  }, (code) => { moduleError.value = code; });
}

async function loadAgents(cursor: string | null): Promise<void> {
  if (!client.value || !context.value) return;
  await run(async () => {
    agentPage.value = await client.value!.listAgents(context.value!.tenantId, cursor, 50);
  }, (code) => { moduleError.value = code; });
}

async function loadPolicies(afterPolicyId: string | null): Promise<void> {
  if (!client.value || !context.value) return;
  await run(async () => {
    policyPage.value = await client.value!.listPolicies(context.value!.tenantId, afterPolicyId, 50);
  }, (code) => { moduleError.value = code; });
}

async function loadPolicyArtifacts(policyId: string, artifactType: PolicyArtifactType): Promise<void> {
  if (!client.value || !context.value) return;
  await run(async () => {
    policyArtifactPage.value = await client.value!.listPolicyArtifacts(
      context.value!.tenantId, policyId, artifactType, 50);
  }, (code) => { moduleError.value = code; });
}

async function submitPolicy(command: PolicyCommand): Promise<void> {
  if (!client.value || !context.value) return;
  await run(async () => {
    policyReceipt.value = await client.value!.submitPolicyAction(command, context.value!.csrfToken);
    operationMessage.value = locale.value === "en-US"
      ? "Policy workflow admitted; execution and authoritative lifecycle state are still pending."
      : "Policy 工作流已持久接收；执行与权威生命周期状态仍在等待中。";
  }, (code) => { moduleError.value = code; });
}

async function loadIncidents(afterIncidentId: string | null): Promise<void> {
  if (!client.value || !context.value) return;
  moduleError.value = "";
  incidentPage.value = null;
  incidentDetail.value = null;
  await run(async () => {
    incidentPage.value = await client.value!.listIncidents(
      context.value!.tenantId, afterIncidentId, 50);
  }, (code) => { moduleError.value = code; });
}

async function loadIncidentDetail(incidentId: string): Promise<void> {
  if (!client.value || !context.value) return;
  moduleError.value = "";
  incidentDetail.value = null;
  await run(async () => {
    incidentDetail.value = await client.value!.getIncident(context.value!.tenantId, incidentId);
  }, (code) => { moduleError.value = code; });
}

async function submitIncident(command: IncidentCommand): Promise<void> {
  if (!client.value || !context.value) return;
  moduleError.value = "";
  operationMessage.value = "";
  incidentReceipt.value = null;
  await run(async () => {
    incidentReceipt.value = await client.value!.submitIncidentAction(
      command, context.value!.csrfToken);
    operationMessage.value = locale.value === "en-US"
      ? "Incident action admitted; execution and authoritative incident or release state remain pending."
      : "事件动作已持久接收；执行及权威事件或发布状态仍在等待中。";
  }, (code) => { moduleError.value = code; });
}

async function loadPacks(search: string, afterPackId: string | null): Promise<void> {
  if (!client.value || !context.value) return;
  moduleError.value = "";
  packPage.value = null;
  await run(async () => {
    packPage.value = await client.value!.listPacks(
      context.value!.tenantId, search, afterPackId, 50);
  }, (code) => { moduleError.value = code; });
}

async function submitPack(command: MarketplaceCommand): Promise<void> {
  if (!client.value || !context.value) return;
  moduleError.value = "";
  operationMessage.value = "";
  packReceipt.value = null;
  await run(async () => {
    packReceipt.value = await client.value!.submitPackAction(command, context.value!.csrfToken);
    operationMessage.value = locale.value === "en-US"
      ? "Pack action admitted; lifecycle execution and per-task authorization remain pending."
      : "Pack 动作已持久接收；生命周期执行与逐任务授权仍在等待中。";
  }, (code) => { moduleError.value = code; });
}

async function resumeTask(taskId: string): Promise<void> {
  if (!context.value) return;
  streamError.value = "";
  await run(async () => {
    if (!agUiClient) {
      const verifier = await createEd25519Verifier(import.meta.env.VITE_AGUI_VERIFY_KEY);
      agUiClient = new AgUiResumeClient(import.meta.env.VITE_CONTROL_API_URL, context.value!.tenantId, verifier,
        { maximumEvents: 100, maximumResponseBytes: 1_000_000, timeoutMs: 10_000 });
    }
    const applied = await agUiClient.resume(taskId);
    if (eventTaskId.value !== taskId) events.value = [];
    eventTaskId.value = taskId;
    events.value = [...events.value, ...applied].slice(-500);
  }, (code) => { streamError.value = code; });
}

async function signOut(): Promise<void> {
  if (!client.value || !context.value) return;
  await run(async () => {
    await client.value!.logout(context.value!.csrfToken);
    agUiClient?.clear();
    context.value = null;
    dashboard.value = null;
    tasks.value = [];
    events.value = [];
    actionReceipt.value = null;
    policyPage.value = null;
    policyArtifactPage.value = null;
    policyReceipt.value = null;
    incidentPage.value = null;
    incidentDetail.value = null;
    incidentReceipt.value = null;
    packPage.value = null;
    packReceipt.value = null;
    fatalError.value = "CONTROL_SIGNED_OUT";
  }, (code) => { moduleError.value = code; });
}

async function refreshDashboardWithoutBusyReset(): Promise<void> {
  if (!client.value || !context.value) return;
  const authoritative = await client.value.dashboard(context.value.tenantId);
  dashboard.value = authoritative;
  tasks.value = extractTaskAuthorityStatuses(authoritative);
}

async function run(action: () => Promise<void>, fail: (code: string) => void): Promise<void> {
  inFlight.value += 1;
  try { await action(); }
  catch (error) { fail(safeCode(error, "CONTROL_OPERATION_FAILED")); }
  finally { inFlight.value -= 1; }
}

function safeCode(error: unknown, fallback: string): string {
  if (error instanceof ControlApiError) return error.code;
  if (error instanceof Error && /^[A-Z][A-Z0-9_]{2,120}$/.test(error.message)) return error.message;
  return fallback;
}
</script>

<template>
  <div v-if="fatalError" class="fatal-error" role="alert">
    <h1>Agent Trust Control Console</h1>
    <p>{{ fatalError }}</p>
    <p>{{ locale === 'en-US' ? 'No authority data or write controls are rendered.' : '不会渲染权威数据或写入控件。' }}</p>
    <a v-if="signInUrl" class="sign-in" :href="signInUrl">{{ locale === 'en-US' ? 'Sign in with enterprise identity' : '使用企业身份登录' }}</a>
  </div>
  <p v-else-if="!dashboard || !context" class="loading" role="status">{{ locale === 'en-US' ? 'Loading authoritative state…' : '正在加载权威状态…' }}</p>
  <ControlConsole v-else :dashboard="dashboard" :tasks="tasks" :events="events" :agent-page="agentPage"
    :policy-page="policyPage" :policy-artifact-page="policyArtifactPage"
    :policy-receipt="policyReceipt" :action-receipt="actionReceipt"
    :incident-page="incidentPage" :incident-detail="incidentDetail"
    :incident-receipt="incidentReceipt" :pack-page="packPage" :pack-receipt="packReceipt"
    :tenant-id="context.tenantId" :requested-by="context.requestedBy" :approval-ids="context.approvalIds"
    :project-id="context.projectId" :busy="busy" :operation-message="operationMessage"
    :approval-strong-auth="context.approvalStrongAuth"
    :stream-error="streamError" :module-error="moduleError" :locale="locale"
    @refresh="loadDashboard" @governed-write="submitGoverned" @approval-intent="submitApproval"
    @resume-task="resumeTask" @load-agents="loadAgents" @load-policies="loadPolicies"
    @load-policy-artifacts="loadPolicyArtifacts" @submit-policy="submitPolicy"
    @load-incidents="loadIncidents" @load-incident-detail="loadIncidentDetail"
    @submit-incident="submitIncident" @load-packs="loadPacks" @submit-pack="submitPack"
    @clear-receipt="actionReceipt = null" @sign-out="signOut" @set-locale="locale = $event" />
</template>
