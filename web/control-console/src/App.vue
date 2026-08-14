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
  ApiKeyIssueResponse,
  AuthorityPage,
  GovernedWriteCommand,
  PolicySimulationRequest,
  PolicySimulationResult,
  QuotaUsage,
} from "./enterprise-api-types";

interface BootContext {
  tenantId: string;
  requestedBy: string;
  projectId: string | null;
  approvalIds: string[];
  csrfToken: string;
}

const context = ref<BootContext | null>(null);
const client = ref<ControlApiClient | null>(null);
const dashboard = ref<EnterpriseDashboard | null>(null);
const tasks = ref<TaskAuthorityStatus[]>([]);
const events = ref<AgUiEventEnvelope[]>([]);
const eventTaskId = ref("");
const agentPage = ref<AuthorityPage<AgentInventoryItem> | null>(null);
const policySimulation = ref<PolicySimulationResult | null>(null);
const issuedApiKey = ref<ApiKeyIssueResponse | null>(null);
const quotaUsage = ref<QuotaUsage | null>(null);
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
      csrfToken: session.csrf_token,
    };
    await loadDashboard();
  } catch (error) {
    fatalError.value = safeCode(error, "CONTROL_CONSOLE_BOOT_FAILED");
  }
});

onBeforeUnmount(() => {
  issuedApiKey.value = null;
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
      case "CREATE_TENANT": await client.value!.createTenant(command.payload, governed); break;
      case "CREATE_ORGANIZATION": await client.value!.createOrganization(command.payload, governed); break;
      case "CREATE_PROJECT": await client.value!.createProject(command.payload, governed); break;
      case "CREATE_INTEGRATION": await client.value!.createIntegration(command.payload, governed); break;
      case "CONSUME_QUOTA": quotaUsage.value = await client.value!.consumeQuota(command.payload, governed); break;
      case "RECORD_COST": await client.value!.recordCost(command.payload, governed); break;
      case "ISSUE_API_KEY":
        issuedApiKey.value = await client.value!.issueApiKey(command.payload, governed);
        break;
      case "REVOKE_API_KEY": await client.value!.revokeApiKey(command.payload, governed); break;
      case "PROMOTE_POLICY":
        await client.value!.promotePolicy(command.resource.slice("policy:".length), command.payload, governed);
        break;
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
    await client.value!.submitApprovalIntent(context.value!.tenantId, value, context.value!.csrfToken, retryKey);
    operationMessage.value = locale.value === "en-US"
      ? "Approval intent accepted; status remains unchanged until a signed authority event arrives."
      : "审批意图已接收；在签名权威事件到达前状态保持不变。";
    await refreshDashboardWithoutBusyReset();
  }, (code) => { moduleError.value = code; });
}

async function loadAgents(cursor: string | null): Promise<void> {
  if (!client.value || !context.value) return;
  await run(async () => {
    agentPage.value = await client.value!.listAgents(context.value!.tenantId, cursor, 50);
  }, (code) => { moduleError.value = code; });
}

async function simulatePolicy(bundleId: string, request: PolicySimulationRequest): Promise<void> {
  if (!client.value || !context.value) return;
  await run(async () => {
    policySimulation.value = await client.value!.simulatePolicy(context.value!.tenantId, bundleId, request,
      context.value!.csrfToken);
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
    issuedApiKey.value = null;
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
    :policy-simulation="policySimulation" :issued-api-key="issuedApiKey" :quota-usage="quotaUsage"
    :project-id="context.projectId" :busy="busy" :operation-message="operationMessage"
    :stream-error="streamError" :module-error="moduleError" :locale="locale"
    @refresh="loadDashboard" @governed-write="submitGoverned" @approval-intent="submitApproval"
    @resume-task="resumeTask" @load-agents="loadAgents" @simulate-policy="simulatePolicy"
    @clear-api-key="issuedApiKey = null" @sign-out="signOut" @set-locale="locale = $event" />
</template>
