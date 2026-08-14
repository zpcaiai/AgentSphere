<script setup lang="ts">
import { computed, reactive, ref } from "vue";
import type { ApiKeyIssueResponse, GovernedWriteCommand, QuotaUsage } from "../enterprise-api-types";

const props = withDefaults(defineProps<{
  tenantId: string;
  projectId: string | null;
  busy?: boolean;
  issuedApiKey?: ApiKeyIssueResponse | null;
  quotaUsage?: QuotaUsage | null;
  locale?: "zh-CN" | "en-US";
}>(), { busy: false, issuedApiKey: null, quotaUsage: null, locale: "zh-CN" });

const emit = defineEmits<{
  submit: [GovernedWriteCommand];
  clearApiKey: [];
}>();

type Operation = "CREATE_TENANT" | "CREATE_ORGANIZATION" | "CREATE_PROJECT" | "CREATE_INTEGRATION"
  | "CONSUME_QUOTA" | "RECORD_COST" | "ISSUE_API_KEY" | "REVOKE_API_KEY" | "PROMOTE_POLICY";

const operation = ref<Operation>("CREATE_ORGANIZATION");
const reason = ref("");
const form = ref<HTMLFormElement>();
const tenant = reactive({ display_name: "", owner_subject: "", data_region: "CN",
  maximum_active_tasks: 100, maximum_export_records: 10_000, maximum_webhooks: 20,
  maximum_api_requests_per_minute: 1_000 });
const organization = reactive({ organization_id: "", display_name: "", sponsor_subject: "" });
const project = reactive({ project_id: props.projectId ?? "", organization_id: "", owner_subject: "", environments: "production" });
const integration = reactive({ integration_id: "", kind: "WEBHOOK" as "IAM" | "NOTIFICATION" | "TICKETING" | "SIEM" | "WEBHOOK",
  endpoint: "https://", secret_ref: "secret://", configuration_digest: "", active: false });
const quota = reactive({ quota_key: "active_tasks", window_started_at: toLocalDateTime(new Date()), amount: 1, limit: 100 });
const cost = reactive({ usage_id: "", project_id: props.projectId ?? "", meter: "model_tokens", quantity: 1,
  unit_cost_micros: 0, source_digest: "", recorded_at: toLocalDateTime(new Date()) });
const apiKey = reactive({ project_id: props.projectId ?? "", scopes: "tasks:read", expires_at: toLocalDateTime(new Date(Date.now() + 86_400_000)) });
const revoke = reactive({ api_key_id: "" });
const policy = reactive({ bundle_id: "", bundle_version: "", impact_report_digest: "", environment: "CANARY" as "CANARY" | "PRODUCTION" });

const labels = computed(() => props.locale === "en-US" ? {
  title: "Governed administration", operation: "Operation", reason: "Business reason",
  submit: "Submit governed intent", authority: "The browser sends an intent only. PEP, separation of duties, ledger and evidence remain authoritative.",
  tenant: "Create tenant", org: "Create organization", project: "Create project", integration: "Create integration",
  quota: "Consume quota", cost: "Record cost", issue: "Issue API key", revoke: "Revoke API key", policy: "Promote policy",
  oneTime: "One-time API key secret", clear: "Clear secret", quotaResult: "Authoritative quota result",
} : {
  title: "受控企业管理", operation: "操作", reason: "业务理由", submit: "提交受控意图",
  authority: "浏览器只提交意图；PEP、职责分离、Ledger 与 Evidence 保持权威。",
  tenant: "创建租户", org: "创建组织", project: "创建项目", integration: "创建集成",
  quota: "消耗配额", cost: "记录成本", issue: "签发 API Key", revoke: "吊销 API Key", policy: "晋级 Policy",
  oneTime: "仅显示一次的 API Key Secret", clear: "清除 Secret", quotaResult: "权威配额结果",
});

const options = computed(() => [
  ["CREATE_TENANT", labels.value.tenant], ["CREATE_ORGANIZATION", labels.value.org],
  ["CREATE_PROJECT", labels.value.project], ["CREATE_INTEGRATION", labels.value.integration],
  ["CONSUME_QUOTA", labels.value.quota], ["RECORD_COST", labels.value.cost],
  ["ISSUE_API_KEY", labels.value.issue], ["REVOKE_API_KEY", labels.value.revoke],
  ["PROMOTE_POLICY", labels.value.policy],
] as Array<[Operation, string]>);

function submit(): void {
  if (!form.value?.reportValidity() || !reason.value.trim()) return;
  const common = { reason: reason.value.trim() };
  let command: GovernedWriteCommand;
  switch (operation.value) {
    case "CREATE_TENANT":
      command = { kind: operation.value, resource: `tenant:${props.tenantId}`, payload: {
        display_name: tenant.display_name.trim(), owner_subject: tenant.owner_subject.trim(), data_region: tenant.data_region,
        quota: {
          maximum_active_tasks: tenant.maximum_active_tasks,
          maximum_export_records: tenant.maximum_export_records,
          maximum_webhooks: tenant.maximum_webhooks,
          maximum_api_requests_per_minute: tenant.maximum_api_requests_per_minute,
        },
      }, ...common };
      break;
    case "CREATE_ORGANIZATION":
      command = { kind: operation.value, resource: `organization:${organization.organization_id}`, payload: {
        organization_id: organization.organization_id.trim(), display_name: organization.display_name.trim(),
        sponsor_subject: organization.sponsor_subject.trim(),
      }, ...common };
      break;
    case "CREATE_PROJECT":
      command = { kind: operation.value, resource: `project:${project.project_id}`, payload: {
        project_id: project.project_id.trim(), organization_id: project.organization_id.trim(),
        owner_subject: project.owner_subject.trim(), environments: csv(project.environments),
      }, ...common };
      break;
    case "CREATE_INTEGRATION": {
      const endpoint = new URL(integration.endpoint);
      if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password) {
        form.value.setCustomValidity("CONTROL_INTEGRATION_ENDPOINT_INVALID");
        form.value.reportValidity();
        form.value.setCustomValidity("");
        return;
      }
      command = { kind: operation.value, resource: `integration:${integration.integration_id}`, payload: {
        integration_id: integration.integration_id, kind: integration.kind, endpoint: endpoint.toString(),
        secret_ref: integration.secret_ref.trim(), configuration_digest: integration.configuration_digest,
        active: integration.active,
      }, ...common };
      break;
    }
    case "CONSUME_QUOTA":
      command = { kind: operation.value, resource: `quota:${quota.quota_key}`, payload: {
        quota_key: quota.quota_key.trim(), window_started_at: toIso(quota.window_started_at),
        amount: quota.amount, limit: quota.limit,
      }, ...common };
      break;
    case "RECORD_COST":
      command = { kind: operation.value, resource: `cost:${cost.usage_id}`, payload: {
        usage_id: cost.usage_id, project_id: cost.project_id.trim(), meter: cost.meter.trim(),
        quantity: cost.quantity, unit_cost_micros: cost.unit_cost_micros,
        source_digest: cost.source_digest, recorded_at: toIso(cost.recorded_at),
      }, ...common };
      break;
    case "ISSUE_API_KEY":
      command = { kind: operation.value, resource: "api-key:new", payload: {
        project_id: apiKey.project_id.trim() || null, scopes: csv(apiKey.scopes), expires_at: toIso(apiKey.expires_at),
      }, ...common };
      break;
    case "REVOKE_API_KEY":
      command = { kind: operation.value, resource: `api-key:${revoke.api_key_id}`, payload: revoke.api_key_id, ...common };
      break;
    case "PROMOTE_POLICY":
      command = { kind: operation.value, resource: `policy:${policy.bundle_id}`, payload: {
        schema_version: "agenttrust.policy-promotion-request.v1",
        bundle_version: policy.bundle_version.trim(), impact_report_digest: policy.impact_report_digest,
        environment: policy.environment,
      }, ...common };
      break;
  }
  emit("submit", command);
}

function csv(value: string): string[] {
  return [...new Set(value.split(",").map((item) => item.trim()).filter(Boolean))].sort();
}
function toIso(value: string): string { return new Date(value).toISOString(); }
function toLocalDateTime(value: Date): string {
  const local = new Date(value.getTime() - value.getTimezoneOffset() * 60_000);
  return local.toISOString().slice(0, 16);
}
</script>

<template>
  <section aria-labelledby="admin-title">
    <h2 id="admin-title">{{ labels.title }}</h2>
    <form ref="form" class="admin-form" @submit.prevent="submit">
      <label for="admin-operation">{{ labels.operation }}</label>
      <select id="admin-operation" v-model="operation">
        <option v-for="item in options" :key="item[0]" :value="item[0]">{{ item[1] }}</option>
      </select>

      <fieldset v-if="operation === 'CREATE_TENANT'">
        <legend>{{ labels.tenant }}</legend>
        <label>Display name <input v-model="tenant.display_name" required maxlength="200" autocomplete="off"></label>
        <label>Owner subject <input v-model="tenant.owner_subject" required maxlength="300" autocomplete="off"></label>
        <label>Data region <input v-model="tenant.data_region" required pattern="[A-Z]{2}(-[A-Z0-9]{1,8})?" maxlength="11"></label>
        <label>Maximum active tasks <input v-model.number="tenant.maximum_active_tasks" required type="number" min="1"></label>
        <label>Maximum export records <input v-model.number="tenant.maximum_export_records" required type="number" min="1"></label>
        <label>Maximum webhooks <input v-model.number="tenant.maximum_webhooks" required type="number" min="1"></label>
        <label>Maximum requests/minute <input v-model.number="tenant.maximum_api_requests_per_minute" required type="number" min="1"></label>
      </fieldset>

      <fieldset v-else-if="operation === 'CREATE_ORGANIZATION'">
        <legend>{{ labels.org }}</legend>
        <label>Organization ID <input v-model="organization.organization_id" required maxlength="200" autocomplete="off"></label>
        <label>Display name <input v-model="organization.display_name" required maxlength="200" autocomplete="off"></label>
        <label>Sponsor subject <input v-model="organization.sponsor_subject" required maxlength="300" autocomplete="off"></label>
      </fieldset>

      <fieldset v-else-if="operation === 'CREATE_PROJECT'">
        <legend>{{ labels.project }}</legend>
        <label>Project ID <input v-model="project.project_id" required maxlength="200" autocomplete="off"></label>
        <label>Organization ID <input v-model="project.organization_id" required maxlength="200" autocomplete="off"></label>
        <label>Owner subject <input v-model="project.owner_subject" required maxlength="300" autocomplete="off"></label>
        <label>Environments <input v-model="project.environments" required pattern="[a-z][a-z0-9-]*(,[a-z][a-z0-9-]*)*" maxlength="1000"></label>
      </fieldset>

      <fieldset v-else-if="operation === 'CREATE_INTEGRATION'">
        <legend>{{ labels.integration }}</legend>
        <label>Integration UUID <input v-model="integration.integration_id" required type="text" pattern="[0-9a-fA-F-]{36}"></label>
        <label>Kind <select v-model="integration.kind"><option v-for="kind in ['IAM','NOTIFICATION','TICKETING','SIEM','WEBHOOK']" :key="kind">{{ kind }}</option></select></label>
        <label>HTTPS endpoint <input v-model="integration.endpoint" required type="url" pattern="https://.*" maxlength="2000" autocomplete="off"></label>
        <label>Secret reference <input v-model="integration.secret_ref" required pattern="[a-z][a-z0-9+.-]*://.+" maxlength="1000" autocomplete="off"></label>
        <label>Configuration digest <input v-model="integration.configuration_digest" required pattern="[a-f0-9]{64}" maxlength="64" autocomplete="off"></label>
        <label class="checkbox"><input v-model="integration.active" type="checkbox"> Active after authority approval</label>
      </fieldset>

      <fieldset v-else-if="operation === 'CONSUME_QUOTA'">
        <legend>{{ labels.quota }}</legend>
        <label>Quota key <input v-model="quota.quota_key" required maxlength="100"></label>
        <label>Window started at <input v-model="quota.window_started_at" required type="datetime-local"></label>
        <label>Amount <input v-model.number="quota.amount" required type="number" min="1"></label>
        <label>Limit <input v-model.number="quota.limit" required type="number" min="1"></label>
      </fieldset>

      <fieldset v-else-if="operation === 'RECORD_COST'">
        <legend>{{ labels.cost }}</legend>
        <label>Usage UUID <input v-model="cost.usage_id" required pattern="[0-9a-fA-F-]{36}"></label>
        <label>Project ID <input v-model="cost.project_id" required maxlength="200"></label>
        <label>Meter <input v-model="cost.meter" required maxlength="100"></label>
        <label>Quantity <input v-model.number="cost.quantity" required type="number" min="1"></label>
        <label>Unit cost (micros) <input v-model.number="cost.unit_cost_micros" required type="number" min="0"></label>
        <label>Source digest <input v-model="cost.source_digest" required pattern="[a-f0-9]{64}" maxlength="64"></label>
        <label>Recorded at <input v-model="cost.recorded_at" required type="datetime-local"></label>
      </fieldset>

      <fieldset v-else-if="operation === 'ISSUE_API_KEY'">
        <legend>{{ labels.issue }}</legend>
        <label>Project ID (optional) <input v-model="apiKey.project_id" maxlength="200"></label>
        <label>Scopes <input v-model="apiKey.scopes" required pattern="[a-z][a-z0-9:_-]*(,[a-z][a-z0-9:_-]*)*" maxlength="1000"></label>
        <label>Expires at <input v-model="apiKey.expires_at" required type="datetime-local"></label>
      </fieldset>

      <fieldset v-else-if="operation === 'REVOKE_API_KEY'">
        <legend>{{ labels.revoke }}</legend>
        <label>API Key UUID <input v-model="revoke.api_key_id" required pattern="[0-9a-fA-F-]{36}"></label>
      </fieldset>

      <fieldset v-else>
        <legend>{{ labels.policy }}</legend>
        <label>Bundle ID <input v-model="policy.bundle_id" required maxlength="200"></label>
        <label>Bundle version <input v-model="policy.bundle_version" required maxlength="200"></label>
        <label>Impact report digest <input v-model="policy.impact_report_digest" required pattern="[a-f0-9]{64}" maxlength="64"></label>
        <label>Environment <select v-model="policy.environment"><option>CANARY</option><option>PRODUCTION</option></select></label>
      </fieldset>

      <label for="admin-reason">{{ labels.reason }}</label>
      <textarea id="admin-reason" v-model="reason" required maxlength="2000" autocomplete="off" />
      <button type="submit" :disabled="busy || !reason.trim()">{{ labels.submit }}</button>
    </form>
    <p class="authority-note">{{ labels.authority }}</p>

    <aside v-if="issuedApiKey" class="one-time-secret" aria-live="assertive">
      <h3>{{ labels.oneTime }}</h3>
      <code>{{ issuedApiKey.one_time_secret }}</code>
      <p>ID: {{ issuedApiKey.api_key_id }} · {{ issuedApiKey.expires_at }}</p>
      <button type="button" @click="emit('clearApiKey')">{{ labels.clear }}</button>
    </aside>
    <aside v-if="quotaUsage" aria-live="polite">
      <h3>{{ labels.quotaResult }}</h3>
      <p>{{ quotaUsage.quota_key }}: {{ quotaUsage.used }} / {{ quotaUsage.limit }}</p>
    </aside>
  </section>
</template>
