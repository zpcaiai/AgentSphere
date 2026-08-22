<script setup lang="ts">
import { computed } from "vue";
import { RouterLink, useRoute } from "vue-router";
import ApprovalConsole from "../../approval-console/src/ApprovalConsole.vue";
import { parseApprovalCases } from "../../approval-console/src/approval-state";
import type { AgUiEventEnvelope, ApprovalIntent } from "../../shared/agui-client";
import AgentInventory from "./components/AgentInventory.vue";
import AdminWorkbench from "./components/AdminWorkbench.vue";
import AuthorityModule from "./components/AuthorityModule.vue";
import IncidentConsole from "./components/IncidentConsole.vue";
import PackMarketplace from "./components/PackMarketplace.vue";
import PolicyStudio from "./components/PolicyStudio.vue";
import TaskRuntimePanel from "./components/TaskRuntimePanel.vue";
import {
  SERVICE_SECTIONS,
  validateDashboard,
  type EnterpriseDashboard,
  type ServiceSection,
  type TaskAuthorityStatus,
} from "./control-state";
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

const props = withDefaults(defineProps<{
  dashboard: EnterpriseDashboard;
  tasks: TaskAuthorityStatus[];
  events?: AgUiEventEnvelope[];
  agentPage?: AuthorityPage<AgentInventoryItem> | null;
  policyPage?: PolicyPage | null;
  policyArtifactPage?: PolicyArtifactPage | null;
  policyReceipt?: PolicyActionReceipt | null;
  incidentPage?: IncidentPage | null;
  incidentDetail?: Incident | null;
  incidentReceipt?: IncidentActionReceipt | null;
  packPage?: PackPage | null;
  packReceipt?: MarketplaceActionReceipt | null;
  actionReceipt?: EnterpriseActionReceipt | null;
  tenantId: string;
  requestedBy: string;
  approvalIds: string[];
  projectId: string | null;
  approvalStrongAuth?: boolean;
  busy?: boolean;
  operationMessage?: string;
  streamError?: string;
  moduleError?: string;
  locale?: "zh-CN" | "en-US";
}>(), {
  events: () => [], agentPage: null, policyPage: null, policyArtifactPage: null,
  policyReceipt: null, incidentPage: null, incidentDetail: null, incidentReceipt: null,
  packPage: null, packReceipt: null, actionReceipt: null,
  busy: false, approvalStrongAuth: false, operationMessage: "", streamError: "", moduleError: "", locale: "zh-CN",
});

const emit = defineEmits<{
  refresh: [];
  governedWrite: [GovernedWriteCommand];
  approvalIntent: [ApprovalIntent];
  resumeTask: [string];
  loadAgents: [string | null];
  loadPolicies: [string | null];
  loadPolicyArtifacts: [string, PolicyArtifactType];
  submitPolicy: [PolicyCommand];
  loadIncidents: [string | null];
  loadIncidentDetail: [string];
  submitIncident: [IncidentCommand];
  loadPacks: [string, string | null];
  submitPack: [MarketplaceCommand];
  clearReceipt: [];
  signOut: [];
  setLocale: ["zh-CN" | "en-US"];
}>();

const route = useRoute();
const safeDashboard = computed(() => validateDashboard(props.dashboard));
const moduleSlug = computed(() => String(route.params.module ?? "overview"));
const sectionForRoute = computed<ServiceSection | null>(() => {
  const candidate = moduleSlug.value.toUpperCase();
  return (SERVICE_SECTIONS as readonly string[]).includes(candidate) ? candidate as ServiceSection : null;
});
const approvals = computed(() => {
  const section = safeDashboard.value.sections.APPROVALS;
  if (!section?.available || section.data === null) return { items: [], error: "" };
  try { return { items: parseApprovalCases(section.data, safeDashboard.value.tenant_id), error: "" }; }
  catch { return { items: [], error: "APPROVAL_AUTHORITY_PAYLOAD_INVALID" }; }
});

const nav = [
  ["overview", "OVERVIEW"], ["tasks", "TASKS"], ["agents", "AGENTS"], ["approvals", "APPROVALS"],
  ["policies", "POLICIES"], ["tools", "TOOLS"], ["credentials", "CREDENTIALS"], ["packs", "PACKS"],
  ["trace", "TRACE"], ["evidence", "EVIDENCE"], ["incidents", "INCIDENTS"], ["compliance", "COMPLIANCE"],
  ["audit", "AUDIT"], ["models", "MODELS"], ["data", "DATA"], ["context", "CONTEXT"],
  ["anomalies", "ANOMALIES"], ["security_evaluations", "SECURITY_EVALUATIONS"],
  ["supply_chain", "SUPPLY_CHAIN"], ["domain_packs", "DOMAIN_PACKS"],
  ["sre", "SRE"], ["deployments", "DEPLOYMENTS"], ["admin", "ADMIN"],
] as const;
</script>

<template>
  <main aria-labelledby="control-title">
    <header class="app-header">
      <div>
        <p class="eyebrow">Agent Trust Control Plane</p>
        <h1 id="control-title">{{ locale === 'en-US' ? 'Enterprise Control Console' : '企业控制台' }}</h1>
      </div>
      <div class="header-actions">
        <label for="locale">Language</label>
        <select id="locale" :value="locale" @change="emit('setLocale', ($event.target as HTMLSelectElement).value as 'zh-CN' | 'en-US')">
          <option value="zh-CN">中文</option><option value="en-US">English</option>
        </select>
        <button type="button" :disabled="busy" @click="emit('refresh')">{{ locale === 'en-US' ? 'Refresh authority' : '刷新权威状态' }}</button>
        <button type="button" :disabled="busy" @click="emit('signOut')">{{ locale === 'en-US' ? 'Sign out' : '退出登录' }}</button>
      </div>
    </header>

    <p v-if="!safeDashboard.complete" class="banner warning" role="alert">
      {{ locale === 'en-US' ? 'Authoritative services unavailable' : '权威服务部分不可用' }}:
      {{ safeDashboard.unavailable_sections.join(', ') }}.
      {{ locale === 'en-US' ? 'Unavailable modules never show cached success.' : '不可用区不会显示缓存的伪成功状态。' }}
    </p>
    <p v-if="operationMessage" class="banner" role="status">{{ operationMessage }}</p>
    <p v-if="moduleError" class="banner error" role="alert">{{ moduleError }}</p>

    <nav class="module-nav" aria-label="控制面模块">
      <RouterLink v-for="item in nav" :key="item[0]" :to="`/modules/${item[0]}`">{{ item[1] }}</RouterLink>
    </nav>

    <section v-if="moduleSlug === 'overview'" aria-labelledby="overview-title">
      <h2 id="overview-title">{{ locale === 'en-US' ? 'Authority overview' : '权威服务概览' }}</h2>
      <div class="overview-grid">
        <article v-for="name in SERVICE_SECTIONS" :key="name">
          <h3>{{ name }}</h3>
          <p :class="safeDashboard.sections[name]?.available ? 'available' : 'unavailable'">
            {{ safeDashboard.sections[name]?.available ? 'AVAILABLE' : 'UNAVAILABLE' }}
          </p>
          <RouterLink :to="`/modules/${name.toLowerCase()}`">{{ locale === 'en-US' ? 'Open module' : '打开模块' }}</RouterLink>
        </article>
      </div>
    </section>

    <TaskRuntimePanel v-else-if="moduleSlug === 'tasks'" :tasks="tasks" :events="events" :busy="busy"
      :stream-error="streamError" :locale="locale" @command="emit('governedWrite', $event)" @resume="emit('resumeTask', $event)" />

    <template v-else-if="moduleSlug === 'agents'">
      <AgentInventory :page="agentPage" :busy="busy" :error="moduleError" :locale="locale" @load="emit('loadAgents', $event)" />
      <AuthorityModule section-name="AGENTS" :section="safeDashboard.sections.AGENTS" :locale="locale" />
    </template>

    <section v-else-if="moduleSlug === 'approvals'" aria-labelledby="approvals-title">
      <h2 id="approvals-title">{{ locale === 'en-US' ? 'Approval inbox' : '审批收件箱' }}</h2>
      <p v-if="approvals.error" role="alert">{{ approvals.error }}</p>
      <p v-else-if="approvals.items.length === 0" role="status">{{ locale === 'en-US' ? 'No authoritative approval cases.' : '暂无权威审批事项。' }}</p>
      <ApprovalConsole v-for="item in approvals.items" :key="item.case_id" :approval-case="item" :busy="busy"
        :strong-auth="approvalStrongAuth"
        :locale="locale" @intent="emit('approvalIntent', $event)" />
    </section>

    <template v-else-if="moduleSlug === 'policies'">
      <PolicyStudio :tenant-id="tenantId" :requested-by="requestedBy" :approval-ids="approvalIds"
        :page="policyPage" :artifact-page="policyArtifactPage" :receipt="policyReceipt"
        :busy="busy" :error="moduleError" :locale="locale"
        @load="emit('loadPolicies', $event)"
        @load-artifacts="(policyId, artifactType) => emit('loadPolicyArtifacts', policyId, artifactType)"
        @submit="emit('submitPolicy', $event)" />
      <AuthorityModule section-name="POLICIES" :section="safeDashboard.sections.POLICIES" :locale="locale" />
    </template>

    <template v-else-if="moduleSlug === 'incidents'">
      <IncidentConsole :tenant-id="tenantId" :requested-by="requestedBy" :approval-ids="approvalIds"
        :page="incidentPage" :detail="incidentDetail" :receipt="incidentReceipt"
        :busy="busy" :error="moduleError" :locale="locale" @load="emit('loadIncidents', $event)"
        @load-detail="emit('loadIncidentDetail', $event)" @submit="emit('submitIncident', $event)" />
      <AuthorityModule section-name="INCIDENTS" :section="safeDashboard.sections.INCIDENTS" :locale="locale" />
    </template>

    <template v-else-if="moduleSlug === 'packs'">
      <PackMarketplace :tenant-id="tenantId" :page="packPage" :receipt="packReceipt"
        :busy="busy" :error="moduleError" :locale="locale"
        @load="(search, after) => emit('loadPacks', search, after)"
        @submit="emit('submitPack', $event)" />
      <AuthorityModule section-name="PACKS" :section="safeDashboard.sections.PACKS" :locale="locale" />
    </template>

    <AdminWorkbench v-else-if="moduleSlug === 'admin'" :tenant-id="safeDashboard.tenant_id" :project-id="projectId"
      :busy="busy" :action-receipt="actionReceipt" :locale="locale"
      @submit="emit('governedWrite', $event)" @clear-receipt="emit('clearReceipt')" />

    <AuthorityModule v-else-if="sectionForRoute" :section-name="sectionForRoute"
      :section="safeDashboard.sections[sectionForRoute]" :locale="locale" />
  </main>
</template>
