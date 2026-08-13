<script setup lang="ts">
import { computed, ref } from "vue";
import {
  buildAdminIntent,
  taskCompletionLabel,
  validateDashboard,
  type GovernedAdminIntent,
  type EnterpriseDashboard,
  type TaskAuthorityStatus,
} from "./control-state";

const props = defineProps<{
  dashboard: EnterpriseDashboard;
  tasks: TaskAuthorityStatus[];
  csrfToken: string;
  projectId: string | null;
  requestedBy: string;
  approvalIds: string[];
}>();
const emit = defineEmits<{ adminIntent: [GovernedAdminIntent] }>();
const reason = ref("");
const safeDashboard = computed(() => validateDashboard(props.dashboard));
const policyDigest = computed(() => safeDashboard.value.sections.POLICIES?.data_digest ?? "");
const digestPattern = /^[a-f0-9]{64}$/;

async function requestAction(operation: string, resource: string): Promise<void> {
  const intent = await buildAdminIntent({
    tenant_id: props.dashboard.tenant_id,
    project_id: props.projectId,
    operation,
    resource,
    requested_by: props.requestedBy,
    approval_ids: props.approvalIds,
    reason: reason.value,
    csrf_token: props.csrfToken,
  });
  emit("adminIntent", intent);
}
</script>

<template>
  <main aria-labelledby="control-title">
    <h1 id="control-title">Agent Trust 企业控制台</h1>
    <p v-if="!safeDashboard.complete" role="alert">
      权威服务部分不可用：{{ safeDashboard.unavailable_sections.join(", ") }}。不可用区不会显示缓存成功状态。
    </p>
    <nav aria-label="控制面模块">
      <a v-for="name in ['TASKS','INCIDENTS','AGENTS','TOOLS','CREDENTIALS','APPROVALS','POLICIES','PACKS','TRACE','EVIDENCE','COMPLIANCE','AUDIT','SRE','DEPLOYMENTS']" :key="name" :href="`#${name}`">{{ name }}</a>
    </nav>
    <section id="TASKS" aria-labelledby="tasks-title">
      <h2 id="tasks-title">任务</h2>
      <ul><li v-for="task in tasks" :key="task.task_id">{{ task.task_id }} — {{ taskCompletionLabel(task) }}</li></ul>
    </section>
    <section v-for="(section, name) in safeDashboard.sections" :id="name" :key="name">
      <h2>{{ name }}</h2>
      <p v-if="!section?.available" role="status">{{ section?.safe_error_code }}</p>
      <p v-else>权威数据可用。摘要：<code>{{ section.data_digest }}</code></p>
    </section>
    <section aria-labelledby="admin-title">
      <h2 id="admin-title">受控管理动作</h2>
      <label for="admin-reason">变更理由</label>
      <textarea id="admin-reason" v-model="reason" autocomplete="off" />
      <button :disabled="!reason || approvalIds.length === 0 || !digestPattern.test(policyDigest)" @click="requestAction('REQUEST_POLICY_PROMOTION', 'policy://selected')">
        提交 Policy 晋级意图
      </button>
      <p>浏览器只提交意图；PEP、职责分离审批、Ledger 和 Evidence 决定结果。</p>
    </section>
  </main>
</template>
