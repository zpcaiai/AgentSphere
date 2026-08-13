<script setup lang="ts">
import { onMounted, ref } from "vue";
import ControlConsole from "./ControlConsole.vue";
import { ControlApiClient } from "./api-client";
import type { EnterpriseDashboard, GovernedAdminIntent, TaskAuthorityStatus } from "./control-state";

const tenantId = document.documentElement.dataset.tenantId ?? "";
const requestedBy = document.documentElement.dataset.subject ?? "";
const projectId = document.documentElement.dataset.projectId ?? null;
const approvalIds = (document.documentElement.dataset.approvalIds ?? "").split(",").filter(Boolean);
const csrfToken = document.cookie.split("; ").find((item) => item.startsWith("XSRF-TOKEN="))?.split("=")[1] ?? "";
const client = new ControlApiClient(import.meta.env.VITE_CONTROL_API_URL);
const dashboard = ref<EnterpriseDashboard | null>(null);
const tasks = ref<TaskAuthorityStatus[]>([]);
const errorCode = ref("");

onMounted(async () => {
  try { dashboard.value = await client.dashboard(tenantId); }
  catch { errorCode.value = "CONTROL_API_UNAVAILABLE"; }
});

async function submit(value: GovernedAdminIntent): Promise<void> {
  try { await client.submitAdminIntent(value); }
  catch { errorCode.value = "CONTROL_ADMIN_INTENT_REJECTED"; }
}
</script>

<template>
  <p v-if="errorCode" role="alert">{{ errorCode }}</p>
  <p v-else-if="!dashboard" role="status">正在加载权威状态…</p>
  <ControlConsole v-else :dashboard="dashboard" :tasks="tasks" :csrf-token="csrfToken"
    :project-id="projectId" :requested-by="requestedBy" :approval-ids="approvalIds" @admin-intent="submit" />
</template>
