<script setup lang="ts">
import { computed, ref } from "vue";
import { createDecisionIntent, type ApprovalCaseView } from "./approval-state";

const props = defineProps<{ approvalCase: ApprovalCaseView }>();
const emit = defineEmits<{ intent: [ReturnType<typeof createDecisionIntent>] }>();
const reason = ref("");
const pending = computed(() => props.approvalCase.status === "PENDING");

function submit(decision: "APPROVE" | "REJECT"): void {
  // The UI emits an intent only. It never changes status locally or creates a grant.
  emit("intent", createDecisionIntent(props.approvalCase, decision, reason.value));
}
</script>

<template>
  <main aria-labelledby="approval-title">
    <h1 id="approval-title">高风险动作审批</h1>
    <dl>
      <dt>安全摘要</dt><dd>{{ approvalCase.safe_summary }}</dd>
      <dt>资源</dt><dd>{{ approvalCase.resource }} @ {{ approvalCase.resource_version }}</dd>
      <dt>Policy</dt><dd>{{ approvalCase.policy_version }}</dd>
      <dt>风险</dt><dd>{{ approvalCase.risk }}</dd>
      <template v-if="approvalCase.domain === 'CODING'">
        <dt>Diff Evidence</dt><dd>{{ approvalCase.diff_artifact_ref ?? '未提供' }}</dd>
        <dt>回滚</dt><dd>{{ approvalCase.rollback_summary ?? '未提供' }}</dd>
      </template>
      <template v-else>
        <dt>当前值</dt><dd>{{ approvalCase.current_value }}</dd>
        <dt>目标值</dt><dd>{{ approvalCase.target_value }}</dd>
        <dt>联锁</dt><dd>{{ approvalCase.interlock_summary }}</dd>
      </template>
    </dl>
    <label for="reason">理由</label>
    <textarea id="reason" v-model="reason" autocomplete="off" />
    <button :disabled="!pending || !reason" @click="submit('APPROVE')">提交批准意图</button>
    <button :disabled="!pending || !reason" @click="submit('REJECT')">提交拒绝意图</button>
    <p role="status">只有服务端签名的 APPROVAL_RECORDED 事件才会改变审批状态。</p>
  </main>
</template>
