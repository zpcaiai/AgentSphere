<script setup lang="ts">
import { computed, ref } from "vue";
import { createDecisionIntent, type ApprovalCaseView } from "./approval-state";

const props = withDefaults(defineProps<{
  approvalCase: ApprovalCaseView;
  busy?: boolean;
  strongAuth?: boolean;
  locale?: "zh-CN" | "en-US";
}>(), { busy: false, strongAuth: false, locale: "zh-CN" });
const emit = defineEmits<{ intent: [ReturnType<typeof createDecisionIntent>] }>();
const reason = ref("");
const pending = computed(() => props.approvalCase.status === "PENDING");
const labels = computed(() => props.locale === "en-US" ? {
  title: "High-risk action approval", summary: "Safe summary", resource: "Resource",
  policy: "Policy", risk: "Risk", diff: "Diff evidence", command: "Command summary",
  network: "Network scope", rollback: "Rollback", current: "Current value", target: "Target value",
  range: "Allowed range", interlock: "Interlock", impact: "Physical impact", evidence: "Evidence",
  reason: "Decision reason", approve: "Submit approval intent", reject: "Submit rejection intent",
  authority: "Only a server-signed APPROVAL_RECORDED event can change approval status.",
  strongAuth: "A recent allowlisted strong-authentication session is required.",
} : {
  title: "高风险动作审批", summary: "安全摘要", resource: "资源", policy: "Policy", risk: "风险",
  diff: "Diff Evidence", command: "命令摘要", network: "网络范围", rollback: "回滚",
  current: "当前值", target: "目标值", range: "允许范围", interlock: "联锁",
  impact: "物理影响", evidence: "证据", reason: "决定理由", approve: "提交批准意图", reject: "提交拒绝意图",
  authority: "只有服务端签名的 APPROVAL_RECORDED 事件才会改变审批状态。",
  strongAuth: "审批需要近期完成且被允许的强身份认证。",
});

function submit(decision: "APPROVE" | "REJECT"): void {
  // The UI emits an intent only. It never changes status locally or creates a grant.
  emit("intent", createDecisionIntent(props.approvalCase, decision, reason.value));
  reason.value = "";
}
</script>

<template>
  <section class="approval-case" :aria-labelledby="`approval-${approvalCase.case_id}`">
    <h3 :id="`approval-${approvalCase.case_id}`">{{ labels.title }}</h3>
    <dl>
      <dt>{{ labels.summary }}</dt><dd>{{ approvalCase.safe_summary }}</dd>
      <dt>{{ labels.resource }}</dt><dd>{{ approvalCase.resource }} @ {{ approvalCase.resource_version }}</dd>
      <dt>{{ labels.policy }}</dt><dd>{{ approvalCase.policy_version }}</dd>
      <dt>{{ labels.risk }}</dt><dd>{{ approvalCase.risk }}</dd>
      <template v-if="approvalCase.domain === 'CODING'">
        <dt>{{ labels.diff }}</dt><dd>{{ approvalCase.coding_details.diff_artifact_ref }}</dd>
        <dt>{{ labels.command }}</dt><dd>{{ approvalCase.coding_details.command_summary }}</dd>
        <dt>{{ labels.network }}</dt><dd>{{ approvalCase.coding_details.network_scope }}</dd>
        <dt>{{ labels.rollback }}</dt><dd>{{ approvalCase.coding_details.rollback_summary }}</dd>
      </template>
      <template v-else>
        <dt>{{ labels.current }}</dt><dd>{{ approvalCase.industrial_details.current_value }}</dd>
        <dt>{{ labels.target }}</dt><dd>{{ approvalCase.industrial_details.target_value }}</dd>
        <dt>{{ labels.range }}</dt><dd>{{ approvalCase.industrial_details.allowed_range }}</dd>
        <dt>{{ labels.interlock }}</dt><dd>{{ approvalCase.industrial_details.interlock_summary }}</dd>
        <dt>{{ labels.impact }}</dt><dd>{{ approvalCase.industrial_details.physical_impact }}</dd>
      </template>
      <dt>{{ labels.evidence }}</dt>
      <dd><ul><li v-for="reference in approvalCase.evidence_refs" :key="reference">{{ reference }}</li></ul></dd>
    </dl>
    <label :for="`reason-${approvalCase.case_id}`">{{ labels.reason }}</label>
    <textarea :id="`reason-${approvalCase.case_id}`" v-model="reason" maxlength="2000" autocomplete="off" />
    <div class="button-row">
      <button type="button" :disabled="!pending || !strongAuth || !reason.trim() || busy" @click="submit('APPROVE')">{{ labels.approve }}</button>
      <button type="button" class="danger" :disabled="!pending || !strongAuth || !reason.trim() || busy" @click="submit('REJECT')">{{ labels.reject }}</button>
    </div>
    <p v-if="!strongAuth" role="alert">{{ labels.strongAuth }}</p>
    <p role="status">{{ labels.authority }}</p>
  </section>
</template>
