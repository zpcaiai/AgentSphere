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
  policy: "Policy", risk: "Risk", diff: "Diff evidence", rollback: "Rollback",
  current: "Current value", target: "Target value", interlock: "Interlock", missing: "Not supplied",
  reason: "Decision reason", approve: "Submit approval intent", reject: "Submit rejection intent",
  authority: "Only a server-signed APPROVAL_RECORDED event can change approval status.",
  strongAuth: "A recent allowlisted strong-authentication session is required.",
} : {
  title: "高风险动作审批", summary: "安全摘要", resource: "资源", policy: "Policy", risk: "风险",
  diff: "Diff Evidence", rollback: "回滚", current: "当前值", target: "目标值", interlock: "联锁",
  missing: "未提供", reason: "决定理由", approve: "提交批准意图", reject: "提交拒绝意图",
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
        <dt>{{ labels.diff }}</dt><dd>{{ approvalCase.diff_artifact_ref ?? labels.missing }}</dd>
        <dt>{{ labels.rollback }}</dt><dd>{{ approvalCase.rollback_summary ?? labels.missing }}</dd>
      </template>
      <template v-else>
        <dt>{{ labels.current }}</dt><dd>{{ approvalCase.current_value ?? labels.missing }}</dd>
        <dt>{{ labels.target }}</dt><dd>{{ approvalCase.target_value ?? labels.missing }}</dd>
        <dt>{{ labels.interlock }}</dt><dd>{{ approvalCase.interlock_summary ?? labels.missing }}</dd>
      </template>
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
