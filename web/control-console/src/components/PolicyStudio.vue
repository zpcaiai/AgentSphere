<script setup lang="ts">
import { ref } from "vue";
import type { PolicySimulationRequest, PolicySimulationResult } from "../enterprise-api-types";

withDefaults(defineProps<{
  result?: PolicySimulationResult | null;
  busy?: boolean;
  error?: string;
  locale?: "zh-CN" | "en-US";
}>(), { result: null, busy: false, error: "", locale: "zh-CN" });
const emit = defineEmits<{ simulate: [string, PolicySimulationRequest] }>();
const bundleId = ref("");
const candidateDigest = ref("");
const corpusDigest = ref("");
const maximumCases = ref(100);

function submit(): void {
  if (bundleId.value.trim() && /^[a-f0-9]{64}$/.test(candidateDigest.value)
    && /^[a-f0-9]{64}$/.test(corpusDigest.value) && maximumCases.value >= 1 && maximumCases.value <= 10_000) {
    emit("simulate", bundleId.value.trim(), {
      schema_version: "agenttrust.policy-simulation-request.v1",
      candidate_digest: candidateDigest.value,
      corpus_digest: corpusDigest.value,
      maximum_cases: maximumCases.value,
    });
  }
}
</script>

<template>
  <section aria-labelledby="policy-studio-title">
    <h2 id="policy-studio-title">Policy Studio</h2>
    <form class="inline-form" @submit.prevent="submit">
      <label>Bundle ID <input v-model="bundleId" required maxlength="200"></label>
      <label>Authority candidate digest <input v-model="candidateDigest" required pattern="[a-f0-9]{64}" maxlength="64" autocomplete="off"></label>
      <label>Authority corpus digest <input v-model="corpusDigest" required pattern="[a-f0-9]{64}" maxlength="64" autocomplete="off"></label>
      <label>Maximum cases <input v-model.number="maximumCases" required type="number" min="1" max="10000"></label>
      <button type="submit" :disabled="busy">{{ locale === 'en-US' ? 'Run side-effect-free simulation' : '运行无副作用模拟' }}</button>
    </form>
    <p v-if="error" role="alert">{{ error }}</p>
    <aside v-if="result" aria-live="polite">
      <h3>{{ locale === 'en-US' ? 'Authoritative impact report' : '权威影响报告' }}</h3>
      <p>{{ result.safe_summary }}</p>
      <code>{{ result.impact_report_digest }}</code>
      <p>{{ locale === 'en-US'
        ? 'Use this digest in the governed promotion workflow; simulation never promotes a bundle.'
        : '在受控晋级工作流中使用此摘要；模拟本身不会晋级 Bundle。' }}</p>
    </aside>
  </section>
</template>
