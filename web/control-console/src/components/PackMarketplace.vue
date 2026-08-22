<script setup lang="ts">
import { computed, onMounted, ref, watch } from "vue";
import { MARKETPLACE_KINDS, marketplaceResource, marketplaceTemplate,
  validateMarketplaceTypedCommand, type MarketplaceKind } from "../marketplace-command";
import type { MarketplaceActionReceipt, MarketplaceCommand, PackInstallation, PackPage,
  PackRelease } from "../enterprise-api-types";

const props = withDefaults(defineProps<{
  tenantId: string;
  page?: PackPage | null;
  receipt?: MarketplaceActionReceipt | null;
  busy?: boolean;
  error?: string;
  locale?: "zh-CN" | "en-US";
}>(), { page: null, receipt: null, busy: false, error: "", locale: "zh-CN" });

const emit = defineEmits<{
  load: [string, string | null];
  submit: [MarketplaceCommand];
}>();

const form = ref<HTMLFormElement>();
const search = ref("");
const kind = ref<MarketplaceKind>("ONBOARD_PUBLISHER");
const expectedVersion = ref(0);
const commandJson = ref("");
const localError = ref("");
const resourceId = computed(() => {
  try { return marketplaceResource(validateMarketplaceTypedCommand(JSON.parse(commandJson.value))); }
  catch { return "INVALID_TYPED_RESOURCE"; }
});
const labels = computed(() => props.locale === "en-US" ? {
  title: "Domain Pack Marketplace", load: "Load authoritative catalog", releases: "Release gate and supply chain",
  installs: "Tenant installation and activation", empty: "No authoritative pack releases or installations.",
  action: "Governed lifecycle command", submit: "Admit canonical pack action",
  pending: "Durably admitted; lifecycle execution is pending and no pack is authorized for a task by this receipt.",
  boundary: "INSTALL does not ACTIVATE. ACTIVE does not grant per-task production authorization. Release certificates are engine evidence only and production closure remains separate.",
} : {
  title: "领域 Pack 市场", load: "加载权威目录", releases: "发布门禁与供应链",
  installs: "租户安装与激活", empty: "暂无权威 Pack 发布或安装。", action: "受治理生命周期命令",
  submit: "提交 Canonical Pack Action",
  pending: "已持久接收；生命周期执行仍在等待中，且该回执不会授权任何任务使用 Pack。",
  boundary: "INSTALL 不等于 ACTIVATE；ACTIVE 不等于逐任务生产授权；发布证书仅是引擎证据，生产闭环仍需独立完成。",
});

watch(kind, (value) => {
  commandJson.value = JSON.stringify(marketplaceTemplate(value), null, 2);
  localError.value = "";
}, { immediate: true });
onMounted(() => emit("load", "", null));

function load(after: string | null): void {
  if (search.value.length > 128 || /[\0\r\n]/.test(search.value)) {
    localError.value = "CONTROL_PACK_QUERY_INVALID"; return;
  }
  localError.value = ""; emit("load", search.value.trim(), after);
}

function selectRelease(item: PackRelease): void {
  if (["SUBMIT_RELEASE", "REVIEW_RELEASE", "REVOKE_RELEASE"].includes(kind.value)) {
    const command = marketplaceTemplate(kind.value);
    command.release_id = item.release_id;
    commandJson.value = JSON.stringify(command, null, 2);
  }
}
function selectInstallation(item: PackInstallation): void {
  if (["REQUEST_INSTALLATION", "APPROVE_INSTALLATION", "INSTALL", "ACTIVATE", "ROLLBACK",
    "DEACTIVATE"].includes(kind.value)) {
    const command = marketplaceTemplate(kind.value);
    command.installation_id = item.installation_id;
    if (kind.value === "REQUEST_INSTALLATION") command.release_id = item.release_id;
    commandJson.value = JSON.stringify(command, null, 2);
  }
}

function submit(): void {
  localError.value = "";
  if (!form.value?.reportValidity() || !Number.isSafeInteger(expectedVersion.value)
    || expectedVersion.value < 0) return;
  try {
    const command = validateMarketplaceTypedCommand(JSON.parse(commandJson.value));
    emit("submit", { schema_version: "agenttrust.marketplace-command.v1", tenant_id: props.tenantId,
      command_id: crypto.randomUUID(), resource_id: marketplaceResource(command),
      expected_resource_version: expectedVersion.value, command, requested_at: new Date().toISOString() });
  } catch (error) {
    localError.value = error instanceof Error && /^[A-Z][A-Z0-9_]{2,120}$/.test(error.message)
      ? error.message : "CONTROL_PACK_COMMAND_INVALID";
  }
}
</script>

<template>
  <section aria-labelledby="pack-marketplace-title">
    <h2 id="pack-marketplace-title">{{ labels.title }}</h2>
    <p class="banner warning" role="note">{{ labels.boundary }}</p>
    <p v-if="error || localError" role="alert">{{ error || localError }}</p>

    <section aria-labelledby="pack-releases-title">
      <h3 id="pack-releases-title">{{ labels.releases }}</h3>
      <div class="module-toolbar"><label for="pack-search">Search
        <input id="pack-search" v-model="search" maxlength="128" autocomplete="off">
      </label><button type="button" :disabled="busy" @click="load(null)">{{ labels.load }}</button></div>
      <p v-if="!page?.releases.length && !page?.installations.length" role="status">{{ labels.empty }}</p>
      <div v-if="page?.releases.length" class="table-scroll"><table>
        <thead><tr><th>Pack / version</th><th>Publisher</th><th>Gate status</th><th>Risk</th>
          <th>Compatibility / regions</th><th>Supply-chain evidence</th><th>Action</th></tr></thead>
        <tbody><tr v-for="item in page.releases" :key="item.release_id">
          <td><code>{{ item.pack_id }}@{{ item.version }}</code><br><code>{{ item.release_id }}</code></td>
          <td>{{ item.publisher_id }}<br>{{ item.visibility }} / {{ item.entitlement }}</td>
          <td>{{ item.review_status }}</td><td>{{ item.risk_rating }}</td>
          <td>{{ item.compatibility.join(', ') }}<br>{{ item.allowed_regions.join(', ') }}</td>
          <td>pack <code>{{ item.pack_digest }}</code><br>certificate <code>{{ item.certificate_digest }}</code></td>
          <td><button type="button" :disabled="busy" :aria-label="`Select pack release ${item.release_id}`"
            @click="selectRelease(item)">Select</button></td>
        </tr></tbody>
      </table></div>
      <button v-if="page?.next_after_pack_id" type="button" :disabled="busy"
        @click="load(page.next_after_pack_id)">Next page</button>
    </section>

    <section aria-labelledby="pack-installations-title">
      <h3 id="pack-installations-title">{{ labels.installs }}</h3>
      <div v-if="page?.installations.length" class="table-scroll"><table>
        <thead><tr><th>Installation</th><th>Pack</th><th>Environment</th><th>State</th>
          <th>Permission expansion</th><th>Previous</th><th>Action</th></tr></thead>
        <tbody><tr v-for="item in page.installations" :key="item.installation_id">
          <td><code>{{ item.installation_id }}</code></td><td><code>{{ item.pack_id }}@{{ item.version }}</code></td>
          <td>{{ item.environment }}</td><td>{{ item.state }}</td>
          <td :class="item.permission_expansion ? 'unavailable' : 'available'">{{ item.permission_expansion }}</td>
          <td><code>{{ item.previous_installation_id ?? '—' }}</code></td>
          <td><button type="button" :disabled="busy" :aria-label="`Select pack installation ${item.installation_id}`"
            @click="selectInstallation(item)">Select</button></td>
        </tr></tbody>
      </table></div>
    </section>

    <form ref="form" class="admin-form" aria-labelledby="pack-action-title" @submit.prevent="submit">
      <h3 id="pack-action-title">{{ labels.action }}</h3>
      <label for="pack-command-kind">Typed command
        <select id="pack-command-kind" v-model="kind"><option v-for="item in MARKETPLACE_KINDS" :key="item">{{ item }}</option></select>
      </label>
      <label for="pack-resource-id">Derived canonical resource
        <input id="pack-resource-id" :value="resourceId" readonly aria-readonly="true">
      </label>
      <label for="pack-resource-version">Expected resource version
        <input id="pack-resource-version" v-model.number="expectedVersion" required type="number" min="0" step="1">
      </label>
      <label for="pack-command-json">Exact {{ kind }} command JSON
        <textarea id="pack-command-json" v-model="commandJson" required rows="22" maxlength="900000" spellcheck="false" />
      </label>
      <button type="submit" :disabled="busy">{{ labels.submit }}</button>
    </form>

    <aside v-if="receipt" class="action-receipt" aria-live="polite">
      <h3>Pack action <code>{{ receipt.action_id }}</code></h3><p>{{ labels.pending }}</p>
      <p>Task: <code>{{ receipt.task_id }}</code></p>
      <p>Ledger evidence: <code>{{ receipt.ledger_evidence_ref }}</code></p>
    </aside>
  </section>
</template>
