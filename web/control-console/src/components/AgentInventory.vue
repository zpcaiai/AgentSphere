<script setup lang="ts">
import type { AgentInventoryItem, AuthorityPage } from "../enterprise-api-types";

withDefaults(defineProps<{
  page?: AuthorityPage<AgentInventoryItem> | null;
  busy?: boolean;
  error?: string;
  locale?: "zh-CN" | "en-US";
}>(), { page: null, busy: false, error: "", locale: "zh-CN" });
const emit = defineEmits<{ load: [string | null] }>();
</script>

<template>
  <section aria-labelledby="agent-inventory-title">
    <h2 id="agent-inventory-title">Agent Inventory</h2>
    <button v-if="!page" type="button" :disabled="busy" @click="emit('load', null)">{{ locale === 'en-US' ? 'Load authoritative inventory' : '加载权威资产清单' }}</button>
    <p v-if="error" role="alert">{{ error }}</p>
    <div v-if="page" class="table-scroll" tabindex="0">
      <table>
        <caption>{{ locale === 'en-US' ? 'Tenant-scoped authoritative agents' : '租户范围内权威 Agent' }}</caption>
        <thead><tr><th scope="col">Agent ID</th><th scope="col">Owner / Sponsor</th><th scope="col">Lifecycle</th><th scope="col">Posture</th><th scope="col">Inventory</th></tr></thead>
        <tbody>
          <tr v-for="agent in page.items" :key="agent.agent_id">
            <td><strong>{{ agent.display_name }}</strong><br><code>{{ agent.agent_id }}</code><br>{{ agent.agent_type }}</td>
            <td>{{ agent.owner_subject }}<br>{{ agent.sponsor_subject }}<br>{{ agent.ownership_status }}</td>
            <td>{{ agent.environment }} / {{ agent.lifecycle }}<br>{{ agent.updated_at }}</td>
            <td>{{ agent.highest_risk ?? 'NONE' }}<br>{{ agent.open_findings }} {{ locale === 'en-US' ? 'open findings' : '项未关闭发现' }}</td>
            <td>{{ agent.endpoint_count }} endpoints · {{ agent.identity_count }} identities<br>{{ agent.tool_count }} tools · {{ agent.pack_count }} packs</td>
          </tr>
          <tr v-if="page.items.length === 0"><td colspan="5">{{ locale === 'en-US' ? 'No agents' : '暂无 Agent' }}</td></tr>
        </tbody>
      </table>
      <button type="button" :disabled="busy || !page.next_cursor" @click="emit('load', page.next_cursor)">{{ locale === 'en-US' ? 'Next page' : '下一页' }}</button>
    </div>
  </section>
</template>
