<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { safeAuthorityRows, type AuthoritySection, type ServiceSection } from "../control-state";

const props = withDefaults(defineProps<{
  sectionName: ServiceSection;
  section?: AuthoritySection<unknown>;
  locale?: "zh-CN" | "en-US";
}>(), { section: undefined, locale: "zh-CN" });

const search = ref("");
const page = ref(0);
const pageSize = 25;
const rows = computed(() => props.section?.available ? safeAuthorityRows(props.section, search.value) : []);
const columns = computed(() => [...new Set(rows.value.flatMap((row) => Object.keys(row.values)))].sort().slice(0, 24));
const pages = computed(() => Math.max(1, Math.ceil(rows.value.length / pageSize)));
const visibleRows = computed(() => rows.value.slice(page.value * pageSize, (page.value + 1) * pageSize));
watch([search, () => props.sectionName], () => { page.value = 0; });
watch(pages, (value) => { if (page.value >= value) page.value = value - 1; });
</script>

<template>
  <section :aria-labelledby="`authority-${sectionName}`">
    <h2 :id="`authority-${sectionName}`">{{ sectionName }}</h2>
    <p v-if="!section" role="status">{{ locale === 'en-US' ? 'Not configured by the BFF.' : 'BFF 未配置此权威服务。' }}</p>
    <p v-else-if="!section.available" role="alert">
      {{ section.safe_error_code }} — {{ locale === 'en-US' ? 'No cached success is shown.' : '不会显示缓存的伪成功状态。' }}
    </p>
    <template v-else>
      <div class="module-toolbar">
        <label :for="`search-${sectionName}`">{{ locale === 'en-US' ? 'Filter safe fields' : '筛选安全字段' }}</label>
        <input :id="`search-${sectionName}`" v-model="search" type="search" maxlength="200" autocomplete="off">
      </div>
      <div class="table-scroll" tabindex="0">
        <table>
          <caption>{{ locale === 'en-US' ? 'Authoritative, safely redacted records' : '已安全脱敏的权威记录' }}</caption>
          <thead><tr><th v-for="column in columns" :key="column" scope="col">{{ column }}</th></tr></thead>
          <tbody>
            <tr v-for="row in visibleRows" :key="row.row_id">
              <td v-for="column in columns" :key="column">{{ row.values[column] ?? '—' }}</td>
            </tr>
            <tr v-if="visibleRows.length === 0"><td :colspan="Math.max(columns.length, 1)">{{ locale === 'en-US' ? 'No records' : '暂无记录' }}</td></tr>
          </tbody>
        </table>
      </div>
      <div class="pagination" aria-label="Pagination">
        <button type="button" :disabled="page === 0" @click="page--">{{ locale === 'en-US' ? 'Previous' : '上一页' }}</button>
        <span>{{ page + 1 }} / {{ pages }}</span>
        <button type="button" :disabled="page + 1 >= pages" @click="page++">{{ locale === 'en-US' ? 'Next' : '下一页' }}</button>
      </div>
      <p class="authority-note">Digest <code>{{ section.data_digest }}</code> · {{ section.fetched_at }}</p>
    </template>
  </section>
</template>
