<script setup lang="ts">
import { computed, ref, watch } from "vue";
import type { AgUiEventEnvelope } from "../../../shared/agui-client";
import { taskCompletionLabel, type TaskAuthorityStatus } from "../control-state";
import type { GovernedWriteCommand, TaskCommand } from "../enterprise-api-types";

const props = withDefaults(defineProps<{
  tasks: TaskAuthorityStatus[];
  events?: AgUiEventEnvelope[];
  busy?: boolean;
  streamError?: string;
  locale?: "zh-CN" | "en-US";
}>(), { events: () => [], busy: false, streamError: "", locale: "zh-CN" });
const emit = defineEmits<{ command: [GovernedWriteCommand]; resume: [string] }>();

const selectedTaskId = ref("");
const commandType = ref<TaskCommand["command_type"]>("PAUSE");
const expectedStateVersion = ref(0);
const payloadDigest = ref("0".repeat(64));
const reason = ref("");
const selectedTask = computed(() => props.tasks.find((task) => task.task_id === selectedTaskId.value));
watch(() => props.tasks, (tasks) => {
  if (!tasks.some((task) => task.task_id === selectedTaskId.value)) selectedTaskId.value = tasks[0]?.task_id ?? "";
}, { immediate: true });
watch(selectedTask, (task) => { expectedStateVersion.value = task?.state_version ?? 0; });

function submitCommand(): void {
  if (!selectedTaskId.value || !reason.value.trim() || !/^[a-f0-9]{64}$/.test(payloadDigest.value)) return;
  const command: TaskCommand = {
    schema_version: "agenttrust.orchestrator-command.v1",
    command_id: crypto.randomUUID(),
    command_type: commandType.value,
    expected_state_version: expectedStateVersion.value,
    payload_digest: payloadDigest.value,
  };
  emit("command", {
    kind: `TASK_${commandType.value}`,
    resource: `task:${selectedTaskId.value}`,
    payload: command,
    reason: reason.value.trim(),
  });
}

function safeEventSummary(event: AgUiEventEnvelope): string {
  for (const key of ["safe_summary", "status", "reason_code", "artifact_ref"]) {
    const value = event.safe_payload[key];
    if (typeof value === "string") return value.slice(0, 500);
  }
  return props.locale === "en-US" ? "Verified event payload withheld" : "已验证事件，载荷保持脱敏";
}
</script>

<template>
  <section aria-labelledby="tasks-title">
    <h2 id="tasks-title">{{ locale === 'en-US' ? 'Task runtime' : '任务运行时' }}</h2>
    <p v-if="tasks.length === 0" role="status">{{ locale === 'en-US' ? 'No authoritative tasks.' : '暂无权威任务。' }}</p>
    <div v-else class="task-grid">
      <ol class="task-list" aria-label="Tasks">
        <li v-for="task in tasks" :key="task.task_id">
          <button type="button" :aria-current="selectedTaskId === task.task_id ? 'true' : undefined" @click="selectedTaskId = task.task_id">
            <strong>{{ task.task_id }}</strong><span class="status-badge">{{ taskCompletionLabel(task) }}</span>
          </button>
        </li>
      </ol>
      <div v-if="selectedTask" class="task-detail">
        <h3>{{ selectedTask.safe_summary ?? selectedTask.task_id }}</h3>
        <dl>
          <dt>Runtime</dt><dd>{{ selectedTask.runtime_status }}</dd>
          <dt>Ledger</dt><dd>{{ selectedTask.ledger_terminal }}</dd>
          <dt>Evaluation</dt><dd>{{ selectedTask.evaluation_passed }}</dd>
          <dt>Evidence</dt><dd>{{ selectedTask.evidence_verified }}</dd>
        </dl>
        <form class="task-command" @submit.prevent="submitCommand">
          <label>Command
            <select v-model="commandType"><option v-for="item in ['START','PAUSE','RESUME','CANCEL','KILL','CHECKPOINT']" :key="item">{{ item }}</option></select>
          </label>
          <label>Expected state version <input v-model.number="expectedStateVersion" type="number" min="0" required></label>
          <label>Payload digest <input v-model="payloadDigest" pattern="[a-f0-9]{64}" maxlength="64" required autocomplete="off"></label>
          <label>{{ locale === 'en-US' ? 'Command reason' : '命令理由' }}
            <textarea v-model="reason" required maxlength="2000" autocomplete="off" />
          </label>
          <button type="submit" :disabled="busy || !reason.trim()">{{ locale === 'en-US' ? 'Submit governed command' : '提交受控命令' }}</button>
        </form>
        <button type="button" :disabled="busy" @click="emit('resume', selectedTask.task_id)">{{ locale === 'en-US' ? 'Resume verified event stream' : '恢复已验证事件流' }}</button>
      </div>
    </div>
    <p v-if="streamError" role="alert">{{ streamError }}</p>
    <ol v-if="events.length" class="event-list" aria-label="Verified AG-UI events">
      <li v-for="event in events" :key="event.event_id">
        <strong>#{{ event.sequence }} {{ event.kind }}</strong> — {{ safeEventSummary(event) }}
      </li>
    </ol>
    <p class="authority-note">{{ locale === 'en-US'
      ? 'The browser cannot mark a task complete; runtime, ledger, evaluation and evidence must all agree.'
      : '浏览器不能将任务标记为完成；Runtime、Ledger、Evaluation 与 Evidence 必须共同确认。' }}</p>
  </section>
</template>
