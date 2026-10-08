<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client.js'

const tasks = ref([])
const selectedId = ref('')
const findings = ref({})
const replayPort = ref(18885)
const replayResult = ref(null)
const replayDialogVisible = ref(false)
const loading = ref(false)
const selectedTask = computed(() => tasks.value.find(task => task.id === selectedId.value))
const rows = computed(() => [
  ...(findings.value['replayable-crashes'] || []).map(item => ({ ...item, type: 'crash' })),
  ...(findings.value['replayable-hangs'] || []).map(item => ({ ...item, type: 'hang' })),
])

async function loadTasks() {
  tasks.value = (await api.tasks()).data
  if (!tasks.value.some(task => task.id === selectedId.value)) {
    selectedId.value = tasks.value[0]?.id || ''
    if (!selectedId.value) {
      findings.value = {}
      replayResult.value = null
    }
  }
}

async function loadFindings() {
  if (!selectedId.value) return
  try {
    findings.value = (await api.findings(selectedId.value)).data
  } catch (error) {
    findings.value = {}
    replayResult.value = null
    ElMessage.error(error.message)
  }
}

async function replay(row) {
  loading.value = true
  replayResult.value = null
  try {
    replayResult.value = (await api.replay(selectedId.value, { sample_group: row.group, sample_name: row.name, port: replayPort.value })).data
    replayDialogVisible.value = true
    ElMessage.success('回放已执行')
  } catch (error) {
    replayResult.value = { returncode: '-', elapsed_ms: '-', stdout: '', stderr: error.message || '回放失败' }
    replayDialogVisible.value = true
    ElMessage.error(error.message)
  } finally {
    loading.value = false
  }
}

watch(selectedId, loadFindings)
watch(selectedTask, value => {
  const port = Number(value?.netinfo?.split('/').pop())
  if (port > 0 && port <= 65535) replayPort.value = port
})
onMounted(loadTasks)
</script>

<template>
  <section class="grid-two" v-loading="loading">
    <div class="panel">
      <div class="panel-heading">
        <div>
          <p>FINDINGS</p>
          <h2>异常样本</h2>
        </div>
        <div style="display:flex; gap:10px">
          <el-input-number v-model="replayPort" :min="1" :max="65535" />
          <el-select v-model="selectedId" style="width: 280px">
            <el-option v-for="task in tasks" :key="task.id" :label="`${task.protocol} · ${task.name}`" :value="task.id" />
          </el-select>
        </div>
      </div>
      <el-table :data="rows" height="520">
        <el-table-column prop="type" label="类型" width="90" />
        <el-table-column prop="name" label="文件" min-width="220" />
        <el-table-column prop="size" label="大小" width="100" />
        <el-table-column label="操作" width="100">
          <template #default="{ row }"><el-button size="small" @click="replay(row)">回放</el-button></template>
        </el-table-column>
      </el-table>
    </div>
    <div class="panel">
      <div class="panel-heading">
        <div>
          <p>REPLAY OUTPUT</p>
          <h2>{{ selectedTask?.protocol || '-' }} 回放输出</h2>
        </div>
      </div>
      <pre class="code-line" style="min-height:520px">{{ replayResult ? `returncode: ${replayResult.returncode}\nelapsed_ms: ${replayResult.elapsed_ms}\ntarget_started: ${replayResult.target_started ?? '-'}\ntarget_ready: ${replayResult.target_ready ?? '-'}\n\nSTDOUT:\n${replayResult.stdout || '-'}\n\nSTDERR:\n${replayResult.stderr || '-'}` : '选择异常样本后执行回放。' }}</pre>
    </div>
    <el-dialog v-model="replayDialogVisible" title="回放结果" width="760px">
      <pre class="code-line">{{ replayResult ? `returncode: ${replayResult.returncode}\nelapsed_ms: ${replayResult.elapsed_ms}\ntarget_started: ${replayResult.target_started ?? '-'}\ntarget_ready: ${replayResult.target_ready ?? '-'}\n\nSTDOUT:\n${replayResult.stdout || '-'}\n\nSTDERR:\n${replayResult.stderr || '-'}` : '暂无回放结果。' }}</pre>
    </el-dialog>
  </section>
</template>
