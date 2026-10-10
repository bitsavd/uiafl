<script setup>
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import MetricCard from '../components/MetricCard.vue'
import SimpleLineChart from '../components/SimpleLineChart.vue'
import { api } from '../api/client.js'
import { useLiveTaskStats } from '../composables/useLiveTaskStats.js'

const tasks = ref([])
const selectedId = ref('')
const detail = ref(null)
const findings = ref({})
const replayPort = ref(18885)
const replayResult = ref(null)
const replayDialogVisible = ref(false)
const loading = ref(false)
const stateUrl = ref('')

const stats = useLiveTaskStats(detail)
let refreshTimer = null
const rows = computed(() => [
  ...(findings.value['replayable-crashes'] || []).map(item => ({ ...item, type: '崩溃' })),
  ...(findings.value['replayable-hangs'] || []).map(item => ({ ...item, type: '超时' })),
])

function metric(value) {
  return value === undefined || value === null || value === '' ? '未采集' : value
}

async function loadTasks() {
  tasks.value = (await api.tasks()).data
  if (!tasks.value.some(task => task.id === selectedId.value)) {
    selectedId.value = tasks.value[0]?.id || ''
    if (!selectedId.value) {
      detail.value = null
      findings.value = {}
      replayResult.value = null
      stateUrl.value = ''
    }
  }
}

async function loadDetail(background = false) {
  if (!selectedId.value) return
  const id = selectedId.value
  if (!background) {
    loading.value = true
    replayResult.value = null
  }
  try {
    const next = (await api.task(id)).data
    const nextFindings = (await api.findings(id)).data
    if (id !== selectedId.value) return
    detail.value = next
    findings.value = nextFindings
    stateUrl.value = next.has_state_machine ? api.stateMachineUrl(id) : ''
  } catch (error) {
    if (background || id !== selectedId.value) return
    detail.value = null
    findings.value = {}
    stateUrl.value = ''
    replayResult.value = null
    ElMessage.error(error.message)
  } finally {
    if (!background) loading.value = false
  }
}

async function replay(row) {
  loading.value = true
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

watch(selectedId, () => loadDetail())
watch(detail, value => {
  const port = Number(value?.netinfo?.split('/').pop())
  if (port > 0 && port <= 65535) replayPort.value = port
})
onMounted(() => {
  loadTasks()
  refreshTimer = window.setInterval(() => loadDetail(true), 8000)
})
onUnmounted(() => window.clearInterval(refreshTimer))
</script>

<template>
  <div v-loading="loading">
    <section class="panel">
      <div class="panel-heading">
        <div>
          <p>ANALYSIS</p>
          <h2>异常分析工作区</h2>
        </div>
        <div style="display:flex; gap:10px">
          <el-input-number v-model="replayPort" :min="1" :max="65535" />
          <el-select v-model="selectedId" style="width: 340px" placeholder="选择检测任务">
            <el-option v-for="task in tasks" :key="task.id" :label="`${task.protocol} · ${task.name}`" :value="task.id" />
          </el-select>
        </div>
      </div>
    </section>

    <template v-if="detail">
      <section class="metric-grid" style="margin-top:16px">
        <MetricCard label="运行时长" :value="metric(stats.run_time)" :hint="detail.status" tone="teal" />
        <MetricCard label="执行次数" :value="metric(stats.execs_done)" hint="执行引擎反馈" />
        <MetricCard label="路径总数" :value="metric(stats.paths_total)" hint="不同执行反馈对应的样本数量" tone="orange" />
        <MetricCard label="崩溃 / 超时" :value="`${stats.unique_crashes || 0} / ${stats.unique_hangs || 0}`" hint="已记录异常样本" tone="red" />
      </section>

      <section class="panel" style="margin-top:16px">
        <dl class="summary-list">
          <div><dt>状态路径数</dt><dd>{{ metric(stats.state_paths) }}</dd></div>
          <div v-if="stats.line_coverage_available"><dt>代码行覆盖率</dt><dd>{{ metric(stats.line_coverage) }}</dd></div>
        </dl>
      </section>

      <section class="grid-two">
        <div class="panel">
          <div class="panel-heading">
            <div>
              <p>TREND</p>
              <h2>速度与覆盖趋势</h2>
            </div>
          </div>
          <SimpleLineChart
            :rows="detail.plot || []"
            :series="[
              { key: 'paths_total', label: '路径总数', color: '#2563eb' },
              { key: 'execs_per_sec', label: '执行速度', color: '#0f766e' },
              ...(stats.line_coverage_available ? [{ key: 'line_coverage_pct', label: '代码行覆盖率', color: '#b45309' }] : []),
            ]"
          />
        </div>

        <div class="panel">
          <div class="panel-heading">
            <div>
              <p>REPLAY</p>
              <h2>异常样本</h2>
            </div>
          </div>
          <el-table :data="rows" height="320">
            <el-table-column prop="type" label="类型" width="80" />
            <el-table-column prop="name" label="样本" min-width="180" />
            <el-table-column prop="size" label="大小" width="90" />
            <el-table-column label="操作" width="90">
              <template #default="{ row }"><el-button size="small" @click="replay(row)">回放</el-button></template>
            </el-table-column>
          </el-table>
        </div>
      </section>

      <section class="grid-two" style="margin-top:16px">
        <div class="panel">
          <div class="panel-heading">
            <div>
              <p>STATE MODEL</p>
              <h2>协议状态机</h2>
            </div>
          </div>
          <div class="state-box">
            <img v-if="stateUrl" :src="stateUrl" alt="协议状态机" />
            <div v-else class="empty-panel">当前任务暂无可用的协议状态机数据。</div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-heading">
            <div>
              <p>OUTPUT</p>
              <h2>回放结果</h2>
            </div>
          </div>
          <pre class="code-line" style="min-height:560px">{{ replayResult ? `returncode: ${replayResult.returncode}\nelapsed_ms: ${replayResult.elapsed_ms}\ntarget_started: ${replayResult.target_started ?? '-'}\ntarget_ready: ${replayResult.target_ready ?? '-'}\n\nSTDOUT:\n${replayResult.stdout || '-'}\n\nSTDERR:\n${replayResult.stderr || '-'}` : '选择异常样本后执行回放。' }}</pre>
        </div>
      </section>
    </template>
    <div v-else class="panel">
      <div class="empty-panel">暂无可分析的检测任务。</div>
    </div>

    <el-dialog v-model="replayDialogVisible" title="回放结果" width="760px">
      <pre class="code-line">{{ replayResult ? `returncode: ${replayResult.returncode}\nelapsed_ms: ${replayResult.elapsed_ms}\ntarget_started: ${replayResult.target_started ?? '-'}\ntarget_ready: ${replayResult.target_ready ?? '-'}\n\nSTDOUT:\n${replayResult.stdout || '-'}\n\nSTDERR:\n${replayResult.stderr || '-'}` : '暂无回放结果。' }}</pre>
    </el-dialog>
  </div>
</template>
