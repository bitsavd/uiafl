<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import MetricCard from '../components/MetricCard.vue'
import { api } from '../api/client.js'

const tasks = ref([])
const selectedId = ref('')
const report = ref('')
const loading = ref(false)

const selectedTask = computed(() => tasks.value.find(task => task.id === selectedId.value))
const stats = computed(() => selectedTask.value?.stats || {})
const reportName = computed(() => selectedTask.value ? `${selectedTask.value.name}-检测报告.md` : '检测报告.md')

function metric(value) {
  return value === undefined || value === null || value === '' ? '未采集' : value
}

async function loadTasks() {
  loading.value = true
  try {
    tasks.value = (await api.tasks()).data
    if (!selectedId.value && tasks.value[0]) selectedId.value = tasks.value[0].id
  } catch (error) {
    ElMessage.error(error.message)
  } finally {
    loading.value = false
  }
}

async function loadReport() {
  if (!selectedId.value) return
  loading.value = true
  try {
    report.value = (await api.report(selectedId.value)).data
  } catch (error) {
    ElMessage.error(error.message)
  } finally {
    loading.value = false
  }
}

function downloadReport() {
  if (!report.value) return
  const blob = new Blob([report.value], { type: 'text/markdown;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = reportName.value
  link.click()
  URL.revokeObjectURL(url)
}

watch(selectedId, loadReport)
onMounted(loadTasks)
</script>

<template>
  <div v-loading="loading">
    <section class="panel">
      <div class="panel-heading">
        <div>
          <p>REPORT CENTER</p>
          <h2>报告中心</h2>
        </div>
        <div class="topbar-actions">
          <el-select v-model="selectedId" placeholder="选择任务" style="width: 320px">
            <el-option v-for="task in tasks" :key="task.id" :label="`${task.protocol} · ${task.name}`" :value="task.id" />
          </el-select>
          <el-button @click="loadReport">刷新</el-button>
          <el-button type="primary" :disabled="!report" @click="downloadReport">导出 Markdown</el-button>
        </div>
      </div>
      <div v-if="selectedTask" class="report-summary">
        <div><span>检测协议</span><strong>{{ selectedTask.protocol }}</strong></div>
        <div><span>目标地址</span><strong>{{ selectedTask.netinfo }}</strong></div>
        <div><span>任务状态</span><strong>{{ selectedTask.status }}</strong></div>
        <div><span>状态机</span><strong>{{ selectedTask.has_state_machine ? '已生成' : '未生成' }}</strong></div>
      </div>
    </section>

    <section v-if="selectedTask" class="metric-grid" style="margin-top:16px">
      <MetricCard label="执行次数" :value="metric(stats.execs_done)" hint="任务累计执行" />
      <MetricCard label="执行速度" :value="metric(stats.execs_per_sec)" hint="每秒执行反馈" tone="teal" />
      <MetricCard label="路径总数" :value="metric(stats.paths_total)" hint="目标反馈路径" tone="orange" />
      <MetricCard label="崩溃 / 超时" :value="`${stats.unique_crashes || 0} / ${stats.unique_hangs || 0}`" hint="异常样本汇总" tone="red" />
    </section>

    <section class="grid-two" style="margin-top:16px">
      <div class="panel">
        <div class="panel-heading">
          <div>
            <p>PREVIEW</p>
            <h2>报告预览</h2>
          </div>
        </div>
        <pre class="report-preview">{{ report || '请选择任务生成报告。' }}</pre>
      </div>

      <div class="panel">
        <div class="panel-heading">
          <div>
            <p>CHECKLIST</p>
            <h2>复核清单</h2>
          </div>
        </div>
        <div class="check-list">
          <label><el-checkbox :model-value="true" disabled /> 任务摘要完整</label>
          <label><el-checkbox :model-value="!!stats.execs_done" disabled /> 执行指标已采集</label>
          <label><el-checkbox :model-value="selectedTask?.has_state_machine" disabled /> 状态机结果可用</label>
          <label><el-checkbox :model-value="Number(stats.unique_crashes || 0) + Number(stats.unique_hangs || 0) > 0" disabled /> 异常样本已记录</label>
        </div>
      </div>
    </section>
  </div>
</template>
