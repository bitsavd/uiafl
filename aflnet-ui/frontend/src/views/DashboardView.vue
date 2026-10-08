<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import MetricCard from '../components/MetricCard.vue'
import SimpleLineChart from '../components/SimpleLineChart.vue'
import { api } from '../api/client.js'

const router = useRouter()
const loading = ref(false)
const tasks = ref([])
let timer = null

const runningTasks = computed(() => tasks.value.filter(task => task.status === 'running'))
const activeTask = computed(() => runningTasks.value[0] || null)
const stats = computed(() => activeTask.value?.stats || {})
const totals = computed(() => {
  const crash = tasks.value.reduce((sum, task) => sum + Number(task.stats?.unique_crashes || 0), 0)
  const hang = tasks.value.reduce((sum, task) => sum + Number(task.stats?.unique_hangs || 0), 0)
  return { crash, hang, running: runningTasks.value.length }
})

function metric(value) {
  return value === undefined || value === null || value === '' ? '未采集' : value
}

async function refresh() {
  loading.value = true
  try {
    tasks.value = (await api.tasks()).data
  } catch (error) {
    ElMessage.error(error.message)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  refresh()
  timer = window.setInterval(refresh, 8000)
})
onUnmounted(() => window.clearInterval(timer))
</script>

<template>
  <div v-loading="loading">
    <section class="metric-grid">
      <MetricCard label="运行任务" :value="totals.running" hint="当前后端记录的 running 任务" tone="teal" />
      <MetricCard label="执行速度" :value="activeTask ? metric(stats.execs_per_sec) : '未运行'" hint="运行中任务反馈" />
      <MetricCard label="路径总数" :value="activeTask ? metric(stats.paths_total) : '未运行'" hint="运行中任务反馈" tone="orange" />
      <MetricCard label="崩溃 / 超时" :value="`${totals.crash} / ${totals.hang}`" hint="所有任务汇总" tone="red" />
    </section>

    <section class="grid-two">
      <div class="panel">
        <div class="panel-heading">
          <div>
            <p>LIVE TREND</p>
            <h2>{{ activeTask?.name || '暂无运行任务' }}</h2>
          </div>
          <el-button type="primary" @click="router.push('/protocols')">新建测试</el-button>
        </div>
        <SimpleLineChart
          v-if="activeTask"
          :rows="activeTask?.plot_tail || []"
          :series="[
            { key: 'paths_total', label: '路径总数', color: '#2563eb' },
            { key: 'execs_per_sec', label: '执行速度', color: '#0f766e' },
            { key: 'n_edges', label: '状态边', color: '#b45309' },
          ]"
        />
        <div v-else class="empty-panel">当前没有运行中的检测任务，启动任务后展示实时趋势。</div>
      </div>

      <div class="panel">
        <div class="panel-heading">
          <div>
            <p>RECENT JOBS</p>
            <h2>最近任务</h2>
          </div>
          <el-button @click="router.push('/tasks')">全部任务</el-button>
        </div>
        <el-table :data="tasks.slice(0, 6)" height="320" @row-click="row => router.push(`/tasks/${row.id}`)">
          <el-table-column prop="name" label="任务" min-width="150" />
          <el-table-column prop="protocol" label="协议" width="90" />
          <el-table-column prop="status" label="状态" width="100" />
          <el-table-column label="路径" width="90">
            <template #default="{ row }">{{ row.stats?.paths_total || '-' }}</template>
          </el-table-column>
        </el-table>
      </div>
    </section>
  </div>
</template>
