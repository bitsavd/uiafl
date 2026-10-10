<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage } from 'element-plus'
import MetricCard from '../components/MetricCard.vue'
import SimpleLineChart from '../components/SimpleLineChart.vue'
import { api } from '../api/client.js'
import { useLiveTaskStats } from '../composables/useLiveTaskStats.js'

const route = useRoute()
const task = ref(null)
const findings = ref({})
const loading = ref(false)
const stateUrl = ref('')
let timer = null

const stats = useLiveTaskStats(task)

function metric(value) {
  return value === undefined || value === null || value === '' ? '未采集' : value
}

async function refresh(background = false) {
  if (!background) loading.value = true
  try {
    task.value = (await api.task(route.params.id)).data
    findings.value = (await api.findings(route.params.id)).data
    stateUrl.value = task.value.has_state_machine ? api.stateMachineUrl(route.params.id) : ''
  } catch (error) {
    if (!background) ElMessage.error(error.message)
  } finally {
    if (!background) loading.value = false
  }
}

async function startTask() {
  try {
    task.value = (await api.startTask(route.params.id)).data
    ElMessage.success('任务已启动')
  } catch (error) {
    ElMessage.error(error.message)
  }
}

async function stopTask() {
  try {
    task.value = (await api.stopTask(route.params.id)).data
    ElMessage.success('已发送停止信号')
  } catch (error) {
    ElMessage.error(error.message)
  }
}

onMounted(() => {
  refresh()
  timer = window.setInterval(() => refresh(true), 8000)
})
onUnmounted(() => window.clearInterval(timer))
</script>

<template>
  <div v-if="task" v-loading="loading">
    <section class="metric-grid">
      <MetricCard label="运行时长" :value="metric(stats.run_time)" :hint="task.status" tone="teal" />
      <MetricCard label="执行次数" :value="metric(stats.execs_done)" hint="执行引擎反馈" />
      <MetricCard label="路径总数" :value="metric(stats.paths_total)" hint="不同执行反馈对应的样本数量" tone="orange" />
      <MetricCard label="崩溃 / 超时" :value="`${stats.unique_crashes || 0} / ${stats.unique_hangs || 0}`" hint="crashes / hangs" tone="red" />
    </section>

    <section class="detail-grid">
      <main>
        <div class="panel">
          <div class="panel-heading">
            <div>
              <p>{{ task.protocol }} · {{ task.netinfo }}</p>
              <h2>{{ task.name }}</h2>
            </div>
            <div>
              <el-button type="primary" :disabled="task.readonly || task.status === 'running'" @click="startTask">启动</el-button>
              <el-button type="danger" :disabled="task.readonly || task.status !== 'running'" @click="stopTask">停止</el-button>
            </div>
          </div>
          <SimpleLineChart
            :rows="task.plot || []"
            :series="[
              { key: 'paths_total', label: '路径总数', color: '#2563eb' },
              { key: 'execs_per_sec', label: '执行速度', color: '#0f766e' },
              ...(stats.line_coverage_available ? [{ key: 'line_coverage_pct', label: '代码行覆盖率', color: '#b45309' }] : []),
            ]"
          />
        </div>

        <div class="panel" style="margin-top:16px">
          <div class="panel-heading">
            <div>
              <p>IPSM</p>
              <h2>协议状态机</h2>
            </div>
          </div>
          <div class="state-box">
            <img v-if="stateUrl" :src="stateUrl" alt="协议状态机" />
            <div v-else class="empty-panel">当前任务暂无可用的协议状态机数据。</div>
          </div>
        </div>
      </main>

      <aside>
        <div class="panel">
          <div class="panel-heading">
            <div>
              <p>CONFIG</p>
              <h3>运行参数摘要</h3>
            </div>
          </div>
          <dl class="summary-list">
            <div><dt>检测协议</dt><dd>{{ task.protocol }}</dd></div>
            <div><dt>目标地址</dt><dd>{{ task.netinfo }}</dd></div>
            <div><dt>运行时长</dt><dd>{{ task.duration || '手动停止' }}</dd></div>
            <div><dt>任务状态</dt><dd>{{ task.status }}</dd></div>
            <div><dt>状态路径数</dt><dd>{{ metric(stats.state_paths) }}</dd></div>
            <div v-if="stats.line_coverage_available"><dt>代码行覆盖率</dt><dd>{{ metric(stats.line_coverage) }}</dd></div>
          </dl>
        </div>

        <div class="panel" style="margin-top:16px">
          <div class="panel-heading">
            <div>
              <p>FINDINGS</p>
              <h3>结果样本</h3>
            </div>
          </div>
          <div class="artifact-list">
            <div class="artifact">
              <div><strong>崩溃样本</strong><span>{{ findings['replayable-crashes']?.length || 0 }} 个文件</span></div>
            </div>
            <div class="artifact">
              <div><strong>超时样本</strong><span>{{ findings['replayable-hangs']?.length || 0 }} 个文件</span></div>
            </div>
            <div class="artifact">
              <div><strong>队列样本</strong><span>{{ findings['replayable-queue']?.length || 0 }} 个文件</span></div>
            </div>
            <div class="artifact">
              <div><strong>状态新增样本</strong><span>{{ findings['replayable-new-ipsm-paths']?.length || 0 }} 个文件</span></div>
            </div>
          </div>
        </div>
      </aside>
    </section>
  </div>
</template>
