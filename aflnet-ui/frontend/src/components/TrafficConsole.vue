<script setup>
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { Delete, Download } from '@element-plus/icons-vue'
import { api } from '../api/client.js'
import { formatPayload, mergeTraffic, trafficResult } from '../utils/traffic.js'

const props = defineProps({ task: { type: Object, required: true } })
const events = ref([])
const available = ref(false)
const loading = ref(true)
const error = ref('')
const skipped = ref(0)
const follow = ref(true)
const mode = ref('hex')
const viewport = ref(null)
let cursor = 0
let busy = false
let generation = 0
let timer
let disposed = false
const activeCase = computed(() => events.value.at(-1)?.case_id)
const labels = { case_begin: 'CASE', send: 'TX 发送', receive: 'RX 接收', skip: '未发送', case_end: '结果' }

function timestamp(value) {
  const date = new Date(value)
  return `${date.toLocaleTimeString('zh-CN', { hourCycle: 'h23' })}.${String(date.getMilliseconds()).padStart(3, '0')}`
}

async function scrollToLatest() {
  await nextTick()
  if (follow.value && viewport.value) viewport.value.scrollTop = viewport.value.scrollHeight
}

function onScroll() {
  const element = viewport.value
  if (element && element.scrollHeight - element.scrollTop - element.clientHeight > 40) follow.value = false
}

async function poll() {
  const id = props.task.id
  if (!id || busy || disposed) return
  busy = true
  const requestGeneration = generation
  try {
    const { data } = await api.taskTraffic(id, cursor)
    if (disposed || requestGeneration !== generation) return
    if (data.reset) events.value = []
    events.value = mergeTraffic(events.value, data.events)
    cursor = data.cursor
    available.value = data.available
    skipped.value += data.skipped || 0
    error.value = ''
    await scrollToLatest()
  } catch (failure) {
    if (!disposed && requestGeneration === generation) error.value = failure.message
  } finally {
    if (requestGeneration === generation) {
      busy = false
      loading.value = false
    }
  }
}

function clearView() { events.value = [] }

function download() {
  const blob = new Blob([JSON.stringify({ task_id: props.task.id, protocol: props.task.protocol,
    target: props.task.netinfo, events: events.value }, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `${props.task.id}-traffic.json`
  link.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 1000)
}

watch(() => props.task.id, () => {
  generation++
  busy = false
  cursor = 0
  events.value = []
  skipped.value = 0
  available.value = false
  loading.value = true
  follow.value = true
  poll()
}, { immediate: true })
watch(follow, value => { if (value) scrollToLatest() })
onMounted(() => { timer = window.setInterval(poll, 1000) })
onUnmounted(() => {
  disposed = true
  generation++
  window.clearInterval(timer)
})
</script>

<template>
  <section class="panel traffic-panel">
    <div class="panel-heading traffic-heading">
      <div>
        <p>LIVE TRAFFIC</p>
        <h2>异常注入与响应</h2>
      </div>
      <span class="traffic-status">{{ task.status === 'running' ? '实时采集' : '收发记录' }}<template v-if="activeCase"> · CASE #{{ activeCase }}</template></span>
    </div>
    <div class="traffic-toolbar">
      <el-radio-group v-model="mode" size="small" aria-label="报文显示格式">
        <el-radio-button value="hex">HEX</el-radio-button>
        <el-radio-button value="text">文本</el-radio-button>
      </el-radio-group>
      <span class="traffic-count">最近 {{ events.length }} 条记录<template v-if="skipped"> · 已跳过 {{ skipped }} 条较早记录</template></span>
      <el-switch v-model="follow" active-text="跟随最新" />
      <el-tooltip content="清空当前显示" placement="top"><el-button :icon="Delete" circle aria-label="清空当前显示" @click="clearView" /></el-tooltip>
      <el-tooltip content="导出当前记录" placement="top"><el-button :icon="Download" circle aria-label="导出当前记录" :disabled="!events.length" @click="download" /></el-tooltip>
    </div>
    <div v-if="error" class="traffic-error" role="status">{{ error }}</div>
    <div ref="viewport" class="traffic-viewport" role="log" aria-label="注入报文与目标响应" aria-live="off" @scroll.passive="onScroll">
      <div v-if="!events.length" class="traffic-empty">
        {{ loading ? '正在读取收发记录…' : available || task.status === 'running' ? '等待检测报文…' : task.status === 'created' ? '任务启动后展示注入报文与目标响应。' : '该任务没有保存收发记录。' }}
      </div>
      <article v-for="event in events" :key="event.seq" class="traffic-event" :class="[`traffic-${event.kind}`, { 'traffic-failure': ['crash', 'timeout', 'execution_error', 'connection_failed'].includes(event.result) }]">
        <div class="traffic-event-heading">
          <time>{{ timestamp(event.timestamp_ms) }}</time>
          <span class="traffic-direction">{{ labels[event.kind] }}</span>
          <strong>#{{ event.case_id }}</strong>
          <span v-if="event.message_index">消息 {{ event.message_index }}</span>
          <span v-if="event.length !== undefined">{{ event.length }} B</span>
          <span v-if="event.truncated" class="traffic-truncated">截取 {{ event.data_hex.length / 2 }} B</span>
        </div>
        <div v-if="event.kind === 'case_begin'" class="traffic-case-meta"><template v-if="event.seed_id != null">源样本 #{{ event.seed_id }}</template><template v-else>输入校准</template> · 目标状态 {{ event.target_state }}<template v-if="event.stage"> · {{ event.stage }}</template></div>
        <template v-if="event.data_hex">
          <pre class="traffic-payload">{{ formatPayload(event.data_hex.slice(0, 128), mode) }}</pre>
          <details v-if="event.data_hex.length > 128" class="traffic-more">
            <summary>展开其余 {{ event.data_hex.length / 2 - 64 }} B</summary>
            <pre class="traffic-payload">{{ formatPayload(event.data_hex.slice(128), mode, 64) }}</pre>
          </details>
        </template>
        <div v-if="event.kind === 'case_end'" class="traffic-case-meta">
          <strong>{{ trafficResult(event.result) }}</strong> · {{ event.elapsed_ms }} ms · 回包 {{ event.response_bytes }} B
          <span v-if="event.result === 'crash' && event.signal"> · 信号 {{ event.signal }}</span>
          <span v-if="event.states?.length"> · 状态 {{ event.states.join(' → ') }}</span>
        </div>
        <div v-else-if="event.result === 'send_error' || event.kind === 'skip'" class="traffic-case-meta">{{ trafficResult(event.result) }}</div>
      </article>
    </div>
  </section>
</template>

<style scoped>
.traffic-panel { margin-top: 16px; min-width: 0; }
.traffic-heading { flex-wrap: wrap; gap: 12px; }
.traffic-status, .traffic-count { color: var(--muted); font-size: 12px; }
.traffic-toolbar { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; margin-bottom: 12px; }
.traffic-count { margin-right: auto; }
.traffic-toolbar .el-button + .el-button { margin-left: 0; }
.traffic-viewport { height: 400px; overflow: auto; border: 1px solid #dbe4ee; border-radius: 6px; background: #f8fafc; overflow-anchor: none; }
.traffic-empty { height: 100%; display: grid; place-items: center; padding: 20px; color: var(--muted); font-size: 13px; text-align: center; }
.traffic-event { padding: 10px 14px; border-bottom: 1px solid #e2e8f0; border-left: 3px solid transparent; }
.traffic-event-heading { display: flex; align-items: center; flex-wrap: wrap; gap: 8px 14px; font-size: 12px; }
.traffic-event-heading time { color: #64748b; font-variant-numeric: tabular-nums; }
.traffic-direction { font-weight: 700; min-width: 60px; }
.traffic-send { border-left-color: #2563eb; }
.traffic-send .traffic-direction { color: #1d4ed8; }
.traffic-receive { border-left-color: #0f766e; }
.traffic-receive .traffic-direction { color: #0f766e; }
.traffic-case_begin { background: #eef2f7; }
.traffic-failure { border-left-color: #dc2626; background: #fff1f2; }
.traffic-failure .traffic-direction, .traffic-error { color: #b91c1c; }
.traffic-truncated { color: #9a5507; }
.traffic-payload { margin: 8px 0 0; font: 12px/1.65 Consolas, monospace; color: #172033; white-space: pre-wrap; overflow-wrap: anywhere; }
.traffic-case-meta { margin-top: 6px; font-size: 12px; color: #475569; line-height: 1.7; overflow-wrap: anywhere; }
.traffic-more { margin-top: 6px; color: #52637b; font-size: 12px; }
.traffic-more summary { cursor: pointer; }
.traffic-error { padding-bottom: 10px; font-size: 12px; }
@media (max-width: 600px) { .traffic-viewport { height: 360px; } .traffic-event { padding: 10px; } }
</style>
