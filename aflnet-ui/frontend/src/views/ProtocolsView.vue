<script setup>
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api/client.js'

const router = useRouter()
const groups = ref([])
const tasks = ref([])
const activeGroupId = ref('industrial')
const activeProtocol = ref(null)
const protocolDialogVisible = ref(false)
const createDialogVisible = ref(false)
const creating = ref(false)
const loading = ref(false)
let timer = null

const form = reactive({
  name: '',
  category: 'industrial',
  protocol: '',
  transport: 'tcp',
  target_host: '127.0.0.1',
  target_port: 18885,
  duration: '10m',
  aflnet_options: {
    state_aware: true,
    region_mutation: true,
    false_negative_reduction: false,
    terminate_server: true,
    state_selection: 3,
    seed_selection: 3,
    startup_delay_us: 20000,
    timeout: '2000+',
    memory_limit: 'none',
    skip_deterministic: true,
  },
})

const activeGroup = computed(() => groups.value.find(group => group.id === activeGroupId.value))
const targetNetinfo = computed(() => `${form.transport}://${form.target_host || '127.0.0.1'}/${form.target_port || ''}`)
const targetProfile = computed(() => {
  const host = String(form.target_host || '').trim().toLowerCase()
  return ['127.0.0.1', 'localhost', '::1'].includes(host) ? 'standard' : 'external'
})

function protocolSummary(protocol) {
  const category = activeGroup.value?.name || '协议'
  return `${category} · ${protocol.transport} · ${protocol.name}`
}

function applyProtocol(protocol, closeDialog = true) {
  activeProtocol.value = protocol
  form.protocol = protocol.id
  form.category = activeGroupId.value
  form.name = `${protocol.id} 协议检测`
  const port = protocol.default_port || (protocol.id === 'RTSP' ? 8554 : protocol.id === 'FTP' ? 2200 : protocol.id === 'DNS' ? 5353 : 18885)
  form.transport = protocol.transport.includes('UDP') ? 'udp' : 'tcp'
  form.target_port = port
  if (closeDialog) protocolDialogVisible.value = false
}

function selectProtocol(protocol) {
  applyProtocol(protocol, true)
}

async function refreshTasks() {
  loading.value = true
  try {
    tasks.value = (await api.tasks()).data
  } catch (error) {
    ElMessage.error(error.message)
  } finally {
    loading.value = false
  }
}

async function loadProtocols() {
  groups.value = (await api.protocols()).data
  if (groups.value[0]?.protocols[0]) applyProtocol(groups.value[0].protocols[0], false)
}

async function createTask() {
  creating.value = true
  try {
    const { data } = await api.createTask({
      name: form.name,
      category: form.category,
      protocol: form.protocol,
      target_profile: targetProfile.value,
      netinfo: targetNetinfo.value,
      duration: form.duration,
      aflnet_options: form.aflnet_options,
    })
    ElMessage.success('检测任务已创建')
    createDialogVisible.value = false
    await refreshTasks()
    router.push(`/tasks/${data.id}`)
  } catch (error) {
    ElMessage.error(error.message)
  } finally {
    creating.value = false
  }
}

async function startTask(row) {
  try {
    await api.startTask(row.id)
    ElMessage.success('任务已启动')
    refreshTasks()
  } catch (error) {
    ElMessage.error(error.message)
  }
}

async function stopTask(row) {
  try {
    await api.stopTask(row.id)
    ElMessage.success('已发送停止信号')
    refreshTasks()
  } catch (error) {
    ElMessage.error(error.message)
  }
}

async function removeTask(row) {
  try {
    await ElMessageBox.confirm(
      `仅从系统任务列表移除“${row.name}”，不会删除对应历史数据。后续可通过历史数据导入重新加入。`,
      '移除任务记录',
      { type: 'warning', confirmButtonText: '移除记录', cancelButtonText: '取消' },
    )
    await api.removeTask(row.id)
    ElMessage.success('任务记录已移除')
    refreshTasks()
  } catch (error) {
    if (error !== 'cancel' && error !== 'close') ElMessage.error(error.message)
  }
}

function metric(value) {
  return value === undefined || value === null || value === '' ? '未采集' : value
}

watch(activeGroupId, () => {
  const first = activeGroup.value?.protocols?.[0]
  if (first) applyProtocol(first, false)
})

onMounted(() => {
  Promise.all([loadProtocols(), refreshTasks()])
  timer = window.setInterval(refreshTasks, 8000)
})
onUnmounted(() => window.clearInterval(timer))
</script>

<template>
  <div>
    <section class="panel">
      <div class="panel-heading">
        <div>
          <p>WORKSPACE</p>
          <h2>检测任务管理</h2>
        </div>
        <div class="topbar-actions">
          <el-button @click="protocolDialogVisible = true">选择协议</el-button>
          <el-button type="primary" @click="createDialogVisible = true">新建任务</el-button>
        </div>
      </div>
      <div class="task-setup-line">
        <div>
          <span>当前协议</span>
          <strong>{{ activeProtocol ? protocolSummary(activeProtocol) : '未选择' }}</strong>
        </div>
        <div>
          <span>目标地址</span>
          <strong>{{ targetNetinfo }}</strong>
        </div>
        <div>
          <span>运行时长</span>
          <strong>{{ form.duration || '手动停止' }}</strong>
        </div>
      </div>
    </section>

    <section class="panel" style="margin-top:16px" v-loading="loading">
      <div class="panel-heading">
        <div>
          <p>JOBS</p>
          <h2>任务列表</h2>
        </div>
      </div>
      <el-table :data="tasks" @row-dblclick="row => router.push(`/tasks/${row.id}`)">
        <el-table-column label="任务" min-width="220">
          <template #default="{ row }">
            <div class="task-title"><strong>{{ row.name }}</strong><el-tag v-if="row.readonly" size="small">样例</el-tag></div>
            <span class="muted">{{ row.protocol }} · {{ row.netinfo }}</span>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="100" />
        <el-table-column label="速度" width="110"><template #default="{ row }">{{ metric(row.stats?.execs_per_sec) }}</template></el-table-column>
        <el-table-column label="路径" width="110"><template #default="{ row }">{{ metric(row.stats?.paths_total) }}</template></el-table-column>
        <el-table-column label="覆盖反馈" width="120"><template #default="{ row }">{{ metric(row.stats?.bitmap_cvg) }}</template></el-table-column>
        <el-table-column label="异常" width="110"><template #default="{ row }">{{ row.stats?.unique_crashes || 0 }} / {{ row.stats?.unique_hangs || 0 }}</template></el-table-column>
        <el-table-column label="操作" width="340" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="router.push(`/tasks/${row.id}`)">详情</el-button>
            <el-button size="small" type="primary" :disabled="row.readonly || row.status === 'running'" @click.stop="startTask(row)">启动</el-button>
            <el-button size="small" type="danger" :disabled="row.readonly || row.status !== 'running'" @click.stop="stopTask(row)">停止</el-button>
            <el-button size="small" :disabled="row.status === 'running'" @click.stop="removeTask(row)">移除记录</el-button>
          </template>
        </el-table-column>
      </el-table>
    </section>

    <el-dialog v-model="protocolDialogVisible" title="选择检测协议" width="780px">
      <div class="protocol-picker">
        <el-tabs v-model="activeGroupId">
          <el-tab-pane v-for="group in groups" :key="group.id" :label="group.name" :name="group.id">
            <p class="muted">{{ group.description }}</p>
            <div class="protocol-grid compact">
              <button
                v-for="protocol in group.protocols"
                :key="protocol.id"
                class="protocol-card"
                :class="{ active: activeProtocol?.id === protocol.id }"
                type="button"
                @click="selectProtocol(protocol)"
              >
                <h3>{{ protocol.name }}</h3>
                <p>{{ protocol.transport }} 传输</p>
              </button>
            </div>
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-dialog>

    <el-dialog v-model="createDialogVisible" title="新建检测任务" width="760px">
      <el-form label-position="top">
        <div class="form-grid">
          <el-form-item label="任务名称"><el-input v-model="form.name" /></el-form-item>
          <el-form-item label="检测协议">
            <el-input :model-value="activeProtocol ? protocolSummary(activeProtocol) : ''" readonly>
              <template #append><el-button @click="protocolDialogVisible = true">选择</el-button></template>
            </el-input>
          </el-form-item>
          <el-form-item label="目标网络协议">
            <el-segmented
              v-model="form.transport"
              :options="[
                { label: 'TCP', value: 'tcp' },
                { label: 'UDP', value: 'udp' },
              ]"
            />
            <div class="form-tip">选择目标服务使用的网络传输协议。</div>
          </el-form-item>
          <el-form-item label="目标主机地址">
            <el-input v-model="form.target_host" placeholder="127.0.0.1" />
            <div class="form-tip">可填写本机地址、真实设备 IP 或远程服务域名。</div>
          </el-form-item>
          <el-form-item label="目标端口">
            <el-input-number v-model="form.target_port" :min="1" :max="65535" />
            <div class="form-tip">单位：端口号。选择协议后会自动填入默认端口，可按目标服务修改。</div>
          </el-form-item>
          <el-form-item label="运行时长">
            <el-input v-model="form.duration" placeholder="如 10m、1h；留空则手动停止" />
            <div class="form-tip">单位：s 秒、m 分钟、h 小时。示例：10m 表示 10 分钟，1h 表示 1 小时。</div>
          </el-form-item>
        </div>
        <div class="form-grid">
          <el-form-item label="状态选择策略">
            <el-input-number v-model="form.aflnet_options.state_selection" :min="1" :max="3" />
            <div class="form-tip">取值范围 1-3：1 随机，2 轮询，3 优先选择高价值状态。</div>
          </el-form-item>
          <el-form-item label="样本选择策略">
            <el-input-number v-model="form.aflnet_options.seed_selection" :min="1" :max="3" />
            <div class="form-tip">取值范围 1-3：1 随机，2 轮询，3 优先选择高价值样本。</div>
          </el-form-item>
          <el-form-item label="启动等待时间">
            <el-input-number v-model="form.aflnet_options.startup_delay_us" :min="0" :max="10000000" :step="1000" />
            <div class="form-tip">单位：微秒 us。默认 20000 表示 20 ms，用于等待目标服务完成启动。</div>
          </el-form-item>
          <el-form-item label="单次执行超时">
            <el-input v-model="form.aflnet_options.timeout" />
            <div class="form-tip">单位：毫秒 ms。可写 2000，也可写 2000+ 表示允许引擎做自适应放宽。</div>
          </el-form-item>
        </div>
        <el-form-item label="检测策略">
          <el-checkbox v-model="form.aflnet_options.state_aware">启用协议状态跟踪</el-checkbox>
          <el-checkbox v-model="form.aflnet_options.region_mutation">启用消息结构变异</el-checkbox>
          <el-checkbox v-model="form.aflnet_options.terminate_server">任务结束后清理目标进程</el-checkbox>
          <el-checkbox v-model="form.aflnet_options.skip_deterministic">快速启动模式</el-checkbox>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createDialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="creating" @click="createTask">创建任务</el-button>
      </template>
    </el-dialog>
  </div>
</template>
