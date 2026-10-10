<script setup>
import { onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { api } from '../api/client.js'

const router = useRouter()
const loading = ref(false)
const tasks = ref([])
let timer = null

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

async function startTask(row) {
  try {
    await ElMessageBox.confirm(`确认启动任务“${row.name}”？`, '启动检测任务')
    await api.startTask(row.id)
    ElMessage.success('任务已启动')
    refresh()
  } catch (error) {
    if (error !== 'cancel') ElMessage.error(error.message || '已取消')
  }
}

async function stopTask(row) {
  try {
    await api.stopTask(row.id)
    ElMessage.success('已发送停止信号')
    refresh()
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
    refresh()
  } catch (error) {
    if (error !== 'cancel' && error !== 'close') ElMessage.error(error.message)
  }
}

onMounted(() => {
  refresh()
  timer = window.setInterval(refresh, 8000)
})
onUnmounted(() => window.clearInterval(timer))
</script>

<template>
  <section class="panel" v-loading="loading">
    <div class="panel-heading">
      <div>
        <p>JOB LIST</p>
        <h2>任务列表</h2>
      </div>
      <el-button type="primary" @click="router.push('/protocols')">新建任务</el-button>
    </div>
    <el-table :data="tasks" @row-dblclick="row => router.push(`/tasks/${row.id}`)">
      <el-table-column label="任务" min-width="220">
        <template #default="{ row }">
          <div class="task-title"><strong>{{ row.name }}</strong><el-tag v-if="row.readonly" size="small">历史</el-tag></div>
          <span class="muted">{{ row.protocol }} · {{ row.netinfo }}</span>
        </template>
      </el-table-column>
      <el-table-column prop="protocol" label="协议" width="100" />
      <el-table-column prop="status" label="状态" width="100" />
      <el-table-column label="速度" width="110"><template #default="{ row }">{{ row.stats?.execs_per_sec || '-' }}</template></el-table-column>
      <el-table-column label="路径" width="100"><template #default="{ row }">{{ row.stats?.paths_total || '-' }}</template></el-table-column>
      <el-table-column label="覆盖率" width="120"><template #default="{ row }">{{ row.stats?.bitmap_cvg || '-' }}</template></el-table-column>
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
</template>
