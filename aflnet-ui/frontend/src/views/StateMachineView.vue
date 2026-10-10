<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client.js'

const tasks = ref([])
const selectedId = ref('')
const stateUrl = ref('')
const selectedTask = computed(() => tasks.value.find(task => task.id === selectedId.value))

async function load() {
  try {
    tasks.value = (await api.tasks()).data
    selectedId.value = tasks.value.find(task => task.has_state_machine)?.id || tasks.value[0]?.id || ''
  } catch (error) {
    ElMessage.error(error.message)
  }
}

watch(selectedId, id => {
  stateUrl.value = id ? api.stateMachineUrl(id) : ''
})

onMounted(load)
</script>

<template>
  <section class="panel">
    <div class="panel-heading">
      <div>
          <p>STATE MODEL</p>
          <h2>协议状态机展示</h2>
      </div>
      <el-select v-model="selectedId" style="width: 360px" placeholder="选择任务">
        <el-option v-for="task in tasks" :key="task.id" :label="`${task.protocol} · ${task.name}`" :value="task.id" />
      </el-select>
    </div>
    <div class="metric-grid" v-if="selectedTask">
      <div class="metric-card"><span class="metric-accent"></span><p>状态节点</p><strong>{{ selectedTask.plot_tail?.at(-1)?.n_nodes ?? '未采集' }}</strong><small>状态模型反馈</small></div>
      <div class="metric-card tone-teal"><span class="metric-accent"></span><p>状态转移</p><strong>{{ selectedTask.plot_tail?.at(-1)?.n_edges ?? '未采集' }}</strong><small>状态模型反馈</small></div>
      <div class="metric-card tone-orange"><span class="metric-accent"></span><p>路径总数</p><strong>{{ selectedTask.stats?.paths_total || '未采集' }}</strong><small>不同执行反馈对应的样本数量</small></div>
      <div class="metric-card tone-red"><span class="metric-accent"></span><p>异常</p><strong>{{ selectedTask.stats?.unique_crashes || 0 }} / {{ selectedTask.stats?.unique_hangs || 0 }}</strong><small>crashes / hangs</small></div>
    </div>
    <div class="state-box">
      <img v-if="stateUrl" :src="stateUrl" alt="协议状态机" />
      <div v-else class="empty-panel">请选择一个已生成状态机的任务。</div>
    </div>
  </section>
</template>
