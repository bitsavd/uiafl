<script setup>
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '../api/client.js'

const loading = ref(false)
const saving = ref(false)
const form = reactive({
  execution: {
    max_parallel_tasks: 1,
    default_duration: '10m',
    default_timeout_ms: '2000+',
    startup_delay_us: 20000,
  },
  limits: {
    max_replay_seconds: 30,
  },
})

function assignSettings(data) {
  Object.assign(form.execution, data.execution || {})
  Object.assign(form.limits, data.limits || {})
}

async function loadSettings() {
  loading.value = true
  try {
    assignSettings((await api.settings()).data)
  } catch (error) {
    ElMessage.error(error.message)
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  try {
    assignSettings((await api.saveSettings(form)).data)
    ElMessage.success('系统设置已保存')
  } catch (error) {
    ElMessage.error(error.message)
  } finally {
    saving.value = false
  }
}

onMounted(loadSettings)
</script>

<template>
  <div v-loading="loading">
    <section class="panel">
      <div class="panel-heading">
        <div>
          <p>SYSTEM SETTINGS</p>
          <h2>系统设置</h2>
        </div>
        <div class="topbar-actions">
          <el-button @click="loadSettings">重置</el-button>
          <el-button type="primary" :loading="saving" @click="save">保存设置</el-button>
        </div>
      </div>

      <el-form label-position="top">
        <div class="settings-grid">
          <div class="settings-section">
            <h3>运行参数</h3>
            <el-form-item label="最大并行任务">
              <el-input-number v-model="form.execution.max_parallel_tasks" :min="1" :max="8" />
              <div class="form-tip">单位：个。限制同时运行的检测任务数量。</div>
            </el-form-item>
            <el-form-item label="默认运行时长">
              <el-input v-model="form.execution.default_duration" placeholder="10m" />
              <div class="form-tip">支持 s/m/h，例如 30s、10m、1h。</div>
            </el-form-item>
          </div>

          <div class="settings-section">
            <h3>执行超时</h3>
            <el-form-item label="单次执行超时">
              <el-input v-model="form.execution.default_timeout_ms" placeholder="2000+" />
              <div class="form-tip">单位：毫秒 ms，可写 2000 或 2000+。</div>
            </el-form-item>
            <el-form-item label="启动等待时间">
              <el-input-number v-model="form.execution.startup_delay_us" :min="0" :max="10000000" :step="1000" />
              <div class="form-tip">单位：微秒 us，用于等待目标服务启动完成。</div>
            </el-form-item>
            <el-form-item label="复现超时">
              <el-input-number v-model="form.limits.max_replay_seconds" :min="5" :max="120" />
              <div class="form-tip">单位：秒。限制单个异常样本复现时间。</div>
            </el-form-item>
          </div>

        </div>
      </el-form>
    </section>
  </div>
</template>
