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
    default_target_profile: 'standard',
    bind_interface: 'default',
    auto_refresh_seconds: 8,
  },
  policies: {
    rate_limit: true,
    retain_results: true,
    coverage_fallback: true,
    auto_replay_after_detection: false,
  },
  limits: {
    max_duration_hours: 24,
    max_replay_seconds: 30,
    max_sample_preview: 20,
  },
})

function assignSettings(data) {
  Object.assign(form.execution, data.execution || {})
  Object.assign(form.policies, data.policies || {})
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
            <el-form-item label="自动刷新间隔">
              <el-input-number v-model="form.execution.auto_refresh_seconds" :min="3" :max="60" />
              <div class="form-tip">单位：秒。用于看板和任务状态刷新。</div>
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

          <div class="settings-section">
            <h3>接入策略</h3>
            <el-form-item label="默认接入方式">
              <el-radio-group v-model="form.execution.default_target_profile">
                <el-radio-button label="standard">标准检测</el-radio-button>
                <el-radio-button label="external">外部目标</el-radio-button>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="默认网口">
              <el-select v-model="form.execution.bind_interface">
                <el-option label="系统默认" value="default" />
                <el-option label="本机回环" value="lo" />
                <el-option label="以太网" value="eth0" />
                <el-option label="无线网络" value="wlan0" />
              </el-select>
            </el-form-item>
            <el-form-item label="最长运行时长">
              <el-input-number v-model="form.limits.max_duration_hours" :min="1" :max="168" />
              <div class="form-tip">单位：小时。用于约束单个任务的上限。</div>
            </el-form-item>
          </div>

          <div class="settings-section">
            <h3>结果策略</h3>
            <el-form-item label="速率保护"><el-switch v-model="form.policies.rate_limit" /></el-form-item>
            <el-form-item label="移除任务时保留结果"><el-switch v-model="form.policies.retain_results" /></el-form-item>
            <el-form-item label="覆盖反馈降级展示"><el-switch v-model="form.policies.coverage_fallback" /></el-form-item>
            <el-form-item label="异常发现后自动回放"><el-switch v-model="form.policies.auto_replay_after_detection" /></el-form-item>
            <el-form-item label="样本预览数量">
              <el-input-number v-model="form.limits.max_sample_preview" :min="5" :max="100" />
              <div class="form-tip">单位：条。控制报告和样本列表的默认展示数量。</div>
            </el-form-item>
          </div>
        </div>
      </el-form>
    </section>
  </div>
</template>
