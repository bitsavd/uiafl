<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import {
  DataAnalysis,
  Files,
  Histogram,
  Operation,
  Refresh,
  Setting,
  Share,
} from '@element-plus/icons-vue'
import { api } from './api/client.js'

const route = useRoute()
const pageTitle = computed(() => route.meta.title || '协议异常检测系统')
const pageEyebrow = computed(() => route.meta.eyebrow || 'PROTOCOL DETECTION')
const healthy = ref(false)
let timer = null

async function checkHealth() {
  try {
    await api.health()
    healthy.value = true
  } catch {
    healthy.value = false
  }
}

onMounted(() => {
  checkHealth()
  timer = window.setInterval(checkHealth, 15000)
})
onUnmounted(() => window.clearInterval(timer))
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <RouterLink to="/" class="brand">
        <div class="brand-mark">P</div>
        <div>
          <strong>协议异常检测系统</strong>
          <span>协议漏洞异常检测</span>
        </div>
      </RouterLink>

      <nav class="nav-list">
        <RouterLink to="/" class="nav-item">
          <el-icon><DataAnalysis /></el-icon><div><span>总览看板</span><small>OVERVIEW</small></div>
        </RouterLink>
        <RouterLink to="/protocols" class="nav-item">
          <el-icon><Operation /></el-icon><div><span>检测任务</span><small>JOBS</small></div>
        </RouterLink>
        <RouterLink to="/analysis" class="nav-item">
          <el-icon><Share /></el-icon><div><span>异常分析</span><small>ANALYSIS</small></div>
        </RouterLink>
        <RouterLink to="/reports" class="nav-item">
          <el-icon><Files /></el-icon><div><span>报告中心</span><small>REPORTS</small></div>
        </RouterLink>
        <RouterLink to="/settings" class="nav-item">
          <el-icon><Setting /></el-icon><div><span>系统设置</span><small>SETTINGS</small></div>
        </RouterLink>
      </nav>

      <div class="sidebar-foot">
        <el-icon><Histogram /></el-icon>
        <div><span>运行模式</span><strong>本地检测引擎</strong></div>
      </div>
    </aside>

    <main class="main-area">
      <header class="topbar">
        <div>
          <p class="eyebrow">{{ pageEyebrow }}</p>
          <h1>{{ pageTitle }}</h1>
        </div>
        <div class="topbar-actions">
          <div class="status-pill" :class="{ offline: !healthy }"><span></span>{{ healthy ? '后端服务正常' : '后端服务不可用' }}</div>
          <el-button :icon="Refresh" @click="checkHealth">刷新</el-button>
        </div>
      </header>
      <section class="page-content">
        <RouterView />
      </section>
    </main>
  </div>
</template>
