import { onUnmounted, ref } from 'vue'
import { formatElapsed } from './useLiveTaskStats.js'

export function taskElapsed(task, now = Date.now()) {
  const stats = task.stats || {}
  const start = Number(stats.start_time) * 1000 || Date.parse(task.started_at || '')
  if (task.status === 'running' && Number.isFinite(start) && start > 0) {
    return formatElapsed(Math.max(0, (now - start) / 1000))
  }
  if (stats.run_seconds !== undefined && stats.run_seconds !== null && stats.run_seconds !== '' && Number.isFinite(Number(stats.run_seconds))) {
    return formatElapsed(Number(stats.run_seconds))
  }
  return stats.run_time || (task.status === 'created' ? '未开始' : '未采集')
}

export function useTaskTimes() {
  const now = ref(Date.now())
  const timer = window.setInterval(() => { now.value = Date.now() }, 1000)
  onUnmounted(() => window.clearInterval(timer))
  return task => taskElapsed(task, now.value)
}
