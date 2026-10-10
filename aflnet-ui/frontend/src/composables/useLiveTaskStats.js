import { computed, onUnmounted, ref, watch } from 'vue'
import { api } from '../api/client.js'

export function formatElapsed(seconds) {
  const value = Math.max(0, Math.floor(seconds))
  const hours = Math.floor(value / 3600)
  const minutes = Math.floor(value / 60) % 60
  const remainder = String(value % 60).padStart(2, '0')
  return hours ? `${hours}时${String(minutes).padStart(2, '0')}分${remainder}秒` : `${minutes}分${remainder}秒`
}

export function useLiveTaskStats(task) {
  const snapshot = ref(null)
  const now = ref(Date.now())
  let generation = 0
  let busy = false

  watch(() => task.value?.id, () => {
    generation += 1
    snapshot.value = null
    busy = false
    poll()
  }, { immediate: true })

  async function poll() {
    const id = task.value?.id
    if (!id || busy) return
    const requestGeneration = generation
    busy = true
    try {
      const { data } = await api.taskStats(id)
      if (generation !== requestGeneration) return
      snapshot.value = { ...data, receivedAt: Date.now() }
      task.value.status = data.status
    } catch {
      // Keep the last successful snapshot on transient connection failures.
    } finally {
      if (generation === requestGeneration) busy = false
    }
  }

  const stats = computed(() => {
    const current = snapshot.value
    const result = { ...(task.value?.stats || {}), ...(current?.stats || {}) }
    if (current && Number.isFinite(Number(result.run_seconds))) {
      const running = current.status === 'running' && task.value?.status === 'running'
      const extra = running ? Math.min(5, Math.max(0, (now.value - current.receivedAt) / 1000)) : 0
      result.run_time = formatElapsed(Number(result.run_seconds) + extra)
    }
    return result
  })

  const timer = window.setInterval(() => {
    now.value = Date.now()
    poll()
  }, 1000)
  onUnmounted(() => {
    generation += 1
    window.clearInterval(timer)
  })
  return stats
}
