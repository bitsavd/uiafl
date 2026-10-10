import assert from 'node:assert/strict'
import { createRenderer, h, ref } from 'vue'
import { api } from '../src/api/client.js'
import { formatElapsed, useLiveTaskStats } from '../src/composables/useLiveTaskStats.js'

globalThis.window = globalThis
const renderer = createRenderer({
  createElement: () => ({}), insert() {}, remove() {}, patchProp() {},
  setElementText() {}, createText: () => ({}), createComment: () => ({}),
  setText() {}, setComment() {}, parentNode: () => null, nextSibling: () => null,
})
assert.equal(formatElapsed(3661), '1时01分01秒')
assert.equal(formatElapsed(59), '0分59秒')
const task = ref({ id: 'first', status: 'running', stats: {}, plot: [{ unix_time: 1 }] })
const started = Date.now()
let status = 'running'
let seconds = 0
let calls = 0
api.taskStats = async id => {
  calls++
  if (status === 'running') seconds = Math.floor((Date.now() - started) / 1000)
  return { data: { id, status, stats: { run_seconds: seconds, execs_done: '42' } } }
}
let stats
const app = renderer.createApp({
  setup() { stats = useLiveTaskStats(task); return () => h('div') },
})
app.mount({})
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))
await sleep(2200)
assert.equal(stats.value.run_time, '0分02秒')
assert.equal(stats.value.execs_done, '42')
assert.deepEqual(task.value.plot, [{ unix_time: 1 }])
assert.ok(calls >= 3)
status = 'stopped'
await sleep(1100)
const stopped = stats.value.run_time
await sleep(1100)
assert.equal(stats.value.run_time, stopped)
app.unmount()
const lastCalls = calls
await sleep(1100)
assert.equal(calls, lastCalls)
console.log('Live stats: per-second timer, unchanged plots, stopped clock and cleanup passed')
