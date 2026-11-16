import assert from 'node:assert/strict'
import { taskElapsed } from '../src/composables/useTaskTimes.js'

assert.equal(taskElapsed({ status: 'created' }), '未开始')
assert.equal(taskElapsed({ status: 'running', stats: { start_time: 100 } }, 165000), '1分05秒')
assert.equal(taskElapsed({ status: 'stopped', stats: { start_time: 100, run_seconds: 65 } }, 300000), '1分05秒')
assert.equal(taskElapsed({ status: 'completed', stats: { run_seconds: 21600 } }), '6时00分00秒')
assert.equal(taskElapsed({ status: 'stopped', stats: { run_seconds: 0 } }), '0分00秒')
assert.equal(taskElapsed({ status: 'stopped' }), '未采集')
console.log('Task table times: actual duration, ticking clock, and stopped records passed')
