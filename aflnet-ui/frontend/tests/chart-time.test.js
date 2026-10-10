import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import vm from 'node:vm'

test('chart ticks show integer hours, minutes and seconds', () => {
  const source = readFileSync(new URL('../src/components/SimpleLineChart.vue', import.meta.url), 'utf8')
  const context = vm.createContext({})
  vm.runInContext(source.slice(source.indexOf('function formatElapsed'), source.indexOf('onMounted(draw)')), context)
  for (const [seconds, expected] of [[0, '00:00:00'], [5, '00:00:05'], [90, '00:01:30'],
    [3600, '01:00:00'], [3661, '01:01:01'], [86400, '24:00:00'], [-1, '00:00:00'], [59.5, '00:01:00']]) {
    assert.equal(context.formatElapsed(seconds), expected)
  }
})
