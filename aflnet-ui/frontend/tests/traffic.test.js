import test from 'node:test'
import assert from 'node:assert/strict'
import { formatPayload, mergeTraffic, trafficResult } from '../src/utils/traffic.js'

test('merge deduplicates, orders and bounds live events', () => {
  const current = Array.from({ length: 300 }, (_, seq) => ({ seq }))
  const merged = mergeTraffic(current, [{ seq: 299 }, { seq: 301 }, { seq: 300 }])
  assert.equal(merged.length, 300)
  assert.equal(merged[0].seq, 2)
  assert.equal(merged.at(-1).seq, 301)
})

test('payload preserves bytes and offsets and renders text safely', () => {
  assert.equal(formatPayload('10020000'), '0000  10 02 00 00')
  assert.equal(formatPayload('41420a00', 'text'), 'AB\n.')
  assert.equal(formatPayload('ff', 'hex', 64), '0040  ff')
  assert.equal(formatPayload(''), '')
  assert.equal(trafficResult('crash'), '崩溃')
})
