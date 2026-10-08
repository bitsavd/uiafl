<script setup>
import { onMounted, ref, watch } from 'vue'

const props = defineProps({
  rows: { type: Array, default: () => [] },
  series: { type: Array, default: () => [] },
})

const canvas = ref(null)

function draw() {
  const el = canvas.value
  if (!el) return
  const ctx = el.getContext('2d')
  const dpr = window.devicePixelRatio || 1
  const rect = el.getBoundingClientRect()
  el.width = Math.max(1, Math.floor(rect.width * dpr))
  el.height = Math.max(1, Math.floor(rect.height * dpr))
  ctx.scale(dpr, dpr)
  const width = rect.width
  const height = rect.height
  ctx.clearRect(0, 0, width, height)
  ctx.fillStyle = '#fff'
  ctx.fillRect(0, 0, width, height)
  const rows = props.rows.filter(row => Number.isFinite(row.unix_time))
  if (rows.length < 2) {
    ctx.fillStyle = '#64748b'
    ctx.font = '13px system-ui'
    ctx.fillText('等待趋势数据...', 24, 38)
    return
  }
  const pad = { left: 66, right: 26, top: 24, bottom: 54 }
  const minT = rows[0].unix_time
  const maxT = rows[rows.length - 1].unix_time || minT + 1
  const chartWidth = width - pad.left - pad.right
  const chartHeight = height - pad.top - pad.bottom

  ctx.strokeStyle = '#b8c7d9'
  ctx.lineWidth = 1
  ctx.beginPath()
  ctx.moveTo(pad.left, pad.top)
  ctx.lineTo(pad.left, height - pad.bottom)
  ctx.lineTo(width - pad.right, height - pad.bottom)
  ctx.stroke()

  ctx.strokeStyle = '#dce5ef'
  ctx.lineWidth = 1
  for (let i = 0; i <= 4; i += 1) {
    const ratio = i / 4
    const y = pad.top + chartHeight * ratio
    ctx.beginPath()
    ctx.moveTo(pad.left, y)
    ctx.lineTo(width - pad.right, y)
    ctx.stroke()
    ctx.fillStyle = '#64748b'
    ctx.font = '11px system-ui'
    ctx.textAlign = 'right'
    ctx.textBaseline = 'middle'
    ctx.fillText(`${Math.round((1 - ratio) * 100)}%`, pad.left - 10, y)
  }

  for (let i = 0; i <= 4; i += 1) {
    const ratio = i / 4
    const x = pad.left + chartWidth * ratio
    const t = minT + (maxT - minT) * ratio
    ctx.strokeStyle = '#dce5ef'
    ctx.beginPath()
    ctx.moveTo(x, height - pad.bottom)
    ctx.lineTo(x, height - pad.bottom + 5)
    ctx.stroke()
    ctx.fillStyle = '#64748b'
    ctx.font = '11px system-ui'
    ctx.textAlign = 'center'
    ctx.textBaseline = 'top'
    ctx.fillText(formatElapsed(t - minT), x, height - pad.bottom + 9)
  }

  props.series.forEach((serie, index) => {
    const values = rows.map(row => Number(row[serie.key] || 0))
    const max = Math.max(...values, 1)
    const color = serie.color || ['#2563eb', '#0f766e', '#b45309'][index % 3]
    const x = row => pad.left + ((row.unix_time - minT) / (maxT - minT || 1)) * chartWidth
    const y = row => pad.top + (1 - Number(row[serie.key] || 0) / max) * chartHeight
    ctx.strokeStyle = color
    ctx.lineWidth = 2
    ctx.beginPath()
    rows.forEach((row, i) => {
      if (i === 0) ctx.moveTo(x(row), y(row))
      else ctx.lineTo(x(row), y(row))
    })
    ctx.stroke()
    ctx.fillStyle = color
    ctx.font = '12px system-ui'
    ctx.textAlign = 'left'
    ctx.textBaseline = 'alphabetic'
    ctx.fillText(serie.label, pad.left + index * 110, height - 12)
  })
}

function formatElapsed(seconds) {
  const total = Math.max(0, Math.round(seconds || 0))
  if (total >= 3600) return `${Math.floor(total / 3600)}h`
  return `${Math.floor(total / 60)}m`
}

onMounted(draw)
watch(() => [props.rows, props.series], draw, { deep: true })
</script>

<template>
  <canvas ref="canvas" class="line-chart"></canvas>
</template>
