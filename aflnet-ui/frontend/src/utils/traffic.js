export const TRAFFIC_LIMIT = 300

export function mergeTraffic(current, incoming) {
  const events = new Map(current.map(event => [event.seq, event]))
  for (const event of incoming) events.set(event.seq, event)
  return [...events.values()].sort((a, b) => a.seq - b.seq).slice(-TRAFFIC_LIMIT)
}

export function formatPayload(hex, mode = 'hex', offset = 0) {
  const bytes = (hex || '').match(/.{2}/g) || []
  if (mode === 'text') {
    return new TextDecoder().decode(Uint8Array.from(bytes, byte => parseInt(byte, 16)))
      .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '.')
  }
  const lines = []
  for (let index = 0; index < bytes.length; index += 16) {
    lines.push(`${(index + offset).toString(16).padStart(4, '0')}  ${bytes.slice(index, index + 16).join(' ')}`)
  }
  return lines.join('\n')
}

export function trafficResult(result) {
  return ({ ok: '完成', no_response: '无响应', connection_failed: '连接失败', timeout: '超时',
    crash: '崩溃', stopped: '已停止', execution_error: '执行失败', target_exit: '目标退出',
    send_error: '发送失败', message_too_large: '超过消息长度限制' })[result] || result || ''
}
