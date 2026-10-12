import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError } from '../api/client'
import type { NotificationDelivery } from '../api/types'

const labels = { pending: '等待发送', processing: '正在发送', delivered: '接收端已确认', exhausted: '重试耗尽', cancelled: '已取消' }

export function NotificationQueue({ onUnauthorized, onOpen }: { onUnauthorized: () => void; onOpen: (reference: string) => void }) {
  const [rows, setRows] = useState<NotificationDelivery[]>([])
  const [total, setTotal] = useState(0)
  const [next, setNext] = useState<number | null>(null)
  const [configured, setConfigured] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const mounted = useRef(false)
  const wanted = useRef(50)
  const requestSerial = useRef(0)
  const failure = useCallback((cause: unknown) => {
    if (cause instanceof ApiError && cause.isUnauthorized) { onUnauthorized(); return }
    if (mounted.current) setError(cause instanceof Error ? cause.message : '通知状态加载失败')
  }, [onUnauthorized])
  const refresh = useCallback(async () => {
    const serial = ++requestSerial.current
    try {
      const collected: NotificationDelivery[] = []
      let offset: number | null = 0
      let count = 0
      let enabled = false
      do {
        const page = await api.operations.notifications(offset ?? 0)
        collected.push(...page.notifications)
        offset = page.next_offset
        count = page.total
        enabled = page.receiver_configured
      } while (offset !== null && collected.length < wanted.current)
      if (mounted.current && serial === requestSerial.current) { setRows(collected); setNext(offset); setTotal(count); setConfigured(enabled); setError(null) }
    } catch (cause) { if (mounted.current && serial === requestSerial.current) failure(cause) }
  }, [failure])
  useEffect(() => {
    mounted.current = true
    void refresh()
    const timer = window.setInterval(() => void refresh(), 15000)
    return () => { mounted.current = false; window.clearInterval(timer) }
  }, [refresh])
  const retry = async (id: string) => {
    if (busy) return
    setBusy(true)
    try { await api.operations.retryNotification(id); await refresh() }
    catch (cause) { failure(cause) }
    finally { if (mounted.current) setBusy(false) }
  }
  return <section className="workflow-queue" aria-label="Notification delivery">
    <h3>通知送达 · {total}</h3>
    <p>接收端确认仅表示通知已被接收；人工接手以工单时间线为准。</p>
    {!configured && <p role="status">尚未配置通知接收端，事件已保留在队列中。</p>}
    {error && <p role="alert">{error}</p>}
    <ul>{rows.map(row => <li key={row.id}>
      <button className="button button--ghost" onClick={() => onOpen(row.ticket_reference)}>{row.ticket_reference}</button>
      {' '}{row.kind === 'ack_timeout' ? '未接手提醒' : '事件通知'} · {labels[row.status]} · 尝试 {row.attempts}
      {row.error_code && <span> · {row.error_code}</span>}
      {(row.status === 'pending' || row.status === 'exhausted') && <button className="button button--ghost" disabled={busy} onClick={() => void retry(row.id)}>重新安排发送</button>}
    </li>)}</ul>
    <button className="button button--ghost" onClick={() => void refresh()}>刷新通知状态</button>
    {next !== null && <button className="button button--ghost" onClick={() => { wanted.current += 50; void refresh() }}>更多通知</button>}
  </section>
}
