import { useCallback, useEffect, useState } from 'react'
import { api, ApiError } from '../api/client'
import type { WorkflowTask } from '../api/types'

/** Security operators see durable submissions that still need recovery. */
export function WorkflowQueue({ onRecovered }: { onRecovered: () => void }) {
  const [tasks, setTasks] = useState<WorkflowTask[]>([])
  const [total, setTotal] = useState(0)
  const [next, setNext] = useState<number | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const load = useCallback(async (offset = 0) => {
    try {
      const page = await api.tickets.workflows(offset)
      setTotal(page.pending)
      setNext(page.next_offset)
      setTasks((previous) => offset ? [...previous, ...page.tasks] : page.tasks)
      setError(null)
    } catch (cause) { setError(cause instanceof ApiError ? cause.message : 'Could not load pending submissions.') }
  }, [])
  useEffect(() => {
    void load()
    const timer = window.setInterval(() => { if (!document.hidden) void load() }, 15000)
    return () => window.clearInterval(timer)
  }, [load])
  async function retry(id: string) {
    setBusy(true)
    try {
      await api.tickets.retryWorkflow(id)
      await load()
      onRecovered()
    } catch (cause) { setError(cause instanceof ApiError ? cause.message : 'Retry failed; the report remains saved.') }
    finally { setBusy(false) }
  }
  return <section className="workflow-queue" aria-label="Pending incident submissions">
    <h3>Pending incident submissions · {total}</h3>
    {error && <p role="alert">{error}</p>}
    <ul>{tasks.map((task) => <li key={task.id}>
      <span className={`pill pill--risk-${task.risk_level}`}>{task.risk_level}</span>
      {' '}{task.status} · attempts {task.attempts} · {task.error_code ?? 'processing'}
      <button className="button button--ghost" onClick={() => void retry(task.id)} disabled={busy}>Retry submission</button>
    </li>)}</ul>
    {next !== null && <button className="button button--ghost" onClick={() => void load(next)} disabled={busy}>Load more submissions</button>}
  </section>
}
