import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, expect, it, vi } from 'vitest'
import { api, ApiError } from '../api/client'
import type { NotificationDelivery } from '../api/types'
import { NotificationQueue } from './NotificationQueue'

afterEach(() => vi.restoreAllMocks())
const row: NotificationDelivery = { id: 'synthetic-event', ticket_reference: 'SEC-SYNTHETIC-1', kind: 'incident', severity: 'high', status: 'delivered', attempts: 1, error_code: null, created_at: null, delivered_at: null, next_attempt_at: null }

it('distinguishes receiver receipt from human acknowledgment and opens the real ticket', async () => {
  vi.spyOn(api.operations, 'notifications').mockResolvedValue({ notifications: [row], total: 1, next_offset: null, receiver_configured: true })
  const open = vi.fn()
  render(<NotificationQueue onUnauthorized={vi.fn()} onOpen={open} />)
  await screen.findByText(/接收端已确认/)
  expect(screen.getByText(/人工接手以工单时间线为准/)).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: '重新安排发送' })).not.toBeInTheDocument()
  await userEvent.click(screen.getByRole('button', { name: row.ticket_reference }))
  expect(open).toHaveBeenCalledWith(row.ticket_reference)
})

it('reports missing configuration and retries without claiming delivery', async () => {
  vi.spyOn(api.operations, 'notifications').mockResolvedValue({ notifications: [{ ...row, status: 'exhausted', error_code: 'ConnectError' }], total: 1, next_offset: null, receiver_configured: false })
  const retry = vi.spyOn(api.operations, 'retryNotification').mockResolvedValue({ ...row, status: 'pending' })
  render(<NotificationQueue onUnauthorized={vi.fn()} onOpen={vi.fn()} />)
  await screen.findByText(/尚未配置/)
  await userEvent.click(await screen.findByRole('button', { name: '重新安排发送' }))
  await waitFor(() => expect(retry).toHaveBeenCalledWith(row.id))
  expect(screen.queryByText('接收端已确认')).not.toBeInTheDocument()
})

it('surfaces loading errors instead of reporting an empty healthy queue', async () => {
  vi.spyOn(api.operations, 'notifications').mockRejectedValue(new Error('Synthetic receiver status unavailable'))
  render(<NotificationQueue onUnauthorized={vi.fn()} onOpen={vi.fn()} />)
  expect(await screen.findByRole('alert')).toHaveTextContent('Synthetic receiver status unavailable')
})

it('preserves expanded pages when refreshed and shows new receiver status', async () => {
  const first = Array.from({ length: 50 }, (_, index) => ({ ...row, id: `event-${index}`, ticket_reference: `SEC-SYNTHETIC-${index}`, status: 'pending' as const }))
  const last = { ...row, id: 'last-event', ticket_reference: 'SEC-SYNTHETIC-LAST', kind: 'ack_timeout' as const }
  const load = vi.spyOn(api.operations, 'notifications').mockImplementation(async (offset = 0) => offset === 0
    ? { notifications: first, total: 51, next_offset: 50, receiver_configured: true }
    : { notifications: [last], total: 51, next_offset: null, receiver_configured: true })
  render(<NotificationQueue onUnauthorized={vi.fn()} onOpen={vi.fn()} />)
  const user = userEvent.setup()
  await user.click(await screen.findByRole('button', { name: '更多通知' }))
  await screen.findByRole('button', { name: last.ticket_reference })
  expect(screen.getByText(/未接手提醒/)).toBeInTheDocument()
  expect(screen.queryByRole('button', { name: '更多通知' })).not.toBeInTheDocument()
  load.mockClear()
  await user.click(screen.getByRole('button', { name: '刷新通知状态' }))
  await waitFor(() => expect(load.mock.calls.map(([offset]) => offset)).toEqual([0, 50]))
  expect(screen.getByRole('button', { name: last.ticket_reference })).toBeInTheDocument()
})

it('expires the session on unauthorized notification access', async () => {
  vi.spyOn(api.operations, 'notifications').mockRejectedValue(new ApiError(401, 'authentication_required', 'Session expired.'))
  const expired = vi.fn()
  render(<NotificationQueue onUnauthorized={expired} onOpen={vi.fn()} />)
  await waitFor(() => expect(expired).toHaveBeenCalledOnce())
  expect(screen.queryByText('接收端已确认')).not.toBeInTheDocument()
})
