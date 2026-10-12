import { act, render, renderHook, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { api } from '../api/client'
import type { ChatMessage, ChatCapabilities, TicketList, TicketSummary, WorkflowTask } from '../api/types'
import { useChat } from '../hooks/useChat'
import { useTickets } from '../hooks/useTickets'
import { RiskBadge } from './RiskBadge'
import { WorkflowQueue } from './WorkflowQueue'

afterEach(() => vi.restoreAllMocks())

const caps: ChatCapabilities = {
  role: 'employee', role_label: 'Employee', scope_description: 'Authorized materials',
  document_count: 7, knowledge_ready: true, categories: {},
  provider: { provider: 'mock', model: 'offline', offline: true },
}
const message = (id: number, role: ChatMessage['role']): ChatMessage => ({
  id, conversation_id: 1, role, content: 'Synthetic text', payload: null, created_at: null,
})
const ticket: TicketSummary = { reference: 'SEC-2026-0001', title: 'Synthetic event',
  category: 'security', severity: 'high', status: 'escalated', source: 'ai_auto',
  owner_role: 'security', escalation_required: true, created_at: null, updated_at: null }
const listing: TicketList = { count: 1, statistics: { total: 2, open: 2, escalated: 2,
  requiring_human: 2, by_status: {}, by_severity: {} }, tickets: [ticket], next_offset: 1 }
const task: WorkflowTask = { id: 'synthetic-task', status: 'pending', attempts: 1, risk_level: 'high',
  ticket_reference: null, error_code: 'ticket_write_failed', created_at: '2026-10-12T00:00:00Z' }

function mockChat() {
  vi.spyOn(api.chat, 'capabilities').mockResolvedValue(caps)
  vi.spyOn(api.chat, 'listConversations').mockResolvedValue({ count: 0, conversations: [] })
  vi.spyOn(api.chat, 'createConversation').mockResolvedValue({ id: 1, title: 'Synthetic', message_count: 0, created_at: null, updated_at: null })
}

describe('reliable submission UI', () => {
  it('does not claim a pending report was submitted', () => {
    render(<RiskBadge level="high" intent="phishing" signals={[]} escalation pending />)
    expect(screen.getByRole('status')).toHaveTextContent('pending retry')
    expect(screen.getByRole('status')).not.toHaveTextContent('ticket is submitted')
  })
  it('distinguishes a submitted ticket from human acceptance', () => {
    render(<RiskBadge level="high" intent="phishing" signals={[]} escalation submitted />)
    expect(screen.getByRole('status')).toHaveTextContent('does not confirm that a person has accepted')
  })
  it('retries a failed message with the original key and deduplicates cached replies', async () => {
    mockChat()
    const send = vi.spyOn(api.chat, 'sendMessage').mockRejectedValueOnce(new Error('Synthetic network failure'))
      .mockResolvedValue({ conversation_id: 1, user_message: message(1, 'user'), assistant_message: message(2, 'assistant') })
    const { result } = renderHook(() => useChat(vi.fn()))
    await waitFor(() => expect(result.current.status).toBe('idle'))
    await act(() => result.current.send('Synthetic incident'))
    expect(result.current.canRetry).toBe(true)
    await act(() => result.current.retry())
    expect(send.mock.calls[0]?.[3]).toBe(send.mock.calls[1]?.[3])
    expect(result.current.messages).toHaveLength(2)
    await act(() => result.current.send('Synthetic incident'))
    expect(result.current.messages).toHaveLength(2)
    expect(send.mock.calls[2]?.[3]).not.toBe(send.mock.calls[1]?.[3])
  })
  it('ignores double sends while a request is still in flight', async () => {
    mockChat()
    let finish: (() => void) | undefined
    const send = vi.spyOn(api.chat, 'sendMessage').mockImplementation(() => new Promise((resolve) => {
      finish = () => resolve({ conversation_id: 1, user_message: message(1, 'user'), assistant_message: message(2, 'assistant') })
    }))
    const { result } = renderHook(() => useChat(vi.fn()))
    await waitFor(() => expect(result.current.status).toBe('idle'))
    let pending: Promise<void>
    act(() => { pending = result.current.send('Synthetic incident') })
    await waitFor(() => expect(send).toHaveBeenCalledTimes(1))
    await act(() => result.current.send('Synthetic incident'))
    expect(send).toHaveBeenCalledTimes(1)
    await act(async () => { finish?.(); await pending })
  })
  it('loads the next ticket page without hiding the first page', async () => {
    const list = vi.spyOn(api.tickets, 'list').mockResolvedValueOnce(listing).mockResolvedValueOnce({
      ...listing, tickets: [{ ...ticket, reference: 'SEC-2026-0002' }], next_offset: null,
    })
    const unauthorized = vi.fn()
    const { result } = renderHook(() => useTickets(unauthorized, true))
    await waitFor(() => expect(result.current.listing?.tickets).toHaveLength(1))
    await act(() => result.current.loadMore())
    expect(list.mock.calls[1]?.[0]).toEqual({ offset: 1 })
    expect(result.current.listing?.tickets.map((entry) => entry.reference)).toEqual(['SEC-2026-0001', 'SEC-2026-0002'])
  })
  it('recovers a pending workflow and refreshes the ticket board', async () => {
    vi.spyOn(api.tickets, 'workflows').mockResolvedValueOnce({ tasks: [task], pending: 1, next_offset: null })
      .mockResolvedValue({ tasks: [], pending: 0, next_offset: null })
    const retry = vi.spyOn(api.tickets, 'retryWorkflow').mockResolvedValue({ ...task, status: 'completed' })
    const recovered = vi.fn()
    render(<WorkflowQueue onRecovered={recovered} />)
    await userEvent.click(await screen.findByRole('button', { name: 'Retry submission' }))
    await waitFor(() => expect(recovered).toHaveBeenCalledTimes(1))
    expect(retry).toHaveBeenCalledWith(task.id)
    expect(screen.queryByText('ticket_write_failed')).not.toBeInTheDocument()
  })
  it('keeps a failed recovery visible', async () => {
    vi.spyOn(api.tickets, 'workflows').mockResolvedValue({ tasks: [task], pending: 1, next_offset: null })
    vi.spyOn(api.tickets, 'retryWorkflow').mockRejectedValue(new Error('Synthetic outage'))
    const recovered = vi.fn()
    render(<WorkflowQueue onRecovered={recovered} />)
    await userEvent.click(await screen.findByRole('button', { name: 'Retry submission' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('report remains saved')
    expect(recovered).not.toHaveBeenCalled()
    expect(screen.getByRole('button', { name: 'Retry submission' })).toBeInTheDocument()
  })
})
