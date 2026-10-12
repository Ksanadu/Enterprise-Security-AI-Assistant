import { useCallback, useEffect, useRef, useState } from 'react'

import { ApiError, api } from '../api/client'
import type { ChatCapabilities, ChatMessage, ConversationSummary } from '../api/types'

export type ChatStatus = 'idle' | 'loading' | 'sending'

export interface UseChatResult {
  conversations: ConversationSummary[]
  activeId: number | null
  messages: ChatMessage[]
  capabilities: ChatCapabilities | null
  status: ChatStatus
  error: string | null
  notice: string | null
  /**
   * Ticket references the user raised themselves, keyed by the assistant message
   * they were raised from. The AI raises a ticket on its own for a high-risk
   * event; this covers the other case - a grounded answer that did not resolve
   * the problem, where the specification says to *offer* a ticket.
   */
  raisedTickets: Record<number, string>
  /** The message whose "Create ticket" request is in flight, if any. */
  raisingTicketId: number | null
  selectConversation: (id: number) => Promise<void>
  startConversation: () => Promise<void>
  removeConversation: (id: number) => Promise<void>
  send: (content: string) => Promise<void>
  raiseTicket: (
    messageId: number,
    title: string,
    description: string,
    category?: string,
  ) => Promise<void>
  dismissError: () => void
  canRetry: boolean
  retry: () => Promise<void>
}

function describe(cause: unknown, fallback: string): string {
  if (cause instanceof ApiError) {
    if (cause.status === 429) {
      return cause.message || 'You are sending messages too quickly. Please wait a moment.'
    }
    return cause.message
  }
  return fallback
}

/**
 * Conversation and message state for the chat workspace.
 *
 * `onUnauthorized` lets the application sign the user out when the token has
 * expired, rather than leaving the UI in a broken half-authenticated state.
 */
export function useChat(onUnauthorized: () => void): UseChatResult {
  const [conversations, setConversations] = useState<ConversationSummary[]>([])
  const [activeId, setActiveId] = useState<number | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [capabilities, setCapabilities] = useState<ChatCapabilities | null>(null)
  const [status, setStatus] = useState<ChatStatus>('loading')
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [raisedTickets, setRaisedTickets] = useState<Record<number, string>>({})
  const [raisingTicketId, setRaisingTicketId] = useState<number | null>(null)
  const [canRetry, setCanRetry] = useState(false)

  // Guards against a late response from a conversation the user has left.
  const activeIdRef = useRef<number | null>(null)
  const sendingRef = useRef(false)
  const retryRef = useRef<{ id: number; content: string; key: string } | null>(null)
  // Held in a ref so the initial load effect does not depend on the identity of
  // the caller's callback. Depending on it directly re-runs the effect on every
  // render and turns the workspace into an endless fetch loop.
  const onUnauthorizedRef = useRef(onUnauthorized)
  useEffect(() => {
    onUnauthorizedRef.current = onUnauthorized
  }, [onUnauthorized])

  const handleFailure = useCallback((cause: unknown, fallback: string) => {
    if (cause instanceof ApiError && cause.isUnauthorized) {
      onUnauthorizedRef.current()
      return
    }
    setError(describe(cause, fallback))
  }, [])

  const refreshList = useCallback(async (): Promise<ConversationSummary[]> => {
    const listing = await api.chat.listConversations()
    setConversations(listing.conversations)
    return listing.conversations
  }, [])

  // Initial load: capabilities + conversation list.
  useEffect(() => {
    let cancelled = false
    async function load() {
      try {
        const [caps, listing] = await Promise.all([
          api.chat.capabilities(),
          api.chat.listConversations(),
        ])
        if (cancelled) return
        setCapabilities(caps)
        setConversations(listing.conversations)
        setStatus('idle')
      } catch (cause) {
        if (cancelled) return
        setStatus('idle')
        handleFailure(cause, 'Could not load your conversations.')
      }
    }
    void load()
    return () => {
      cancelled = true
    }
  }, [handleFailure])

  const selectConversation = useCallback(
    async (id: number) => {
      activeIdRef.current = id
      setActiveId(id)
      setStatus('loading')
      setError(null)
      setNotice(null)
      try {
        const detail = await api.chat.getConversation(id)
        if (activeIdRef.current !== id) return
        setMessages(detail.messages)
        setRaisedTickets(Object.fromEntries(detail.messages.flatMap((message) =>
          message.payload?.requested_ticket_reference
            ? [[message.id, message.payload.requested_ticket_reference]] : [])))
      } catch (cause) {
        if (activeIdRef.current !== id) return
        handleFailure(cause, 'Could not open that conversation.')
        setMessages([])
      } finally {
        if (activeIdRef.current === id) setStatus('idle')
      }
    },
    [handleFailure],
  )

  const startConversation = useCallback(async () => {
    setStatus('loading')
    setError(null)
    try {
      const created = await api.chat.createConversation(null)
      await refreshList()
      activeIdRef.current = created.id
      setActiveId(created.id)
      setMessages([])
      setNotice('New conversation started. Ask a security question to begin.')
      setStatus('idle')
    } catch (cause) {
      setStatus('idle')
      handleFailure(cause, 'Could not start a new conversation.')
    }
  }, [handleFailure, refreshList])

  const removeConversation = useCallback(
    async (id: number) => {
      setError(null)
      try {
        await api.chat.deleteConversation(id)
        if (activeIdRef.current === id) {
          activeIdRef.current = null
          setActiveId(null)
          setMessages([])
        }
        await refreshList()
      } catch (cause) {
        handleFailure(cause, 'Could not delete that conversation.')
      }
    },
    [handleFailure, refreshList],
  )

  const send = useCallback(
    async (content: string) => {
      const trimmed = content.trim()
      if (!trimmed || sendingRef.current) return
      sendingRef.current = true

      let conversationId = activeIdRef.current
      setError(null)
      setNotice(null)
      setStatus('sending')
      setCanRetry(false)

      try {
        if (conversationId === null) {
          const created = await api.chat.createConversation(null)
          conversationId = created.id
          activeIdRef.current = created.id
          setActiveId(created.id)
        }

        const previousRequest = retryRef.current
        const requestKey = previousRequest?.id === conversationId && previousRequest.content === trimmed
          ? previousRequest.key
          : Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, '0')).join('')
        retryRef.current = { id: conversationId, content: trimmed, key: requestKey }
        const result = await api.chat.sendMessage(conversationId, trimmed, undefined, requestKey)
        retryRef.current = null
        if (activeIdRef.current !== conversationId) {
          // The user switched conversations while the answer was generating.
          await refreshList()
          return
        }
        setMessages((previous) => {
          const ids = new Set(previous.map((message) => message.id))
          return [...previous, ...[result.user_message, result.assistant_message].filter((message) => !ids.has(message.id))]
        })
        await refreshList()
      } catch (cause) {
        setCanRetry(retryRef.current !== null)
        handleFailure(cause, 'The assistant could not answer. Please try again.')
      } finally {
        sendingRef.current = false
        setStatus('idle')
      }
    },
    [handleFailure, refreshList],
  )

  const dismissError = useCallback(() => setError(null), [])
  const retry = useCallback(async () => {
    const pending = retryRef.current
    if (pending && activeIdRef.current === pending.id) await send(pending.content)
  }, [send])

  const raiseTicket = useCallback(
    // `other` rather than `security`: the category decides the owning queue on the
    // server, and defaulting a self-raised ticket to the security queue would file
    // routine requests there at medium severity.
    async (messageId: number, title: string, description: string, category = 'other') => {
      setError(null)
      setNotice(null)
      setRaisingTicketId(messageId)
      try {
        const ticket = await api.tickets.raise(title, description, category, undefined, messageId)
        setRaisedTickets((previous) => ({ ...previous, [messageId]: ticket.reference }))
        setNotice(`Ticket ${ticket.reference} raised. The service desk can follow up.`)
      } catch (cause) {
        handleFailure(cause, 'Could not raise a ticket. Please try again.')
      } finally {
        setRaisingTicketId(null)
      }
    },
    [handleFailure],
  )

  return {
    conversations,
    activeId,
    messages,
    capabilities,
    status,
    error,
    notice,
    raisedTickets,
    raisingTicketId,
    selectConversation,
    startConversation,
    removeConversation,
    send,
    raiseTicket,
    dismissError,
    canRetry,
    retry,
  }
}
