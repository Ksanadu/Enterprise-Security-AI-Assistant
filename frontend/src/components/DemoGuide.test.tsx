import { useState } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { ChatCapabilities, ChatMessage } from '../api/types'
import { DemoGuide } from './DemoGuide'
import { Composer } from './Composer'

const capabilities: ChatCapabilities = { role: 'employee', role_label: 'Employee', document_count: 7,
  scope_description: 'Authorized documents', provider: { provider: 'mock', model: 'offline', offline: true },
  knowledge_ready: true, categories: {} }

describe('live demo guide', () => {
  it('fills an example without submitting a report until Send is pressed', async () => {
    const send = vi.fn().mockResolvedValue(undefined)
    function Harness() {
      const [suggestion, setSuggestion] = useState<{ text: string; id: number } | null>(null)
      return <><DemoGuide capabilities={capabilities} messages={[]} role="employee"
        onExample={(text) => setSuggestion({ text, id: 1 })} />
        <Composer disabled={false} sending={false} maxLength={2000} onSend={send} suggestion={suggestion} /></>
    }
    render(<Harness />)
    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: /A · 安全知识/ }))
    expect(screen.getByRole('textbox')).toHaveValue('公司密码有什么要求？')
    expect(send).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Send' }))
    expect(send).toHaveBeenCalledWith('公司密码有什么要求？')
    expect(screen.getByLabelText('Actual response pipeline')).toHaveTextContent('等待提问')
  })
  it('renders actual risk and pending delivery from the latest answer', () => {
    const message: ChatMessage = { id: 7, conversation_id: 1, content: 'Synthetic incident', created_at: null, role: 'assistant', payload: {
      answer: 'Synthetic incident', recommended_actions: [], provider: 'mock', model: 'offline', offline: true,
      intent: 'phishing', intent_confidence: 1, intent_source: 'rules', risk_level: 'high', peak_risk_level: 'high',
      risk_signals: [], risk_reason: 'Synthetic fact', human_escalation: true, create_ticket: true,
      blocked: false, block_reason: null, block_categories: [], context_injection_blocked: 0,
      ticket_status: null, clarifying_question: null,
      grounded: false, source_documents: [], workflow_status: 'pending', workflow_action: 'create', ticket_reference: null } }
    render(<DemoGuide capabilities={capabilities} messages={[message]} role="security" onExample={vi.fn()} />)
    expect(screen.getByLabelText('Actual response pipeline')).toHaveTextContent('报告已存，等待重试')
    expect(screen.getByText(/人工演示/)).toBeInTheDocument()
    expect(screen.getByText(/风险与事件时间线 · 1 轮/)).toBeInTheDocument()
  })
  it('does not describe a configured hosted model as quality accepted', () => {
    render(<DemoGuide capabilities={{ ...capabilities, knowledge_ready: false,
      provider: { provider: 'openai_compatible', model: 'synthetic', offline: false } }} messages={[]} role="employee" onExample={vi.fn()} />)
    expect(screen.getByText('真实服务配置 · 质量待验收')).toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('知识库尚未就绪')
  })
})
