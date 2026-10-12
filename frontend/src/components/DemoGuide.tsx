import type { ChatCapabilities, ChatMessage, Role } from '../api/types'
import { intentLabel, riskLabel } from './labels'

const SCENARIOS = [
  { title: 'A · 安全知识', text: '公司密码有什么要求？', tip: '展开回答下方来源，核对政策片段。' },
  { title: 'B · 钓鱼报告', text: '我点击了可疑邮件里的链接。', tip: '先记录 Medium 事件，再在同一对话补充验证码泄露事实。' },
  { title: '补充事实', text: '是的，我输入了验证码。', tip: '紧接钓鱼报告发送，观察原工单升级而非重复建单。' },
  { title: 'C · 可疑附件', text: '我打开了可疑邮件附件后，电脑出现了奇怪的弹窗。', tip: '观察 High 风险、Security 工单和人工处理要求。' },
  { title: 'D · VPN 帮助', text: '今天我突然连不上公司的 VPN。', tip: '使用员工可读指南；必要时手动提交 IT 工单。' },
  { title: 'E · 权限对比', text: 'What is the malware incident response procedure?', tip: '退出后用安全团队账号重复提问，比较可读来源。' },
]

export function DemoGuide({ capabilities, messages, role, onExample }: {
  capabilities: ChatCapabilities | null
  messages: ChatMessage[]
  role: Role
  onExample: (text: string) => void
}) {
  const answers = messages.filter((message) => message.role === 'assistant' && message.payload)
  const last = answers.at(-1)?.payload
  const stages = [
    ['意图识别', last ? intentLabel(last.intent) : '等待提问'],
    ['权限范围', capabilities ? `${capabilities.document_count} 份可读知识` : '等待加载'],
    ['使用来源', last ? `${last.source_documents.length} 个来源片段` : '等待检索'],
    ['回答依据', last ? last.grounded ? '离线摘录有来源' : last.source_documents.length ? '上下文已提供，答案待核验' : '无可用依据 / 已拒绝' : '等待回答'],
    ['风险评估', last ? `${riskLabel(last.risk_level)} · 峰值 ${riskLabel(last.peak_risk_level)}` : '等待评估'],
    ['工单状态', last ? last.workflow_status === 'pending' ? '报告已存，等待重试' : last.ticket_reference ?? last.requested_ticket_reference ?? '本轮未提交工单' : '等待结果'],
  ]
  return <details className="demo-guide" open>
    <summary>演示导览 · 实时后端流程</summary>
    <div className="demo-guide__content">
      <header className="demo-guide__intro">
        <div><h2>从一条报告到可追踪的安全事件</h2>
          <p>全部使用模拟数据。先创建新对话，再选择场景填入输入框；核对内容后点击 Send。补充事实沿用同一对话。</p></div>
        <span className="demo-guide__mode">{capabilities?.provider.offline ? '离线生成 · Mock' : '真实服务配置 · 质量待验收'}</span>
      </header>
      {!capabilities?.knowledge_ready && <p role="status">知识库尚未就绪。安全报告仍可保存；回答可能没有来源。</p>}
      <div className="demo-guide__scenarios">{SCENARIOS.map((scenario) => <button key={scenario.title}
        type="button" className="demo-guide__scenario" onClick={() => onExample(scenario.text)}>
        <strong>{scenario.title}</strong><span>{scenario.text}</span><small>{scenario.tip}</small>
      </button>)}</div>
      <ol className="demo-guide__pipeline" aria-label="Actual response pipeline">{stages.map(([label, value]) =>
        <li key={label}><span>{label}</span><strong>{value}</strong></li>)}</ol>
      {answers.length > 0 && <details className="demo-guide__timeline"><summary>当前会话的风险与事件时间线 · {answers.length} 轮</summary>
        <ol>{answers.map((message) => <li key={message.id}>
          <span className={`pill pill--risk-${message.payload?.risk_level ?? 'unknown'}`}>{riskLabel(message.payload?.risk_level ?? null)}</span>
          {' '}{message.payload?.ticket_reference ?? '本轮无工单'} · {message.payload?.workflow_status === 'pending' ? '待重试' : message.payload?.workflow_action}
        </li>)}</ol></details>}
      <p className="demo-guide__handoff">{role === 'security'
        ? '人工演示：打开 Tickets → 选中事件 → Move to in progress 确认接手 → 添加备注 → 解决事件；Dashboard 查看实际统计。'
        : '角色对比和人工处理：退出当前账号，再登录 Security Team 演示账号；所有权限由后端验证。'}
        {' '}故障演示使用独立演示实例及启动脚本的 SimulateModelFailure 参数。</p>
    </div>
  </details>
}
