import type { RiskLevel, RiskSignal } from '../api/types'
import { intentLabel, riskLabel } from './labels'

export interface RiskBadgeProps {
  level: RiskLevel | null
  intent: string | null
  signals: RiskSignal[]
  escalation: boolean
  submitted?: boolean
  pending?: boolean
}

/**
 * The assessment panel under an answer.
 *
 * It shows what the *backend* decided. The client renders the decision; it does
 * not make one, and it never shows a control that would let the user argue with
 * the risk level.
 */
export function RiskBadge({ level, intent, signals, escalation, submitted = false, pending = false }: RiskBadgeProps) {
  return (
    <section className="assessment" aria-label="Assessment">
      <div className="assessment__row">
        <span className="assessment__label">Intent</span>
        <span className="pill pill--intent">{intentLabel(intent)}</span>
        <span className="assessment__label">Risk</span>
        <span className={`pill pill--risk-${level ?? 'unknown'}`}>{riskLabel(level)}</span>
      </div>

      {escalation && (
        <p className="assessment__escalation" role="status">
          {pending
            ? 'Human review is required. The report is saved; ticket submission is pending retry. Contact the security team directly if urgent.'
            : submitted
              ? 'Human review is required. The ticket is submitted to the security queue; this does not confirm that a person has accepted it.'
              : 'Human review is required. Contact the security team; ticket submission has not been confirmed.'}
        </p>
      )}

      {signals.length > 0 && (
        <ul className="assessment__signals">
          {signals.map((signal) => (
            <li key={`${signal.label}-${signal.evidence}`}>
              <code>{signal.label}</code>
              {signal.evidence && (
                <span className="assessment__evidence"> — “{signal.evidence}”</span>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}
