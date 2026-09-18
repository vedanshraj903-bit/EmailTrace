import type { ReactNode } from 'react'
import type { AuthResult, RiskLevel, Severity, Verdict } from '../api/types'
import { VERDICT_LABEL, authTone, type Tone } from '../lib/format'
import { Icon, type IconName } from './Icon'

const TONE_ICON: Record<Tone, IconName> = {
  good: 'check',
  neutral: 'minus',
  warning: 'info',
  serious: 'alert',
  critical: 'octagon',
}

export function Badge({ tone, label, icon }: { tone: Tone; label: string; icon?: IconName | null }) {
  const iconName = icon === undefined ? TONE_ICON[tone] : icon
  return (
    <span className={`badge tone-${tone}`}>
      {iconName && <Icon name={iconName} size={13} />}
      {label}
    </span>
  )
}

const SEVERITY_TONE: Record<Severity, Tone> = {
  info: 'neutral',
  low: 'warning',
  medium: 'warning',
  high: 'serious',
  critical: 'critical',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge tone={SEVERITY_TONE[severity]} label={severity[0].toUpperCase() + severity.slice(1)} />
}

const LEVEL_TONE: Record<RiskLevel, Tone> = { low: 'good', medium: 'warning', high: 'serious', critical: 'critical' }

export function LevelBadge({ level }: { level: RiskLevel }) {
  return <Badge tone={LEVEL_TONE[level]} label={`${level[0].toUpperCase()}${level.slice(1)} risk`} />
}

const VERDICT_TONE: Record<Verdict, Tone> = {
  legitimate: 'good',
  suspicious: 'warning',
  phishing: 'critical',
  impersonation: 'critical',
  fraud: 'critical',
}

export function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return <Badge tone={VERDICT_TONE[verdict]} label={VERDICT_LABEL[verdict]} />
}

export function AuthBadge({ result }: { result: AuthResult | string | null | undefined }) {
  return <Badge tone={authTone(result)} label={(result ?? 'n/a').toUpperCase()} />
}

export function BoolBadge({ value, good, bad }: { value: boolean | null | undefined; good: string; bad: string }) {
  if (value === null || value === undefined) return <Badge tone="neutral" label="Unknown" />
  return value ? <Badge tone="good" label={good} /> : <Badge tone="critical" label={bad} />
}

interface CardProps {
  title?: ReactNode
  hint?: ReactNode
  actions?: ReactNode
  flush?: boolean
  className?: string
  children: ReactNode
}

export function Card({ title, hint, actions, flush, className, children }: CardProps) {
  return (
    <section className={`card ${className ?? ''}`}>
      {(title || actions) && (
        <header className="card-header">
          <div>
            {title && <h2>{title}</h2>}
            {hint && <p className="hint">{hint}</p>}
          </div>
          {actions}
        </header>
      )}
      <div className={flush ? 'card-body flush' : 'card-body'}>{children}</div>
    </section>
  )
}

export function KeyValue({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([key, value], index) => (
        <div key={index} style={{ display: 'contents' }}>
          <dt>{key}</dt>
          <dd>{value ?? '—'}</dd>
        </div>
      ))}
    </dl>
  )
}

export function EmptyState({ icon = 'info', title, children, compact }: {
  icon?: IconName
  title: string
  children?: ReactNode
  compact?: boolean
}) {
  return (
    <div className={compact ? 'state compact' : 'state'}>
      <Icon name={icon} size={compact ? 18 : 24} />
      <strong>{title}</strong>
      {children && <div className="muted">{children}</div>}
    </div>
  )
}

export function ErrorState({ error, onRetry }: { error: Error; onRetry?: () => void }) {
  return (
    <div className="state">
      <Icon name="alert" size={24} />
      <strong>Could not load data</strong>
      <div className="muted">{error.message}</div>
      {onRetry && (
        <button className="btn btn-sm" onClick={onRetry}>
          <Icon name="refresh" size={14} /> Retry
        </button>
      )}
    </div>
  )
}

export function Alert({ tone, children }: { tone: Tone; children: ReactNode }) {
  return (
    <div className={`alert tone-${tone}`} role={tone === 'critical' ? 'alert' : 'status'}>
      <Icon name={TONE_ICON[tone]} size={15} />
      <div>{children}</div>
    </div>
  )
}

export function Skeleton({ height = 16, width = '100%' }: { height?: number; width?: number | string }) {
  return <div className="skeleton" style={{ height, width }} />
}

export interface TabItem<K extends string> {
  key: K
  label: string
  count?: number
}

export function Tabs<K extends string>({ items, active, onChange }: {
  items: TabItem<K>[]
  active: K
  onChange: (key: K) => void
}) {
  return (
    <div className="tabs" role="tablist">
      {items.map((item) => (
        <button
          key={item.key}
          role="tab"
          className="tab"
          aria-selected={item.key === active}
          onClick={() => onChange(item.key)}
        >
          {item.label}
          {item.count !== undefined && <span className="count tabular">{item.count}</span>}
        </button>
      ))}
    </div>
  )
}
