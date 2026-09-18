import { Link } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api/client'
import type { RiskLevel, Stats, Verdict } from '../api/types'
import { CaseTable } from '../components/CaseTable'
import { Icon } from '../components/Icon'
import { Card, EmptyState, ErrorState, Skeleton, VerdictBadge } from '../components/ui'
import { countryName, formatShortDate } from '../lib/format'
import { useResource } from '../lib/useResource'

const DAYS = 30

interface DayRow {
  day: string
  high: number // high + critical
  medium: number
  low: number
}

/** Single-digit counts read as 00–09 so columns of numbers line up. */
function pad2(value: number): string {
  return value >= 0 && value < 10 ? `0${value}` : String(value)
}

const RISK_SERIES = [
  { key: 'high', label: 'High / critical risk', color: 'var(--risk-high)' },
  { key: 'medium', label: 'Medium risk', color: 'var(--risk-medium)' },
  { key: 'low', label: 'Low risk', color: 'var(--risk-low)' },
] as const

/** The API omits days with no traffic; fill them so the time axis stays continuous. */
function fillDays(daily: Stats['daily']): DayRow[] {
  const byDay = new Map(daily.map(([day, total, high, medium]) => [day, { total, high, medium }]))
  const rows: DayRow[] = []
  const today = new Date()
  for (let offset = DAYS - 1; offset >= 0; offset--) {
    const date = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - offset))
    const day = date.toISOString().slice(0, 10)
    const entry = byDay.get(day)
    const high = entry?.high ?? 0
    const medium = entry?.medium ?? 0
    rows.push({ day, high, medium, low: (entry?.total ?? 0) - high - medium })
  }
  return rows
}

function StatTile({ label, value, hint, risk }: {
  label: string
  value: number | string
  hint?: string
  risk?: 'high' | 'medium' | 'low'
}) {
  return (
    <div className={`card stat ${risk ? `risk-${risk}` : ''}`}>
      <span className="stat-label">{label}</span>
      <span className="stat-value tabular">{typeof value === 'number' ? pad2(value) : value}</span>
      {hint && <span className="muted small">{hint}</span>}
    </div>
  )
}

function ActivityTooltip({ active, payload }: { active?: boolean; payload?: readonly { payload?: unknown }[] }) {
  if (!active || !payload?.length) return null
  const row = payload[0].payload as DayRow
  return (
    <div className="chart-tooltip">
      <strong>{formatShortDate(row.day)}</strong>
      {RISK_SERIES.map((series) => (
        <span key={series.key}>
          <i className="swatch" style={{ background: series.color }} /> {series.label}
          <b className="tabular">{pad2(row[series.key])}</b>
        </span>
      ))}
    </div>
  )
}

function ActivityChart({ stats }: { stats: Stats }) {
  const rows = fillDays(stats.daily)
  if (rows.every((row) => row.high + row.medium + row.low === 0)) {
    return <EmptyState compact icon="clock" title={`No messages analyzed in the last ${DAYS} days`} />
  }
  return (
    <figure className="chart">
      <div className="chart-legend">
        {RISK_SERIES.map((series) => (
          <span key={series.key}>
            <i className="swatch" style={{ background: series.color }} /> {series.label}
          </span>
        ))}
      </div>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={rows} margin={{ top: 8, right: 4, bottom: 0, left: -18 }} barCategoryGap={3}>
          <CartesianGrid vertical={false} stroke="var(--grid)" />
          <XAxis
            dataKey="day"
            tickFormatter={formatShortDate}
            tick={{ fill: 'var(--ink-muted)', fontSize: 11.5 }}
            tickLine={false}
            axisLine={{ stroke: 'var(--axis)' }}
            interval="preserveStartEnd"
            minTickGap={24}
          />
          <YAxis
            allowDecimals={false}
            tickFormatter={pad2}
            tick={{ fill: 'var(--ink-muted)', fontSize: 11.5 }}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip content={(props) => <ActivityTooltip active={props.active} payload={props.payload} />} cursor={{ fill: 'var(--surface-hover)' }} />
          {/* Stacked low → high so the most serious risk sits on top. */}
          <Bar dataKey="low" stackId="a" fill="var(--risk-low)" stroke="var(--surface)" strokeWidth={1} />
          <Bar dataKey="medium" stackId="a" fill="var(--risk-medium)" stroke="var(--surface)" strokeWidth={1} />
          <Bar dataKey="high" stackId="a" fill="var(--risk-high)" stroke="var(--surface)" strokeWidth={1} radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
      <figcaption className="sr-only">
        Messages analyzed per day over the last {DAYS} days, split by risk level.
      </figcaption>
    </figure>
  )
}

function BarList({ rows, empty, mono }: { rows: [string, number][]; empty: string; mono?: boolean }) {
  if (rows.length === 0) return <EmptyState compact title={empty} />
  const max = Math.max(...rows.map(([, count]) => count))
  return (
    <ul className="bar-list">
      {rows.map(([label, count]) => (
        <li key={label}>
          <span className={mono ? 'mono break' : 'break'}>{label}</span>
          <span className="tabular">{pad2(count)}</span>
          <span className="bar" aria-hidden="true">
            <span style={{ width: `${(count / max) * 100}%` }} />
          </span>
        </li>
      ))}
    </ul>
  )
}

const VERDICT_ORDER: Verdict[] = ['fraud', 'phishing', 'impersonation', 'suspicious', 'legitimate']

export default function DashboardPage() {
  const stats = useResource('stats', (signal) => api.stats(signal))
  const recent = useResource('recent', (signal) => api.list({ limit: 8 }, signal))

  if (stats.error) {
    return (
      <div className="page">
        <h1>Dashboard</h1>
        <Card>
          <ErrorState error={stats.error} onRetry={stats.reload} />
        </Card>
      </div>
    )
  }

  const data = stats.data
  const count = (level: RiskLevel) => data?.by_level[level] ?? 0
  const malicious = data ? (data.by_verdict.phishing ?? 0) + (data.by_verdict.fraud ?? 0) + (data.by_verdict.impersonation ?? 0) : 0

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Dashboard</h1>
          <p className="subtitle">Threat activity across all analyzed messages.</p>
        </div>
        <Link to="/analyze" className="btn btn-primary">
          <Icon name="upload" size={15} /> Analyze email
        </Link>
      </header>

      <div className="grid grid-4">
        {data ? (
          <>
            <StatTile label="Cases analyzed" value={data.total} />
            <StatTile label="Critical risk" value={count('critical')} risk={count('critical') ? 'high' : undefined} />
            <StatTile label="High risk" value={count('high')} risk={count('high') ? 'high' : undefined} />
            <StatTile
              label="Phishing, impersonation or fraud"
              value={malicious}
              hint={data.total ? `${Math.round((malicious / data.total) * 100)}% of all cases` : undefined}
            />
          </>
        ) : (
          Array.from({ length: 4 }, (_, i) => <Skeleton key={i} height={92} />)
        )}
      </div>

      <div className="grid grid-main-side">
        <Card title="Activity" hint={`Messages analyzed per day, last ${DAYS} days`}>
          {data ? <ActivityChart stats={data} /> : <Skeleton height={240} />}
        </Card>
        <Card title="Verdicts">
          {data ? (
            data.total === 0 ? (
              <EmptyState compact title="No cases yet" />
            ) : (
              <ul className="bar-list">
                {VERDICT_ORDER.map((verdict) => {
                  const value = data.by_verdict[verdict] ?? 0
                  return (
                    <li key={verdict}>
                      <VerdictBadge verdict={verdict} />
                      <span className="tabular">{pad2(value)}</span>
                      <span className="bar" aria-hidden="true">
                        <span style={{ width: `${(value / data.total) * 100}%` }} />
                      </span>
                    </li>
                  )
                })}
              </ul>
            )
          ) : (
            <Skeleton height={200} />
          )}
        </Card>
      </div>

      <div className="grid grid-main-side">
        <Card
          title="Latest cases"
          flush
          actions={
            <Link to="/cases" className="btn btn-sm">
              View all
            </Link>
          }
        >
          {recent.error ? (
            <ErrorState error={recent.error} onRetry={recent.reload} />
          ) : !recent.data ? (
            <div className="card-body stack">
              {Array.from({ length: 4 }, (_, i) => (
                <Skeleton key={i} height={34} />
              ))}
            </div>
          ) : recent.data.items.length === 0 ? (
            <EmptyState icon="mail" title="No cases yet">
              <Link to="/analyze">Analyze an email</Link> to get started.
            </EmptyState>
          ) : (
            <CaseTable items={recent.data.items} compact />
          )}
        </Card>
        <div className="stack gap-16">
          <Card title="Top origin countries">
            {data ? (
              <BarList
                rows={data.top_countries.map(([code, count]) => [countryName({ country: null, country_code: code }) ?? code, count])}
                empty="No geolocated origins yet"
              />
            ) : (
              <Skeleton height={120} />
            )}
          </Card>
          <Card title="Top origin networks">
            {data ? <BarList rows={data.top_origin_asns} empty="No ASN data yet" mono /> : <Skeleton height={120} />}
          </Card>
        </div>
      </div>
    </div>
  )
}
