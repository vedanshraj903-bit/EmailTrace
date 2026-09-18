import { Link } from 'react-router-dom'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { api } from '../api/client'
import type { RiskLevel, Stats, Verdict } from '../api/types'
import { CaseTable } from '../components/CaseTable'
import { Icon } from '../components/Icon'
import { Card, EmptyState, ErrorState, Skeleton, VerdictBadge } from '../components/ui'
import { formatShortDate, type Tone } from '../lib/format'
import { useResource } from '../lib/useResource'

const DAYS = 30

interface DayRow {
  day: string
  flagged: number
  other: number
}

/** The API omits days with no traffic; fill them so the time axis stays continuous. */
function fillDays(daily: Stats['daily']): DayRow[] {
  const byDay = new Map(daily.map(([day, total, flagged]) => [day, { total, flagged }]))
  const rows: DayRow[] = []
  const today = new Date()
  for (let offset = DAYS - 1; offset >= 0; offset--) {
    const date = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - offset))
    const day = date.toISOString().slice(0, 10)
    const entry = byDay.get(day)
    rows.push({ day, flagged: entry?.flagged ?? 0, other: (entry?.total ?? 0) - (entry?.flagged ?? 0) })
  }
  return rows
}

function StatTile({ label, value, hint, tone }: { label: string; value: number | string; hint?: string; tone?: Tone }) {
  return (
    <div className={`card stat ${tone ? `tone-${tone}` : ''}`}>
      <span className="stat-label">{label}</span>
      <span className="stat-value tabular">{value}</span>
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
      <span>
        <i className="swatch" style={{ background: 'var(--series-1)' }} /> High / critical risk
        <b className="tabular">{row.flagged}</b>
      </span>
      <span>
        <i className="swatch" style={{ background: 'var(--series-2)' }} /> Low / medium risk
        <b className="tabular">{row.other}</b>
      </span>
    </div>
  )
}

function ActivityChart({ stats }: { stats: Stats }) {
  const rows = fillDays(stats.daily)
  if (rows.every((row) => row.flagged + row.other === 0)) {
    return <EmptyState compact icon="clock" title={`No messages analyzed in the last ${DAYS} days`} />
  }
  return (
    <figure className="chart">
      <div className="chart-legend">
        <span>
          <i className="swatch" style={{ background: 'var(--series-1)' }} /> High / critical risk
        </span>
        <span>
          <i className="swatch" style={{ background: 'var(--series-2)' }} /> Low / medium risk
        </span>
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
            tick={{ fill: 'var(--ink-muted)', fontSize: 11.5 }}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip content={(props) => <ActivityTooltip active={props.active} payload={props.payload} />} cursor={{ fill: 'var(--surface-hover)' }} />
          <Bar dataKey="flagged" stackId="a" fill="var(--series-1)" stroke="var(--surface)" strokeWidth={1} />
          <Bar dataKey="other" stackId="a" fill="var(--series-2)" stroke="var(--surface)" strokeWidth={1} radius={[4, 4, 0, 0]} />
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
          <span className="tabular">{count}</span>
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
            <StatTile label="Critical risk" value={count('critical')} tone={count('critical') ? 'critical' : undefined} />
            <StatTile label="High risk" value={count('high')} tone={count('high') ? 'serious' : undefined} />
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
                      <span className="tabular">{value}</span>
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
            {data ? <BarList rows={data.top_countries} empty="No geolocated origins yet" /> : <Skeleton height={120} />}
          </Card>
          <Card title="Top origin networks">
            {data ? <BarList rows={data.top_origin_asns} empty="No ASN data yet" mono /> : <Skeleton height={120} />}
          </Card>
        </div>
      </div>
    </div>
  )
}
