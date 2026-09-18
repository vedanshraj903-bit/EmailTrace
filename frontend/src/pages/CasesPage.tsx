import { Link, useSearchParams } from 'react-router-dom'
import { api } from '../api/client'
import { CaseTable } from '../components/CaseTable'
import { Icon } from '../components/Icon'
import { EmptyState, ErrorState, Skeleton } from '../components/ui'
import { VERDICT_LABEL } from '../lib/format'
import { useResource } from '../lib/useResource'

const PAGE_SIZE = 25

export default function CasesPage() {
  const [params, setParams] = useSearchParams()
  const q = params.get('q') ?? ''
  const level = params.get('level') ?? ''
  const verdict = params.get('verdict') ?? ''
  const page = Math.max(0, Number(params.get('page') ?? 0) || 0)

  function update(changes: Record<string, string>) {
    const next = new URLSearchParams(params)
    for (const [key, value] of Object.entries(changes)) {
      if (value) next.set(key, value)
      else next.delete(key)
    }
    if (!('page' in changes)) next.delete('page')
    setParams(next, { replace: true })
  }

  const key = `${q}|${level}|${verdict}|${page}`
  const { data, error, loading, reload } = useResource(key, (signal) =>
    api.list({ q, level, verdict, limit: PAGE_SIZE, offset: page * PAGE_SIZE }, signal),
  )
  const pages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1
  const filtered = Boolean(q || level || verdict)

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Cases</h1>
          <p className="subtitle">Every analyzed message, newest first.</p>
        </div>
        <Link to="/analyze" className="btn btn-primary">
          <Icon name="upload" size={15} /> Analyze email
        </Link>
      </header>

      <form
        className="row filters"
        onSubmit={(event) => {
          event.preventDefault()
          update({ q: String(new FormData(event.currentTarget).get('q') ?? '').trim() })
        }}
      >
        <label className="search">
          <Icon name="search" size={15} />
          <span className="sr-only">Search</span>
          <input
            className="input"
            type="search"
            name="q"
            key={q}
            placeholder="Subject, sender, domain or IP"
            defaultValue={q}
          />
        </label>
        <select className="select" aria-label="Risk level" value={level} onChange={(e) => update({ level: e.target.value })}>
          <option value="">All risk levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select className="select" aria-label="Verdict" value={verdict} onChange={(e) => update({ verdict: e.target.value })}>
          <option value="">All verdicts</option>
          {Object.entries(VERDICT_LABEL).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
        {filtered && (
          <button type="button" className="btn btn-sm" onClick={() => setParams({}, { replace: true })}>
            Clear filters
          </button>
        )}
      </form>

      <section className="card">
        {error ? (
          <ErrorState error={error} onRetry={reload} />
        ) : !data ? (
          <div className="card-body stack">
            {Array.from({ length: 6 }, (_, i) => (
              <Skeleton key={i} height={34} />
            ))}
          </div>
        ) : data.items.length === 0 ? (
          filtered ? (
            <EmptyState icon="search" title="No cases match these filters" />
          ) : (
            <EmptyState icon="mail" title="No cases yet">
              <Link to="/analyze">Analyze your first email</Link> to start building the case library.
            </EmptyState>
          )
        ) : (
          <div className={loading ? 'loading-fade' : ''}>
            <CaseTable items={data.items} />
            <footer className="pager">
              <span className="muted tabular">
                {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + data.items.length} of {data.total}
              </span>
              <span className="spacer" />
              <button className="btn btn-sm" disabled={page === 0} onClick={() => update({ page: String(page - 1) })}>
                Previous
              </button>
              <button
                className="btn btn-sm"
                disabled={page + 1 >= pages}
                onClick={() => update({ page: String(page + 1) })}
              >
                Next
              </button>
            </footer>
          </div>
        )}
      </section>
    </div>
  )
}
