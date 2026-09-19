import { useEffect, useRef } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { MailboxStatus } from '../api/types'
import { formatRelative } from '../lib/format'
import { useResource } from '../lib/useResource'
import { useToast } from '../lib/toast'
import { Alert, Card, EmptyState, LevelBadge, Skeleton } from './ui'

const POLL_MS = 5_000

function stateLabel(status: MailboxStatus): string {
  const where = `${status.folder} · ${status.account}`
  switch (status.state) {
    case 'connected':
      return `Watching ${where}${status.last_check ? ` · checked ${formatRelative(status.last_check)}` : ''}`
    case 'connecting':
      return `Connecting to ${where}…`
    case 'error':
      return `Not connected · ${where}`
    default:
      return 'Off'
  }
}

/** New mail in the watched inbox is analyzed by the backend; this card shows it as it lands. */
export function LiveMailbox({ onNewMail }: { onNewMail: () => void }) {
  const { data, error, reload } = useResource('mailbox', (signal) => api.mailbox(signal))
  const notify = useToast()
  const seen = useRef<number | null>(null)

  useEffect(() => {
    const timer = window.setInterval(() => {
      if (document.visibilityState === 'visible') reload()
    }, POLL_MS)
    return () => window.clearInterval(timer)
  }, [reload])

  // Refresh the rest of the dashboard and flag dangerous mail whenever the count moves.
  useEffect(() => {
    if (!data) return
    const previous = seen.current
    seen.current = data.analyzed
    if (previous === null || data.analyzed <= previous) return
    onNewMail()
    for (const event of data.recent.slice(0, data.analyzed - previous)) {
      if (event.level === 'high' || event.level === 'critical') {
        notify(
          <>
            <strong>{event.level === 'critical' ? 'Critical' : 'High'}-risk email</strong> from {event.from_address}:{' '}
            <Link to={`/cases/${event.analysis_id}`}>{event.subject || '(no subject)'}</Link>
          </>,
          'critical',
        )
      }
    }
  }, [data, notify, onNewMail])

  const live = data?.state === 'connected'
  return (
    <Card
      title="Live mailbox"
      hint={data ? stateLabel(data) : error ? 'API unreachable' : 'Checking…'}
      actions={data?.enabled ? <span className={live ? 'live' : 'live off'}>{live ? 'Live' : 'Offline'}</span> : undefined}
      flush
    >
      {!data ? (
        <div className="card-body">
          <Skeleton height={34} />
        </div>
      ) : !data.enabled ? (
        <EmptyState compact icon="mail" title="No mailbox connected">
          Add <code>IMAP_USER</code> and <code>IMAP_PASSWORD</code> to <code>backend/.env</code> and restart the
          backend to analyze new mail automatically.
        </EmptyState>
      ) : (
        <>
          {data.error && (
            <div className="card-body">
              <Alert tone="serious">{data.error}</Alert>
            </div>
          )}
          {data.recent.length === 0 ? (
            data.state === 'error' ? null : (
              <EmptyState compact icon="clock" title="Waiting for new mail">
                Emails that arrive from now on are analyzed within {data.poll_seconds} seconds. Nothing is marked
                read, moved or deleted.
              </EmptyState>
            )
          ) : (
            <ul className="mail-feed">
              {data.recent.map((event) => (
                <li key={event.analysis_id}>
                  <Link to={`/cases/${event.analysis_id}`}>
                    <span className="mail-subject break">{event.subject || '(no subject)'}</span>
                    <span className="muted small break">
                      {event.from_address} · {formatRelative(event.received_at)}
                    </span>
                  </Link>
                  <span className="tabular">{event.score}</span>
                  <LevelBadge level={event.level} />
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </Card>
  )
}
