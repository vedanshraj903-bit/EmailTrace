import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { MailboxStatus } from '../api/types'
import { formatRelative } from '../lib/format'
import { useResource } from '../lib/useResource'
import { useToast } from '../lib/toast'
import { Icon } from './Icon'
import { Alert, Card, EmptyState, LevelBadge, Skeleton } from './ui'

const POLL_MS = 5_000
const SCAN_COUNT = 10

type Action = 'check' | 'pause' | 'resume' | 'scan'

function stateLabel(status: MailboxStatus): string {
  const where = `${status.folder} · ${status.account}`
  switch (status.state) {
    case 'connected':
      return `Watching ${where}${status.last_check ? ` · checked ${formatRelative(status.last_check)}` : ''}`
    case 'connecting':
      return `Connecting to ${where}…`
    case 'paused':
      return `Paused · ${where}`
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
  const scanning = useRef(false)
  const [busy, setBusy] = useState<Action | null>(null)

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

  // Report the result of "Scan recent" once the backend has finished it.
  useEffect(() => {
    if (!data) return
    if (scanning.current && !data.scan_pending && data.notice) notify(data.notice, 'good')
    scanning.current = data.scan_pending
  }, [data, notify])

  const run = async (action: Action) => {
    setBusy(action)
    try {
      if (action === 'scan') {
        await api.mailboxScan(SCAN_COUNT)
        scanning.current = true
        notify(`Scanning the ${SCAN_COUNT} most recent emails…`)
      } else {
        await api.mailboxAction(action)
        if (action === 'pause') notify('Live mailbox paused. New mail will be analyzed when you resume.')
        if (action === 'resume') notify('Live mailbox resumed.', 'good')
      }
      reload()
      window.setTimeout(reload, 1_500) // reconnecting takes a moment; show the settled state promptly
    } catch (err) {
      notify((err as Error).message, 'serious')
    } finally {
      setBusy(null)
    }
  }

  const live = data?.state === 'connected'
  const paused = data?.state === 'paused'
  const controls = data?.enabled ? (
    <div className="row mailbox-controls">
      <span className={live ? 'live' : 'live off'}>{live ? 'Live' : paused ? 'Paused' : 'Offline'}</span>
      <button
        className="btn btn-sm"
        onClick={() => void run('check')}
        disabled={busy !== null || paused}
        title={data.state === 'error' ? 'Try connecting again now' : 'Look for new mail now'}
      >
        <Icon name="refresh" size={14} /> {data.state === 'error' ? 'Retry now' : 'Check now'}
      </button>
      <button
        className="btn btn-sm"
        onClick={() => void run('scan')}
        disabled={busy !== null || !live || data.scan_pending}
        title={`Analyze the ${SCAN_COUNT} newest emails already in the inbox, skipping any analyzed before`}
      >
        <Icon name="mail" size={14} /> {data.scan_pending ? 'Scanning…' : `Scan last ${SCAN_COUNT}`}
      </button>
      <button className="btn btn-sm" onClick={() => void run(paused ? 'resume' : 'pause')} disabled={busy !== null}>
        {paused ? 'Resume' : 'Pause'}
      </button>
    </div>
  ) : undefined

  return (
    <Card
      title="Live mailbox"
      className="mailbox-card"
      hint={data ? stateLabel(data) : error ? 'API unreachable' : 'Checking…'}
      actions={controls}
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
            data.state === 'error' ? null : paused ? (
              <EmptyState compact icon="clock" title="Paused">
                Mail that arrives while paused is analyzed as soon as you resume.
              </EmptyState>
            ) : (
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
