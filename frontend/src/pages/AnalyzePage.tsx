import { useCallback, useEffect, useRef, useState, type DragEvent } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { Icon, type IconName } from '../components/Icon'
import { Alert, Card, Tabs } from '../components/ui'
import { formatBytes } from '../lib/format'
import { useToast } from '../lib/toast'

type Mode = 'file' | 'paste'

const CHECKS: { icon: IconName; label: string }[] = [
  { icon: 'lock', label: 'Re-verifying SPF, DKIM and DMARC' },
  { icon: 'server', label: 'Rebuilding the Received chain hop by hop' },
  { icon: 'pin', label: 'Locating IPs: ASN, reverse DNS, Tor, blocklists' },
  { icon: 'globe', label: 'Checking domain age, WHOIS and look-alikes' },
  { icon: 'link', label: 'Inspecting links and attachments' },
  { icon: 'mail', label: 'Scoring content with the ML classifier' },
  { icon: 'graph', label: 'Correlating with earlier cases' },
]
// The API answers in one response, so this walk-through shows what is being checked,
// not measured progress; the list keeps cycling until the result arrives.
const STEP_MS = 900

function ScanProgress({ name }: { name: string }) {
  const [step, setStep] = useState(0)
  const [elapsed, setElapsed] = useState(0)

  useEffect(() => {
    const started = performance.now()
    const timer = window.setInterval(() => {
      const ms = performance.now() - started
      setElapsed(ms / 1000)
      setStep(Math.floor(ms / STEP_MS))
    }, 100)
    return () => window.clearInterval(timer)
  }, [])

  const active = step % CHECKS.length
  const lapped = step >= CHECKS.length
  return (
    <div className="stack" aria-live="polite">
      <div className="row">
        <span className="spinner" />
        <strong className="break">Examining {name}</strong>
      </div>
      <ul className="scan">
        {CHECKS.map((check, index) => (
          <li key={check.label} className={index === active ? 'active' : lapped || index < active ? 'seen' : ''}>
            <span className="scan-dot" aria-hidden="true" />
            <Icon name={check.icon} size={14} />
            {check.label}
          </li>
        ))}
      </ul>
      <div className="scan-footer">
        <Icon name="clock" size={13} /> {elapsed.toFixed(1)} s · live DNS and WHOIS lookups can take a few seconds
      </div>
    </div>
  )
}

export default function AnalyzePage() {
  const navigate = useNavigate()
  const location = useLocation()
  const notify = useToast()
  const input = useRef<HTMLInputElement>(null)
  const [mode, setMode] = useState<Mode>('file')
  const [file, setFile] = useState<File | null>(null)
  const [raw, setRaw] = useState('')
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const run = useCallback(
    async (source: File | string) => {
      setBusy(true)
      setError(null)
      try {
        const result = typeof source === 'string' ? await api.analyzeRaw(source) : await api.analyzeFile(source)
        notify(`Case opened: score ${result.risk.score}`, result.risk.score >= 50 ? 'serious' : 'good')
        navigate(`/cases/${result.id}`)
      } catch (err) {
        setError((err as Error).message)
        setBusy(false)
      }
    },
    [navigate, notify],
  )

  // A file dropped anywhere in the app arrives here in navigation state; start at once.
  const dropped = (location.state as { file?: File } | null)?.file
  const handled = useRef<File | null>(null)
  useEffect(() => {
    if (!dropped || handled.current === dropped) return // StrictMode runs effects twice in development
    handled.current = dropped
    setMode('file')
    setFile(dropped)
    navigate('.', { replace: true, state: null }) // do not re-run on refresh or back
    void run(dropped)
  }, [dropped, navigate, run])

  const ready = mode === 'file' ? file !== null : raw.trim().length > 0

  function submit() {
    if (!ready || busy) return
    void run(mode === 'file' ? file! : raw)
  }

  function onDrop(event: DragEvent) {
    event.preventDefault() // claims the drop so the app-wide handler leaves it alone
    setDragging(false)
    const next = event.dataTransfer.files[0]
    if (next) setFile(next)
  }

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <div className="kicker">New case</div>
          <h1>Open an investigation</h1>
          <p className="subtitle">
            Hand over the original message (.eml) with its full headers. It is hashed and sealed as evidence{' '}
            <span className="mark">before</span> any analysis runs.
          </p>
        </div>
      </header>

      <div className="grid grid-main-side">
        <Card>
          {busy ? (
            <ScanProgress name={mode === 'file' && file ? file.name : 'pasted source'} />
          ) : (
            <div className="stack">
              <Tabs<Mode>
                items={[
                  { key: 'file', label: 'Upload file' },
                  { key: 'paste', label: 'Paste raw source' },
                ]}
                active={mode}
                onChange={setMode}
              />

              {mode === 'file' ? (
                <div
                  className={`dropzone ${dragging ? 'dragging' : ''} ${file ? 'has-file' : ''}`}
                  onDragOver={(event) => {
                    event.preventDefault()
                    setDragging(true)
                  }}
                  onDragLeave={() => setDragging(false)}
                  onDrop={onDrop}
                  onClick={() => input.current?.click()}
                  onKeyDown={(event) => (event.key === 'Enter' || event.key === ' ') && input.current?.click()}
                  role="button"
                  tabIndex={0}
                >
                  <input
                    ref={input}
                    type="file"
                    accept=".eml,.msg,.txt,message/rfc822"
                    className="sr-only"
                    onChange={(event) => setFile(event.target.files?.[0] ?? null)}
                  />
                  <Icon name={file ? 'file' : 'upload'} size={30} />
                  {file ? (
                    <>
                      <strong className="break">{file.name}</strong>
                      <span className="muted">{formatBytes(file.size)} · click to choose another file</span>
                    </>
                  ) : (
                    <>
                      <strong>Drop the .eml here</strong>
                      <span className="muted">or click to browse. You can also drop a file anywhere in the app.</span>
                    </>
                  )}
                </div>
              ) : (
                <textarea
                  className="textarea"
                  placeholder={'Received: from …\nFrom: …\nSubject: …\n\nPaste the full message source, including all headers.'}
                  value={raw}
                  onChange={(event) => setRaw(event.target.value)}
                  spellCheck={false}
                />
              )}

              {error && <Alert tone="critical">{error}</Alert>}

              <div className="row">
                <span className="spacer" />
                <button className="btn btn-primary" disabled={!ready} onClick={submit}>
                  <Icon name="search" size={15} /> Analyze
                </button>
              </div>
            </div>
          )}
        </Card>

        <Card title="What gets examined">
          <ul className="checklist">
            {CHECKS.map((check) => (
              <li key={check.label}>
                <Icon name={check.icon} size={15} /> {check.label}
              </li>
            ))}
          </ul>
          <p className="muted small">
            Forwarded copies lose the original headers. Export the message as .eml, or use “Show original” in your
            mail client and paste the full source.
          </p>
        </Card>
      </div>
    </div>
  )
}
