import { useRef, useState, type DragEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import { Icon } from '../components/Icon'
import { Alert, Card, Tabs } from '../components/ui'
import { formatBytes } from '../lib/format'

type Mode = 'file' | 'paste'

export default function AnalyzePage() {
  const navigate = useNavigate()
  const input = useRef<HTMLInputElement>(null)
  const [mode, setMode] = useState<Mode>('file')
  const [file, setFile] = useState<File | null>(null)
  const [raw, setRaw] = useState('')
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const ready = mode === 'file' ? file !== null : raw.trim().length > 0

  async function submit() {
    if (!ready || busy) return
    setBusy(true)
    setError(null)
    try {
      const result = mode === 'file' ? await api.analyzeFile(file!) : await api.analyzeRaw(raw)
      navigate(`/cases/${result.id}`)
    } catch (err) {
      setError((err as Error).message)
      setBusy(false)
    }
  }

  function onDrop(event: DragEvent) {
    event.preventDefault()
    setDragging(false)
    const dropped = event.dataTransfer.files[0]
    if (dropped) setFile(dropped)
  }

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Analyze an email</h1>
          <p className="subtitle">
            Upload the original message (.eml) with full headers. It is hashed and stored as evidence before analysis.
          </p>
        </div>
      </header>

      <div className="grid grid-main-side">
        <Card>
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
                <Icon name={file ? 'file' : 'upload'} size={28} />
                {file ? (
                  <>
                    <strong className="break">{file.name}</strong>
                    <span className="muted">{formatBytes(file.size)} · click to choose another file</span>
                  </>
                ) : (
                  <>
                    <strong>Drop an .eml file here</strong>
                    <span className="muted">or click to browse</span>
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
              <button className="btn btn-primary" disabled={!ready || busy} onClick={submit}>
                {busy ? <span className="spinner" /> : <Icon name="search" size={15} />}
                {busy ? 'Analyzing…' : 'Analyze'}
              </button>
            </div>
          </div>
        </Card>

        <Card title="What gets checked">
          <ul className="checklist">
            <li><Icon name="lock" size={15} /> SPF, DKIM and DMARC re-verified, compared with the receiver's verdict</li>
            <li><Icon name="server" size={15} /> Received chain reconstructed hop by hop, with delays and anomalies</li>
            <li><Icon name="pin" size={15} /> Originating IP located, with ASN, reverse DNS, Tor and blocklist checks</li>
            <li><Icon name="globe" size={15} /> Sender domain age, WHOIS, DNS and look-alike brand detection</li>
            <li><Icon name="link" size={15} /> Links and attachments inspected for deceptive or risky patterns</li>
            <li><Icon name="mail" size={15} /> Content scored by the ML classifier plus social-engineering cues</li>
            <li><Icon name="graph" size={15} /> Correlated with earlier cases that share infrastructure</li>
          </ul>
          <p className="muted small">
            Forwarded copies lose the original headers. Export the message as .eml, or use "Show original"
            in your mail client and paste the full source.
          </p>
        </Card>
      </div>
    </div>
  )
}
