// KeyValue rows are [label, value] tuples keyed by index inside KeyValue; jsx-key flags them falsely.
/* oxlint-disable react/jsx-key */
import { lazy, Suspense, useState, type ReactNode } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import type { AnalysisResult, Finding, Severity } from '../api/types'
import { CampaignGraphView } from '../components/CampaignGraphView'
import { Icon } from '../components/Icon'
import { ScoreGauge } from '../components/ScoreGauge'
import {
  Alert,
  AuthBadge,
  Badge,
  BoolBadge,
  Card,
  EmptyState,
  ErrorState,
  KeyValue,
  LevelBadge,
  SeverityBadge,
  Skeleton,
  Tabs,
  VerdictBadge,
} from '../components/ui'
import {
  ATTRIBUTION_LABEL,
  CATEGORY_LABEL,
  formatBytes,
  formatDateTime,
  formatDuration,
  HOSTING_LABEL,
  INDICATOR_LABEL,
  percent,
  scoreTone,
} from '../lib/format'
import { useResource } from '../lib/useResource'

const TraceMap = lazy(() => import('../components/TraceMap').then((m) => ({ default: m.TraceMap })))

type TabKey = 'overview' | 'auth' | 'route' | 'domain' | 'content' | 'artifacts' | 'related' | 'custody'

const SEVERITY_RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

function address(a: { display_name: string; address: string }) {
  return a.display_name ? `${a.display_name} <${a.address}>` : a.address
}

/* ---------- Overview ------------------------------------------------------ */

function Findings({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return <EmptyState compact icon="check" title="No findings" />
  }
  const sorted = [...findings].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity])
  return (
    <ul className="findings">
      {sorted.map((finding) => (
        <li key={finding.code}>
          <SeverityBadge severity={finding.severity} />
          <div>
            <strong>{finding.title}</strong>
            <p className="secondary">{finding.detail}</p>
          </div>
          <span className="chip">{CATEGORY_LABEL[finding.category]}</span>
        </li>
      ))}
    </ul>
  )
}

function RiskBreakdown({ result }: { result: AnalysisResult }) {
  return (
    <ul className="risk-components">
      {result.risk.components.map((component) => (
        <li key={component.key} className={component.available ? '' : 'unavailable'}>
          <div className="row">
            <strong>{component.label}</strong>
            <span className="spacer" />
            <span className="tabular secondary">
              {component.available ? `${component.points.toFixed(1)} / ${component.weight} pts` : 'No data'}
            </span>
          </div>
          <span className={`meter tone-${scoreTone(component.severity * 100)}`} aria-hidden="true">
            <span style={{ width: `${component.available ? (component.points / component.weight) * 100 : 0}%` }} />
          </span>
          {component.reasons.length > 0 && (
            <ul className="reasons">
              {component.reasons.map((reason) => (
                <li key={reason}>{reason}</li>
              ))}
            </ul>
          )}
        </li>
      ))}
    </ul>
  )
}

function Overview({ result }: { result: AnalysisResult }) {
  const { summary } = result
  return (
    <div className="grid grid-main-side">
      <Card title="Findings" hint={`${result.findings.length} indicators, most severe first`}>
        <Findings findings={result.findings} />
      </Card>
      <div className="stack gap-16">
        <Card title="Message">
          <KeyValue
            rows={[
              ['From', <span className="mono">{address(summary.from)}</span>],
              [
                'Reply-To',
                summary.reply_to.length ? <span className="mono">{summary.reply_to.map(address).join(', ')}</span> : null,
              ],
              ['Return-Path', summary.return_path ? <span className="mono">{summary.return_path}</span> : null],
              ['To', summary.to.length ? summary.to.map(address).join(', ') : null],
              ['Date', formatDateTime(summary.date)],
              ['Message-ID', <span className="mono">{summary.message_id || '—'}</span>],
              ['File', result.filename ?? 'Pasted source'],
              ['Size', formatBytes(result.size)],
              ['SHA-256', <span className="mono">{result.sha256}</span>],
            ]}
          />
        </Card>
        <Card title="Score breakdown" hint={`Signal coverage ${percent(result.risk.coverage)}`}>
          <RiskBreakdown result={result} />
        </Card>
      </div>
    </div>
  )
}

/* ---------- Authentication ------------------------------------------------ */

function AuthenticationTab({ result }: { result: AnalysisResult }) {
  const { spf, dkim, dmarc, recorded, mismatches } = result.authentication
  return (
    <div className="stack gap-16">
      {mismatches.length > 0 && (
        <Alert tone="serious">
          <strong>Our verification disagrees with the receiving server.</strong>
          <ul className="plain">
            {mismatches.map((m) => (
              <li key={m}>{m}</li>
            ))}
          </ul>
        </Alert>
      )}
      <div className="grid grid-3">
        <Card title="SPF" actions={<AuthBadge result={spf.result} />}>
          <KeyValue
            rows={[
              ['Domain', <span className="mono">{spf.domain || '—'}</span>],
              ['Checked IP', <span className="mono">{spf.ip ?? '—'}</span>],
              ['IP source', spf.ip_source],
              ['Record', spf.record ? <code className="break">{spf.record}</code> : null],
            ]}
          />
          {spf.explanation && <p className="muted small top-gap">{spf.explanation}</p>}
        </Card>
        <Card title="DKIM" actions={dkim.length === 0 ? <AuthBadge result="none" /> : undefined}>
          {dkim.length === 0 ? (
            <p className="muted">The message carries no DKIM signature.</p>
          ) : (
            <div className="stack">
              {dkim.map((sig, i) => (
                <div key={i} className="stack tight">
                  <div className="row">
                    <span className="mono">
                      {sig.selector}._domainkey.{sig.domain}
                    </span>
                    <span className="spacer" />
                    <AuthBadge result={sig.result} />
                  </div>
                  {sig.detail && <p className="muted small">{sig.detail}</p>}
                </div>
              ))}
            </div>
          )}
        </Card>
        <Card title="DMARC" actions={<AuthBadge result={dmarc.result} />}>
          <KeyValue
            rows={[
              ['From domain', <span className="mono">{dmarc.from_domain}</span>],
              ['Policy', dmarc.policy ? <code>p={dmarc.policy}</code> : 'No record'],
              ['SPF aligned', <BoolBadge value={dmarc.spf_aligned} good="Aligned" bad="Not aligned" />],
              ['DKIM aligned', <BoolBadge value={dmarc.dkim_aligned} good="Aligned" bad="Not aligned" />],
              ['Disposition', dmarc.disposition],
              ['Record', dmarc.record ? <code className="break">{dmarc.record}</code> : null],
            ]}
          />
        </Card>
      </div>
      <Card title="Receiver's recorded results" hint="From the Authentication-Results header added on delivery">
        {recorded.raw ? (
          <>
            <KeyValue
              rows={[
                ['Recorded by', <span className="mono">{recorded.authserv_id ?? '—'}</span>],
                ['SPF', <AuthBadge result={recorded.spf} />],
                ['DKIM', <AuthBadge result={recorded.dkim} />],
                ['DMARC', <AuthBadge result={recorded.dmarc} />],
              ]}
            />
            <pre className="raw top-gap">{recorded.raw}</pre>
          </>
        ) : (
          <p className="muted">No Authentication-Results header was present.</p>
        )}
      </Card>
    </div>
  )
}

/* ---------- Route & origin ------------------------------------------------ */

function RouteTab({ result }: { result: AnalysisResult }) {
  const { origin, hops } = result
  const listed = origin.dnsbl.filter((entry) => entry.listed)
  const geo = origin.geo
  return (
    <div className="stack gap-16">
      <div className="grid grid-main-side">
        <Card
          title="Geographic trace"
          hint={
            origin.webmail_masked
              ? "Mail-server locations only. The sender's own location is not recorded in this message."
              : 'Approximate IP geolocation. Circles show the accuracy radius.'
          }
          flush
        >
          {hops.some((hop) => hop.geo) || geo ? (
            <Suspense fallback={<Skeleton height={380} />}>
              <TraceMap hops={hops} origin={origin} />
            </Suspense>
          ) : (
            <EmptyState icon="pin" title="No IPs could be geolocated">
              Configure a MaxMind GeoLite2 database or an ipinfo token to enable the map.
            </EmptyState>
          )}
        </Card>
        <Card title="Origin">
          {origin.note && (
            <div className="bottom-gap">
              <Alert tone={origin.webmail_masked ? 'warning' : 'neutral'}>{origin.note}</Alert>
            </div>
          )}
          <KeyValue
            rows={[
              origin.webmail_masked
                ? ['Sender IP', <Badge tone="neutral" label={`Hidden by ${result.domain.registered_domain || 'the provider'}`} />]
                : ['Originating IP', <span className="mono">{origin.ip ?? 'Not determinable'}</span>],
              ...(origin.webmail_masked
                ? ([['Provider server', <span className="mono">{origin.ip ?? '—'}</span>]] as [ReactNode, ReactNode][])
                : []),
              ['Determined from', origin.source === 'none' ? '—' : origin.source],
              [
                origin.webmail_masked ? 'Server location' : 'Location',
                geo ? [geo.city, geo.region, geo.country].filter(Boolean).join(', ') || '—' : null,
              ],
              ['Accuracy', geo ? `± ${geo.accuracy_radius_km} km${geo.radius_source === 'default' ? ' (estimated)' : ''}` : null],
              ['Network', origin.asn ? <span>{origin.asn} · {origin.org}</span> : origin.org],
              ['Hosting', HOSTING_LABEL[origin.hosting_class]],
              ['Reverse DNS', <span className="mono">{origin.ptr ?? '—'}</span>],
              ['FCrDNS', <BoolBadge value={origin.fcrdns} good="Confirmed" bad="Mismatch" />],
              ['Tor exit node', origin.tor_exit === null ? <Badge tone="neutral" label="Unknown" /> : origin.tor_exit ? <Badge tone="critical" label="Tor exit" /> : <Badge tone="good" label="No" />],
              [
                'Blocklists',
                origin.dnsbl.length === 0 ? (
                  'Not checked'
                ) : listed.length ? (
                  <span className="row">{listed.map((entry) => <Badge key={entry.zone} tone="critical" label={entry.zone} />)}</span>
                ) : (
                  <Badge tone="good" label={`Clean on ${origin.dnsbl.length} lists`} />
                ),
              ],
              [
                'SMTP probe',
                origin.smtp_probe ? (
                  origin.smtp_probe.error ? (
                    <span className="muted">{origin.smtp_probe.error}</span>
                  ) : (
                    <span className="mono">{origin.smtp_probe.banner}</span>
                  )
                ) : null,
              ],
            ]}
          />
        </Card>
      </div>

      <Card title="Delivery path" hint="Received headers, oldest hop first" flush>
        {hops.length === 0 ? (
          <EmptyState compact title="No Received headers" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th className="num">#</th>
                  <th>From</th>
                  <th>By</th>
                  <th>Location</th>
                  <th>Time</th>
                  <th className="num">Delay</th>
                  <th>Anomalies</th>
                </tr>
              </thead>
              <tbody>
                {hops.map((hop) => (
                  <tr key={hop.index}>
                    <td className="num">{hop.index + 1}</td>
                    <td className="break">
                      <span className="mono">{hop.from_ip ?? '—'}</span>
                      {!hop.public && hop.from_ip && <span className="chip left-gap">private</span>}
                      <div className="muted mono">{hop.from_rdns ?? hop.from_helo ?? ''}</div>
                    </td>
                    <td className="mono break">{hop.by_host ?? '—'}</td>
                    <td>{hop.geo ? [hop.geo.city, hop.geo.country_code].filter(Boolean).join(', ') || '—' : '—'}</td>
                    <td className="nowrap">{formatDateTime(hop.timestamp)}</td>
                    <td className="num nowrap">{hop.delay_s === null ? '—' : formatDuration(hop.delay_s)}</td>
                    <td>
                      {hop.anomalies.length === 0 ? (
                        <span className="muted">—</span>
                      ) : (
                        <div className="stack tight">
                          {hop.anomalies.map((a) => (
                            <Badge key={a} tone="warning" label={a} />
                          ))}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}

/* ---------- Domain -------------------------------------------------------- */

function DomainTab({ result }: { result: AnalysisResult }) {
  const { domain } = result
  const { whois, dns, lookalike } = domain
  return (
    <div className="stack gap-16">
      {lookalike.matched_brand && (
        <Alert tone="critical">
          <strong>Look-alike of {lookalike.matched_brand}</strong> ({lookalike.brand_domain}) via {lookalike.technique}
          {lookalike.distance !== null && `, edit distance ${lookalike.distance}`}.
          {lookalike.punycode && lookalike.unicode_form && (
            <> Punycode domain renders as <span className="mono">{lookalike.unicode_form}</span>.</>
          )}
        </Alert>
      )}
      <div className="grid grid-2">
        <Card title="Sender domain">
          <KeyValue
            rows={[
              ['Domain', <span className="mono">{domain.domain}</span>],
              ['Registered domain', <span className="mono">{domain.registered_domain}</span>],
              ['Free mail provider', domain.free_mail_provider ? <Badge tone="warning" label="Yes" /> : 'No'],
              [
                'Disposable',
                domain.disposable_list_loaded ? (
                  domain.disposable ? <Badge tone="critical" label="Disposable" /> : 'No'
                ) : (
                  <span className="muted">List not loaded</span>
                ),
              ],
            ]}
          />
        </Card>
        <Card title="WHOIS">
          {!whois.available ? (
            <p className="muted">{whois.error ?? 'WHOIS lookups are disabled.'}</p>
          ) : (
            <KeyValue
              rows={[
                ['Registrar', whois.registrar],
                ['Created', whois.created ? formatDateTime(whois.created) : null],
                [
                  'Domain age',
                  whois.age_days === null ? null : (
                    <Badge tone={whois.age_days < 30 ? 'critical' : whois.age_days < 180 ? 'warning' : 'good'} label={`${whois.age_days} days`} />
                  ),
                ],
                ['Expires', whois.expires ? formatDateTime(whois.expires) : null],
                ['Privacy protected', whois.privacy_protected === null ? null : whois.privacy_protected ? 'Yes' : 'No'],
                ['Country', whois.country],
                ['Name servers', whois.name_servers.length ? <span className="mono">{whois.name_servers.join(', ')}</span> : null],
              ]}
            />
          )}
        </Card>
      </div>
      <Card title="DNS records">
        {dns.error && <Alert tone="warning">{dns.error}</Alert>}
        <KeyValue
          rows={[
            ['MX', dns.mx.length ? <span className="mono">{dns.mx.join(', ')}</span> : <Badge tone="warning" label="None" />],
            ['A', dns.a.length ? <span className="mono">{dns.a.join(', ')}</span> : null],
            ['SPF', dns.spf ? <code className="break">{dns.spf}</code> : <Badge tone="warning" label="None" />],
            ['DMARC', dns.dmarc ? <code className="break">{dns.dmarc}</code> : <Badge tone="warning" label="None" />],
          ]}
        />
      </Card>
    </div>
  )
}

/* ---------- Content ------------------------------------------------------- */

function ContentTab({ result }: { result: AnalysisResult }) {
  const { classifier, cues, word_count } = result.content
  const cueEntries = Object.entries(cues).filter(([, matches]) => matches.length > 0)
  const probability = classifier.malicious_probability
  return (
    <div className="grid grid-2">
      <Card title="ML classifier">
        {!classifier.available ? (
          <p className="muted">{classifier.reason ?? 'The classifier model is not loaded.'}</p>
        ) : (
          <div className="stack">
            <div className="row">
              <span className="big-number tabular">{probability === null ? '—' : percent(probability)}</span>
              <span className="secondary">probability malicious</span>
              <span className="spacer" />
              {classifier.label && <Badge tone={probability !== null && probability >= 0.5 ? 'critical' : 'good'} label={classifier.label} />}
            </div>
            <ul className="bar-list">
              {Object.entries(classifier.probabilities)
                .sort(([, a], [, b]) => b - a)
                .map(([label, p]) => (
                  <li key={label}>
                    <span>{label}</span>
                    <span className="tabular">{percent(p, 1)}</span>
                    <span className="bar" aria-hidden="true">
                      <span style={{ width: `${p * 100}%` }} />
                    </span>
                  </li>
                ))}
            </ul>
            <KeyValue rows={Object.entries(classifier.model).map(([k, v]) => [k, String(v)])} />
          </div>
        )}
      </Card>
      <Card title="Social-engineering cues" hint={`${word_count} words analyzed`}>
        {cueEntries.length === 0 ? (
          <EmptyState compact icon="check" title="No manipulation cues found" />
        ) : (
          <dl className="cues">
            {cueEntries.map(([cue, matches]) => (
              <div key={cue}>
                <dt>{cue.replace(/_/g, ' ')}</dt>
                <dd className="row">
                  {matches.map((m) => (
                    <span key={m} className="chip">
                      “{m}”
                    </span>
                  ))}
                </dd>
              </div>
            ))}
          </dl>
        )}
      </Card>
    </div>
  )
}

/* ---------- Links & attachments ------------------------------------------ */

function ArtifactsTab({ result }: { result: AnalysisResult }) {
  return (
    <div className="stack gap-16">
      <Card title="Links" hint={`${result.links.length} found`} flush>
        {result.links.length === 0 ? (
          <EmptyState compact icon="link" title="No links" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Destination</th>
                  <th>Link text</th>
                  <th>Flags</th>
                </tr>
              </thead>
              <tbody>
                {result.links.map((link, i) => (
                  <tr key={i}>
                    <td className="break">
                      <strong className="mono">{link.host}</strong>
                      <div className="muted mono small">{link.href}</div>
                    </td>
                    <td className="break">{link.text || <span className="muted">—</span>}</td>
                    <td>
                      <div className="row">
                        {link.flags.length ? link.flags.map((f) => <Badge key={f} tone="serious" label={f} />) : <span className="muted">—</span>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <Card title="Attachments" hint={`${result.attachments.length} found`} flush>
        {result.attachments.length === 0 ? (
          <EmptyState compact icon="file" title="No attachments" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>File</th>
                  <th className="num">Size</th>
                  <th>SHA-256</th>
                  <th>Flags</th>
                </tr>
              </thead>
              <tbody>
                {result.attachments.map((file) => (
                  <tr key={file.sha256 + file.filename}>
                    <td className="break">
                      <strong>{file.filename || '(unnamed)'}</strong>
                      <div className="muted mono small">{file.content_type}</div>
                    </td>
                    <td className="num nowrap">{formatBytes(file.size)}</td>
                    <td className="mono small break">{file.sha256}</td>
                    <td>
                      <div className="row">
                        {file.flags.length ? file.flags.map((f) => <Badge key={f} tone="serious" label={f} />) : <span className="muted">—</span>}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  )
}

/* ---------- Related ------------------------------------------------------- */

function RelatedTab({ result }: { result: AnalysisResult }) {
  const graph = useResource(`graph:${result.id}`, (signal) => api.graph(result.id, signal))
  const { behaviour } = result
  const windows = [behaviour.ip, behaviour.domain].filter((w) => w !== null)
  return (
    <div className="stack gap-16">
      {windows.length > 0 && (
        <div className="grid grid-2">
          {windows.map((w) => (
            <Card
              key={w.key}
              title={w.key === 'ip' ? 'Sending velocity: origin IP' : 'Sending velocity: sender domain'}
              actions={w.burst ? <Badge tone="serious" label="Burst detected" /> : undefined}
            >
              <KeyValue
                rows={[
                  [w.key === 'ip' ? 'IP' : 'Domain', <span className="mono">{w.value}</span>],
                  ['Last 5 minutes', w.count_5m],
                  ['Last hour', w.count_1h],
                  ['Z-score vs history', w.zscore === null ? 'Not enough history' : w.zscore.toFixed(2)],
                  ['History window', `${w.history_hours} h`],
                ]}
              />
            </Card>
          ))}
        </div>
      )}
      <Card title="Related cases" hint="Earlier cases sharing at least one indicator" flush>
        {result.related.length === 0 ? (
          <EmptyState compact icon="graph" title="No related cases found" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th className="num">Score</th>
                  <th>Case</th>
                  <th>Shared indicators</th>
                  <th>Analyzed</th>
                </tr>
              </thead>
              <tbody>
                {result.related.map((rel) => (
                  <tr key={rel.id}>
                    <td className="num">
                      <strong>{rel.score}</strong>
                    </td>
                    <td className="break">
                      <Link to={`/cases/${rel.id}`}>{rel.subject || '(no subject)'}</Link>
                      <div className="row top-gap-sm">
                        <VerdictBadge verdict={rel.verdict} />
                        <span className="muted mono">{rel.from_address}</span>
                      </div>
                    </td>
                    <td>
                      <div className="stack tight">
                        {rel.shared.map((s) => (
                          <span key={s.kind + s.value} className="small">
                            <span className="muted">{INDICATOR_LABEL[s.kind] ?? s.kind}:</span> <span className="mono break">{s.value}</span>
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="nowrap">{formatDateTime(rel.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      {result.related.length > 0 && (
        <Card title="Campaign graph">
          {graph.error ? (
            <ErrorState error={graph.error} onRetry={graph.reload} />
          ) : graph.data ? (
            <CampaignGraphView graph={graph.data} focusId={result.id} />
          ) : (
            <Skeleton height={440} />
          )}
        </Card>
      )}
    </div>
  )
}

/* ---------- Custody ------------------------------------------------------- */

function CustodyTab({ id }: { id: string }) {
  const { data, error, reload } = useResource(`custody:${id}`, (signal) => api.custody(id, signal))
  return (
    <Card title="Chain of custody" hint="Every action recorded against this evidence, in order">
      {error ? (
        <ErrorState error={error} onRetry={reload} />
      ) : !data ? (
        <Skeleton height={120} />
      ) : data.length === 0 ? (
        <EmptyState compact title="No custody events recorded" />
      ) : (
        <ol className="timeline">
          {data.map((event, i) => (
            <li key={i}>
              <span className="timeline-dot" aria-hidden="true" />
              <div>
                <div className="row">
                  <strong>{event.event}</strong>
                  <span className="muted small">{formatDateTime(event.at)}</span>
                </div>
                <p className="secondary small break">{event.detail}</p>
              </div>
            </li>
          ))}
        </ol>
      )}
    </Card>
  )
}

/* ---------- Page ---------------------------------------------------------- */

function CaseHeader({ result }: { result: AnalysisResult }) {
  const navigate = useNavigate()
  const [deleting, setDeleting] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function remove() {
    setDeleting(true)
    try {
      await api.remove(result.id)
      navigate('/cases', { replace: true })
    } catch (err) {
      setError((err as Error).message)
      setDeleting(false)
      setConfirming(false)
    }
  }

  return (
    <header className="page-header">
      <div className="min-0">
        <Link to="/cases" className="back-link">
          <Icon name="back" size={14} /> Cases
        </Link>
        <h1 className="break">{result.summary.subject || '(no subject)'}</h1>
        <p className="subtitle mono break">{address(result.summary.from)}</p>
        <p className="muted small">
          Analyzed {formatDateTime(result.created_at)} · case <span className="mono">{result.id}</span>
        </p>
        {error && <Alert tone="critical">{error}</Alert>}
      </div>
      <div className="row">
        <a className="btn" href={api.reportUrl(result.id)} target="_blank" rel="noreferrer">
          <Icon name="download" size={15} /> PDF report
        </a>
        <a className="btn" href={api.evidenceUrl(result.id)} download>
          <Icon name="file" size={15} /> Original .eml
        </a>
        {confirming ? (
          <>
            <button className="btn btn-danger" disabled={deleting} onClick={remove}>
              {deleting ? <span className="spinner" /> : <Icon name="trash" size={15} />} Confirm delete
            </button>
            <button className="btn" disabled={deleting} onClick={() => setConfirming(false)}>
              Cancel
            </button>
          </>
        ) : (
          <button className="btn btn-danger" onClick={() => setConfirming(true)}>
            <Icon name="trash" size={15} /> Delete
          </button>
        )}
      </div>
    </header>
  )
}

function Verdict({ result }: { result: AnalysisResult }) {
  const { risk, attribution } = result
  return (
    <div className="card verdict">
      <div className="verdict-score">
        <ScoreGauge score={risk.score} level={risk.level} />
        <div className="row center">
          <LevelBadge level={risk.level} />
        </div>
      </div>
      <div className="verdict-body">
        <div className="row">
          <span className="eyebrow">Verdict</span>
          <VerdictBadge verdict={risk.verdict} />
        </div>
        <div className="row">
          <span className="eyebrow">Attribution</span>
          <strong>{ATTRIBUTION_LABEL[attribution.assessment]}</strong>
          <span className="muted small">{percent(attribution.confidence)} confidence</span>
        </div>
        {attribution.rationale.length > 0 && (
          <ul className="rationale">
            {attribution.rationale.map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        )}
        {risk.coverage < 0.6 && (
          <Alert tone="warning">
            Only {percent(risk.coverage)} of risk signals were available (for example, lookups disabled or
            headers missing). Treat the score as provisional.
          </Alert>
        )}
      </div>
    </div>
  )
}

export default function CasePage() {
  const { id = '' } = useParams()
  // Remount per case so tab state resets when following a related-case link.
  return <CaseView key={id} id={id} />
}

function CaseView({ id }: { id: string }) {
  const [tab, setTab] = useState<TabKey>('overview')
  const { data: result, error, reload } = useResource(id, (signal) => api.get(id, signal))

  if (error) {
    return (
      <div className="page">
        <Link to="/cases" className="back-link">
          <Icon name="back" size={14} /> Cases
        </Link>
        <Card>
          {error instanceof ApiError && error.status === 404 ? (
            <EmptyState icon="search" title="Case not found">
              It may have been deleted. <Link to="/cases">Back to all cases</Link>
            </EmptyState>
          ) : (
            <ErrorState error={error} onRetry={reload} />
          )}
        </Card>
      </div>
    )
  }

  if (!result) {
    return (
      <div className="page">
        <Skeleton height={28} width={360} />
        <Skeleton height={180} />
        <Skeleton height={320} />
      </div>
    )
  }

  const tabs: { key: TabKey; label: string; count?: number }[] = [
    { key: 'overview', label: 'Overview', count: result.findings.length },
    { key: 'auth', label: 'Authentication' },
    { key: 'route', label: 'Route & origin', count: result.hops.length },
    { key: 'domain', label: 'Domain' },
    { key: 'content', label: 'Content' },
    { key: 'artifacts', label: 'Links & files', count: result.links.length + result.attachments.length },
    { key: 'related', label: 'Related', count: result.related.length },
    { key: 'custody', label: 'Chain of custody' },
  ]

  return (
    <div className="page">
      <CaseHeader result={result} />
      <Verdict result={result} />
      {result.errors.length > 0 && (
        <Alert tone="warning">
          <strong>Some checks could not complete.</strong>
          <ul className="plain">
            {result.errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </Alert>
      )}
      <Tabs items={tabs} active={tab} onChange={setTab} />
      {tab === 'overview' && <Overview result={result} />}
      {tab === 'auth' && <AuthenticationTab result={result} />}
      {tab === 'route' && <RouteTab result={result} />}
      {tab === 'domain' && <DomainTab result={result} />}
      {tab === 'content' && <ContentTab result={result} />}
      {tab === 'artifacts' && <ArtifactsTab result={result} />}
      {tab === 'related' && <RelatedTab result={result} />}
      {tab === 'custody' && <CustodyTab id={result.id} />}
    </div>
  )
}
