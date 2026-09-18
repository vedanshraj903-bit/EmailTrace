import { Suspense, lazy } from 'react'
import { Link, NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { api } from './api/client'
import type { Health } from './api/types'
import { Icon, type IconName } from './components/Icon'
import { Badge, Skeleton } from './components/ui'
import { useResource } from './lib/useResource'

const DashboardPage = lazy(() => import('./pages/DashboardPage'))
const AnalyzePage = lazy(() => import('./pages/AnalyzePage'))
const CasesPage = lazy(() => import('./pages/CasesPage'))
const CasePage = lazy(() => import('./pages/CasePage'))
const GraphPage = lazy(() => import('./pages/GraphPage'))

const NAV: { to: string; label: string; icon: IconName; end?: boolean }[] = [
  { to: '/', label: 'Dashboard', icon: 'dashboard', end: true },
  { to: '/analyze', label: 'Analyze email', icon: 'upload' },
  { to: '/cases', label: 'Cases', icon: 'list' },
  { to: '/graph', label: 'Campaigns', icon: 'graph' },
]

function SystemStatus() {
  const { data, error } = useResource<Health>('health', (signal) => api.health(signal))
  // Geolocation and ASN can come from either provider; show which one is active.
  const geoSource = (maxmind: boolean | undefined) =>
    data ? [maxmind && 'MaxMind', data.ipinfo_token && 'IPinfo'].filter(Boolean).join(' + ') || false : undefined
  const rows: [string, boolean | string | undefined][] = [
    ['ML classifier', data?.classifier_loaded],
    ['GeoIP city', geoSource(data?.maxmind_city)],
    ['GeoIP ASN', geoSource(data?.maxmind_asn)],
    ['WHOIS lookups', data?.whois_enabled],
    ['Tor exit list', data ? data.tor_exit_nodes > 0 : undefined],
    ['Disposable list', data ? data.disposable_domains > 0 : undefined],
  ]
  return (
    <div className="system-status">
      <h3>System status</h3>
      {error ? (
        <Badge tone="critical" label="API unreachable" />
      ) : (
        <ul>
          {rows.map(([label, ok]) => (
            <li key={label}>
              <span>{label}</span>
              {ok === undefined ? (
                <Skeleton width={42} height={14} />
              ) : (
                <Badge tone={ok ? 'good' : 'neutral'} label={typeof ok === 'string' ? ok : ok ? 'On' : 'Off'} />
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

function PageFallback() {
  return (
    <div className="page">
      <Skeleton height={28} width={260} />
      <Skeleton height={180} />
    </div>
  )
}

export default function App() {
  return (
    <div className="shell">
      <aside className="sidebar">
        <Link to="/" className="brand">
          <Icon name="shield" size={24} />
          <span>
            <span className="brand-name">EmailTrace</span>
            <br />
            <span className="brand-tag">Email threat forensics</span>
          </span>
        </Link>
        <nav className="nav" aria-label="Main">
          {NAV.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end}>
              <Icon name={item.icon} size={16} />
              {item.label}
            </NavLink>
          ))}
        </nav>
        <SystemStatus />
      </aside>
      <main className="main">
        <Suspense fallback={<PageFallback />}>
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/analyze" element={<AnalyzePage />} />
            <Route path="/cases" element={<CasesPage />} />
            <Route path="/cases/:id" element={<CasePage />} />
            <Route path="/graph" element={<GraphPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Suspense>
      </main>
    </div>
  )
}
