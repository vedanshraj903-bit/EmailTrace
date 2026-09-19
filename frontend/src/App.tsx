import { Suspense, lazy, useEffect, useRef, useState } from 'react'
import { Link, NavLink, Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import { api } from './api/client'
import type { Health } from './api/types'
import { CommandPalette } from './components/CommandPalette'
import { Icon, type IconName } from './components/Icon'
import { Skeleton } from './components/ui'
import { useResource } from './lib/useResource'

// Each page is its own chunk; hovering a nav link starts the download before the click.
const loaders = {
  dashboard: () => import('./pages/DashboardPage'),
  analyze: () => import('./pages/AnalyzePage'),
  cases: () => import('./pages/CasesPage'),
  case: () => import('./pages/CasePage'),
  graph: () => import('./pages/GraphPage'),
}
const DashboardPage = lazy(loaders.dashboard)
const AnalyzePage = lazy(loaders.analyze)
const CasesPage = lazy(loaders.cases)
const CasePage = lazy(loaders.case)
const GraphPage = lazy(loaders.graph)

const NAV: { to: string; label: string; icon: IconName; load: () => Promise<unknown>; end?: boolean }[] = [
  { to: '/', label: 'Dashboard', icon: 'dashboard', load: loaders.dashboard, end: true },
  { to: '/analyze', label: 'Analyze email', icon: 'upload', load: loaders.analyze },
  { to: '/cases', label: 'Cases', icon: 'list', load: () => Promise.all([loaders.cases(), loaders.case()]) },
  { to: '/graph', label: 'Campaigns', icon: 'graph', load: loaders.graph },
]

const IS_MAC = typeof navigator !== 'undefined' && /Mac|iPhone|iPad/.test(navigator.platform)

function SystemStatus() {
  const { data, error } = useResource<Health>('health', (signal) => api.health(signal))
  // Geolocation and ASN can come from either provider; name the active one.
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
        <span className="status-dot down">API unreachable</span>
      ) : (
        <ul>
          {rows.map(([label, ok]) => (
            <li key={label}>
              <span>{label}</span>
              {ok === undefined ? (
                <Skeleton width={42} height={12} />
              ) : (
                <span className={`status-dot ${ok ? 'on' : ''}`}>{typeof ok === 'string' ? ok : ok ? 'On' : 'Off'}</span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

/** Drop an .eml file anywhere in the app to analyze it. */
function useGlobalDrop(onFile: (file: File) => void) {
  const [dragging, setDragging] = useState(false)
  const depth = useRef(0)

  useEffect(() => {
    const hasFiles = (event: DragEvent) => Array.from(event.dataTransfer?.types ?? []).includes('Files')
    const enter = (event: DragEvent) => {
      if (!hasFiles(event)) return
      depth.current += 1
      setDragging(true)
    }
    const leave = (event: DragEvent) => {
      if (!hasFiles(event)) return
      depth.current = Math.max(0, depth.current - 1)
      if (depth.current === 0) setDragging(false)
    }
    const over = (event: DragEvent) => {
      if (hasFiles(event)) event.preventDefault()
    }
    const drop = (event: DragEvent) => {
      depth.current = 0
      setDragging(false)
      if (event.defaultPrevented || !hasFiles(event)) return // a page-level dropzone already took it
      event.preventDefault()
      const file = event.dataTransfer?.files[0]
      if (file) onFile(file)
    }
    window.addEventListener('dragenter', enter)
    window.addEventListener('dragleave', leave)
    window.addEventListener('dragover', over)
    window.addEventListener('drop', drop)
    return () => {
      window.removeEventListener('dragenter', enter)
      window.removeEventListener('dragleave', leave)
      window.removeEventListener('dragover', over)
      window.removeEventListener('drop', drop)
    }
  }, [onFile])

  return dragging
}

function PageFallback() {
  return (
    <div className="page">
      <Skeleton height={34} width={280} />
      <Skeleton height={200} />
    </div>
  )
}

export default function App() {
  const navigate = useNavigate()
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [dropHandler] = useState(() => (file: File) => navigate('/analyze', { state: { file } }))
  const dragging = useGlobalDrop(dropHandler)

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        setPaletteOpen((open) => !open)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="shell">
      <aside className="sidebar">
        <Link to="/" className="brand">
          <span className="brand-mark">
            <Icon name="search" size={18} strokeWidth={2.4} />
          </span>
          <span>
            <span className="brand-name">EmailTrace</span>
            <br />
            <span className="brand-tag">Forensic desk</span>
          </span>
        </Link>

        <button className="search-trigger" onClick={() => setPaletteOpen(true)}>
          <Icon name="search" size={15} />
          <span className="label">Search cases…</span>
          <kbd>{IS_MAC ? '⌘K' : 'Ctrl K'}</kbd>
        </button>

        <nav className="nav" aria-label="Main">
          <div className="nav-label">Case file</div>
          {NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onMouseEnter={() => void item.load()}
              onFocus={() => void item.load()}
            >
              <Icon name={item.icon} size={16} />
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="sidebar-footer">
          <SystemStatus />
        </div>
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

      {paletteOpen && <CommandPalette onClose={() => setPaletteOpen(false)} />}

      {dragging && (
        <div className="drop-overlay" aria-hidden="true">
          <div className="drop-card">
            <Icon name="upload" size={32} />
            <strong>Drop to open a new case</strong>
            <span>The message is hashed and analyzed straight away.</span>
          </div>
        </div>
      )}
    </div>
  )
}
