import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api/client'
import type { AnalysisListItem } from '../api/types'
import { VERDICT_LABEL } from '../lib/format'
import { useTheme } from '../lib/theme'
import { Icon, type IconName } from './Icon'

interface Command {
  id: string
  group: string
  title: string
  meta?: string
  icon: IconName
  run: () => void
}

/**
 * ⌘K / Ctrl+K: jump to a page, run an action, or open a case by subject, sender, domain or IP.
 * Mounted only while open, so every opening starts with a clean query.
 */
export function CommandPalette({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate()
  const { resolved, setMode } = useTheme()
  const [query, setQuery] = useState('')
  const [cases, setCases] = useState<AnalysisListItem[]>([])
  const [active, setActive] = useState(0)
  const list = useRef<HTMLUListElement>(null)

  // Case search, debounced so typing does not fire a request per keystroke.
  useEffect(() => {
    const controller = new AbortController()
    const timer = window.setTimeout(() => {
      api
        .list({ q: query.trim(), limit: 6 }, controller.signal)
        .then((page) => setCases(page.items))
        .catch(() => undefined)
    }, 140)
    return () => {
      window.clearTimeout(timer)
      controller.abort()
    }
  }, [query])

  const commands = useMemo<Command[]>(() => {
    const go = (path: string) => () => navigate(path)
    const base: Command[] = [
      { id: 'analyze', group: 'Actions', title: 'Analyze an email', meta: 'upload .eml', icon: 'upload', run: go('/analyze') },
      {
        id: 'theme',
        group: 'Actions',
        title: `Switch to ${resolved === 'dark' ? 'light' : 'dark'} mode`,
        icon: resolved === 'dark' ? 'sun' : 'moon',
        run: () => setMode(resolved === 'dark' ? 'light' : 'dark'),
      },
      { id: 'dash', group: 'Go to', title: 'Dashboard', icon: 'dashboard', run: go('/') },
      { id: 'cases', group: 'Go to', title: 'All cases', icon: 'list', run: go('/cases') },
      { id: 'graph', group: 'Go to', title: 'Campaign graph', icon: 'graph', run: go('/graph') },
      { id: 'critical', group: 'Go to', title: 'Critical-risk cases', icon: 'octagon', run: go('/cases?level=critical') },
    ]
    const q = query.trim().toLowerCase()
    const matched = q ? base.filter((c) => c.title.toLowerCase().includes(q)) : base
    const caseCommands: Command[] = cases.map((item) => ({
      id: `case:${item.id}`,
      group: q ? 'Matching cases' : 'Recent cases',
      title: item.subject || '(no subject)',
      meta: `${item.score} · ${VERDICT_LABEL[item.verdict]}`,
      icon: 'mail',
      run: go(`/cases/${item.id}`),
    }))
    return [...matched, ...caseCommands]
  }, [cases, navigate, query, resolved, setMode])

  useEffect(() => {
    list.current?.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' })
  }, [active])

  const select = (command: Command | undefined) => {
    if (!command) return
    onClose()
    command.run()
  }

  const onKeyDown = (event: KeyboardEvent) => {
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setActive((i) => Math.min(i + 1, commands.length - 1))
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      setActive((i) => Math.max(i - 1, 0))
    } else if (event.key === 'Enter') {
      event.preventDefault()
      select(commands[active])
    } else if (event.key === 'Escape') {
      onClose()
    }
  }

  let lastGroup = ''
  return (
    <div className="overlay" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <div className="palette" role="dialog" aria-modal="true" aria-label="Command palette" onKeyDown={onKeyDown}>
        <label className="palette-input">
          <Icon name="search" size={18} />
          <span className="sr-only">Search commands and cases</span>
          <input
            autoFocus
            value={query}
            onChange={(event) => {
              setQuery(event.target.value)
              setActive(0)
            }}
            placeholder="Search cases, or jump to…"
            role="combobox"
            aria-expanded="true"
            aria-controls="palette-list"
            aria-activedescendant={commands[active] ? `cmd-${commands[active].id}` : undefined}
          />
          <kbd>esc</kbd>
        </label>
        <ul className="palette-list" id="palette-list" role="listbox" ref={list}>
          {commands.length === 0 && <li className="palette-empty">Nothing matches “{query}”.</li>}
          {commands.map((command, index) => {
            const header = command.group !== lastGroup ? command.group : null
            lastGroup = command.group
            return (
              <li key={command.id} role="presentation">
                {header && <div className="palette-group">{header}</div>}
                <div
                  id={`cmd-${command.id}`}
                  role="option"
                  aria-selected={index === active}
                  className="palette-item"
                  onMouseMove={() => setActive(index)}
                  onClick={() => select(command)}
                >
                  <Icon name={command.icon} size={16} />
                  <span className="palette-title">{command.title}</span>
                  {command.meta && <span className="palette-meta">{command.meta}</span>}
                </div>
              </li>
            )
          })}
        </ul>
        <div className="palette-footer">
          <span>
            <kbd>↑</kbd>
            <kbd>↓</kbd> move
          </span>
          <span>
            <kbd>
              <Icon name="enter" size={11} />
            </kbd>{' '}
            open
          </span>
          <span>
            <kbd>esc</kbd> close
          </span>
        </div>
      </div>
    </div>
  )
}
