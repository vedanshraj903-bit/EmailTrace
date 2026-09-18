import { Link, useNavigate } from 'react-router-dom'
import type { AnalysisListItem } from '../api/types'
import { formatDateTime, formatRelative } from '../lib/format'
import { LevelBadge, VerdictBadge } from './ui'

export function CaseTable({ items, compact }: { items: AnalysisListItem[]; compact?: boolean }) {
  const navigate = useNavigate()
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th className="num">Score</th>
            <th>Verdict</th>
            <th>Subject / sender</th>
            {!compact && <th>Origin</th>}
            <th>Received</th>
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.id} className="clickable" onClick={() => navigate(`/cases/${item.id}`)}>
              <td className="num">
                <strong>{item.score}</strong>
              </td>
              <td>
                <div className="stack tight">
                  <VerdictBadge verdict={item.verdict} />
                  {!compact && <LevelBadge level={item.level} />}
                </div>
              </td>
              <td className="break">
                <Link to={`/cases/${item.id}`} onClick={(event) => event.stopPropagation()}>
                  {item.subject || <span className="muted">(no subject)</span>}
                </Link>
                <div className="muted mono">{item.from_address || '—'}</div>
              </td>
              {!compact && (
                <td>
                  <span className="mono">{item.origin_ip ?? '—'}</span>
                  {item.country && <div className="muted">{item.country}</div>}
                </td>
              )}
              <td title={formatDateTime(item.created_at)} className="nowrap">
                {formatRelative(item.created_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
