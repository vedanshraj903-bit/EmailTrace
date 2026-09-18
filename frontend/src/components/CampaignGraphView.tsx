import { forceCollide, forceLink, forceManyBody, forceSimulation, forceX, forceY } from 'd3-force'
import type { SimulationLinkDatum, SimulationNodeDatum } from 'd3-force'
import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import type { CampaignGraph } from '../api/types'
import { INDICATOR_LABEL, scoreTone } from '../lib/format'
import { EmptyState } from './ui'

interface Node extends SimulationNodeDatum {
  id: string
  kind: string
  label: string
  score: number | null
  degree: number
}

type Link = SimulationLinkDatum<Node>

const CASE_R = 13
const INDICATOR_R = 6
const MIN_VIEW_W = 760
const MIN_VIEW_H = 420

function truncate(text: string, length: number): string {
  return text.length > length ? `${text.slice(0, length - 1)}…` : text
}

/** Static force layout: computed once per dataset so the picture is stable and cheap to render. */
function layout(graph: CampaignGraph) {
  const degree = new Map<string, number>()
  for (const edge of graph.edges) {
    degree.set(edge.source, (degree.get(edge.source) ?? 0) + 1)
    degree.set(edge.target, (degree.get(edge.target) ?? 0) + 1)
  }
  const nodes: Node[] = graph.nodes.map((n) => ({ ...n, degree: degree.get(n.id) ?? 0 }))
  const links: Link[] = graph.edges.map((e) => ({ source: e.source, target: e.target }))
  forceSimulation(nodes)
    .force('link', forceLink<Node, Link>(links).id((d) => d.id).distance(120).strength(0.6))
    .force('charge', forceManyBody().strength(-520))
    .force('collide', forceCollide<Node>((d) => (d.kind === 'case' ? CASE_R + 24 : INDICATOR_R + 30)))
    .force('x', forceX(0).strength(0.05))
    .force('y', forceY(0).strength(0.07))
    .stop()
    .tick(320)

  const xs = nodes.map((n) => n.x ?? 0)
  const ys = nodes.map((n) => n.y ?? 0)
  const pad = 70
  const minX = Math.min(...xs) - pad
  const minY = Math.min(...ys) - pad / 1.5
  const width = Math.max(...xs) - Math.min(...xs) + pad * 2
  const height = Math.max(...ys) - Math.min(...ys) + pad * 1.3
  // A floor on the viewBox keeps small graphs at natural scale instead of magnifying labels to fill the card.
  const w = Math.max(width, MIN_VIEW_W)
  const h = Math.max(height, MIN_VIEW_H)
  const box = { x: minX - (w - width) / 2, y: minY - (h - height) / 2, w, h }
  return { nodes, links: links as { source: Node; target: Node }[], box }
}

export function CampaignGraphView({ graph, focusId, height = 440 }: {
  graph: CampaignGraph
  focusId?: string
  height?: number
}) {
  const navigate = useNavigate()
  const [hovered, setHovered] = useState<string | null>(null)
  const { nodes, links, box } = useMemo(() => layout(graph), [graph])

  const neighbours = useMemo(() => {
    const map = new Map<string, Set<string>>()
    for (const link of links) {
      if (!map.has(link.source.id)) map.set(link.source.id, new Set())
      if (!map.has(link.target.id)) map.set(link.target.id, new Set())
      map.get(link.source.id)!.add(link.target.id)
      map.get(link.target.id)!.add(link.source.id)
    }
    return map
  }, [links])

  if (graph.nodes.length === 0) {
    return (
      <EmptyState icon="graph" title="No shared infrastructure yet">
        Cases appear here once two or more share an IP, domain, Reply-To, DKIM signer, link domain or attachment.
      </EmptyState>
    )
  }

  const active = (id: string) => !hovered || hovered === id || neighbours.get(hovered)?.has(id)
  const caseCount = nodes.filter((n) => n.kind === 'case').length

  return (
    <div className="graph">
      <svg
        viewBox={`${box.x} ${box.y} ${box.w} ${box.h}`}
        style={{ height, width: '100%' }}
        role="img"
        aria-label={`Correlation graph of ${caseCount} cases and ${nodes.length - caseCount} shared indicators`}
      >
        <g className="graph-links">
          {links.map((link, i) => (
            <line
              key={i}
              x1={link.source.x}
              y1={link.source.y}
              x2={link.target.x}
              y2={link.target.y}
              className={active(link.source.id) && active(link.target.id) ? '' : 'dim'}
            />
          ))}
        </g>
        {nodes.map((node) => {
          const isCase = node.kind === 'case'
          const dim = !active(node.id)
          const tone = isCase ? scoreTone(node.score ?? 0) : 'neutral'
          return (
            <g
              key={node.id}
              transform={`translate(${node.x},${node.y})`}
              className={`graph-node ${isCase ? 'case' : 'indicator'} tone-${tone} ${dim ? 'dim' : ''} ${
                node.id === `case:${focusId}` ? 'focus' : ''
              }`}
              onMouseEnter={() => setHovered(node.id)}
              onMouseLeave={() => setHovered(null)}
              onClick={isCase ? () => navigate(`/cases/${node.id.slice(5)}`) : undefined}
            >
              <title>
                {isCase
                  ? `${node.label} · score ${node.score}`
                  : `${INDICATOR_LABEL[node.kind] ?? node.kind}: ${node.label} · shared by ${node.degree} cases`}
              </title>
              {isCase ? (
                <>
                  <circle r={CASE_R + 8} className="hit" />
                  <circle r={CASE_R} />
                  <text className="score" dy="0.35em">
                    {node.score}
                  </text>
                </>
              ) : (
                <>
                  <circle r={INDICATOR_R + 8} className="hit" />
                  <rect x={-INDICATOR_R} y={-INDICATOR_R} width={INDICATOR_R * 2} height={INDICATOR_R * 2} transform="rotate(45)" />
                </>
              )}
              {(!isCase || hovered === node.id || node.id === `case:${focusId}`) && (
                <text className="label" y={isCase ? CASE_R + 14 : INDICATOR_R + 13}>
                  {isCase ? truncate(node.label, 34) : `${INDICATOR_LABEL[node.kind] ?? node.kind}: ${truncate(node.label, 28)}`}
                </text>
              )}
            </g>
          )
        })}
      </svg>
      <div className="graph-legend">
        <span>
          <svg width="14" height="14" aria-hidden="true">
            <circle cx="7" cy="7" r="6" className="legend-case" />
          </svg>
          Case (number = risk score)
        </span>
        <span>
          <svg width="14" height="14" aria-hidden="true">
            <rect x="3" y="3" width="8" height="8" transform="rotate(45 7 7)" className="legend-indicator" />
          </svg>
          Shared indicator
        </span>
        <span className="muted">Hover to trace links · click a case to open it</span>
      </div>
    </div>
  )
}
