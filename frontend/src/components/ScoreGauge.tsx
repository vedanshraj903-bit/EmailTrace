import type { RiskLevel } from '../api/types'
import { scoreTone } from '../lib/format'

const RADIUS = 52
const ARC = Math.PI * RADIUS // half circle

/** Semicircular 0–100 gauge. Colour encodes the band; the number and level label carry the value. */
export function ScoreGauge({ score, level }: { score: number; level: RiskLevel }) {
  const clamped = Math.max(0, Math.min(100, score))
  const tone = scoreTone(clamped)
  return (
    <figure className={`gauge tone-${tone}`} aria-label={`Risk score ${clamped} out of 100, ${level}`}>
      <svg viewBox="0 0 128 72" width="100%" role="img">
        <path d="M 12 64 A 52 52 0 0 1 116 64" className="gauge-track" />
        <path
          d="M 12 64 A 52 52 0 0 1 116 64"
          className="gauge-value"
          strokeDasharray={ARC}
          strokeDashoffset={ARC * (1 - clamped / 100)}
        />
      </svg>
      <figcaption>
        <span className="gauge-score tabular">{clamped}</span>
        <span className="gauge-scale">/ 100</span>
      </figcaption>
    </figure>
  )
}
