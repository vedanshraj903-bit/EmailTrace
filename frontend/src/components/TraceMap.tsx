import 'leaflet/dist/leaflet.css'
import L from 'leaflet'
import { useEffect, useMemo, useState } from 'react'
import { Circle, CircleMarker, MapContainer, Polyline, Popup, TileLayer, Tooltip, useMap } from 'react-leaflet'
import type { GeoPoint, Hop, Origin } from '../api/types'
import { locationLabel } from '../lib/format'
import { useTheme } from '../lib/theme'

interface MapPoint {
  key: string
  geo: GeoPoint
  hops: number[] // 1-based hop numbers that share this location/IP
  isOrigin: boolean
}

const GROW_MS = 1400


/** Grows the accuracy circle from zero to its true radius (the "radius up" effect). */
function useGrowingRadius(target: number, key: string): number {
  const [radius, setRadius] = useState(0)
  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setRadius(target)
      return
    }
    let frame = 0
    const start = performance.now()
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / GROW_MS)
      setRadius(target * (1 - Math.pow(1 - t, 3))) // ease-out cubic
      if (t < 1) frame = requestAnimationFrame(tick)
    }
    setRadius(0)
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [target, key])
  return radius
}

function FitBounds({ points, radiusMeters }: { points: MapPoint[]; radiusMeters: number }) {
  const map = useMap()
  useEffect(() => {
    if (points.length === 0) return
    const bounds = L.latLngBounds(points.map((p) => [p.geo.lat, p.geo.lon] as [number, number]))
    const origin = points.find((p) => p.isOrigin)
    if (origin) bounds.extend(L.latLng(origin.geo.lat, origin.geo.lon).toBounds(radiusMeters * 2))
    map.fitBounds(bounds, { padding: [36, 36], maxZoom: 11 })
  }, [map, points, radiusMeters])
  return null
}


export function TraceMap({ hops, origin }: { hops: Hop[]; origin: Origin }) {
  const dark = useTheme().resolved === 'dark'

  const points = useMemo<MapPoint[]>(() => {
    const byIp = new Map<string, MapPoint>()
    for (const hop of hops) {
      if (!hop.geo) continue
      const existing = byIp.get(hop.geo.ip)
      if (existing) existing.hops.push(hop.index + 1)
      else byIp.set(hop.geo.ip, { key: hop.geo.ip, geo: hop.geo, hops: [hop.index + 1], isOrigin: false })
    }
    if (origin.geo) {
      const existing = byIp.get(origin.geo.ip)
      if (existing) existing.isOrigin = true
      else byIp.set(origin.geo.ip, { key: origin.geo.ip, geo: origin.geo, hops: [], isOrigin: true })
    }
    return [...byIp.values()]
  }, [hops, origin.geo])

  // Relay path in hop order (oldest first), skipping consecutive duplicates.
  const path = useMemo(() => {
    const coords: [number, number][] = []
    const ordered = origin.geo && origin.source === 'x-originating-ip' ? [origin.geo] : []
    for (const geo of [...ordered, ...hops.map((h) => h.geo)]) {
      if (!geo) continue
      const last = coords[coords.length - 1]
      if (!last || last[0] !== geo.lat || last[1] !== geo.lon) coords.push([geo.lat, geo.lon])
    }
    return coords
  }, [hops, origin])

  const targetRadius = (origin.geo?.accuracy_radius_km ?? 0) * 1000
  const radius = useGrowingRadius(targetRadius, origin.geo?.ip ?? '')

  if (points.length === 0) return null

  // OpenStreetMap's standard tiles need no API key; dark mode darkens them with a CSS filter.
  const tiles = 'https://tile.openstreetmap.org/{z}/{x}/{y}.png'

  const originColor = origin.webmail_masked ? '#898781' : '#d03b3b'

  return (
    <div className="trace-map">
      <MapContainer center={[20, 78]} zoom={3} scrollWheelZoom={false} worldCopyJump style={{ height: '100%' }}>
        <TileLayer
          url={tiles}
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          className={dark ? 'tiles-dark' : 'tiles-light'}
          maxZoom={19}
        />
        <FitBounds points={points} radiusMeters={targetRadius} />
        {path.length > 1 && (
          <Polyline positions={path} pathOptions={{ color: '#2a78d6', weight: 2, dashArray: '6 6', opacity: 0.9 }} />
        )}
        {origin.geo && (
          <Circle
            center={[origin.geo.lat, origin.geo.lon]}
            radius={radius}
            pathOptions={{ color: originColor, weight: 1.5, fillColor: originColor, fillOpacity: 0.12 }}
          />
        )}
        {points.map((point) => (
          <CircleMarker
            key={point.key}
            center={[point.geo.lat, point.geo.lon]}
            radius={point.isOrigin ? 8 : 6}
            pathOptions={{
              color: dark ? '#1a1a19' : '#fcfcfb',
              weight: 2,
              fillColor: point.isOrigin ? originColor : '#2a78d6',
              fillOpacity: 1,
            }}
          >
            <Tooltip direction="top" offset={[0, -8]}>
              {point.isOrigin ? 'Origin' : `Hop ${point.hops.join(', ')}`} · {point.geo.ip}
            </Tooltip>
            <Popup>
              <div className="map-popup">
                <strong>{point.isOrigin ? 'Estimated origin' : `Relay hop ${point.hops.join(', ')}`}</strong>
                <span className="mono">{point.geo.ip}</span>
                <span>{locationLabel(point.geo)}</span>
                <span>
                  {point.geo.asn} {point.geo.org}
                </span>
                <span className="muted">
                  {point.geo.lat.toFixed(4)}, {point.geo.lon.toFixed(4)} · ±{point.geo.accuracy_radius_km} km (
                  {point.geo.radius_source === 'maxmind' ? 'MaxMind accuracy radius' : 'default city-level radius'})
                </span>
              </div>
            </Popup>
          </CircleMarker>
        ))}
      </MapContainer>
      <div className="map-legend" aria-hidden="true">
        <span>
          <i className="dot" style={{ background: originColor }} /> {origin.webmail_masked ? 'Provider server' : 'Origin'}
        </span>
        <span>
          <i className="dot" style={{ background: '#2a78d6' }} /> Relay hop
        </span>
        <span>
          <i className="ring" style={{ borderColor: originColor }} /> Accuracy radius
        </span>
        {path.length > 1 && (
          <span>
            <i className="dash" /> Relay path
          </span>
        )}
      </div>
    </div>
  )
}
