import type { AttributionAssessment, AuthResult, FindingCategory, GeoPoint, HostingClass, Verdict } from '../api/types'

const dateTime = new Intl.DateTimeFormat(undefined, {
  year: 'numeric',
  month: 'short',
  day: '2-digit',
  hour: '2-digit',
  minute: '2-digit',
  second: '2-digit',
})
const shortDate = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric' })
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' })

export function formatDateTime(value: string | null | undefined): string {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : dateTime.format(date)
}

export function formatShortDate(value: string): string {
  const date = new Date(`${value}T00:00:00`)
  return Number.isNaN(date.getTime()) ? value : shortDate.format(date)
}

export function formatRelative(value: string): string {
  const seconds = (new Date(value).getTime() - Date.now()) / 1000
  const units: [Intl.RelativeTimeFormatUnit, number][] = [
    ['day', 86400],
    ['hour', 3600],
    ['minute', 60],
  ]
  for (const [unit, size] of units) {
    if (Math.abs(seconds) >= size) return relative.format(Math.round(seconds / size), unit)
  }
  return 'just now'
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export function formatDuration(seconds: number): string {
  const abs = Math.abs(seconds)
  const sign = seconds < 0 ? '−' : '+'
  if (abs < 60) return `${sign}${abs.toFixed(0)} s`
  if (abs < 3600) return `${sign}${(abs / 60).toFixed(1)} min`
  return `${sign}${(abs / 3600).toFixed(1)} h`
}

export function percent(value: number, digits = 0): string {
  return `${(value * 100).toFixed(digits)}%`
}

export const VERDICT_LABEL: Record<Verdict, string> = {
  legitimate: 'Legitimate',
  suspicious: 'Suspicious',
  phishing: 'Phishing',
  impersonation: 'Impersonation',
  fraud: 'Fraud / BEC',
}

export const ATTRIBUTION_LABEL: Record<AttributionAssessment, string> = {
  legitimate_sender: 'Legitimate sender',
  compromised_account: 'Likely compromised account',
  spoofed_domain: 'Spoofed sender domain',
  anonymized_infrastructure: 'Anonymised infrastructure',
  attacker_controlled_infrastructure: 'Attacker-controlled infrastructure',
  undetermined: 'Undetermined',
}

export const CATEGORY_LABEL: Record<FindingCategory, string> = {
  auth: 'Authentication',
  domain: 'Domain',
  infra: 'Infrastructure',
  header: 'Headers',
  link: 'Links',
  attachment: 'Attachments',
  content: 'Content',
  behaviour: 'Behaviour',
  geo: 'Geolocation',
}

export const HOSTING_LABEL: Record<HostingClass, string> = {
  mail_provider: 'Mail provider',
  cloud_hosting: 'Cloud / VPS hosting',
  isp: 'ISP / enterprise network',
  unknown: 'Unknown',
}

export const INDICATOR_LABEL: Record<string, string> = {
  origin_ip: 'Origin IP',
  sender: 'Sender',
  from_domain: 'Sender domain',
  reply_to: 'Reply-To',
  dkim_domain: 'DKIM signer',
  link_domain: 'Link domain',
  attachment: 'Attachment',
}

export type Tone = 'good' | 'neutral' | 'warning' | 'serious' | 'critical'

export function authTone(result: AuthResult | string | null | undefined): Tone {
  switch (result) {
    case 'pass':
      return 'good'
    case 'fail':
    case 'permerror':
      return 'critical'
    case 'softfail':
      return 'serious'
    case 'none':
    case 'neutral':
      return 'warning'
    default:
      return 'neutral'
  }
}

export function scoreTone(score: number): Tone {
  if (score >= 75) return 'critical'
  if (score >= 50) return 'serious'
  if (score >= 25) return 'warning'
  return 'good'
}

const regionNames = new Intl.DisplayNames(undefined, { type: 'region' })

/** Full country name, falling back to the ISO code (IPinfo only returns the code). */
export function countryName(geo: Pick<GeoPoint, 'country' | 'country_code'>): string | null {
  if (geo.country && geo.country.length > 2) return geo.country
  const code = geo.country_code ?? geo.country
  if (!code) return null
  try {
    return regionNames.of(code.toUpperCase()) ?? code
  } catch {
    return code
  }
}

/** Narrowest to broadest, skipping repeats (a city and its district often share a name). */
export function locationLabel(geo: GeoPoint, short = false): string {
  const parts = short
    ? [geo.city, geo.district, geo.country_code]
    : [geo.city, geo.district, geo.region, countryName(geo)]
  const unique = parts.filter((part, i): part is string => Boolean(part) && !parts.slice(0, i).includes(part))
  return unique.join(', ') || 'Unknown location'
}

