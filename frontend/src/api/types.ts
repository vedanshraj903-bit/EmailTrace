// Mirrors backend/app/schemas.py. Keep the two in sync.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
export type Verdict = 'legitimate' | 'suspicious' | 'phishing' | 'impersonation' | 'fraud'
export type AuthResult =
  | 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'temperror' | 'permerror' | 'policy' | 'unknown'
export type FindingCategory =
  | 'auth' | 'domain' | 'infra' | 'header' | 'link' | 'attachment' | 'content' | 'behaviour' | 'geo'
export type AttributionAssessment =
  | 'legitimate_sender'
  | 'compromised_account'
  | 'spoofed_domain'
  | 'anonymized_infrastructure'
  | 'attacker_controlled_infrastructure'
  | 'undetermined'

export interface Finding {
  code: string
  severity: Severity
  category: FindingCategory
  title: string
  detail: string
}

export interface Address {
  display_name: string
  address: string
  domain: string
}

export interface Summary {
  subject: string
  from: Address
  reply_to: Address[]
  return_path: string
  to: Address[]
  message_id: string
  date: string | null
}

export interface SpfCheck {
  result: AuthResult
  domain: string
  ip: string | null
  ip_source: string
  explanation: string
  record: string | null
}

export interface DkimCheck {
  domain: string
  selector: string
  result: AuthResult
  detail: string
}

export interface DmarcCheck {
  result: AuthResult
  from_domain: string
  record: string | null
  record_domain: string | null
  policy: string | null
  subdomain_policy: string | null
  adkim: 'r' | 's'
  aspf: 'r' | 's'
  spf_aligned: boolean
  dkim_aligned: boolean
  disposition: string
}

export interface RecordedAuth {
  authserv_id: string | null
  spf: string | null
  dkim: string | null
  dmarc: string | null
  raw: string | null
}

export interface Authentication {
  spf: SpfCheck
  dkim: DkimCheck[]
  dmarc: DmarcCheck
  recorded: RecordedAuth
  mismatches: string[]
}

export interface DnsRecords {
  mx: string[]
  a: string[]
  spf: string | null
  dmarc: string | null
  error: string | null
}

export interface Whois {
  available: boolean
  registered: boolean | null
  registrar: string | null
  created: string | null
  expires: string | null
  age_days: number | null
  privacy_protected: boolean | null
  country: string | null
  name_servers: string[]
  error: string | null
}

export interface Lookalike {
  matched_brand: string | null
  brand_domain: string | null
  distance: number | null
  technique: string | null
  punycode: boolean
  unicode_form: string | null
}

export interface DomainIntel {
  domain: string
  registered_domain: string
  free_mail_provider: boolean
  disposable: boolean
  disposable_list_loaded: boolean
  dns: DnsRecords
  whois: Whois
  lookalike: Lookalike
}

export interface GeoPoint {
  ip: string
  lat: number
  lon: number
  accuracy_radius_km: number
  radius_source: 'maxmind' | 'default'
  coord_source: 'ipinfo' | 'maxmind'
  country: string | null
  country_code: string | null
  region: string | null
  district: string | null
  subdistrict: string | null
  city: string | null
  postal: string | null
  org: string | null
  asn: string | null
  timezone: string | null
}

export interface DnsblListing {
  zone: string
  listed: boolean | null
  code: string | null
}

export interface SmtpProbe {
  host: string
  banner: string | null
  starttls: boolean | null
  error: string | null
}

export type HostingClass = 'mail_provider' | 'cloud_hosting' | 'isp' | 'unknown'

export interface Origin {
  ip: string | null
  source: 'x-originating-ip' | 'received-chain' | 'none'
  boundary_ip: string | null
  webmail_masked: boolean
  note: string | null
  ptr: string | null
  fcrdns: boolean | null
  generic_ptr: boolean
  asn: string | null
  org: string | null
  hosting_class: HostingClass
  tor_exit: boolean | null
  dnsbl: DnsblListing[]
  smtp_probe: SmtpProbe | null
  geo: GeoPoint | null
}

export interface Hop {
  index: number
  from_helo: string | null
  from_rdns: string | null
  from_ip: string | null
  by_host: string | null
  protocol: string | null
  timestamp: string | null
  delay_s: number | null
  public: boolean
  geo: GeoPoint | null
  anomalies: string[]
  raw: string
}

export interface ClassifierResult {
  available: boolean
  label: string | null
  malicious_probability: number | null
  probabilities: Record<string, number>
  model: Record<string, string | number>
  reason: string | null
}

export interface ContentAnalysis {
  classifier: ClassifierResult
  cues: Record<string, string[]>
  word_count: number
}

export interface LinkOut {
  href: string
  text: string
  host: string
  flags: string[]
}

export interface AttachmentOut {
  filename: string
  content_type: string
  size: number
  sha256: string
  flags: string[]
}

export interface VelocityWindow {
  key: string
  value: string
  count_5m: number
  count_1h: number
  zscore: number | null
  history_hours: number
  burst: boolean
}

export interface Behaviour {
  reference_time: string
  ip: VelocityWindow | null
  domain: VelocityWindow | null
}

export interface RiskComponent {
  key: string
  label: string
  weight: number
  severity: number
  points: number
  available: boolean
  reasons: string[]
}

export interface Risk {
  score: number
  level: RiskLevel
  verdict: Verdict
  coverage: number
  components: RiskComponent[]
}

export interface Attribution {
  assessment: AttributionAssessment
  confidence: number
  rationale: string[]
}

export interface SharedIndicator {
  kind: string
  value: string
}

export interface RelatedCase {
  id: string
  subject: string
  from_address: string
  created_at: string
  score: number
  verdict: Verdict
  shared: SharedIndicator[]
}

export interface AnalysisResult {
  id: string
  created_at: string
  sha256: string
  size: number
  filename: string | null
  summary: Summary
  risk: Risk
  attribution: Attribution
  findings: Finding[]
  authentication: Authentication
  domain: DomainIntel
  origin: Origin
  hops: Hop[]
  content: ContentAnalysis
  links: LinkOut[]
  attachments: AttachmentOut[]
  behaviour: Behaviour
  related: RelatedCase[]
  errors: string[]
}

export interface AnalysisListItem {
  id: string
  created_at: string
  subject: string
  from_address: string
  from_domain: string
  origin_ip: string | null
  country: string | null
  score: number
  level: RiskLevel
  verdict: Verdict
}

export interface AnalysisPage {
  items: AnalysisListItem[]
  total: number
}

export interface GraphNode {
  id: string
  kind: string
  label: string
  score: number | null
}

export interface GraphEdge {
  source: string
  target: string
}

export interface CampaignGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export interface CustodyEvent {
  event: string
  at: string
  detail: string
}

export interface Stats {
  total: number
  by_level: Partial<Record<RiskLevel, number>>
  by_verdict: Partial<Record<Verdict, number>>
  top_countries: [string, number][]
  top_origin_asns: [string, number][]
  daily: [string, number, number, number][] // date, total, high/critical, medium
}

export interface Health {
  status: string
  classifier_loaded: boolean
  maxmind_city: boolean
  maxmind_asn: boolean
  ipinfo_token: boolean
  disposable_domains: number
  tor_exit_nodes: number
  whois_enabled: boolean
  smtp_probe_enabled: boolean
}

export interface MailboxEvent {
  analysis_id: string
  received_at: string
  subject: string
  from_address: string
  score: number
  level: RiskLevel
  verdict: Verdict
}

export interface MailboxStatus {
  enabled: boolean
  state: 'disabled' | 'connecting' | 'connected' | 'paused' | 'error'
  account: string | null
  folder: string
  poll_seconds: number
  last_check: string | null
  error: string | null
  notice: string | null
  scan_pending: boolean
  analyzed: number
  recent: MailboxEvent[]
}
