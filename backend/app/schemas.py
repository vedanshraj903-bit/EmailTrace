"""API response models. Mirrored by frontend/src/api/types.ts."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["info", "low", "medium", "high", "critical"]
Category = Literal["auth", "domain", "infra", "header", "link", "attachment", "content", "behaviour", "geo"]
AuthResult = Literal["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy", "unknown"]


class Finding(BaseModel):
    code: str
    severity: Severity
    category: Category
    title: str
    detail: str = ""


class AddressOut(BaseModel):
    display_name: str
    address: str
    domain: str


class Summary(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    subject: str
    from_: AddressOut = Field(alias="from")
    reply_to: list[AddressOut]
    return_path: str
    to: list[AddressOut]
    message_id: str
    date: datetime | None


# --- Authentication -------------------------------------------------------


class SpfCheck(BaseModel):
    result: AuthResult
    domain: str
    ip: str | None
    ip_source: str
    explanation: str = ""
    record: str | None = None


class DkimCheck(BaseModel):
    domain: str
    selector: str
    result: AuthResult
    detail: str = ""


class DmarcCheck(BaseModel):
    result: AuthResult
    from_domain: str
    record: str | None
    record_domain: str | None
    policy: str | None
    subdomain_policy: str | None
    adkim: Literal["r", "s"] = "r"
    aspf: Literal["r", "s"] = "r"
    spf_aligned: bool
    dkim_aligned: bool
    disposition: str


class RecordedAuth(BaseModel):
    authserv_id: str | None
    spf: str | None
    dkim: str | None
    dmarc: str | None
    raw: str | None


class Authentication(BaseModel):
    spf: SpfCheck
    dkim: list[DkimCheck]
    dmarc: DmarcCheck
    recorded: RecordedAuth
    mismatches: list[str]


# --- Domain intelligence --------------------------------------------------


class DnsRecords(BaseModel):
    mx: list[str]
    a: list[str]
    spf: str | None
    dmarc: str | None
    error: str | None = None


class Whois(BaseModel):
    available: bool
    registered: bool | None = None
    registrar: str | None = None
    created: datetime | None = None
    expires: datetime | None = None
    age_days: int | None = None
    privacy_protected: bool | None = None
    country: str | None = None
    name_servers: list[str] = []
    error: str | None = None


class Lookalike(BaseModel):
    matched_brand: str | None
    brand_domain: str | None
    distance: int | None
    technique: str | None
    punycode: bool
    unicode_form: str | None


class DomainIntel(BaseModel):
    domain: str
    registered_domain: str
    free_mail_provider: bool
    disposable: bool
    disposable_list_loaded: bool
    dns: DnsRecords
    whois: Whois
    lookalike: Lookalike


# --- Infrastructure / geo -------------------------------------------------


class GeoPoint(BaseModel):
    ip: str
    lat: float
    lon: float
    accuracy_radius_km: int
    radius_source: Literal["maxmind", "default"]
    coord_source: Literal["ipinfo", "maxmind"]
    # Administrative hierarchy, broadest first. district/subdistrict come from reverse geocoding the
    # coordinates (OpenStreetMap), so they are only as precise as the IP location itself.
    country: str | None = None
    country_code: str | None = None
    region: str | None = None  # state / province
    district: str | None = None
    subdistrict: str | None = None  # tehsil / taluk / county
    city: str | None = None
    postal: str | None = None
    org: str | None = None
    asn: str | None = None
    timezone: str | None = None


class DnsblListing(BaseModel):
    zone: str
    listed: bool | None  # None = the list refused or failed the query
    code: str | None = None


class SmtpProbe(BaseModel):
    host: str
    banner: str | None
    starttls: bool | None
    error: str | None


class Origin(BaseModel):
    ip: str | None
    source: Literal["x-originating-ip", "received-chain", "none"]
    boundary_ip: str | None
    webmail_masked: bool
    note: str | None
    ptr: str | None
    fcrdns: bool | None
    generic_ptr: bool
    asn: str | None
    org: str | None
    hosting_class: Literal["mail_provider", "cloud_hosting", "isp", "unknown"]
    tor_exit: bool | None
    dnsbl: list[DnsblListing]
    smtp_probe: SmtpProbe | None
    geo: GeoPoint | None


class Hop(BaseModel):
    index: int
    from_helo: str | None
    from_rdns: str | None
    from_ip: str | None
    by_host: str | None
    protocol: str | None
    timestamp: datetime | None
    delay_s: float | None
    public: bool
    geo: GeoPoint | None
    anomalies: list[str]
    raw: str


# --- Content / links / behaviour -----------------------------------------


class ClassifierResult(BaseModel):
    available: bool
    label: str | None = None
    malicious_probability: float | None = None
    probabilities: dict[str, float] = {}
    model: dict[str, str | float] = {}
    reason: str | None = None


class ContentAnalysis(BaseModel):
    classifier: ClassifierResult
    cues: dict[str, list[str]]
    word_count: int


class LinkOut(BaseModel):
    href: str
    text: str
    host: str
    flags: list[str]


class AttachmentOut(BaseModel):
    filename: str
    content_type: str
    size: int
    sha256: str
    flags: list[str]


class VelocityWindow(BaseModel):
    key: str
    value: str
    count_5m: int
    count_1h: int
    zscore: float | None
    history_hours: int
    burst: bool


class Behaviour(BaseModel):
    reference_time: datetime
    ip: VelocityWindow | None
    domain: VelocityWindow | None


# --- Risk / attribution ---------------------------------------------------


class RiskComponent(BaseModel):
    key: str
    label: str
    weight: float
    severity: float
    points: float
    available: bool
    reasons: list[str]


class Risk(BaseModel):
    score: int
    level: Literal["low", "medium", "high", "critical"]
    verdict: Literal["legitimate", "suspicious", "phishing", "impersonation", "fraud"]
    coverage: float
    components: list[RiskComponent]


class Attribution(BaseModel):
    assessment: Literal[
        "legitimate_sender",
        "compromised_account",
        "spoofed_domain",
        "anonymized_infrastructure",
        "attacker_controlled_infrastructure",
        "undetermined",
    ]
    confidence: float
    rationale: list[str]


class SharedIndicator(BaseModel):
    kind: str
    value: str


class RelatedCase(BaseModel):
    id: str
    subject: str
    from_address: str
    created_at: datetime
    score: int
    verdict: str
    shared: list[SharedIndicator]


class AnalysisResult(BaseModel):
    id: str
    created_at: datetime
    sha256: str
    size: int
    filename: str | None
    summary: Summary
    risk: Risk
    attribution: Attribution
    findings: list[Finding]
    authentication: Authentication
    domain: DomainIntel
    origin: Origin
    hops: list[Hop]
    content: ContentAnalysis
    links: list[LinkOut]
    attachments: list[AttachmentOut]
    behaviour: Behaviour
    related: list[RelatedCase]
    errors: list[str]


class AnalysisListItem(BaseModel):
    id: str
    created_at: datetime
    subject: str
    from_address: str
    from_domain: str
    origin_ip: str | None
    country: str | None
    score: int
    level: str
    verdict: str


class AnalysisPage(BaseModel):
    items: list[AnalysisListItem]
    total: int


class GraphNode(BaseModel):
    id: str
    kind: str
    label: str
    score: int | None = None


class GraphEdge(BaseModel):
    source: str
    target: str


class CampaignGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class CustodyEvent(BaseModel):
    event: str
    at: datetime
    detail: str


class Stats(BaseModel):
    total: int
    by_level: dict[str, int]
    by_verdict: dict[str, int]
    top_countries: list[tuple[str, int]]
    top_origin_asns: list[tuple[str, int]]
    daily: list[tuple[str, int, int, int]]  # date, total, high/critical, medium


class MailboxEvent(BaseModel):
    analysis_id: str
    received_at: datetime
    subject: str
    from_address: str
    score: int
    level: str
    verdict: str


class MailboxStatus(BaseModel):
    enabled: bool
    state: Literal["disabled", "connecting", "connected", "error"]
    account: str | None  # masked; the full address and password never leave the server
    folder: str
    poll_seconds: int
    last_check: datetime | None
    error: str | None
    analyzed: int
    recent: list[MailboxEvent]


class Health(BaseModel):
    status: str
    classifier_loaded: bool
    maxmind_city: bool
    maxmind_asn: bool
    ipinfo_token: bool
    disposable_domains: int
    tor_exit_nodes: int
    whois_enabled: bool
    smtp_probe_enabled: bool
