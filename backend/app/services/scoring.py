"""Explainable risk scoring and origin attribution.

Score = sum(weight * severity) / sum(weight of components that could be evaluated) * 100.
Components that could not run (no model, DNS timeout) are excluded rather than counted as clean,
and `coverage` reports how much of the total weight was actually evaluated.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.schemas import (
    Attribution,
    Authentication,
    ClassifierResult,
    DomainIntel,
    Finding,
    Origin,
    Risk,
    RiskComponent,
)

SEVERITY_VALUE = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.0}

WEIGHTS = {
    "dmarc": 25.0,
    "content": 25.0,
    "domain": 20.0,
    "spf_dkim": 15.0,
    "anomalies": 15.0,
}

# Single signals strong enough to set a minimum score on their own.
ESCALATIONS: dict[str, tuple[int, str]] = {
    "attachment_critical": (75, "executable or disguised attachment"),
    "link_lookalike": (60, "links to a brand lookalike domain"),
    "display_name_brand": (55, "brand impersonation in the display name"),
    "helo_forgery": (50, "forged relay identity"),
    "bec_language": (50, "payment-diversion request under pressure"),
}


@dataclass
class _Component:
    key: str
    label: str
    severity: float = 0.0
    available: bool = True

    def __post_init__(self) -> None:
        self.reasons: list[str] = []

    def raise_to(self, severity: float, reason: str) -> None:
        self.severity = max(self.severity, severity)
        self.reasons.append(reason)


def _dmarc_component(auth: Authentication) -> _Component:
    c = _Component("dmarc", "DMARC alignment")
    dmarc = auth.dmarc
    if dmarc.result == "temperror":
        c.available = False
        c.reasons.append("DMARC record could not be retrieved")
    elif dmarc.result == "fail":
        c.raise_to(
            1.0,
            f"DMARC failed: neither SPF nor DKIM authenticates {dmarc.from_domain} "
            f"(published policy p={dmarc.policy or 'none'})",
        )
    elif dmarc.result == "none":
        c.raise_to(
            0.4,
            f"{dmarc.from_domain or 'The sender domain'} publishes no DMARC policy, so spoofing it is not prevented",
        )
    elif dmarc.result == "permerror":
        c.raise_to(0.6, "From header has no valid domain to authenticate")
    if dmarc.result == "pass":
        c.reasons.append("DMARC passed with an aligned " + ("DKIM signature" if dmarc.dkim_aligned else "SPF result"))
    return c


def _content_component(classifier: ClassifierResult, findings: list[Finding]) -> _Component:
    c = _Component("content", "Content analysis (Naive Bayes + language cues)")
    if classifier.available and classifier.malicious_probability is not None:
        p = classifier.malicious_probability
        c.raise_to(p, f"Naive Bayes model: {p:.0%} probability of a malicious class (top label '{classifier.label}')")
    cue_findings = [f for f in findings if f.category == "content"]
    for finding in cue_findings:
        c.raise_to(SEVERITY_VALUE[finding.severity], f"{finding.title}: {finding.detail}")
    if not classifier.available and not cue_findings:
        c.reasons.append("No trained model loaded; no social-engineering wording detected")
    return c


def _domain_component(domain: DomainIntel) -> _Component:
    c = _Component("domain", "Sender domain reputation")
    if not domain.domain:
        c.raise_to(0.6, "No sender domain")
        return c
    if domain.disposable:
        c.raise_to(1.0, f"{domain.domain} is a disposable/throwaway mailbox provider")
    look = domain.lookalike
    if look.technique:
        severity = {"homoglyph substitution": 1.0, "typosquatting (edit distance)": 1.0}.get(look.technique, 0.75)
        if look.technique.startswith("same name"):
            severity = 0.5
        c.raise_to(
            severity, f"{domain.domain} imitates {look.brand_domain} ({look.matched_brand}) via {look.technique}"
        )
    if look.punycode:
        c.raise_to(0.7, f"Internationalised domain renders as {look.unicode_form}")
    if domain.whois.registered is False:
        c.raise_to(1.0, f"{domain.registered_domain} is not a registered domain; the From address is fabricated")
    age = domain.whois.age_days
    if age is not None:
        if age < 30:
            c.raise_to(1.0, f"Domain registered only {age} days ago")
        elif age < 90:
            c.raise_to(0.6, f"Domain registered {age} days ago")
        elif age < 365:
            c.raise_to(0.2, f"Domain is less than a year old ({age} days)")
    if domain.whois.privacy_protected and age is not None and age < 365:
        c.raise_to(0.3, "Young domain with hidden registrant details")
    if not domain.dns.error and not domain.dns.mx and not domain.dns.a:
        c.raise_to(0.6, f"{domain.domain} has no MX or A record and cannot receive replies")
    elif not domain.dns.error and not domain.dns.mx:
        c.raise_to(0.3, f"{domain.domain} has no MX record")
    if not c.reasons:
        c.reasons.append("No domain-level risk indicators")
    return c


def _spf_dkim_component(auth: Authentication) -> _Component:
    c = _Component("spf_dkim", "SPF and DKIM")
    spf_scores = {"fail": 1.0, "softfail": 0.6, "none": 0.4, "neutral": 0.3, "permerror": 0.5}
    if auth.spf.result in spf_scores:
        c.raise_to(
            spf_scores[auth.spf.result],
            f"SPF {auth.spf.result} for {auth.spf.domain or 'unknown domain'} from {auth.spf.ip or 'unknown IP'}",
        )
    passing = [d for d in auth.dkim if d.result == "pass"]
    failing = [d for d in auth.dkim if d.result in ("fail", "permerror")]
    if not auth.dkim:
        c.raise_to(0.4, "Message is not DKIM-signed")
    elif failing and not passing:
        c.raise_to(0.8, "DKIM signature invalid for " + ", ".join(sorted({d.domain for d in failing})))
    for mismatch in auth.mismatches:
        c.raise_to(
            0.5,
            f"Receiver verdict differs from re-evaluation ({mismatch}); keys or records may have changed "
            "since delivery, or the Authentication-Results header was altered",
        )
    if auth.spf.result == "temperror" and all(d.result == "temperror" for d in auth.dkim):
        c.available = False
    if not c.reasons:
        c.reasons.append("SPF and DKIM passed")
    return c


def _anomaly_component(findings: list[Finding], origin: Origin, burst: bool) -> _Component:
    c = _Component("anomalies", "Header, link, attachment and infrastructure anomalies")
    for finding in findings:
        if finding.category in ("header", "link", "attachment", "infra"):
            c.raise_to(SEVERITY_VALUE[finding.severity], finding.title)
    if origin.tor_exit:
        c.raise_to(1.0, f"Origin {origin.ip} is a Tor exit node")
    listed = [l.zone for l in origin.dnsbl if l.listed]
    if listed:
        c.raise_to(0.8, f"Origin IP is blacklisted on {', '.join(listed)}")
    if origin.hosting_class == "cloud_hosting" and not origin.webmail_masked:
        c.raise_to(0.4, f"Sent directly from cloud/VPS hosting ({origin.org or origin.asn})")
    if origin.ip and not origin.webmail_masked:
        if not origin.ptr:
            c.raise_to(0.3, "Origin IP has no reverse DNS")
        elif origin.generic_ptr:
            c.raise_to(0.3, f"Origin reverse DNS looks residential or dynamic ({origin.ptr})")
        elif origin.fcrdns is False:
            c.raise_to(0.2, "Origin reverse DNS is not forward-confirmed")
    if burst:
        c.raise_to(0.7, "Sending burst: unusual message velocity from this IP or sender")
    if not c.reasons:
        c.reasons.append("No structural anomalies")
    return c


def score(
    auth: Authentication,
    domain: DomainIntel,
    classifier: ClassifierResult,
    origin: Origin,
    findings: list[Finding],
    burst: bool,
) -> Risk:
    components = [
        _dmarc_component(auth),
        _content_component(classifier, findings),
        _domain_component(domain),
        _spf_dkim_component(auth),
        _anomaly_component(findings, origin, burst),
    ]
    available_weight = sum(WEIGHTS[c.key] for c in components if c.available)
    raw = sum(WEIGHTS[c.key] * c.severity for c in components if c.available)
    value = round(100 * raw / available_weight) if available_weight else 0

    codes = {f.code for f in findings}
    for code, (floor, reason) in ESCALATIONS.items():
        if code in codes and value < floor:
            value = floor
            components[-1].reasons.append(f"Score raised to {floor}: {reason}")

    level = "critical" if value >= 75 else "high" if value >= 50 else "medium" if value >= 25 else "low"
    return Risk(
        score=value,
        level=level,
        verdict=_verdict(value, codes, domain, classifier),
        coverage=round(available_weight / sum(WEIGHTS.values()), 2),
        components=[
            RiskComponent(
                key=c.key,
                label=c.label,
                weight=WEIGHTS[c.key],
                severity=round(c.severity, 3),
                points=round(WEIGHTS[c.key] * c.severity, 1) if c.available else 0.0,
                available=c.available,
                reasons=c.reasons,
            )
            for c in components
        ],
    )


def _verdict(value: int, codes: set[str], domain: DomainIntel, classifier: ClassifierResult) -> str:
    if value < 25:
        return "legitimate"
    if value < 40:
        return "suspicious"
    if "bec_language" in codes or ("reply_to_mismatch" in codes and "executive_freemail" in codes):
        return "fraud"
    if codes & {"display_name_brand", "display_name_address", "link_lookalike"} or domain.lookalike.technique:
        return "impersonation"
    if codes & {"credential_lure", "attachment_critical", "attachment_risky", "link_text_mismatch", "link_ip"}:
        return "phishing"
    if classifier.available and classifier.label and "phish" in classifier.label.lower():
        return "phishing"
    return "suspicious"


def attribute(risk: Risk, auth: Authentication, domain: DomainIntel, origin: Origin) -> Attribution:
    rationale: list[str] = []
    authenticated = auth.dmarc.result == "pass"
    age = domain.whois.age_days
    young = age is not None and age < 90
    attacker_domain = domain.disposable or bool(domain.lookalike.technique) or young

    if origin.tor_exit:
        rationale.append(f"Origin {origin.ip} is a Tor exit node, so the true sender location is hidden")
        return Attribution(assessment="anonymized_infrastructure", confidence=0.85, rationale=rationale)

    if domain.whois.registered is False:
        rationale.append(f"{domain.registered_domain} does not exist, so the From address was fabricated")
        if origin.ip:
            rationale.append(f"Actual sending infrastructure: {origin.ip} ({origin.org or 'unknown network'})")
        return Attribution(assessment="spoofed_domain", confidence=0.85, rationale=rationale)

    if auth.dmarc.result == "fail" and not attacker_domain:
        rationale.append(
            f"DMARC failed for {auth.dmarc.from_domain}: the sender does not control the domain shown in From"
        )
        if auth.dmarc.policy in ("reject", "quarantine"):
            rationale.append(
                f"The domain owner publishes p={auth.dmarc.policy}, so this message should have been blocked"
            )
        if origin.ip:
            rationale.append(f"Actual sending infrastructure: {origin.ip} ({origin.org or 'unknown network'})")
        return Attribution(
            assessment="spoofed_domain", confidence=0.8 if auth.dmarc.record else 0.6, rationale=rationale
        )

    if attacker_domain and risk.score >= 40:
        if domain.lookalike.technique:
            rationale.append(f"{domain.domain} imitates {domain.lookalike.brand_domain}")
        if young:
            rationale.append(f"Domain registered {age} days ago")
        if domain.disposable:
            rationale.append("Disposable mailbox provider")
        if authenticated:
            rationale.append("Authentication passes, which proves the attacker operates this domain's mail setup")
        if origin.hosting_class == "cloud_hosting":
            rationale.append(f"Sent from rented hosting: {origin.org or origin.asn}")
        return Attribution(assessment="attacker_controlled_infrastructure", confidence=0.75, rationale=rationale)

    if authenticated and risk.score >= 50:
        if domain.free_mail_provider:
            rationale.append(
                f"Authenticated {domain.registered_domain} mailbox: either registered by the attacker "
                "or taken over; the provider can identify the account holder"
            )
            return Attribution(assessment="attacker_controlled_infrastructure", confidence=0.55, rationale=rationale)
        rationale.append(
            f"{domain.domain} is established and the message is fully authenticated, yet its content "
            "is malicious; this pattern fits a compromised mailbox inside the sending organisation"
        )
        return Attribution(assessment="compromised_account", confidence=0.6, rationale=rationale)

    if authenticated and risk.score < 25:
        rationale.append(f"Authenticated by {auth.dmarc.from_domain} with no significant risk indicators")
        return Attribution(
            assessment="legitimate_sender", confidence=round(0.6 + 0.3 * risk.coverage, 2), rationale=rationale
        )

    rationale.append("Evidence is insufficient to attribute the origin with confidence")
    if origin.webmail_masked:
        rationale.append("The provider masks the sender's client IP")
    return Attribution(assessment="undetermined", confidence=0.3, rationale=rationale)
