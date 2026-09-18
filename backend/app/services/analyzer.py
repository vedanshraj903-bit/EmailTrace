"""End-to-end analysis pipeline for one raw message."""

from __future__ import annotations

import logging
import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from app.config import get_settings
from app.db import Database, utcnow
from app.repository import Repository
from app.schemas import (
    AddressOut,
    AnalysisResult,
    Authentication,
    Behaviour,
    ContentAnalysis,
    DomainIntel,
    Finding,
    Origin,
    Summary,
)
from app.services import authentication, domain_intel, infrastructure, patterns, scoring
from app.services.classifier import ContentClassifier
from app.services.feeds import FREE_MAIL_PROVIDERS, Feeds
from app.services.geo import GeoLocator, IpInfo
from app.services.parser import Address, ParsedEmail, parse_email

log = logging.getLogger(__name__)

_ADDRESS = re.compile(r"([\w.+-]+)@([\w-]+(?:\.[\w-]+)+)")


class Analyzer:
    def __init__(self, db: Database, feeds: Feeds, geo: GeoLocator, classifier: ContentClassifier) -> None:
        self.db = db
        self.repo = Repository(db)
        self.feeds = feeds
        self.geo = geo
        self.classifier = classifier
        self.settings = get_settings()
        self._pool = ThreadPoolExecutor(max_workers=12, thread_name_prefix="analysis")

    # --- evidence ----------------------------------------------------------

    def _store_evidence(self, raw: bytes, sha256: str) -> Path:
        path = self.settings.evidence_dir / f"{sha256}.eml"
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
            os.chmod(path, 0o444)  # evidence is immutable once stored
        return path

    def evidence_path(self, sha256: str) -> Path:
        return self.settings.evidence_dir / f"{sha256}.eml"

    # --- pipeline ----------------------------------------------------------

    def analyze(self, raw: bytes, filename: str | None = None) -> AnalysisResult:
        parsed = parse_email(raw)
        errors: list[str] = []

        def guarded(fn, *args, label: str, fallback=None):
            try:
                return fn(*args)
            except Exception as exc:  # one failing module must not sink the whole report
                log.exception("%s failed", label)
                errors.append(f"{label}: {type(exc).__name__}: {exc}")
                return fallback

        origin_ip, origin_source = infrastructure.find_origin_ip(parsed)
        boundary_ip, _ = authentication.boundary_ip(parsed)
        hop_ips = {h.from_ip for h in parsed.hops if h.ip_is_public and h.from_ip}
        lookup_ips = sorted(hop_ips | {ip for ip in (origin_ip, boundary_ip) if ip})

        auth_future = self._pool.submit(guarded, authentication.analyze, parsed, raw, label="authentication")
        domain_future = self._pool.submit(
            guarded, domain_intel.analyze, parsed.from_.domain, self.feeds, self.db, label="domain intelligence"
        )
        geo_futures = {
            ip: self._pool.submit(guarded, self.geo.lookup, ip, label=f"geolocation {ip}") for ip in lookup_ips
        }
        report = patterns.analyze(parsed, self.feeds)
        classification = self.classifier.predict(parsed.subject, parsed.text_body)

        auth: Authentication = auth_future.result()
        domain: DomainIntel = domain_future.result()
        if auth is None or domain is None:
            raise RuntimeError("; ".join(errors) or "core analysis failed")
        ip_info: dict[str, IpInfo] = {ip: f.result() for ip, f in geo_futures.items() if f.result() is not None}

        for hop in report.hops:
            if hop.from_ip in ip_info:
                hop.geo = ip_info[hop.from_ip].geo

        origin: Origin = guarded(
            infrastructure.analyze,
            parsed,
            origin_ip,
            origin_source,
            ip_info.get(origin_ip or ""),
            boundary_ip,
            domain.dns.mx,
            self.feeds,
            label="infrastructure",
        ) or infrastructure.analyze(parsed, None, "none", None, boundary_ip, [], self.feeds)

        sent_at = patterns.sent_time(parsed) or utcnow()
        sender_key = (
            parsed.from_.address.lower()
            if domain.registered_domain in FREE_MAIL_PROVIDERS
            else domain.registered_domain
        )
        behaviour = Behaviour(
            reference_time=sent_at,
            # A provider's shared outbound server says nothing about this sender's sending rate.
            ip=None if origin.webmail_masked else self.repo.velocity("origin_ip", origin.ip, sent_at, "Origin IP"),
            domain=self.repo.velocity(
                "sender_key", sender_key, sent_at, "Sender address" if "@" in sender_key else "Sender domain"
            ),
        )
        burst = any(w.burst for w in (behaviour.ip, behaviour.domain) if w)

        findings = report.findings + _module_findings(auth, domain, origin, burst)
        risk = scoring.score(auth, domain, classification, origin, findings, burst)
        attribution = scoring.attribute(risk, auth, domain, origin)

        analysis_id = uuid.uuid4().hex[:16]
        indicators = self._indicators(parsed, auth, domain, origin, report)
        result = AnalysisResult(
            id=analysis_id,
            created_at=utcnow(),
            sha256=parsed.sha256,
            size=parsed.size,
            filename=filename,
            summary=self._summary(parsed),
            risk=risk,
            attribution=attribution,
            findings=sorted(findings, key=lambda f: -scoring.SEVERITY_VALUE[f.severity]),
            authentication=auth,
            domain=domain,
            origin=origin,
            hops=report.hops,
            content=ContentAnalysis(
                classifier=classification, cues=report.cues, word_count=len(parsed.text_body.split())
            ),
            links=report.links,
            attachments=report.attachments,
            behaviour=behaviour,
            related=self.repo.related(indicators),
            errors=errors,
        )
        if self.settings.mask_pii:
            _mask_recipients(result)

        self._store_evidence(raw, parsed.sha256)
        self.repo.save(result, sent_at, sender_key or "", indicators)
        self.db.log_custody(
            analysis_id,
            parsed.sha256,
            "ingested",
            f"{filename or 'raw upload'} ({parsed.size} bytes), SHA-256 {parsed.sha256}",
        )
        return result

    # --- helpers -----------------------------------------------------------

    def _summary(self, parsed: ParsedEmail) -> Summary:
        def out(address: Address) -> AddressOut:
            return AddressOut(display_name=address.display_name, address=address.address, domain=address.domain)

        return Summary(
            subject=parsed.subject,
            from_=out(parsed.from_),
            reply_to=[out(a) for a in parsed.reply_to],
            return_path=parsed.return_path,
            to=[out(a) for a in parsed.to],
            message_id=parsed.message_id,
            date=parsed.date,
        )

    def _indicators(
        self, parsed, auth: Authentication, domain: DomainIntel, origin: Origin, report: patterns.PatternReport
    ) -> set[tuple[str, str]]:
        common = FREE_MAIL_PROVIDERS | self.feeds.brand_domains
        items: set[tuple[str, str]] = set()
        if origin.ip and not origin.webmail_masked:
            items.add(("origin_ip", origin.ip))
        if parsed.from_.address:
            items.add(("sender", parsed.from_.address.lower()))
        if domain.registered_domain and domain.registered_domain not in common:
            items.add(("from_domain", domain.registered_domain))
        for reply in parsed.reply_to:
            items.add(("reply_to", reply.address.lower()))
        for check in auth.dkim:
            if check.domain and check.domain not in common:
                items.add(("dkim_domain", check.domain))
        for link in report.links:
            if link.host:
                registered = domain_intel.dns_utils.registered_domain(link.host)
                if registered not in common:
                    items.add(("link_domain", registered))
        for attachment in report.attachments:
            items.add(("attachment", attachment.sha256))
        return items


def _module_findings(auth: Authentication, domain: DomainIntel, origin: Origin, burst: bool) -> list[Finding]:
    out: list[Finding] = []

    def add(code, severity, category, title, detail=""):
        out.append(Finding(code=code, severity=severity, category=category, title=title, detail=detail))

    dmarc = auth.dmarc
    if dmarc.result == "fail":
        add(
            "dmarc_fail",
            "high",
            "auth",
            f"DMARC failed for {dmarc.from_domain}",
            f"Neither SPF ({auth.spf.result}) nor DKIM produced an authenticated identifier aligned with the From "
            f"domain. Policy: p={dmarc.policy or 'none'}.",
        )
    elif dmarc.result == "none":
        add("dmarc_missing", "low", "auth", f"{dmarc.from_domain or 'Sender'} publishes no DMARC policy")
    if auth.spf.result in ("fail", "softfail"):
        add(
            "spf_" + auth.spf.result,
            "high" if auth.spf.result == "fail" else "medium",
            "auth",
            f"SPF {auth.spf.result}: {auth.spf.ip} is not authorised to send for {auth.spf.domain}",
            auth.spf.explanation,
        )
    for check in auth.dkim:
        if check.result in ("fail", "permerror"):
            add("dkim_fail", "medium", "auth", f"DKIM signature for {check.domain} is invalid", check.detail)
    if auth.mismatches:
        add(
            "auth_mismatch",
            "medium",
            "auth",
            "Receiver's authentication verdict differs from re-evaluation",
            "; ".join(auth.mismatches),
        )

    if domain.disposable:
        add("disposable_domain", "high", "domain", f"{domain.domain} is a disposable email provider")
    if domain.lookalike.technique:
        add(
            "lookalike_domain",
            "high",
            "domain",
            f"Sender domain imitates {domain.lookalike.brand_domain}",
            f"{domain.domain} vs {domain.lookalike.brand_domain}: {domain.lookalike.technique}",
        )
    if domain.whois.registered is False:
        add(
            "unregistered_domain",
            "high",
            "domain",
            f"Sender domain {domain.registered_domain} does not exist",
            "The domain is not registered, so no one can legitimately send from it.",
        )
    age = domain.whois.age_days
    if age is not None and age < 90:
        add(
            "young_domain",
            "high" if age < 30 else "medium",
            "domain",
            f"Sender domain registered {age} days ago",
            f"Registrar: {domain.whois.registrar or 'unknown'}",
        )
    if domain.domain and not domain.dns.error and not domain.dns.mx:
        add(
            "no_mx",
            "medium" if not domain.dns.a else "low",
            "domain",
            f"{domain.domain} has no MX record",
            "Legitimate sending domains normally accept replies and bounces.",
        )

    if origin.tor_exit:
        add("tor_exit", "critical", "infra", f"Sent from a Tor exit node ({origin.ip})")
    listed = [l.zone for l in origin.dnsbl if l.listed]
    if listed:
        add("dnsbl_listed", "high", "infra", f"Origin IP {origin.ip} is blacklisted", ", ".join(listed))
    if origin.webmail_masked:
        add("webmail_masked", "info", "geo", "Sender IP masked by the mail provider", origin.note or "")
    if burst:
        add("velocity_burst", "high", "behaviour", "Burst of messages from the same source")
    return out


def _mask_recipients(result: AnalysisResult) -> None:
    """Mask recipient mailboxes (the victims); sender data stays intact as evidence."""

    def mask(address: str) -> str:
        return _ADDRESS.sub(lambda m: f"{m.group(1)[:1]}***@{m.group(2)}", address)

    for recipient in result.summary.to:
        recipient.address = mask(recipient.address)
    for hop in result.hops:
        hop.raw = re.sub(r"for <[^>]+>", lambda m: mask(m.group(0)), hop.raw)
