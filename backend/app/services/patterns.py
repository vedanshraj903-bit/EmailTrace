"""Rule-based anomaly detection over headers, relay chain, links, attachments and wording."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import PurePosixPath

from app.schemas import AttachmentOut, Finding, Hop, LinkOut
from app.services import dns_utils
from app.services.domain_intel import detect_lookalike
from app.services.feeds import FREE_MAIL_PROVIDERS, Feeds
from app.services.parser import ParsedEmail

URL_SHORTENERS = frozenset(
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd",
        "buff.ly",
        "rebrand.ly",
        "cutt.ly",
        "rb.gy",
        "shorturl.at",
        "tiny.cc",
        "t.ly",
        "s.id",
        "bl.ink",
        "short.io",
        "lnkd.in",
        "v.gd",
        "clck.ru",
        "qrco.de",
    }
)
SUSPICIOUS_TLDS = frozenset(
    {
        "zip",
        "mov",
        "xyz",
        "top",
        "tk",
        "ml",
        "ga",
        "cf",
        "gq",
        "click",
        "link",
        "work",
        "rest",
        "cam",
        "icu",
        "buzz",
        "monster",
        "sbs",
        "cfd",
        "quest",
        "support",
        "live",
        "shop",
        "online",
        "site",
        "info",
    }
)
EXECUTABLE_EXT = frozenset(
    {
        ".exe",
        ".scr",
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".wsf",
        ".wsh",
        ".hta",
        ".bat",
        ".cmd",
        ".ps1",
        ".msi",
        ".jar",
        ".lnk",
        ".iso",
        ".img",
        ".vhd",
        ".vhdx",
        ".cab",
        ".cpl",
        ".dll",
        ".com",
        ".pif",
        ".reg",
        ".appx",
    }
)
MACRO_EXT = frozenset({".docm", ".xlsm", ".pptm", ".xlam", ".dotm", ".xlsb"})
ARCHIVE_EXT = frozenset({".zip", ".rar", ".7z", ".gz", ".tar", ".ace", ".arj", ".z"})
MARKUP_EXT = frozenset({".html", ".htm", ".shtml", ".xhtml", ".svg", ".mht"})
DOCUMENT_EXT = frozenset({".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".jpg", ".png"})

_EXEC_TITLES = re.compile(
    r"\b(ceo|cfo|coo|cto|managing director|md|director|chairman|president|principal|registrar|"
    r"vice[- ]chancellor|dean|commissioner|secretary)\b",
    re.IGNORECASE,
)
_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")
_DOMAIN_IN_TEXT = re.compile(r"^(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]|$)", re.IGNORECASE)

CUE_LEXICON: dict[str, tuple[str, ...]] = {
    "urgency": (
        "urgent",
        "immediately",
        "within 24 hours",
        "within 48 hours",
        "act now",
        "final notice",
        "last warning",
        "will be suspended",
        "will be blocked",
        "will be deactivated",
        "account suspended",
        "expires today",
        "action required",
        "time sensitive",
        "as soon as possible",
        "right away",
    ),
    "credential_harvesting": (
        "verify your account",
        "verify your identity",
        "confirm your password",
        "reset your password",
        "update your kyc",
        "kyc",
        "login to",
        "log in to",
        "sign in to",
        "unusual sign-in",
        "unusual activity",
        "otp",
        "one time password",
        "cvv",
        "atm pin",
        "net banking",
        "security alert",
        "validate your",
    ),
    "payment_diversion": (
        "wire transfer",
        "bank details",
        "change of bank",
        "new bank account",
        "updated account details",
        "beneficiary",
        "remittance",
        "outstanding invoice",
        "overdue invoice",
        "payment pending",
        "neft",
        "rtgs",
        "imps",
        "swift",
        "gift card",
        "google play card",
        "processing fee",
        "refund",
    ),
    "authority_pressure": (
        "confidential",
        "keep this between us",
        "are you available",
        "quick favour",
        "quick favor",
        "i am in a meeting",
        "legal action",
        "arrest",
        "police",
        "cyber cell",
        "court",
        "penalty",
        "income tax",
        "customs",
        "fir",
    ),
    "reward_lure": (
        "lottery",
        "you have won",
        "prize",
        "cashback",
        "reward points",
        "congratulations",
        "claim now",
        "free gift",
        "lucky winner",
        "selected for",
    ),
}
_CUE_PATTERNS = {
    category: [(phrase, re.compile(rf"(?<![\w]){re.escape(phrase)}(?![\w])", re.IGNORECASE)) for phrase in phrases]
    for category, phrases in CUE_LEXICON.items()
}


@dataclass
class PatternReport:
    findings: list[Finding] = field(default_factory=list)
    hops: list[Hop] = field(default_factory=list)
    links: list[LinkOut] = field(default_factory=list)
    attachments: list[AttachmentOut] = field(default_factory=list)
    cues: dict[str, list[str]] = field(default_factory=dict)

    def add(self, code: str, severity: str, category: str, title: str, detail: str = "") -> None:
        self.findings.append(Finding(code=code, severity=severity, category=category, title=title, detail=detail))


def _org(domain: str) -> str:
    return dns_utils.registered_domain(domain) if domain else ""


def _message_id_domain(message_id: str) -> str:
    match = re.search(r"@([^>\s]+)>?$", message_id.strip())
    return match.group(1).lower().rstrip(".") if match else ""


def analyze_headers(parsed: ParsedEmail, feeds: Feeds, report: PatternReport) -> None:
    from_domain = parsed.from_.domain
    from_org = _org(from_domain)
    display = parsed.from_.display_name

    if not parsed.from_.address or "@" not in parsed.from_.address:
        report.add("from_malformed", "high", "header", "From header is missing or malformed")

    for reply in parsed.reply_to:
        if reply.domain and _org(reply.domain) != from_org:
            free = _org(reply.domain) in FREE_MAIL_PROVIDERS and from_org not in FREE_MAIL_PROVIDERS
            report.add(
                "reply_to_mismatch",
                "high" if free else "medium",
                "header",
                "Replies are redirected to a different domain",
                f"From uses {from_domain}, but Reply-To sends answers to {reply.address}"
                + (" (a free mailbox, a common payment-diversion setup)." if free else "."),
            )
            break

    if parsed.return_path and "@" in parsed.return_path:
        rp_org = _org(parsed.return_path.rpartition("@")[2])
        if rp_org and rp_org != from_org:
            report.add(
                "return_path_mismatch",
                "low",
                "header",
                "Envelope sender differs from the visible sender",
                f"Return-Path domain {rp_org} vs From domain {from_org}. Normal for mailing services, "
                "but it means SPF does not vouch for the From domain.",
            )

    if display:
        embedded = _EMAIL_IN_TEXT.search(display)
        if embedded and _org(embedded.group(1)) != from_org:
            report.add(
                "display_name_address",
                "high",
                "header",
                "Display name shows a different email address",
                f'"{display}" is shown to the reader, but the real sender is {parsed.from_.address}.',
            )
        lowered = display.lower()
        for brand in feeds.brands:
            if from_org in brand.domains:
                continue
            hit = next((k for k in brand.keywords if re.search(rf"\b{re.escape(k)}\b", lowered)), None)
            if hit:
                report.add(
                    "display_name_brand",
                    "high",
                    "header",
                    f"Display name impersonates {brand.name}",
                    f'Display name "{display}" references {brand.name}, but the mail comes from {from_domain}, '
                    f"which is not one of its domains ({', '.join(brand.domains[:3])}).",
                )
                break
        if _EXEC_TITLES.search(display) and from_org in FREE_MAIL_PROVIDERS:
            report.add(
                "executive_freemail",
                "medium",
                "header",
                "Executive title on a free mailbox",
                f'"{display}" claims a senior role but writes from {from_domain}.',
            )

    if not parsed.message_id:
        report.add(
            "message_id_missing",
            "medium",
            "header",
            "Message-ID header is missing",
            "Every standards-compliant mail client adds one; bulk and scripted mailers often do not.",
        )
    else:
        mid_org = _org(_message_id_domain(parsed.message_id))
        relay_orgs = {_org(h.by_host) for h in parsed.hops if h.by_host} | {
            _org(h.from_rdns or "") for h in parsed.hops
        }
        if mid_org and mid_org != from_org and mid_org not in relay_orgs:
            report.add(
                "message_id_domain",
                "low",
                "header",
                "Message-ID was generated by an unrelated domain",
                f"Message-ID domain {mid_org} matches neither the From domain nor any relay.",
            )

    first_seen = next((h.timestamp for h in parsed.hops if h.timestamp), None)
    if parsed.date is None:
        report.add("date_missing", "low", "header", "Date header is missing or unparseable")
    elif first_seen:
        drift = (first_seen - parsed.date).total_seconds()
        if drift < -900:
            report.add(
                "date_future",
                "medium",
                "header",
                "Date header is later than the first relay timestamp",
                f"The message claims to be written {abs(drift) / 60:.0f} minutes after the first server received it.",
            )
        elif drift > 86400:
            report.add(
                "date_stale",
                "low",
                "header",
                "Long gap between Date header and first relay",
                f"{drift / 3600:.1f} hours passed between the claimed send time and first receipt.",
            )


def analyze_hops(parsed: ParsedEmail, report: PatternReport) -> None:
    previous_ts = None
    for hop in parsed.hops:
        anomalies: list[str] = []
        delay = None
        if hop.timestamp and previous_ts:
            delay = (hop.timestamp - previous_ts).total_seconds()
            if delay < -300:
                anomalies.append(f"timestamp is {abs(delay) / 60:.0f} min earlier than the previous hop")
            elif delay > 3600:
                anomalies.append(f"held for {delay / 3600:.1f} h before this hop")
        if hop.timestamp:
            previous_ts = hop.timestamp

        helo = (hop.from_helo or "").lower()
        if helo and hop.from_ip:
            try:
                helo_ip = ipaddress.ip_address(helo)
            except ValueError:
                helo_ip = None
            if helo_ip is not None and str(helo_ip) != hop.from_ip:
                anomalies.append(f"HELO claims IP {helo} but the connection came from {hop.from_ip}")
            elif helo_ip is None and "." in helo and hop.from_rdns:
                helo_org, rdns_org = _org(helo), _org(hop.from_rdns)
                big = ("google.com", "gmail.com", "outlook.com", "microsoft.com", "yahoo.com", "hotmail.com")
                if helo_org in big and rdns_org != helo_org:
                    anomalies.append(f"HELO claims to be {helo} but reverse DNS is {hop.from_rdns}")

        report.hops.append(
            Hop(
                index=hop.index,
                from_helo=hop.from_helo,
                from_rdns=hop.from_rdns,
                from_ip=hop.from_ip,
                by_host=hop.by_host,
                protocol=hop.protocol,
                timestamp=hop.timestamp,
                delay_s=delay,
                public=hop.ip_is_public,
                geo=None,
                anomalies=anomalies,
                raw=hop.raw,
            )
        )

    reversed_hops = [h for h in report.hops if any("earlier than" in a for a in h.anomalies)]
    if reversed_hops:
        report.add(
            "hop_time_reversal",
            "medium",
            "header",
            "Relay timestamps go backwards",
            f"{len(reversed_hops)} hop(s) are stamped before the hop that handed them the message, which points "
            "to injected Received headers or badly skewed server clocks.",
        )
    forged = [a for h in report.hops for a in h.anomalies if a.startswith("HELO claims")]
    if forged:
        report.add("helo_forgery", "high", "infra", "Relay identity does not match its connection", "; ".join(forged))
    if not parsed.hops:
        report.add(
            "no_received",
            "medium",
            "header",
            "No Received headers",
            "The message carries no relay trace; it was not delivered through SMTP or the headers were stripped.",
        )
    elif len(parsed.hops) > 12:
        report.add("many_hops", "low", "header", f"Unusually long relay chain ({len(parsed.hops)} hops)")


def analyze_links(parsed: ParsedEmail, feeds: Feeds, report: PatternReport) -> None:
    for link in parsed.links:
        flags: list[str] = []
        host = link.host
        is_ip = False
        try:
            ipaddress.ip_address(host.strip("[]"))
            is_ip = True
        except ValueError:
            pass
        if is_ip:
            flags.append("raw IP address instead of a domain")
        elif host:
            if host in URL_SHORTENERS or _org(host) in URL_SHORTENERS:
                flags.append("URL shortener hides the destination")
            if "xn--" in host:
                flags.append("internationalised (punycode) domain")
            suffix = dns_utils.domain_parts(host)[2]
            if suffix.split(".")[-1] in SUSPICIOUS_TLDS:
                flags.append(f"high-abuse TLD .{suffix}")
            lookalike = detect_lookalike(host, feeds)
            if lookalike.technique:
                flags.append(f"imitates {lookalike.brand_domain} ({lookalike.technique})")
            subdomain = dns_utils.domain_parts(host)[0]
            if subdomain.count(".") >= 3:
                flags.append("deeply nested subdomains")
        if "@" in link.href.split("//", 1)[-1].split("/", 1)[0]:
            flags.append("userinfo '@' in URL disguises the real host")
        shown = _DOMAIN_IN_TEXT.match(link.text.strip()) if link.text else None
        if shown and host and _org(shown.group(1)) != _org(host):
            flags.append(f"text shows {shown.group(1).lower()} but the link opens {host}")
        report.links.append(LinkOut(href=link.href, text=link.text, host=host, flags=flags))

    deceptive = [l for l in report.links if any(f.startswith("text shows") for f in l.flags)]
    if deceptive:
        report.add(
            "link_text_mismatch",
            "high",
            "link",
            "Link text disguises its destination",
            "; ".join(next(f for f in l.flags if f.startswith("text shows")) for l in deceptive[:3]),
        )
    imitations = [l for l in report.links if any(f.startswith("imitates") for f in l.flags)]
    if imitations:
        report.add(
            "link_lookalike",
            "high",
            "link",
            "Links point to brand lookalike domains",
            ", ".join(sorted({l.host for l in imitations})[:5]),
        )
    ip_links = [l for l in report.links if "raw IP address instead of a domain" in l.flags]
    if ip_links:
        report.add(
            "link_ip",
            "high",
            "link",
            "Links point directly to IP addresses",
            ", ".join(sorted({l.host for l in ip_links})[:5]),
        )
    shorteners = [l for l in report.links if "URL shortener hides the destination" in l.flags]
    if shorteners:
        report.add(
            "link_shortener",
            "medium",
            "link",
            "Shortened links hide their destination",
            ", ".join(sorted({l.host for l in shorteners})),
        )
    risky_tld = [l for l in report.links if any(f.startswith("high-abuse TLD") for f in l.flags)]
    if risky_tld:
        report.add(
            "link_tld",
            "low",
            "link",
            "Links use high-abuse top-level domains",
            ", ".join(sorted({l.host for l in risky_tld})[:5]),
        )


def analyze_attachments(parsed: ParsedEmail, report: PatternReport) -> None:
    for attachment in parsed.attachments:
        name = attachment.filename.lower().strip()
        suffixes = [s for s in PurePosixPath(name).suffixes if len(s) <= 6]
        ext = suffixes[-1] if suffixes else ""
        flags: list[str] = []
        if len(suffixes) >= 2 and suffixes[-2] in DOCUMENT_EXT and ext in EXECUTABLE_EXT | MARKUP_EXT | ARCHIVE_EXT:
            flags.append(f"double extension disguises a {ext} file")
        if ext in EXECUTABLE_EXT:
            flags.append("executable or script file")
        elif ext in MACRO_EXT:
            flags.append("macro-enabled Office document")
        elif ext in MARKUP_EXT:
            flags.append("HTML/SVG attachment (used for local credential-harvesting pages)")
        elif ext in ARCHIVE_EXT:
            flags.append("archive can conceal its contents from scanners")
        if ext == ".pdf" and attachment.content_type not in ("application/pdf", "application/octet-stream"):
            flags.append(f"declared type {attachment.content_type} does not match .pdf")
        report.attachments.append(
            AttachmentOut(
                filename=attachment.filename,
                content_type=attachment.content_type,
                size=attachment.size,
                sha256=attachment.sha256,
                flags=flags,
            )
        )
        if flags:
            critical = any(f.startswith(("double extension", "executable")) for f in flags)
            report.add(
                "attachment_" + ("critical" if critical else "risky"),
                "critical" if critical else "high",
                "attachment",
                f"Risky attachment: {attachment.filename}",
                "; ".join(flags),
            )


def analyze_cues(parsed: ParsedEmail, report: PatternReport) -> None:
    text = f"{parsed.subject}\n{parsed.text_body}"
    for category, patterns in _CUE_PATTERNS.items():
        hits = [phrase for phrase, pattern in patterns if pattern.search(text)]
        if hits:
            report.cues[category] = hits
    if "payment_diversion" in report.cues and ("authority_pressure" in report.cues or "urgency" in report.cues):
        report.add(
            "bec_language",
            "high",
            "content",
            "Business email compromise language",
            "Combines payment instructions (" + ", ".join(report.cues["payment_diversion"][:3]) + ") with "
            "pressure (" + ", ".join((report.cues.get("authority_pressure") or report.cues["urgency"])[:3]) + ").",
        )
    if "credential_harvesting" in report.cues and "urgency" in report.cues:
        report.add(
            "credential_lure",
            "high",
            "content",
            "Urgent request for credentials or verification",
            ", ".join(report.cues["credential_harvesting"][:4]),
        )
    elif len(report.cues) >= 2:
        report.add(
            "social_engineering",
            "medium",
            "content",
            "Social-engineering wording",
            "; ".join(f"{k.replace('_', ' ')}: {', '.join(v[:2])}" for k, v in report.cues.items()),
        )


def analyze(parsed: ParsedEmail, feeds: Feeds) -> PatternReport:
    report = PatternReport()
    analyze_headers(parsed, feeds, report)
    analyze_hops(parsed, report)
    analyze_links(parsed, feeds, report)
    analyze_attachments(parsed, report)
    analyze_cues(parsed, report)
    return report


def sent_time(parsed: ParsedEmail) -> datetime | None:
    """Best estimate of the send time: the first relay stamp (server clock), else the sender's Date header."""
    return next((h.timestamp for h in parsed.hops if h.timestamp), None) or parsed.date
