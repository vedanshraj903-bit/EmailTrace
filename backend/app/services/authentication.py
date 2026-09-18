"""SPF, DKIM and DMARC evaluation (RFC 7208, 6376, 7489) plus comparison with the receiver's verdict."""

from __future__ import annotations

import logging
import re

import dkim
import spf

from app.schemas import Authentication, DkimCheck, DmarcCheck, RecordedAuth, SpfCheck
from app.services import dns_utils
from app.services.parser import ParsedEmail, is_public_ip

logging.getLogger("dkim").setLevel(logging.CRITICAL)

_CLIENT_IP = re.compile(r"client-ip=\[?([0-9A-Fa-f:.]+)\]?", re.IGNORECASE)
_DESIGNATES = re.compile(r"designates\s+\[?([0-9A-Fa-f:.]+)\]?\s+as", re.IGNORECASE)
_SENDER_IP_IS = re.compile(r"sender IP is\s+([0-9A-Fa-f:.]+)", re.IGNORECASE)
_REMOTE_IP = re.compile(r"smtp\.remote-ip=\[?([0-9A-Fa-f:.]+)\]?", re.IGNORECASE)
_AR_METHOD = {m: re.compile(rf"\b{m}=([a-z]+)", re.IGNORECASE) for m in ("spf", "dkim", "dmarc")}
_KNOWN = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy"}


def _norm(result: str | None) -> str:
    result = (result or "").lower()
    return result if result in _KNOWN else "unknown"


def boundary_ip(parsed: ParsedEmail) -> tuple[str | None, str]:
    """IP that handed the message to the recipient's MX, i.e. the address SPF applies to.

    Receiver-stamped headers are authoritative; the Received chain is a fallback because internal
    hops of large providers also use global addresses.
    """
    sources = [
        (parsed.received_spf[:1], (_CLIENT_IP, _DESIGNATES), "Received-SPF header"),
        (parsed.auth_results[:1], (_SENDER_IP_IS, _REMOTE_IP, _DESIGNATES), "Authentication-Results header"),
    ]
    for headers, patterns, label in sources:
        for header in headers:
            for pattern in patterns:
                match = pattern.search(header)
                if match and is_public_ip(match.group(1)):
                    return match.group(1), label
    for hop in reversed(parsed.hops):  # newest first
        if hop.ip_is_public:
            return hop.from_ip, "topmost public Received hop"
    return None, "not found"


def check_spf(parsed: ParsedEmail) -> SpfCheck:
    ip, ip_source = boundary_ip(parsed)
    mail_from = parsed.return_path or ""
    helo = next((h.from_helo for h in reversed(parsed.hops) if h.from_ip == ip and h.from_helo), "") or ""
    domain = mail_from.rpartition("@")[2].lower() if "@" in mail_from else helo.lower()

    record = None
    if domain:
        try:
            record = dns_utils.txt_with_prefix(domain, "v=spf1")
        except dns_utils.DnsLookupError:
            record = None

    if not ip:
        return SpfCheck(
            result="none",
            domain=domain,
            ip=None,
            ip_source=ip_source,
            explanation="No public sending IP could be determined from the headers.",
            record=record,
        )
    if not domain:
        return SpfCheck(
            result="none",
            domain="",
            ip=ip,
            ip_source=ip_source,
            explanation="No envelope sender (Return-Path) or HELO name to evaluate.",
            record=None,
        )

    sender = mail_from if "@" in mail_from else f"postmaster@{domain}"
    try:
        result, explanation = spf.check2(i=ip, s=sender, h=helo or domain, timeout=10, querytime=10)
    except Exception as exc:  # pyspf raises assorted errors on malformed input
        result, explanation = "temperror", str(exc)
    return SpfCheck(
        result=_norm(result), domain=domain, ip=ip, ip_source=ip_source, explanation=explanation, record=record
    )


def _dkim_tags(header: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in header.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags[key.strip().lower()] = re.sub(r"\s+", "", value)
    return tags


def check_dkim(parsed: ParsedEmail, raw: bytes) -> list[DkimCheck]:
    if not parsed.dkim_signatures:
        return []
    canonical = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
    checks: list[DkimCheck] = []
    for idx, header in enumerate(parsed.dkim_signatures):
        tags = _dkim_tags(header)
        domain, selector = tags.get("d", "").lower(), tags.get("s", "")
        try:
            ok = dkim.DKIM(canonical).verify(idx=idx)
            result, detail = (
                ("pass", "Signature verified against the published key.")
                if ok
                else ("fail", "Body hash or header signature does not match; the message was altered or forged.")
            )
        except dkim.KeyFormatError as exc:
            result, detail = "permerror", f"Invalid public key: {exc}"
        except dkim.ValidationError as exc:
            result, detail = "permerror", f"Malformed signature: {exc}"
        except dkim.DKIMException as exc:
            message = str(exc)
            result = "temperror" if "dns" in message.lower() or "key" in message.lower() else "permerror"
            detail = message
        except Exception as exc:  # dns timeouts surface as generic errors inside dkimpy
            result, detail = "temperror", f"{type(exc).__name__}: {exc}"
        checks.append(DkimCheck(domain=domain, selector=selector, result=result, detail=detail))
    return checks


def aligned(auth_domain: str, from_domain: str, mode: str) -> bool:
    if not auth_domain or not from_domain:
        return False
    auth_domain, from_domain = auth_domain.lower().rstrip("."), from_domain.lower().rstrip(".")
    if mode == "s":
        return auth_domain == from_domain
    return dns_utils.registered_domain(auth_domain) == dns_utils.registered_domain(from_domain)


def _parse_dmarc(record: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    for part in record.split(";"):
        key, sep, value = part.partition("=")
        if sep:
            tags[key.strip().lower()] = value.strip().lower()
    return tags


def check_dmarc(from_domain: str, spf_check: SpfCheck, dkim_checks: list[DkimCheck]) -> DmarcCheck:
    record = record_domain = None
    if from_domain:
        org = dns_utils.registered_domain(from_domain)
        for candidate in dict.fromkeys([from_domain, org]):  # exact domain first, then organizational
            try:
                found = dns_utils.txt_with_prefix(f"_dmarc.{candidate}", "v=DMARC1")
            except dns_utils.DnsLookupError:
                found = None
            if found:
                record, record_domain = found, candidate
                break

    tags = _parse_dmarc(record) if record else {}
    adkim = "s" if tags.get("adkim") == "s" else "r"
    aspf = "s" if tags.get("aspf") == "s" else "r"
    spf_aligned = spf_check.result == "pass" and aligned(spf_check.domain, from_domain, aspf)
    dkim_aligned = any(c.result == "pass" and aligned(c.domain, from_domain, adkim) for c in dkim_checks)

    policy = tags.get("p")
    subdomain_policy = tags.get("sp")
    effective = subdomain_policy if (record_domain and record_domain != from_domain and subdomain_policy) else policy

    if not from_domain:
        result, disposition = "permerror", "no valid From domain"
    elif not record:
        result, disposition = "none", "no DMARC policy published"
    elif spf_aligned or dkim_aligned:
        result, disposition = "pass", "deliver"
    else:
        result = "fail"
        disposition = {"reject": "reject", "quarantine": "quarantine"}.get(effective or "", "none (monitor only)")

    return DmarcCheck(
        result=result,
        from_domain=from_domain,
        record=record,
        record_domain=record_domain,
        policy=policy,
        subdomain_policy=subdomain_policy,
        adkim=adkim,
        aspf=aspf,
        spf_aligned=spf_aligned,
        dkim_aligned=dkim_aligned,
        disposition=disposition,
    )


def recorded_results(parsed: ParsedEmail) -> RecordedAuth:
    """Verdict written by the receiving server. Only the topmost header is trusted: lower ones can be forged."""
    if not parsed.auth_results:
        return RecordedAuth(authserv_id=None, spf=None, dkim=None, dmarc=None, raw=None)
    header = parsed.auth_results[0]
    authserv = header.split(";", 1)[0].strip() or None
    found: dict[str, str | None] = {}
    for method, pattern in _AR_METHOD.items():
        match = pattern.search(header)
        found[method] = match.group(1).lower() if match else None
    return RecordedAuth(authserv_id=authserv, raw=header, **found)


def analyze(parsed: ParsedEmail, raw: bytes) -> Authentication:
    spf_check = check_spf(parsed)
    dkim_checks = check_dkim(parsed, raw)
    dmarc_check = check_dmarc(parsed.from_.domain, spf_check, dkim_checks)
    recorded = recorded_results(parsed)

    ours = {
        "spf": spf_check.result,
        "dkim": "pass" if any(c.result == "pass" for c in dkim_checks) else ("fail" if dkim_checks else "none"),
        "dmarc": dmarc_check.result,
    }
    mismatches: list[str] = []
    for method, value in ours.items():
        theirs = getattr(recorded, method)
        # temperror on our side means we could not evaluate, which is not evidence of tampering.
        if theirs and value not in ("temperror", "unknown") and theirs != value:
            mismatches.append(f"{method.upper()}: receiver recorded '{theirs}', re-evaluation gives '{value}'")

    return Authentication(spf=spf_check, dkim=dkim_checks, dmarc=dmarc_check, recorded=recorded, mismatches=mismatches)
