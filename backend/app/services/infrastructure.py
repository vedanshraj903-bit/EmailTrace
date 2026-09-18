"""Origin identification and sending-infrastructure fingerprinting."""

from __future__ import annotations

import ipaddress
import re
import smtplib

from app.config import get_settings
from app.schemas import DnsblListing, Origin, SmtpProbe
from app.services import dns_utils
from app.services.feeds import Feeds
from app.services.geo import IpInfo
from app.services.parser import ParsedEmail

# Matched against "<PTR> <org>" in lowercase.
_MAIL_PROVIDERS = re.compile(
    r"google\.com|googlemail|outlook\.com|protection\.outlook|hotmail|yahoo|yahoodns|zoho|amazonses|"
    r"sendgrid|mailgun|sparkpost|mandrill|mailchimp|mcsv\.net|sendinblue|brevo|postmarkapp|mailjet|"
    r"protonmail|proton\.ch|icloud|me\.com|rediffmail|mimecast|messagelabs|pphosted|barracuda"
)
_CLOUD_HOSTING = re.compile(
    r"amazon|aws|digitalocean|ovh|hetzner|linode|akamai|vultr|choopa|contabo|google cloud|googleusercontent|"
    r"microsoft|azure|alibaba|tencent|oracle|scaleway|leaseweb|m247|hostinger|namecheap|ionos|hostwinds|"
    r"colocrossing|psychz|datacamp|cdn77|servers\.com|kamatera|a2 hosting|bluehost|godaddy|secureserver"
)
_GENERIC_PTR = re.compile(
    r"\d{1,3}[-.x]\d{1,3}[-.x]\d{1,3}[-.x]\d{1,3}|\b(?:dynamic|dyn|dhcp|pool|dsl|adsl|cable|broadband|dial|ppp|"
    r"pppoe|customer|cust|client|static|unassigned|residential|host\d+|ip\d+)\b",
    re.IGNORECASE,
)
DNSBL_ZONES = ("zen.spamhaus.org", "bl.spamcop.net", "psbl.surriel.com")


def find_origin_ip(parsed: ParsedEmail) -> tuple[str | None, str]:
    if parsed.x_originating_ip and ipaddress.ip_address(parsed.x_originating_ip).is_global:
        return parsed.x_originating_ip, "x-originating-ip"
    for hop in parsed.hops:  # oldest first
        if hop.ip_is_public:
            return hop.from_ip, "received-chain"
    return None, "none"


def classify_hosting(ptr: str | None, org: str | None) -> str:
    haystack = f"{ptr or ''} {org or ''}".lower()
    if not haystack.strip():
        return "unknown"
    if _MAIL_PROVIDERS.search(haystack):
        return "mail_provider"
    if _CLOUD_HOSTING.search(haystack):
        return "cloud_hosting"
    return "isp" if org else "unknown"


def is_generic_ptr(ptr: str | None) -> bool:
    return bool(ptr and _GENERIC_PTR.search(ptr))


def check_dnsbl(ip: str) -> list[DnsblListing]:
    address = ipaddress.ip_address(ip)
    if address.version != 4:
        return []
    reversed_ip = ".".join(reversed(ip.split(".")))
    listings: list[DnsblListing] = []
    for zone in DNSBL_ZONES:
        try:
            answers = dns_utils.query(f"{reversed_ip}.{zone}", "A")
        except dns_utils.DnsLookupError:
            listings.append(DnsblListing(zone=zone, listed=None, code="lookup failed"))
            continue
        if not answers:
            listings.append(DnsblListing(zone=zone, listed=False))
        elif any(a.startswith("127.255.255.") for a in answers):
            # Spamhaus answers 127.255.255.x when queried through public/open resolvers.
            listings.append(DnsblListing(zone=zone, listed=None, code="query refused by list operator"))
        else:
            listings.append(DnsblListing(zone=zone, listed=True, code=", ".join(answers)))
    return listings


def probe_smtp(domain: str, mx_hosts: list[str]) -> SmtpProbe | None:
    settings = get_settings()
    if not settings.enable_smtp_probe or not mx_hosts:
        return None
    host = mx_hosts[0]
    try:
        with smtplib.SMTP(timeout=settings.smtp_timeout_s) as client:
            _, banner = client.connect(host, 25)
            client.ehlo("emailtrace.local")
            return SmtpProbe(
                host=host, banner=banner.decode(errors="replace"), starttls=client.has_extn("starttls"), error=None
            )
    except (TimeoutError, OSError, smtplib.SMTPException) as exc:
        return SmtpProbe(host=host, banner=None, starttls=None, error=f"{type(exc).__name__}: {exc}")


def analyze(
    parsed: ParsedEmail,
    origin_ip: str | None,
    source: str,
    ip_info: IpInfo | None,
    boundary_ip: str | None,
    mx_hosts: list[str],
    feeds: Feeds,
) -> Origin:
    probe = probe_smtp(parsed.from_.domain, mx_hosts)
    if not origin_ip:
        return Origin(
            ip=None,
            source="none",
            boundary_ip=boundary_ip,
            webmail_masked=False,
            note="No public IP address found in the Received chain; the message may have been submitted internally.",
            ptr=None,
            fcrdns=None,
            generic_ptr=False,
            asn=None,
            org=None,
            hosting_class="unknown",
            tor_exit=None,
            dnsbl=[],
            smtp_probe=probe,
            geo=None,
        )

    ptr = dns_utils.reverse_lookup(origin_ip) or (ip_info.hostname if ip_info else None)
    fcrdns = dns_utils.forward_confirms(ptr, origin_ip) if ptr else False
    org = ip_info.org if ip_info else None
    hosting = classify_hosting(ptr, org)

    masked = source == "received-chain" and hosting == "mail_provider"
    note = None
    if masked:
        note = (
            "Sent through a mailbox or email-delivery provider that does not disclose the author's client IP. "
            "The location shown is the provider's server, not the sender."
        )
    elif source == "x-originating-ip":
        note = "Client IP disclosed by the provider in the X-Originating-IP header."

    return Origin(
        ip=origin_ip,
        source=source,  # type: ignore[arg-type]
        boundary_ip=boundary_ip,
        webmail_masked=masked,
        note=note,
        ptr=ptr,
        fcrdns=fcrdns,
        generic_ptr=is_generic_ptr(ptr),
        asn=ip_info.asn if ip_info else None,
        org=org,
        hosting_class=hosting,  # type: ignore[arg-type]
        tor_exit=(origin_ip in feeds.tor_exits) if feeds.tor_loaded else None,
        dnsbl=check_dnsbl(origin_ip),
        smtp_probe=probe,
        geo=ip_info.geo if ip_info else None,
    )
