"""Thin, cached wrappers around dnspython with consistent error handling."""

from __future__ import annotations

from functools import lru_cache

import dns.exception
import dns.resolver
import dns.reversename
import tldextract

from app.config import get_settings

# Use the bundled public-suffix snapshot so parsing never blocks on a network fetch.
_extract = tldextract.TLDExtract(suffix_list_urls=())


class DnsLookupError(Exception):
    """Raised for resolver failures that are not a definitive "no such record"."""


@lru_cache(maxsize=1)
def _resolver() -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver()
    timeout = get_settings().dns_timeout_s
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver


@lru_cache(maxsize=4096)
def _query(name: str, rdtype: str) -> tuple[str, ...]:
    try:
        answer = _resolver().resolve(name, rdtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return ()
    except (dns.resolver.NoNameservers, dns.exception.Timeout, dns.resolver.LifetimeTimeout) as exc:
        raise DnsLookupError(f"{rdtype} {name}: {type(exc).__name__}") from exc
    if rdtype == "TXT":
        return tuple(b"".join(r.strings).decode("utf-8", errors="replace") for r in answer)
    if rdtype == "MX":
        records = sorted(answer, key=lambda r: r.preference)
        return tuple(str(r.exchange).rstrip(".").lower() for r in records)
    return tuple(str(r).rstrip(".") for r in answer)


def query(name: str, rdtype: str) -> list[str]:
    return list(_query(name.rstrip(".").lower(), rdtype))


def txt_with_prefix(name: str, prefix: str) -> str | None:
    prefix = prefix.lower()
    return next((t for t in query(name, "TXT") if t.lower().startswith(prefix)), None)


def reverse_lookup(ip: str) -> str | None:
    try:
        names = query(str(dns.reversename.from_address(ip)), "PTR")
    except DnsLookupError:
        return None
    return names[0].lower() if names else None


def forward_confirms(hostname: str, ip: str) -> bool:
    try:
        addresses = query(hostname, "AAAA" if ":" in ip else "A")
    except DnsLookupError:
        return False
    return ip in addresses


def registered_domain(domain: str) -> str:
    """Organizational domain per the public suffix list (e.g. mail.sbi.co.in -> sbi.co.in)."""
    parts = _extract(domain.lower().rstrip("."))
    return parts.top_domain_under_public_suffix or domain.lower()


def domain_parts(domain: str) -> tuple[str, str, str]:
    parts = _extract(domain.lower().rstrip("."))
    return parts.subdomain, parts.domain, parts.suffix
