"""Sender-domain intelligence: disposable providers, DNS posture, WHOIS age and brand lookalikes."""

from __future__ import annotations

import re
from datetime import UTC, datetime

import whois
from whois.exceptions import WhoisDomainNotFoundError

from app.config import get_settings
from app.db import Database, utcnow
from app.schemas import DnsRecords, DomainIntel, Lookalike, Whois
from app.services import dns_utils
from app.services.feeds import FREE_MAIL_PROVIDERS, Feeds

_PRIVACY_MARKERS = re.compile(
    r"privacy|redacted|proxy|whoisguard|withheld|protected|domains by proxy|contact privacy|data protected",
    re.IGNORECASE,
)

# Visually confusable characters mapped to their ASCII skeleton (subset of Unicode TR39).
_CONFUSABLES = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "9": "g",
        "@": "a",
        "$": "s",
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ԁ": "d",
        "ѕ": "s",
        "һ": "h",
        "ӏ": "l",
        "ɡ": "g",
        "ο": "o",
        "α": "a",
        "ν": "v",
        "ρ": "p",
        "τ": "t",
        "ι": "i",
        "ı": "i",
        "ł": "l",
        "ß": "b",
    }
)
_MULTI_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("cl", "d"), ("nn", "m"))


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _max_typo_distance(brand_label: str) -> int:
    # Short names produce too many innocent near-misses (lic/lib, meta/beta), so only
    # homoglyphs are considered for them.
    if len(brand_label) < 5:
        return 0
    return 1 if len(brand_label) < 9 else 2


def skeleton(label: str) -> str:
    value = label.lower().translate(_CONFUSABLES).replace("-", "")
    for sequence, replacement in _MULTI_CONFUSABLES:
        value = value.replace(sequence, replacement)
    return value


def _to_unicode(domain: str) -> tuple[str, bool]:
    if "xn--" not in domain:
        return domain, False
    try:
        return domain.encode("ascii").decode("idna"), True
    except UnicodeError:
        return domain, True


def detect_lookalike(domain: str, feeds: Feeds) -> Lookalike:
    unicode_domain, punycode = _to_unicode(domain.lower())
    registered = dns_utils.registered_domain(domain)
    no_match = Lookalike(
        matched_brand=None,
        brand_domain=None,
        distance=None,
        technique=None,
        punycode=punycode,
        unicode_form=unicode_domain if punycode else None,
    )
    if registered in feeds.brand_domains or any(registered.endswith("." + d) for d in feeds.brand_domains):
        return no_match

    subdomain, label, suffix = dns_utils.domain_parts(unicode_domain)
    label_skeleton = skeleton(label)
    tokens = set(re.split(r"[-_.\d]+", label.lower())) - {""}
    sub_tokens = set(re.split(r"[-_.\d]+", subdomain.lower())) - {""}

    best: tuple[int, Lookalike] | None = None
    for brand in feeds.brands:
        for brand_domain in brand.domains:
            _, brand_label, brand_suffix = dns_utils.domain_parts(brand_domain)
            if not brand_label or brand_label in {"gov", "nic"}:
                continue
            distance = levenshtein(label.lower(), brand_label)
            technique: str | None = None
            rank = 99
            if label.lower() == brand_label and suffix != brand_suffix:
                technique, rank = "same name on a different TLD", 3
            elif label_skeleton == skeleton(brand_label) and label.lower() != brand_label:
                technique, rank = "homoglyph substitution", 0
            elif 0 < distance <= _max_typo_distance(brand_label):
                technique, rank = "typosquatting (edit distance)", 1
            elif len(brand_label) >= 3 and brand_label in tokens and label.lower() != brand_label:
                technique, rank = "combosquatting (brand plus extra words)", 2
            elif len(brand_label) >= 3 and brand_label in sub_tokens:
                technique, rank = "brand name placed in subdomain", 2
            if technique and (best is None or rank < best[0]):
                best = (
                    rank,
                    Lookalike(
                        matched_brand=brand.name,
                        brand_domain=brand_domain,
                        distance=distance,
                        technique=technique,
                        punycode=punycode,
                        unicode_form=unicode_domain if punycode else None,
                    ),
                )
    return best[1] if best else no_match


def _first_datetime(value: object) -> datetime | None:
    if isinstance(value, list):
        dates = [v for v in value if isinstance(v, datetime)]
        value = min(dates) if dates else None
    if not isinstance(value, datetime):
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def lookup_whois(domain: str, db: Database) -> Whois:
    settings = get_settings()
    if not settings.enable_whois:
        return Whois(available=False, error="WHOIS lookups disabled")
    cache_key = f"whois:{domain}"
    if (cached := db.cache_get(cache_key)) is not None:
        record = Whois.model_validate(cached)
    else:
        try:
            data = whois.whois(domain, quiet=True, timeout=8)
        except WhoisDomainNotFoundError:
            # Registries answer "not found" for free domains; confirm with DNS before calling it unregistered.
            try:
                delegated = bool(dns_utils.query(domain, "NS"))
            except dns_utils.DnsLookupError:
                delegated = True
            if delegated:
                return Whois(available=False, error="WHOIS server has no record for this domain")
            return Whois(available=True, registered=False, error="Domain is not registered and has no DNS delegation")
        except Exception as exc:  # python-whois raises bare exceptions for unknown TLDs/servers
            return Whois(available=False, error=f"WHOIS query failed: {type(exc).__name__}")
        created = _first_datetime(data.get("creation_date"))
        if not created and not data.get("registrar"):
            return Whois(available=False, error="WHOIS server returned no registration data")
        blob = " ".join(str(data.get(k) or "") for k in ("registrant_name", "org", "name", "emails", "text"))
        name_servers = data.get("name_servers") or []
        if isinstance(name_servers, str):
            name_servers = [name_servers]
        country = data.get("country")
        record = Whois(
            available=True,
            registered=True,
            registrar=str(data.get("registrar")) if data.get("registrar") else None,
            created=created,
            expires=_first_datetime(data.get("expiration_date")),
            privacy_protected=bool(_PRIVACY_MARKERS.search(blob)),
            country=str(country[0] if isinstance(country, list) else country) if country else None,
            name_servers=sorted({str(ns).lower().rstrip(".") for ns in name_servers})[:6],
        )
        db.cache_set(cache_key, record.model_dump(mode="json"), settings.whois_cache_ttl_h)
    if record.created:
        record.age_days = (utcnow() - record.created).days
    return record


def lookup_dns(domain: str) -> DnsRecords:
    errors: list[str] = []

    def safe(fn, *args):
        try:
            return fn(*args)
        except dns_utils.DnsLookupError as exc:
            errors.append(str(exc))
            return None

    return DnsRecords(
        mx=safe(dns_utils.query, domain, "MX") or [],
        a=safe(dns_utils.query, domain, "A") or [],
        spf=safe(dns_utils.txt_with_prefix, domain, "v=spf1"),
        dmarc=safe(dns_utils.txt_with_prefix, f"_dmarc.{domain}", "v=DMARC1")
        or safe(dns_utils.txt_with_prefix, f"_dmarc.{dns_utils.registered_domain(domain)}", "v=DMARC1"),
        error="; ".join(errors) or None,
    )


def analyze(domain: str, feeds: Feeds, db: Database) -> DomainIntel:
    registered = dns_utils.registered_domain(domain) if domain else ""
    empty_dns = DnsRecords(mx=[], a=[], spf=None, dmarc=None, error="no sender domain")
    return DomainIntel(
        domain=domain,
        registered_domain=registered,
        free_mail_provider=registered in FREE_MAIL_PROVIDERS,
        disposable=feeds.is_disposable(domain) if domain else False,
        disposable_list_loaded=bool(feeds.disposable),
        dns=lookup_dns(domain) if domain else empty_dns,
        # WHOIS is only meaningful for the registrable domain, and free-mail providers are long-lived.
        whois=lookup_whois(registered, db)
        if registered and registered not in FREE_MAIL_PROVIDERS
        else Whois(available=False, error="skipped for well-known mailbox provider" if registered else "no domain"),
        lookalike=detect_lookalike(domain, feeds)
        if domain
        else Lookalike(
            matched_brand=None, brand_domain=None, distance=None, technique=None, punycode=False, unicode_form=None
        ),
    )
