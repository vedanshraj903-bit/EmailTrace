"""Raw RFC 5322 message parsing: headers, relay chain, body, links and attachments."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

from bs4 import BeautifulSoup

_WS = re.compile(r"\s+")
_URL = re.compile(r"""\bhttps?://[^\s<>"')\]]+""", re.IGNORECASE)
_BRACKET_IP = re.compile(r"\[(?:IPv6:)?([0-9A-Fa-f:.]+)\]")
_BARE_IP = re.compile(r"(?<![\w.:])((?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7})(?![\w.:])")
_FROM_CLAUSE = re.compile(r"^\s*from\s+(.*?)(?=\s+by\s+|\s+with\s+|\s+id\s+|\s+for\s+|$)", re.IGNORECASE)
_BY_CLAUSE = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)
_WITH_CLAUSE = re.compile(r"\bwith\s+([A-Za-z0-9_-]+)", re.IGNORECASE)
_HOSTNAME = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+\.?$"
)


@dataclass
class Address:
    display_name: str
    address: str

    @property
    def domain(self) -> str:
        return self.address.rpartition("@")[2].lower() if "@" in self.address else ""


@dataclass
class ReceivedHop:
    index: int  # 0 = oldest hop (closest to the sender)
    raw: str
    from_helo: str | None
    from_rdns: str | None
    from_ip: str | None
    by_host: str | None
    protocol: str | None
    timestamp: datetime | None
    ip_is_public: bool


@dataclass
class Link:
    href: str
    text: str
    host: str


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    sha256: str


@dataclass
class ParsedEmail:
    sha256: str
    size: int
    subject: str
    from_: Address
    reply_to: list[Address]
    return_path: str
    to: list[Address]
    message_id: str
    date: datetime | None
    headers: list[tuple[str, str]]
    hops: list[ReceivedHop]
    auth_results: list[str]
    received_spf: list[str]
    dkim_signatures: list[str]
    x_originating_ip: str | None
    text_body: str
    html_body: str
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        name = name.lower()
        return next((v for k, v in self.headers if k.lower() == name), None)


def is_public_ip(value: str | None) -> bool:
    if not value:
        return False
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _valid_ip(candidate: str) -> str | None:
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _collapse(value: str) -> str:
    return _WS.sub(" ", value).strip()


def _parse_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        dt = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError, IndexError):
        return None
    return dt if dt.tzinfo else None  # naive dates cannot be compared across hops


def parse_received(value: str, index: int) -> ReceivedHop:
    raw = _collapse(value)
    body, _, date_part = raw.rpartition(";")
    if not body:  # no ';' present
        body, date_part = raw, ""

    from_helo = from_rdns = from_ip = None
    from_match = _FROM_CLAUSE.search(body)
    if from_match:
        clause = from_match.group(1)
        head = clause.split(" ", 1)[0].strip("[]")
        from_helo = head or None

        # Prefer the bracketed address the receiving MTA recorded over anything in the HELO.
        for candidate in _BRACKET_IP.findall(clause):
            if ip := _valid_ip(candidate):
                from_ip = ip
                break
        if from_ip is None:
            for candidate in _BARE_IP.findall(clause):
                if ip := _valid_ip(candidate):
                    from_ip = ip
                    break

        paren = re.search(r"\(([^)]*)\)", clause)
        if paren:
            first = paren.group(1).split()[0] if paren.group(1).split() else ""
            first = first.rstrip(".")
            if _HOSTNAME.match(first) and not _valid_ip(first) and first.lower() != "unknown":
                from_rdns = first.lower()

    by_match = _BY_CLAUSE.search(body)
    with_match = _WITH_CLAUSE.search(body)
    return ReceivedHop(
        index=index,
        raw=raw,
        from_helo=from_helo,
        from_rdns=from_rdns,
        from_ip=from_ip,
        by_host=by_match.group(1).rstrip(".").lower() if by_match else None,
        protocol=with_match.group(1).upper() if with_match else None,
        timestamp=_parse_date(date_part),
        ip_is_public=is_public_ip(from_ip),
    )


def _addresses(values: list[str]) -> list[Address]:
    return [Address(name.strip(), addr.strip()) for name, addr in getaddresses(values) if addr]


def _decode_part(part: EmailMessage) -> str:
    try:
        content = part.get_content()
        return content if isinstance(content, str) else ""
    except (LookupError, UnicodeDecodeError, AssertionError, KeyError):
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="replace")


def _extract_links(text_body: str, html_body: str) -> list[Link]:
    from urllib.parse import urlsplit

    seen: set[tuple[str, str]] = set()
    links: list[Link] = []

    def add(href: str, text: str) -> None:
        href = href.strip()
        if not href.lower().startswith(("http://", "https://")):
            return
        key = (href, text)
        if key in seen:
            return
        seen.add(key)
        try:
            host = (urlsplit(href).hostname or "").lower()
        except ValueError:
            host = ""
        links.append(Link(href=href, text=_collapse(text)[:200], host=host))

    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")
        for anchor in soup.find_all("a", href=True):
            add(anchor["href"], anchor.get_text(" "))
    for match in _URL.findall(text_body):
        add(match.rstrip(".,;"), "")
    return links


def _from_address(modern: EmailMessage, legacy: EmailMessage) -> Address:
    """Decoded From address; falls back to a lenient parse when the header is malformed."""
    try:
        header = modern["From"]
        addresses = getattr(header, "addresses", ()) if header is not None else ()
        if addresses:
            first = addresses[0]
            return Address(_collapse(first.display_name or ""), first.addr_spec or "")
    except (ValueError, IndexError, TypeError):
        pass
    name, addr = parseaddr(str(legacy.get("From", "")))
    return Address(_collapse(name), addr)


def html_to_text(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "head"]):
        tag.decompose()
    return _collapse(soup.get_text(" "))


def parse_email(raw: bytes) -> ParsedEmail:
    msg: EmailMessage = message_from_bytes(raw, policy=policy.compat32.clone(linesep="\n"))  # type: ignore[assignment]
    # compat32 keeps malformed headers readable; the default policy raises on some forged ones.
    headers = [(k, _collapse(str(v))) for k, v in msg.items()]

    def all_of(name: str) -> list[str]:
        return [str(v) for v in (msg.get_all(name) or [])]

    received = all_of("Received")
    total = len(received)
    # Headers are prepended by each MTA, so the last Received header is the oldest hop.
    hops = [parse_received(value, total - 1 - i) for i, value in enumerate(received)]
    hops.sort(key=lambda h: h.index)

    text_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[Attachment] = []
    modern = message_from_bytes(raw, policy=policy.default)
    for part in modern.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                Attachment(
                    filename=filename or "(unnamed)",
                    content_type=part.get_content_type(),
                    size=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                )
            )
            continue
        ctype = part.get_content_type()
        if ctype == "text/plain":
            text_parts.append(_decode_part(part))  # type: ignore[arg-type]
        elif ctype == "text/html":
            html_parts.append(_decode_part(part))  # type: ignore[arg-type]

    html_body = "\n".join(html_parts)
    text_body = "\n".join(text_parts).strip() or (html_to_text(html_body) if html_body else "")

    from_addr = _from_address(modern, msg)
    return_path = parseaddr(str(msg.get("Return-Path", "")))[1]
    xoip = msg.get("X-Originating-IP") or msg.get("X-Sender-IP")
    xoip_value = _valid_ip(str(xoip).strip(" []")) if xoip else None

    return ParsedEmail(
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
        subject=_collapse(str(modern.get("Subject", ""))),
        from_=from_addr,
        reply_to=_addresses(all_of("Reply-To")),
        return_path=return_path,
        to=_addresses(all_of("To")),
        message_id=_collapse(str(msg.get("Message-ID", ""))),
        date=_parse_date(str(msg.get("Date", "")) or None),
        headers=headers,
        hops=hops,
        auth_results=[_collapse(v) for v in all_of("Authentication-Results")],
        received_spf=[_collapse(v) for v in all_of("Received-SPF")],
        dkim_signatures=[_collapse(v) for v in all_of("DKIM-Signature")],
        x_originating_ip=xoip_value,
        text_body=text_body,
        html_body=html_body,
        links=_extract_links(text_body, html_body),
        attachments=attachments,
    )
