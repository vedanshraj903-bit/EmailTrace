"""Forensic PDF report with evidence hash and chain-of-custody log."""

from __future__ import annotations

from datetime import UTC
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.schemas import AnalysisResult, CustodyEvent, GeoPoint

INK = colors.HexColor("#1b2330")
MUTED = colors.HexColor("#5b6675")
RULE = colors.HexColor("#d5dae1")
LEVEL_COLOR = {
    "low": colors.HexColor("#2f7d4f"),
    "medium": colors.HexColor("#a86b00"),
    "high": colors.HexColor("#c2410c"),
    "critical": colors.HexColor("#b42318"),
}


def location_label(geo: GeoPoint, short: bool = False) -> str:
    """Narrowest to broadest: city, sub-district, district, state, PIN, country."""
    if short:
        parts = [geo.city, geo.district, geo.country_code]
    else:
        parts = [geo.city, geo.subdistrict, geo.district, geo.region, geo.postal, geo.country or geo.country_code]
    unique = [p for i, p in enumerate(parts) if p and p not in parts[:i]]  # city and district often share a name
    return ", ".join(unique) or "unknown"


def _styles():
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=base["Title"], fontSize=17, textColor=INK, alignment=0, spaceAfter=2),
        "h2": ParagraphStyle("h2", parent=base["Heading2"], fontSize=11.5, textColor=INK, spaceBefore=10, spaceAfter=4),
        "body": ParagraphStyle("body", parent=base["BodyText"], fontSize=8.8, leading=11.5, textColor=INK),
        "muted": ParagraphStyle("muted", parent=base["BodyText"], fontSize=8, leading=10, textColor=MUTED),
        "mono": ParagraphStyle("mono", parent=base["Code"], fontSize=7.4, leading=9.2, textColor=INK),
    }


def _p(text: object, style) -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "—")), style)


def _table(rows: list[list], widths: list[float], header: bool = True) -> Table:
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0)
    commands = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, RULE),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
    ]
    if header:
        commands += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f5"))]
    table.setStyle(TableStyle(commands))
    return table


def build_pdf(result: AnalysisResult, custody: list[CustodyEvent]) -> bytes:
    s = _styles()
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title=f"Email forensic report {result.id}",
        author="EmailTrace",
    )
    width = doc.width
    story: list = []
    summary, risk = result.summary, result.risk

    story += [
        _p("Email Forensic Analysis Report", s["title"]),
        _p(f"Case {result.id} · generated from analysis at {result.created_at:%Y-%m-%d %H:%M:%S} UTC", s["muted"]),
        Spacer(0, 6),
    ]
    verdict = Table(
        [
            [
                Paragraph(
                    f"<b>{risk.score}</b>/100",
                    ParagraphStyle("score", fontSize=20, leading=22, textColor=LEVEL_COLOR[risk.level]),
                ),
                _p(f"Risk level: {risk.level.upper()}   Verdict: {risk.verdict.upper()}", s["body"]),
                _p(
                    f"Attribution: {result.attribution.assessment.replace('_', ' ')} "
                    f"({result.attribution.confidence:.0%} confidence). Evidence coverage {risk.coverage:.0%}.",
                    s["body"],
                ),
            ]
        ],
        colWidths=[28 * mm, 55 * mm, width - 83 * mm],
    )
    verdict.setStyle(
        TableStyle(
            [
                ("BOX", (0, 0), (-1, -1), 0.6, RULE),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story += [verdict]

    story += [
        _p("1. Evidence", s["h2"]),
        _table(
            [
                [_p("File", s["body"]), _p(result.filename or "raw upload", s["body"])],
                [_p("Size", s["body"]), _p(f"{result.size:,} bytes", s["body"])],
                [_p("SHA-256", s["body"]), _p(result.sha256, s["mono"])],
                [_p("Subject", s["body"]), _p(summary.subject, s["body"])],
                [_p("From", s["body"]), _p(f"{summary.from_.display_name} <{summary.from_.address}>", s["body"])],
                [_p("Reply-To", s["body"]), _p(", ".join(a.address for a in summary.reply_to) or "—", s["body"])],
                [_p("Return-Path", s["body"]), _p(summary.return_path or "—", s["body"])],
                [_p("Message-ID", s["body"]), _p(summary.message_id or "—", s["mono"])],
                [_p("Date header", s["body"]), _p(summary.date.isoformat() if summary.date else "—", s["body"])],
            ],
            [30 * mm, width - 30 * mm],
            header=False,
        ),
    ]

    story += [_p("2. Score breakdown", s["h2"])]
    rows = [[_p(h, s["body"]) for h in ("Component", "Weight", "Points", "Evidence")]]
    for c in risk.components:
        rows.append(
            [
                _p(c.label, s["body"]),
                _p(f"{c.weight:.0f}", s["body"]),
                _p(f"{c.points:.1f}" if c.available else "n/a", s["body"]),
                _p("; ".join(c.reasons), s["body"]),
            ]
        )
    story += [_table(rows, [48 * mm, 14 * mm, 14 * mm, width - 76 * mm])]

    story += [_p("3. Findings", s["h2"])]
    rows = [[_p(h, s["body"]) for h in ("Severity", "Finding", "Detail")]]
    for f in result.findings:
        rows.append([_p(f.severity.upper(), s["body"]), _p(f.title, s["body"]), _p(f.detail, s["body"])])
    story += [_table(rows, [18 * mm, 60 * mm, width - 78 * mm]) if len(rows) > 1 else _p("No findings.", s["body"])]

    auth = result.authentication
    story += [
        _p("4. Sender authentication", s["h2"]),
        _table(
            [
                [_p(h, s["body"]) for h in ("Check", "Result", "Detail")],
                [
                    _p("SPF", s["body"]),
                    _p(auth.spf.result, s["body"]),
                    _p(
                        f"{auth.spf.domain} from {auth.spf.ip} ({auth.spf.ip_source}). {auth.spf.explanation}",
                        s["body"],
                    ),
                ],
                *[
                    [
                        _p("DKIM", s["body"]),
                        _p(d.result, s["body"]),
                        _p(f"d={d.domain} s={d.selector}. {d.detail}", s["body"]),
                    ]
                    for d in auth.dkim
                ],
                [
                    _p("DMARC", s["body"]),
                    _p(auth.dmarc.result, s["body"]),
                    _p(
                        f"{auth.dmarc.record or 'no record'}; SPF aligned: {auth.dmarc.spf_aligned}, "
                        f"DKIM aligned: {auth.dmarc.dkim_aligned}; disposition: {auth.dmarc.disposition}",
                        s["body"],
                    ),
                ],
                [
                    _p("Receiver", s["body"]),
                    _p(auth.recorded.authserv_id or "—", s["body"]),
                    _p(f"spf={auth.recorded.spf} dkim={auth.recorded.dkim} dmarc={auth.recorded.dmarc}", s["body"]),
                ],
            ],
            [20 * mm, 20 * mm, width - 40 * mm],
        ),
    ]

    origin, domain = result.origin, result.domain
    geo = origin.geo
    story += [
        _p("5. Origin and infrastructure", s["h2"]),
        _table(
            [
                [_p("Origin IP", s["body"]), _p(f"{origin.ip or '—'} (source: {origin.source})", s["body"])],
                [
                    _p("Network", s["body"]),
                    _p(f"{origin.asn or ''} {origin.org or ''} · {origin.hosting_class.replace('_', ' ')}", s["body"]),
                ],
                [
                    _p("Reverse DNS", s["body"]),
                    _p(f"{origin.ptr or 'none'} (forward-confirmed: {origin.fcrdns})", s["body"]),
                ],
                [
                    _p("Location", s["body"]),
                    _p(
                        f"{location_label(geo)} ({geo.lat:.4f}, {geo.lon:.4f}) ±{geo.accuracy_radius_km} km"
                        if geo
                        else "unavailable",
                        s["body"],
                    ),
                ],
                [_p("Tor exit", s["body"]), _p(origin.tor_exit, s["body"])],
                [
                    _p("Blacklists", s["body"]),
                    _p(
                        ", ".join(
                            f"{l.zone}: {'listed' if l.listed else 'clean' if l.listed is False else l.code}"
                            for l in origin.dnsbl
                        )
                        or "—",
                        s["body"],
                    ),
                ],
                [_p("Note", s["body"]), _p(origin.note or "—", s["body"])],
                [
                    _p("Sender domain", s["body"]),
                    _p(
                        f"{domain.domain}; registrar {domain.whois.registrar or 'unknown'}; "
                        f"age {domain.whois.age_days if domain.whois.age_days is not None else 'unknown'} days; "
                        f"MX: {', '.join(domain.dns.mx) or 'none'}",
                        s["body"],
                    ),
                ],
            ],
            [30 * mm, width - 30 * mm],
            header=False,
        ),
    ]

    story += [_p("6. Relay path (oldest first)", s["h2"])]
    rows = [[_p(h, s["body"]) for h in ("#", "From", "IP", "By", "Time (UTC)", "Location")]]
    for hop in result.hops:
        loc = location_label(hop.geo, short=True) if hop.geo else ""
        rows.append(
            [
                _p(hop.index + 1, s["body"]),
                _p(hop.from_rdns or hop.from_helo, s["mono"]),
                _p(hop.from_ip, s["mono"]),
                _p(hop.by_host, s["mono"]),
                _p(hop.timestamp.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S") if hop.timestamp else "—", s["body"]),
                _p(loc or "—", s["body"]),
            ]
        )
    story += [_table(rows, [8 * mm, 42 * mm, 30 * mm, 42 * mm, 30 * mm, width - 152 * mm])]

    flagged_links = [l for l in result.links if l.flags]
    if flagged_links or result.attachments:
        story += [_p("7. Indicators of compromise", s["h2"])]
        rows = [[_p(h, s["body"]) for h in ("Type", "Value", "Flags")]]
        rows += [
            [_p("URL", s["body"]), _p(l.href, s["mono"]), _p("; ".join(l.flags), s["body"])] for l in flagged_links
        ]
        rows += [
            [
                _p("File", s["body"]),
                _p(f"{a.filename}\nsha256 {a.sha256}", s["mono"]),
                _p("; ".join(a.flags) or "—", s["body"]),
            ]
            for a in result.attachments
        ]
        story += [_table(rows, [14 * mm, 90 * mm, width - 104 * mm])]

    rows = [[_p(h, s["body"]) for h in ("Time (UTC)", "Event", "Detail")]]
    rows += [
        [_p(e.at.strftime("%Y-%m-%d %H:%M:%S"), s["body"]), _p(e.event, s["body"]), _p(e.detail, s["body"])]
        for e in custody
    ]
    story += [KeepTogether([_p("8. Chain of custody", s["h2"]), _table(rows, [34 * mm, 26 * mm, width - 60 * mm])])]
    story += [
        Spacer(0, 8),
        _p(
            "Automated analysis. Geolocation is approximate and reflects the network that relayed the message, which "
            "may be a provider, proxy or VPN rather than the author. Findings support, and do not replace, "
            "investigator judgement.",
            s["muted"],
        ),
    ]

    doc.build(story)
    return buffer.getvalue()
