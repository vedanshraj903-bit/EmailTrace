"""Deterministic tests that need no network access."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.db import Database
from app.repository import Repository
from app.schemas import (
    Authentication,
    ClassifierResult,
    DkimCheck,
    DmarcCheck,
    DnsRecords,
    DomainIntel,
    GeoPoint,
    Lookalike,
    Origin,
    RecordedAuth,
    SpfCheck,
    Whois,
)
from app.services import authentication, dns_utils, patterns, scoring
from app.services.classifier import normalize_text
from app.services.domain_intel import detect_lookalike, levenshtein, skeleton
from app.services.feeds import Feeds
from app.services.infrastructure import classify_hosting, find_origin_ip, is_generic_ptr
from app.services.parser import parse_email, parse_received
from app.services.report import location_label
from app.services.reverse_geocode import parse_address

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def feeds() -> Feeds:
    return Feeds()


@pytest.fixture(scope="module")
def phishing():
    return parse_email((FIXTURES / "phishing_kyc.eml").read_bytes())


@pytest.fixture(scope="module")
def bec():
    return parse_email((FIXTURES / "bec_invoice.eml").read_bytes())


# --- parser ------------------------------------------------------------------


def test_received_header_extracts_bracketed_ip_and_time():
    hop = parse_received(
        "from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41]) by mx.google.com with SMTPS "
        "id a1; Tue, 16 Sep 2025 02:10:11 -0700 (PDT)",
        0,
    )
    assert hop.from_ip == "209.85.220.41"
    assert hop.from_rdns == "mail-sor-f41.google.com"
    assert hop.by_host == "mx.google.com"
    assert hop.protocol == "SMTPS"
    assert hop.timestamp == datetime(2025, 9, 16, 9, 10, 11, tzinfo=UTC)
    assert hop.ip_is_public


def test_received_header_ipv6_and_by_only():
    hop = parse_received(
        "from DB9PR01 (2603:10a6:10:2d4::5) by AM0PR02 (2603:10a6:208:1::1) with Microsoft SMTP "
        "Server; Tue, 16 Sep 2025 09:00:00 +0000",
        0,
    )
    assert hop.from_ip == "2603:10a6:10:2d4::5"
    internal = parse_received(
        "by 2002:a05:6a00:1a2b:b0:6f1:2345:6789 with SMTP id x; Tue, 16 Sep 2025 02:10:10 -0700", 0
    )
    assert internal.from_ip is None and internal.from_helo is None


def test_hops_are_ordered_oldest_first(phishing):
    assert [h.index for h in phishing.hops] == [0, 1, 2]
    assert phishing.hops[0].from_ip == "192.168.43.7"
    assert phishing.hops[1].from_ip == "159.89.174.23"


def test_parse_links_attachments_and_addresses(phishing):
    assert phishing.from_.display_name == "SBI Alerts"
    assert phishing.from_.domain == "onlinesbi-verify.com"
    assert phishing.reply_to[0].address == "sbi.kyc.desk@gmail.com"
    hrefs = {l.href for l in phishing.links}
    assert "http://159.89.174.23/sbi/login.php" in hrefs
    assert phishing.attachments[0].filename == "KYC_Form.pdf.exe"
    assert len(phishing.sha256) == 64


def test_origin_is_first_public_hop(phishing):
    assert find_origin_ip(phishing) == ("159.89.174.23", "received-chain")


# --- authentication ----------------------------------------------------------


def test_boundary_ip_prefers_received_spf(bec):
    assert authentication.boundary_ip(bec) == ("209.85.220.41", "Received-SPF header")


def test_recorded_results(bec):
    recorded = authentication.recorded_results(bec)
    assert recorded.authserv_id == "mx.google.com"
    assert (recorded.spf, recorded.dkim, recorded.dmarc) == ("pass", "pass", "pass")


def test_alignment_modes():
    assert authentication.aligned("mail.sbi.co.in", "sbi.co.in", "r")
    assert not authentication.aligned("mail.sbi.co.in", "sbi.co.in", "s")
    assert not authentication.aligned("sbi-alerts.com", "sbi.co.in", "r")
    assert dns_utils.registered_domain("a.b.example.co.uk") == "example.co.uk"


def test_dmarc_fail_when_nothing_aligned(monkeypatch):
    monkeypatch.setattr(
        dns_utils, "txt_with_prefix", lambda name, prefix: "v=DMARC1; p=reject" if name == "_dmarc.sbi.co.in" else None
    )
    spf = SpfCheck(result="pass", domain="evil.example", ip="1.2.3.4", ip_source="test")
    dkim = [DkimCheck(domain="evil.example", selector="s1", result="pass")]
    result = authentication.check_dmarc("sbi.co.in", spf, dkim)
    assert result.result == "fail" and result.disposition == "reject"
    ok = authentication.check_dmarc("sbi.co.in", spf, [DkimCheck(domain="mail.sbi.co.in", selector="s", result="pass")])
    assert ok.result == "pass" and ok.dkim_aligned


# --- domain intelligence -----------------------------------------------------


def test_levenshtein_and_skeleton():
    assert levenshtein("paypal", "paypa1") == 1
    assert skeleton("paypa1") == "paypal"
    assert skeleton("rnicrosoft") == "microsoft"


@pytest.mark.parametrize(
    "domain,technique",
    [
        ("paypa1.com", "homoglyph substitution"),
        ("flipkarrt.com", "typosquatting (edit distance)"),
        ("hdfcbank-kyc.com", "combosquatting (brand plus extra words)"),
        ("sbi.secure-login.xyz", "brand name placed in subdomain"),
    ],
)
def test_lookalike_detection(feeds, domain, technique):
    assert detect_lookalike(domain, feeds).technique == technique


@pytest.mark.parametrize("domain", ["sbi.co.in", "alerts.hdfcbank.com", "college.ac.in", "lib.com", "beta.com"])
def test_lookalike_no_false_positive(feeds, domain):
    assert detect_lookalike(domain, feeds).technique is None


def test_disposable_matches_parent_domain(feeds):
    feeds.disposable = frozenset({"mailinator.com"})
    assert feeds.is_disposable("mailinator.com")
    assert feeds.is_disposable("eu.mailinator.com")
    assert not feeds.is_disposable("gmail.com")


# --- infrastructure ----------------------------------------------------------


def test_hosting_classification():
    assert classify_hosting("mail-sor-f41.google.com", "Google LLC") == "mail_provider"
    assert classify_hosting(None, "DigitalOcean, LLC") == "cloud_hosting"
    assert classify_hosting(None, "Bharti Airtel Ltd.") == "isp"
    assert is_generic_ptr("ec2-3-5-7-9.compute-1.amazonaws.com")
    assert is_generic_ptr("abts-kk-dynamic-012.34.56.78.airtelbroadband.in")
    assert not is_generic_ptr("mx1.college.ac.in")


# --- patterns ----------------------------------------------------------------


def test_phishing_patterns(phishing, feeds):
    report = patterns.analyze(phishing, feeds)
    codes = {f.code for f in report.findings}
    assert {
        "reply_to_mismatch",
        "display_name_brand",
        "link_text_mismatch",
        "link_ip",
        "link_shortener",
        "attachment_critical",
        "credential_lure",
    } <= codes
    assert "urgency" in report.cues


def test_bec_patterns(bec, feeds):
    report = patterns.analyze(bec, feeds)
    codes = {f.code for f in report.findings}
    assert {"bec_language", "reply_to_mismatch", "executive_freemail"} <= codes
    reply = next(f for f in report.findings if f.code == "reply_to_mismatch")
    assert reply.severity == "medium"  # gmail -> outlook: both free mail


def test_hop_time_reversal_detected(feeds):
    raw = (FIXTURES / "phishing_kyc.eml").read_bytes().replace(b"04:44:01 +0000", b"05:44:01 +0000")
    report = patterns.analyze(parse_email(raw), feeds)
    assert "hop_time_reversal" in {f.code for f in report.findings}


# --- scoring -----------------------------------------------------------------


def _auth(dmarc_result: str, spf_result: str = "pass") -> Authentication:
    return Authentication(
        spf=SpfCheck(result=spf_result, domain="example.com", ip="8.8.8.8", ip_source="test"),
        dkim=[DkimCheck(domain="example.com", selector="s", result="pass")],
        dmarc=DmarcCheck(
            result=dmarc_result,
            from_domain="example.com",
            record="v=DMARC1; p=reject",
            record_domain="example.com",
            policy="reject",
            subdomain_policy=None,
            spf_aligned=dmarc_result == "pass",
            dkim_aligned=dmarc_result == "pass",
            disposition="deliver",
        ),
        recorded=RecordedAuth(authserv_id=None, spf=None, dkim=None, dmarc=None, raw=None),
        mismatches=[],
    )


def _domain(age: int | None = 4000) -> DomainIntel:
    return DomainIntel(
        domain="example.com",
        registered_domain="example.com",
        free_mail_provider=False,
        disposable=False,
        disposable_list_loaded=True,
        dns=DnsRecords(mx=["mx.example.com"], a=["1.1.1.1"], spf=None, dmarc=None),
        whois=Whois(available=True, age_days=age),
        lookalike=Lookalike(
            matched_brand=None, brand_domain=None, distance=None, technique=None, punycode=False, unicode_form=None
        ),
    )


def _origin() -> Origin:
    return Origin(
        ip="8.8.8.8",
        source="received-chain",
        boundary_ip="8.8.8.8",
        webmail_masked=False,
        note=None,
        ptr="mail.example.com",
        fcrdns=True,
        generic_ptr=False,
        asn="AS1",
        org="Example ISP",
        hosting_class="isp",
        tor_exit=False,
        dnsbl=[],
        smtp_probe=None,
        geo=None,
    )


def test_clean_message_scores_low():
    risk = scoring.score(_auth("pass"), _domain(), ClassifierResult(available=False), _origin(), [], False)
    assert risk.score < 25 and risk.verdict == "legitimate"
    assert risk.coverage == 1.0


def test_unavailable_component_is_excluded_not_counted_clean():
    risk = scoring.score(
        _auth("temperror", "temperror"), _domain(), ClassifierResult(available=False), _origin(), [], False
    )
    dmarc = next(c for c in risk.components if c.key == "dmarc")
    assert not dmarc.available and risk.coverage == 0.75


def test_spoofed_domain_attribution():
    auth = _auth("fail", "fail")
    risk = scoring.score(auth, _domain(), ClassifierResult(available=False), _origin(), [], False)
    assert risk.score >= 40
    assert scoring.attribute(risk, auth, _domain(), _origin()).assessment == "spoofed_domain"


def test_critical_attachment_escalates(phishing, feeds):
    report = patterns.analyze(phishing, feeds)
    risk = scoring.score(_auth("pass"), _domain(), ClassifierResult(available=False), _origin(), report.findings, False)
    assert risk.score >= 75 and risk.level == "critical"


# --- behaviour ---------------------------------------------------------------


def test_velocity_burst(tmp_path, bec):
    repo = Repository(Database(tmp_path / "t.db"))
    base = datetime(2025, 9, 16, 9, 0, tzinfo=UTC)
    template = {"id": "x", "created_at": base.isoformat()}
    with repo.db.connect() as conn:
        for i in range(4):
            conn.execute(
                "INSERT INTO analyses(id, created_at, sent_at, sha256, subject, from_address, from_domain, sender_key,"
                " origin_ip, score, level, verdict, result_json) VALUES (?, ?, ?, '', '', '', '', 'd', '5.6.7.8', 0,"
                " 'low', 'legitimate', '{}')",
                (f"{template['id']}{i}", template["created_at"], (base - timedelta(minutes=i)).isoformat()),
            )
    window = repo.velocity("origin_ip", "5.6.7.8", base, "Origin IP")
    assert window.count_5m == 5 and window.burst
    quiet = repo.velocity("origin_ip", "9.9.9.9", base, "Origin IP")
    assert quiet.count_5m == 1 and not quiet.burst


def test_normalize_text_maps_raw_and_corpus_formats_to_same_tokens():
    raw = normalize_text("Verify now", "Pay $500 at https://evil.example/login or call 555 0199")
    corpus = normalize_text("", "verify now pay moneytoken at httpevilexamplelogin or call escapenumber escapenumber")
    assert raw.split()[-5:] == corpus.split()[-5:] == ["urltoken", "or", "call", "numtoken", "numtoken"]
    assert "moneytoken" in raw and "escape" not in corpus


def test_parse_address_india_keeps_district_and_tehsil():
    admin = parse_address(
        {
            "city": "Bokaro",
            "county": "Chas",
            "state_district": "Bokaro",
            "state": "Jharkhand",
            "postcode": "827004",
            "country": "India",
            "country_code": "in",
        }
    )
    assert (admin.state, admin.district, admin.subdistrict, admin.city) == ("Jharkhand", "Bokaro", "Chas", "Bokaro")


def test_parse_address_county_is_district_when_no_state_district():
    admin = parse_address(
        {"town": "Hamina", "county": "Kymenlaakso", "state": "Southern Finland", "country": "Finland"}
    )
    assert (admin.district, admin.subdistrict, admin.city) == ("Kymenlaakso", None, "Hamina")


def test_location_label_orders_narrow_to_broad_without_repeats():
    geo = GeoPoint(
        ip="1.2.3.4",
        lat=23.67,
        lon=86.15,
        accuracy_radius_km=25,
        radius_source="default",
        coord_source="ipinfo",
        country="India",
        country_code="IN",
        region="Jharkhand",
        district="Bokaro",
        subdistrict="Chas",
        city="Bokaro",
        postal="827004",
    )
    assert location_label(geo) == "Bokaro, Chas, Jharkhand, 827004, India"
    assert location_label(geo, short=True) == "Bokaro, IN"


class _FakeImap:
    """Folder with UIDVALIDITY 7 holding the given UIDs; records every command sent."""

    def __init__(self, uids: list[int]) -> None:
        self.uids = uids
        self.commands: list[tuple] = []

    def status(self, folder, items):
        return "OK", [f'"INBOX" (UIDVALIDITY 7 UIDNEXT {max(self.uids) + 1})'.encode()]

    def uid(self, command, *args):
        self.commands.append((command, *args))
        if command == "SEARCH" and args[1] == "ALL":
            return "OK", [" ".join(map(str, self.uids)).encode()]
        if command == "SEARCH":
            start = int(args[1].split()[1].split(":")[0])
            return "OK", [" ".join(str(u) for u in self.uids if u >= start).encode() or str(self.uids[-1]).encode()]
        if "RFC822.SIZE" in args[1]:
            return "OK", [f"1 (UID {args[0]} RFC822.SIZE 100)".encode()]
        return "OK", [(f"1 (UID {args[0]} BODY[] {{9}}".encode(), b"raw " + args[0].encode()), b")"]


def _watcher(tmp_path, analyzed: list[bytes]):
    import hashlib
    from types import SimpleNamespace

    from app.config import Settings
    from app.services.mailbox import MailboxWatcher

    def analyze(raw, filename):
        analyzed.append(raw)
        summary = SimpleNamespace(subject="s", from_=SimpleNamespace(address="a@b.com"))
        risk = SimpleNamespace(score=90, level="critical", verdict="phishing")
        return SimpleNamespace(id="x", summary=summary, risk=risk)

    settings = Settings(imap_user="someone123@gmail.com", imap_password="secret", _env_file=None)
    known = {hashlib.sha256(b"raw 1").hexdigest()}  # UID 1 is already a case
    repo = SimpleNamespace(sha_in_use=lambda sha: sha in known)
    analyzer = SimpleNamespace(db=Database(tmp_path / "t.db"), analyze=analyze, repo=repo)
    return MailboxWatcher(settings, analyzer)


def test_mailbox_only_analyses_new_mail_without_marking_it_read(tmp_path):
    analyzed: list[bytes] = []
    watcher = _watcher(tmp_path, analyzed)
    conn = _FakeImap([1, 2, 3])
    last = watcher._start_position(conn)
    assert last == 3  # existing mail is left alone
    assert watcher._fetch_new(conn, last) == 3 and analyzed == []

    conn.uids = [1, 2, 3, 4, 5]
    assert watcher._fetch_new(conn, last) == 5
    assert analyzed == [b"raw 4", b"raw 5"]
    assert all("BODY[]" not in c[2] for c in conn.commands if c[0] == "FETCH")  # PEEK only
    assert watcher.status().analyzed == 2 and watcher.status().recent[0].level == "critical"

    # A restart resumes after UID 5 instead of repeating or skipping mail.
    assert _watcher(tmp_path, [])._start_position(conn) == 5


def test_mailbox_status_masks_account_and_hides_password(tmp_path):
    status = _watcher(tmp_path, []).status()
    assert status.account == "so***23@gmail.com"
    assert "secret" not in status.model_dump_json()


def test_mailbox_scan_recent_skips_mail_already_analyzed(tmp_path):
    analyzed: list[bytes] = []
    watcher = _watcher(tmp_path, analyzed)
    conn = _FakeImap([1, 2, 3])
    watcher.scan_recent(10)
    assert watcher.status().scan_pending
    watcher._scan(conn, last_uid=3)
    assert analyzed == [b"raw 2", b"raw 3"]
    status = watcher.status()
    assert not status.scan_pending
    assert status.notice == "Scanned 3 recent emails: 2 new, 1 already analyzed or skipped."


def test_mailbox_pause_and_resume(tmp_path):
    watcher = _watcher(tmp_path, [])
    watcher.pause()
    assert watcher.status().state == "paused"
    watcher.resume()
    assert watcher.status().state == "connecting"
    watcher.check_now()
    assert watcher._wake.is_set()
