"""HTTP API."""

from __future__ import annotations

import hashlib
import logging
import threading
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from app.config import get_settings
from app.db import Database
from app.schemas import AnalysisPage, AnalysisResult, CampaignGraph, CustodyEvent, Health, MailboxStatus, Stats
from app.services import geoip_update
from app.services.analyzer import Analyzer
from app.services.classifier import ContentClassifier
from app.services.feeds import Feeds
from app.services.geo import GeoLocator
from app.services.mailbox import MailboxWatcher
from app.services.report import build_pdf

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("emailtrace")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    db = Database(settings.database_path)
    feeds = Feeds()
    feeds.refresh_in_background()
    geo = GeoLocator(db)

    def refresh_geoip() -> None:
        if geoip_update.update(settings):
            geo.reload_databases()

    threading.Thread(target=refresh_geoip, name="geoip-refresh", daemon=True).start()
    classifier = ContentClassifier(settings.model_path)

    analyzer = Analyzer(db, feeds, geo, classifier)
    for sha in db.purge_older_than(settings.retention_days):
        if not analyzer.repo.sha_in_use(sha):
            analyzer.evidence_path(sha).unlink(missing_ok=True)

    app.state.analyzer = analyzer
    app.state.mailbox = MailboxWatcher(settings, analyzer)
    app.state.mailbox.start()
    yield
    app.state.mailbox.stop()
    geo.close()


app = FastAPI(title="EmailTrace API", version="1.0.0", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=get_settings().cors_origins,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)


def analyzer_dep(request: Request) -> Analyzer:
    return request.app.state.analyzer


AnalyzerDep = Annotated[Analyzer, Depends(analyzer_dep)]


def _require(analyzer: Analyzer, analysis_id: str) -> AnalysisResult:
    result = analyzer.repo.get(analysis_id)
    if result is None:
        raise HTTPException(404, "Analysis not found")
    return result


@app.get("/api/health", response_model=Health)
def health(analyzer: AnalyzerDep) -> Health:
    settings = get_settings()
    return Health(
        status="ok",
        classifier_loaded=analyzer.classifier.available,
        maxmind_city=analyzer.geo.city_reader is not None,
        maxmind_asn=analyzer.geo.asn_reader is not None,
        ipinfo_token=bool(settings.ipinfo_token),
        disposable_domains=len(analyzer.feeds.disposable),
        tor_exit_nodes=len(analyzer.feeds.tor_exits),
        whois_enabled=settings.enable_whois,
        smtp_probe_enabled=settings.enable_smtp_probe,
    )


@app.post("/api/analyses", response_model=AnalysisResult, response_model_by_alias=True, status_code=201)
def create_analysis(
    analyzer: AnalyzerDep,
    file: Annotated[UploadFile | None, File()] = None,
    raw: Annotated[str | None, Form()] = None,
) -> AnalysisResult:
    """Analyse a raw message uploaded as an .eml file or pasted as text (headers + body)."""
    limit = get_settings().max_upload_bytes
    if file is not None:
        data = file.file.read(limit + 1)
        filename = file.filename
    elif raw:
        data = raw.encode("utf-8", errors="surrogateescape")
        filename = None
    else:
        raise HTTPException(422, "Upload an .eml file or paste the raw message source.")
    if len(data) > limit:
        raise HTTPException(413, f"Message exceeds {limit // (1024 * 1024)} MB.")
    head = data[:4096].lower()
    if b":" not in head or not any(h in head for h in (b"from:", b"received:", b"subject:", b"message-id:")):
        raise HTTPException(422, "This does not look like a raw email. Export the original message with full headers.")
    return analyzer.analyze(data, filename)


@app.get("/api/analyses", response_model=AnalysisPage)
def list_analyses(
    analyzer: AnalyzerDep,
    q: str = "",
    level: str = "",
    verdict: str = "",
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AnalysisPage:
    return analyzer.repo.list(q.strip(), level, verdict, limit, offset)


@app.get("/api/analyses/{analysis_id}", response_model=AnalysisResult, response_model_by_alias=True)
def get_analysis(analysis_id: str, analyzer: AnalyzerDep) -> AnalysisResult:
    return _require(analyzer, analysis_id)


@app.delete("/api/analyses/{analysis_id}", status_code=204)
def delete_analysis(analysis_id: str, analyzer: AnalyzerDep) -> Response:
    sha = analyzer.repo.delete(analysis_id)
    if sha is None:
        raise HTTPException(404, "Analysis not found")
    analyzer.db.log_custody(analysis_id, sha, "deleted", "case removed by analyst")
    if not analyzer.repo.sha_in_use(sha):
        path = analyzer.evidence_path(sha)
        if path.exists():
            path.chmod(0o644)
            path.unlink()
    return Response(status_code=204)


def _custody(analyzer: Analyzer, analysis_id: str) -> list[CustodyEvent]:
    return [
        CustodyEvent(event=r["event"], at=r["at"], detail=r["detail"]) for r in analyzer.db.custody_events(analysis_id)
    ]


@app.get("/api/analyses/{analysis_id}/custody", response_model=list[CustodyEvent])
def custody(analysis_id: str, analyzer: AnalyzerDep) -> list[CustodyEvent]:
    _require(analyzer, analysis_id)
    return _custody(analyzer, analysis_id)


@app.get("/api/analyses/{analysis_id}/evidence")
def evidence(analysis_id: str, analyzer: AnalyzerDep) -> Response:
    result = _require(analyzer, analysis_id)
    path = analyzer.evidence_path(result.sha256)
    if not path.exists():
        raise HTTPException(410, "Evidence file was purged by the retention policy.")
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != result.sha256:
        analyzer.db.log_custody(analysis_id, result.sha256, "integrity_failure", "stored file hash mismatch")
        raise HTTPException(409, "Stored evidence failed its integrity check.")
    analyzer.db.log_custody(analysis_id, result.sha256, "evidence_exported", "hash verified before export")
    return Response(
        data,
        media_type="message/rfc822",
        headers={"Content-Disposition": f'attachment; filename="{result.sha256[:12]}.eml"'},
    )


@app.get("/api/analyses/{analysis_id}/report.pdf")
def report(analysis_id: str, analyzer: AnalyzerDep) -> Response:
    result = _require(analyzer, analysis_id)
    analyzer.db.log_custody(analysis_id, result.sha256, "report_generated", "PDF forensic report")
    pdf = build_pdf(result, _custody(analyzer, analysis_id))
    return Response(
        pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="emailtrace-{analysis_id}.pdf"'},
    )


@app.get("/api/graph", response_model=CampaignGraph)
def graph(analyzer: AnalyzerDep, analysis_id: str | None = None) -> CampaignGraph:
    return analyzer.repo.graph(analysis_id)


@app.get("/api/stats", response_model=Stats)
def stats(analyzer: AnalyzerDep) -> Stats:
    return analyzer.repo.stats()


@app.get("/api/mailbox", response_model=MailboxStatus)
def mailbox(request: Request) -> MailboxStatus:
    return request.app.state.mailbox.status()


def _mailbox_control(request: Request) -> MailboxWatcher:
    watcher: MailboxWatcher = request.app.state.mailbox
    if not watcher.enabled:
        raise HTTPException(409, "No mailbox is connected. Set IMAP_USER and IMAP_PASSWORD in backend/.env.")
    return watcher


@app.post("/api/mailbox/check", response_model=MailboxStatus)
def mailbox_check(request: Request) -> MailboxStatus:
    watcher = _mailbox_control(request)
    watcher.check_now()
    return watcher.status()


@app.post("/api/mailbox/pause", response_model=MailboxStatus)
def mailbox_pause(request: Request) -> MailboxStatus:
    watcher = _mailbox_control(request)
    watcher.pause()
    return watcher.status()


@app.post("/api/mailbox/resume", response_model=MailboxStatus)
def mailbox_resume(request: Request) -> MailboxStatus:
    watcher = _mailbox_control(request)
    watcher.resume()
    return watcher.status()


@app.post("/api/mailbox/scan", response_model=MailboxStatus)
def mailbox_scan(request: Request, count: Annotated[int, Query(ge=1, le=50)] = 10) -> MailboxStatus:
    watcher = _mailbox_control(request)
    watcher.scan_recent(count)
    return watcher.status()


@app.post("/api/model/reload", response_model=Health)
def reload_model(analyzer: AnalyzerDep) -> Health:
    analyzer.classifier.load()
    return health(analyzer)
