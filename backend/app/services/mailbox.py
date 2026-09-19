"""Live mailbox: watches an IMAP folder and analyses each new message as it arrives.

The folder is opened read-only and messages are fetched with BODY.PEEK, so nothing is marked
as read, moved or deleted. Only mail that arrives after the first connection is analysed,
unless IMAP_BACKFILL asks for the most recent N messages as well.
"""

from __future__ import annotations

import contextlib
import imaplib
import logging
import re
import threading
from collections import deque
from datetime import datetime

from app.config import Settings
from app.db import utcnow
from app.schemas import MailboxEvent, MailboxStatus
from app.services.analyzer import Analyzer

log = logging.getLogger(__name__)

RECONNECT_S = 30
AUTH_RETRY_S = 300  # a rejected password will not fix itself; retry slowly
_UIDVALIDITY = re.compile(rb"UIDVALIDITY (\d+)")
_UIDNEXT = re.compile(rb"UIDNEXT (\d+)")


def mask_address(address: str) -> str:
    """jane.doe42@gmail.com → ja***42@gmail.com, so the status API never exposes the full mailbox."""
    local, _, domain = address.partition("@")
    shown = f"{local[:2]}***{local[-2:]}" if len(local) > 4 else f"{local[:1]}***"
    return f"{shown}@{domain}" if domain else shown


class MailboxWatcher:
    def __init__(self, settings: Settings, analyzer: Analyzer) -> None:
        self._settings = settings
        self._analyzer = analyzer
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._state = "connecting" if self.enabled else "disabled"
        self._error: str | None = None
        self._last_check: datetime | None = None
        self._analyzed = 0
        self._recent: deque[MailboxEvent] = deque(maxlen=20)
        self._validity = 0

    @property
    def enabled(self) -> bool:
        return bool(self._settings.imap_user and self._settings.imap_password)

    @property
    def _state_key(self) -> str:
        return f"imap:{self._settings.imap_user.lower()}:{self._settings.imap_folder}"

    # --- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        if not self.enabled:
            log.info("mailbox: IMAP_USER / IMAP_PASSWORD not set; live mailbox is off")
            return
        self._thread = threading.Thread(target=self._run, name="mailbox", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def status(self) -> MailboxStatus:
        with self._lock:
            return MailboxStatus(
                enabled=self.enabled,
                state=self._state,
                account=mask_address(self._settings.imap_user) if self.enabled else None,
                folder=self._settings.imap_folder,
                poll_seconds=self._settings.imap_poll_s,
                last_check=self._last_check,
                error=self._error,
                analyzed=self._analyzed,
                recent=list(reversed(self._recent)),
            )

    def _set(self, state: str, error: str | None = None) -> None:
        with self._lock:
            self._state, self._error = state, error

    # --- watch loop --------------------------------------------------------

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._watch()
            except imaplib.IMAP4.error as exc:
                detail = exc.args[0] if exc.args else exc
                message = detail.decode(errors="replace") if isinstance(detail, bytes) else str(detail)
                auth = "AUTHENTICATIONFAILED" in message or "Invalid credentials" in message
                self._set("error", "Login rejected. Check IMAP_USER and the app password." if auth else message)
                log.warning("mailbox: %s", message)
                self._stop.wait(AUTH_RETRY_S if auth else RECONNECT_S)
            except (OSError, imaplib.IMAP4.abort) as exc:
                self._set("error", f"Connection lost: {exc}")
                log.warning("mailbox: connection lost: %s", exc)
                self._stop.wait(RECONNECT_S)

    def _watch(self) -> None:
        s = self._settings
        self._set("connecting")
        conn = imaplib.IMAP4_SSL(s.imap_host, s.imap_port, timeout=30)
        try:
            conn.login(s.imap_user, s.imap_password)
            last_uid = self._start_position(conn)
            conn.select(f'"{s.imap_folder}"', readonly=True)
            self._set("connected")
            log.info("mailbox: watching %s for %s", s.imap_folder, mask_address(s.imap_user))
            while not self._stop.is_set():
                conn.noop()  # lets the server report new mail on the selected folder
                last_uid = self._fetch_new(conn, last_uid)
                with self._lock:
                    self._last_check = utcnow()
                self._stop.wait(s.imap_poll_s)
        finally:
            with contextlib.suppress(OSError, imaplib.IMAP4.error, imaplib.IMAP4.abort):
                conn.logout()

    def _start_position(self, conn: imaplib.IMAP4_SSL) -> int:
        """Returns the highest UID already handled, so a restart neither repeats nor skips mail."""
        _, data = conn.status(f'"{self._settings.imap_folder}"', "(UIDVALIDITY UIDNEXT)")
        raw = data[0] or b""
        validity = int(m.group(1)) if (m := _UIDVALIDITY.search(raw)) else 0
        uidnext = int(m.group(1)) if (m := _UIDNEXT.search(raw)) else 1
        saved = self._analyzer.db.cache_get(self._state_key)
        self._validity = validity
        if saved and saved.get("uidvalidity") == validity:
            return int(saved["last_uid"])
        # First run, or the server renumbered the folder: start from now, plus any requested backfill.
        start = max(0, uidnext - 1 - self._settings.imap_backfill)
        self._save_position(start)
        return start

    def _save_position(self, last_uid: int) -> None:
        state = {"uidvalidity": self._validity, "last_uid": last_uid}
        self._analyzer.db.cache_set(self._state_key, state, 24 * 365 * 10)

    def _fetch_new(self, conn: imaplib.IMAP4_SSL, last_uid: int) -> int:
        _, data = conn.uid("SEARCH", None, f"UID {last_uid + 1}:*")
        # "n:*" always matches the newest message, even when its UID is below n.
        uids = sorted(u for u in map(int, (data[0] or b"").split()) if u > last_uid)
        if not uids:
            return last_uid
        for uid in uids:
            if self._stop.is_set():
                break
            self._analyze_uid(conn, uid)
            last_uid = uid
            self._save_position(last_uid)
        return last_uid

    def _analyze_uid(self, conn: imaplib.IMAP4_SSL, uid: int) -> None:
        limit = self._settings.max_upload_bytes
        _, size_data = conn.uid("FETCH", str(uid), "(RFC822.SIZE)")
        size = int(m.group(1)) if size_data and (m := re.search(rb"RFC822\.SIZE (\d+)", size_data[0] or b"")) else 0
        if size > limit:
            log.info("mailbox: skipping UID %s (%s bytes exceeds the upload limit)", uid, size)
            return
        _, data = conn.uid("FETCH", str(uid), "(BODY.PEEK[])")
        raw = next((part[1] for part in data if isinstance(part, tuple)), None)
        if not raw:
            return
        try:
            result = self._analyzer.analyze(raw, f"mailbox {self._settings.imap_folder} #{uid}")
        except Exception:  # one unparseable message must not stop the watcher
            log.exception("mailbox: analysis failed for UID %s", uid)
            return
        event = MailboxEvent(
            analysis_id=result.id,
            received_at=utcnow(),
            subject=result.summary.subject,
            from_address=result.summary.from_.address,
            score=result.risk.score,
            level=result.risk.level,
            verdict=result.risk.verdict,
        )
        with self._lock:
            self._recent.append(event)
            self._analyzed += 1
        log.info("mailbox: analysed UID %s → %s (%s)", uid, result.risk.level, result.risk.score)
