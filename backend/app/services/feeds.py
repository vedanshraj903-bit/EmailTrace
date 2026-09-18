"""Downloadable reference lists (disposable domains, Tor exit nodes, protected brands) cached on disk."""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import httpx

from app.config import DATA_DIR, get_settings

log = logging.getLogger(__name__)

DISPOSABLE_URL = (
    "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/"
    "main/disposable_email_blocklist.conf"
)
TOR_EXIT_URL = "https://check.torproject.org/torbulkexitlist"
TOR_EXIT_PATH = DATA_DIR / "tor_exit_nodes.txt"

FREE_MAIL_PROVIDERS = frozenset(
    {
        "gmail.com",
        "googlemail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "msn.com",
        "outlook.in",
        "yahoo.com",
        "yahoo.co.in",
        "yahoo.in",
        "ymail.com",
        "rocketmail.com",
        "rediffmail.com",
        "icloud.com",
        "me.com",
        "mac.com",
        "aol.com",
        "proton.me",
        "protonmail.com",
        "pm.me",
        "zoho.com",
        "zohomail.com",
        "zohomail.in",
        "gmx.com",
        "gmx.net",
        "mail.com",
        "yandex.com",
        "yandex.ru",
        "tutanota.com",
        "tuta.io",
        "mail.ru",
        "inbox.com",
        "fastmail.com",
        "hushmail.com",
    }
)


@dataclass(frozen=True)
class Brand:
    name: str
    domains: tuple[str, ...]
    keywords: tuple[str, ...]


def _read_lines(path: Path) -> set[str]:
    if not path.exists():
        return set()
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    return {line.strip().lower() for line in lines if line.strip() and not line.startswith("#")}


def _is_stale(path: Path, max_age_h: float) -> bool:
    return not path.exists() or (time.time() - path.stat().st_mtime) > max_age_h * 3600


class Feeds:
    def __init__(self) -> None:
        settings = get_settings()
        self._disposable_path = settings.disposable_list_path
        self._refresh_h = settings.feed_refresh_h
        self.disposable: frozenset[str] = frozenset(_read_lines(self._disposable_path))
        self.tor_exits: frozenset[str] = frozenset(_read_lines(TOR_EXIT_PATH))
        self.tor_loaded = TOR_EXIT_PATH.exists()
        raw_brands = json.loads(settings.brands_path.read_text(encoding="utf-8"))
        self.brands: tuple[Brand, ...] = tuple(
            Brand(b["name"], tuple(d.lower() for d in b["domains"]), tuple(k.lower() for k in b.get("keywords", [])))
            for b in raw_brands
        )
        self.brand_domains: frozenset[str] = frozenset(d for b in self.brands for d in b.domains)

    def _download(self, url: str, path: Path) -> bool:
        try:
            response = httpx.get(url, timeout=20, follow_redirects=True)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            log.warning("feed download failed for %s: %s", url, exc)
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(response.text, encoding="utf-8")
        tmp.replace(path)
        return True

    def refresh(self) -> None:
        if _is_stale(self._disposable_path, self._refresh_h * 14) and self._download(
            DISPOSABLE_URL, self._disposable_path
        ):
            self.disposable = frozenset(_read_lines(self._disposable_path))
        if _is_stale(TOR_EXIT_PATH, self._refresh_h) and self._download(TOR_EXIT_URL, TOR_EXIT_PATH):
            self.tor_exits = frozenset(_read_lines(TOR_EXIT_PATH))
            self.tor_loaded = True
        log.info("feeds: %d disposable domains, %d tor exit nodes", len(self.disposable), len(self.tor_exits))

    def refresh_in_background(self) -> None:
        threading.Thread(target=self.refresh, name="feed-refresh", daemon=True).start()

    def is_disposable(self, domain: str) -> bool:
        # The blocklist contains registrable domains; also match any parent (e.g. x.mailinator.com).
        labels = domain.lower().split(".")
        return any(".".join(labels[i:]) in self.disposable for i in range(len(labels) - 1))
