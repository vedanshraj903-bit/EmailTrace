"""Downloads MaxMind GeoLite2 City/ASN databases with the account ID + licence key from settings.

Run manually (from backend/):  python -m app.services.geoip_update [--force]
The API also calls update() at startup, in the background, when the databases are missing or stale.
"""

from __future__ import annotations

import io
import logging
import sys
import tarfile
import time
from pathlib import Path

import httpx

from app.config import Settings, get_settings

log = logging.getLogger(__name__)

DOWNLOAD_URL = "https://download.maxmind.com/geoip/databases/{edition}/download?suffix=tar.gz"
# GeoLite2 is republished twice a week; refreshing weekly keeps well inside MaxMind's 30-day update rule.
MAX_AGE_DAYS = 7


def _stale(path: Path) -> bool:
    return not path.exists() or (time.time() - path.stat().st_mtime) > MAX_AGE_DAYS * 86400


def credentials_configured(settings: Settings) -> bool:
    return bool(settings.maxmind_account_id and settings.maxmind_license_key)


def _download(edition: str, target: Path, settings: Settings) -> None:
    response = httpx.get(
        DOWNLOAD_URL.format(edition=edition),
        auth=(settings.maxmind_account_id, settings.maxmind_license_key),
        follow_redirects=True,
        timeout=120,
    )
    if response.status_code == 401:
        raise RuntimeError("MaxMind rejected the account ID / licence key (HTTP 401)")
    response.raise_for_status()
    with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as archive:
        member = next((m for m in archive.getmembers() if m.name.endswith(".mmdb")), None)
        if member is None:
            raise RuntimeError(f"{edition} archive contains no .mmdb file")
        data = archive.extractfile(member).read()
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(".tmp")
    tmp.write_bytes(data)
    tmp.replace(target)  # atomic: a running reader never sees a half-written file


def update(settings: Settings | None = None, force: bool = False) -> list[Path]:
    """Refreshes whichever databases are missing or stale. Returns the paths that were written."""
    settings = settings or get_settings()
    if not credentials_configured(settings):
        log.info("MaxMind credentials not set; skipping GeoLite2 download")
        return []
    written = []
    for edition, path in (("GeoLite2-City", settings.maxmind_city_db), ("GeoLite2-ASN", settings.maxmind_asn_db)):
        if not force and not _stale(path):
            continue
        try:
            _download(edition, path, settings)
        except (httpx.HTTPError, RuntimeError, tarfile.TarError) as exc:
            log.warning("GeoLite2 download failed for %s: %s", edition, exc)
            continue
        log.info("downloaded %s to %s", edition, path)
        written.append(path)
    return written


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    current = get_settings()
    if not credentials_configured(current):
        sys.exit("Set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY in backend/.env first.")
    paths = update(current, force="--force" in sys.argv)
    print("\n".join(f"updated {p}" for p in paths) or "databases are up to date (use --force to re-download)")
