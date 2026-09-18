"""Administrative breakdown (district, sub-district, …) for a coordinate, via OpenStreetMap Nominatim.

IP databases stop at city/state; Nominatim adds the district levels. The public service allows one
request per second with an identifying User-Agent (https://operations.osmfoundation.org/policies/nominatim/),
so calls are serialised, and results are cached per ~1 km grid cell.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass

import httpx

from app.config import get_settings
from app.db import Database

log = logging.getLogger(__name__)

USER_AGENT = "EmailTrace/1.0 (email forensics; self-hosted)"
MIN_INTERVAL_S = 1.1
CACHE_TTL_H = 24 * 90  # boundaries change rarely


@dataclass(frozen=True)
class AdminArea:
    country: str | None = None
    state: str | None = None
    district: str | None = None
    subdistrict: str | None = None
    city: str | None = None
    postal: str | None = None


def parse_address(address: dict) -> AdminArea:
    """Maps Nominatim's address keys, which vary by country, onto one hierarchy."""
    district = address.get("state_district") or address.get("district")
    county = address.get("county")
    if not district and county:  # many countries put the district-level unit in "county"
        district, county = county, None
    city = (
        address.get("city")
        or address.get("town")
        or address.get("municipality")
        or address.get("village")
        or address.get("suburb")
    )
    return AdminArea(
        country=address.get("country"),
        state=address.get("state") or address.get("region") or address.get("province"),
        district=district,
        subdistrict=county or address.get("subdistrict"),
        city=city,
        postal=address.get("postcode"),
    )


class ReverseGeocoder:
    def __init__(self, db: Database) -> None:
        settings = get_settings()
        self._db = db
        self._enabled = settings.enable_reverse_geocode
        self._url = settings.nominatim_url.rstrip("/")
        self._http = httpx.Client(timeout=settings.http_timeout_s, headers={"User-Agent": USER_AGENT})
        self._lock = threading.Lock()
        self._last_call = 0.0

    def lookup(self, lat: float, lon: float) -> AdminArea | None:
        if not self._enabled:
            return None
        cache_key = f"nominatim:{lat:.2f},{lon:.2f}"
        if (cached := self._db.cache_get(cache_key)) is not None:
            return parse_address(cached) if cached else None
        with self._lock:  # one request at a time, spaced per the usage policy
            wait = MIN_INTERVAL_S - (time.monotonic() - self._last_call)
            if wait > 0:
                time.sleep(wait)
            try:
                response = self._http.get(
                    f"{self._url}/reverse",
                    params={
                        "lat": lat,
                        "lon": lon,
                        "format": "jsonv2",
                        "zoom": 10,
                        "addressdetails": 1,
                        "accept-language": "en",  # otherwise names come back in the local script
                    },
                )
                response.raise_for_status()
                address = response.json().get("address") or {}
            except (httpx.HTTPError, ValueError) as exc:
                log.warning("reverse geocoding failed for %.4f,%.4f: %s", lat, lon, exc)
                return None
            finally:
                self._last_call = time.monotonic()
        self._db.cache_set(cache_key, address, CACHE_TTL_H)
        return parse_address(address) if address else None

    def close(self) -> None:
        self._http.close()
