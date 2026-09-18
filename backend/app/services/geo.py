"""IP geolocation: IPinfo supplies coordinates, MaxMind GeoLite2 supplies the accuracy radius and ASN."""

from __future__ import annotations

import logging
from dataclasses import dataclass

import geoip2.database
import geoip2.errors
import httpx

from app.config import get_settings
from app.db import Database
from app.schemas import GeoPoint

log = logging.getLogger(__name__)


@dataclass
class IpInfo:
    geo: GeoPoint | None
    asn: str | None
    org: str | None
    hostname: str | None


def _open_reader(path) -> geoip2.database.Reader | None:
    try:
        return geoip2.database.Reader(str(path)) if path.exists() else None
    except (OSError, ValueError) as exc:
        log.warning("cannot open MaxMind database %s: %s", path, exc)
        return None


class GeoLocator:
    def __init__(self, db: Database) -> None:
        settings = get_settings()
        self._db = db
        self._token = settings.ipinfo_token
        self._timeout = settings.http_timeout_s
        self._default_radius = settings.default_accuracy_radius_km
        self._cache_ttl = settings.ip_cache_ttl_h
        self._city_path = settings.maxmind_city_db
        self._asn_path = settings.maxmind_asn_db
        self.city_reader = _open_reader(self._city_path)
        self.asn_reader = _open_reader(self._asn_path)
        self._http = httpx.Client(timeout=self._timeout)

    def reload_databases(self) -> None:
        """Swaps in freshly downloaded MaxMind files; lookups in flight keep the old reader until they finish."""
        old = (self.city_reader, self.asn_reader)
        self.city_reader = _open_reader(self._city_path)
        self.asn_reader = _open_reader(self._asn_path)
        for reader in old:
            if reader:
                reader.close()

    def _ipinfo(self, ip: str) -> dict | None:
        cache_key = f"ipinfo:{ip}"
        if (cached := self._db.cache_get(cache_key)) is not None:
            return cached or None
        # Sent as a header, not a query parameter, so the token never appears in URLs or request logs.
        headers = {"Authorization": f"Bearer {self._token}"} if self._token else {}
        try:
            response = self._http.get(f"https://ipinfo.io/{ip}/json", headers=headers)
            if response.status_code == 429:
                log.warning("IPinfo rate limit reached; set IPINFO_TOKEN")
                return None
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            log.warning("IPinfo lookup failed for %s: %s", ip, exc)
            return None
        data = {} if data.get("bogon") else data
        self._db.cache_set(cache_key, data, self._cache_ttl)
        return data or None

    def _maxmind_city(self, ip: str):
        if not self.city_reader:
            return None
        try:
            return self.city_reader.city(ip)
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return None

    def _maxmind_asn(self, ip: str) -> tuple[str | None, str | None]:
        if not self.asn_reader:
            return None, None
        try:
            record = self.asn_reader.asn(ip)
        except (geoip2.errors.AddressNotFoundError, ValueError):
            return None, None
        asn = f"AS{record.autonomous_system_number}" if record.autonomous_system_number else None
        return asn, record.autonomous_system_organization

    def lookup(self, ip: str) -> IpInfo:
        info = self._ipinfo(ip) or {}
        city = self._maxmind_city(ip)
        mm_asn, mm_org = self._maxmind_asn(ip)

        asn = org = None
        if info.get("org"):  # "AS15169 Google LLC"
            first, _, rest = info["org"].partition(" ")
            asn, org = (first, rest) if first.startswith("AS") else (None, info["org"])
        asn, org = asn or mm_asn, org or mm_org

        lat = lon = None
        coord_source = "ipinfo"
        if info.get("loc") and "," in info["loc"]:
            lat_s, lon_s = info["loc"].split(",", 1)
            lat, lon = float(lat_s), float(lon_s)
        elif city and city.location.latitude is not None:
            lat, lon, coord_source = city.location.latitude, city.location.longitude, "maxmind"

        geo = None
        if lat is not None and lon is not None:
            radius = city.location.accuracy_radius if city and city.location.accuracy_radius else None
            geo = GeoPoint(
                ip=ip,
                lat=lat,
                lon=lon,
                accuracy_radius_km=radius or self._default_radius,
                radius_source="maxmind" if radius else "default",
                coord_source=coord_source,
                city=info.get("city") or (city.city.name if city else None),
                region=info.get("region") or (city.subdivisions.most_specific.name if city else None),
                country=(city.country.name if city and city.country.name else None) or info.get("country"),
                country_code=info.get("country") or (city.country.iso_code if city else None),
                org=org,
                asn=asn,
                timezone=info.get("timezone") or (city.location.time_zone if city else None),
            )
        return IpInfo(geo=geo, asn=asn, org=org, hostname=info.get("hostname"))

    def close(self) -> None:
        self._http.close()
        for reader in (self.city_reader, self.asn_reader):
            if reader:
                reader.close()
