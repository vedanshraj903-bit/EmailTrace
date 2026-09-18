"""Runtime configuration, loaded from environment variables or backend/.env."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=BASE_DIR / ".env", extra="ignore")

    # External intelligence
    ipinfo_token: str = ""
    # GeoLite2 downloads (maxmind.com → Manage License Keys); the databases refresh weekly when set.
    maxmind_account_id: str = ""
    maxmind_license_key: str = ""
    maxmind_city_db: Path = DATA_DIR / "geoip" / "GeoLite2-City.mmdb"
    maxmind_asn_db: Path = DATA_DIR / "geoip" / "GeoLite2-ASN.mmdb"

    # Storage
    database_path: Path = DATA_DIR / "emailtrace.db"
    evidence_dir: Path = DATA_DIR / "evidence"
    model_path: Path = BASE_DIR / "ml" / "model.joblib"
    disposable_list_path: Path = DATA_DIR / "disposable_domains.txt"
    brands_path: Path = DATA_DIR / "protected_brands.json"

    # Network behaviour
    dns_timeout_s: float = 3.0
    http_timeout_s: float = 4.0
    enable_whois: bool = True
    enable_smtp_probe: bool = False  # outbound :25 is blocked on most networks
    smtp_timeout_s: float = 5.0

    # Geolocation fallback when only IPinfo answers (it has no accuracy radius)
    default_accuracy_radius_km: int = 25

    # Privacy / compliance
    mask_pii: bool = False
    retention_days: int = 180
    max_upload_bytes: int = 15 * 1024 * 1024

    # Cache lifetimes
    whois_cache_ttl_h: int = 24 * 7
    ip_cache_ttl_h: int = 24
    feed_refresh_h: int = 12

    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
