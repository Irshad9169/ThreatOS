"""
core/settings.py
────────────────
All runtime configuration loaded from environment variables.
pydantic-settings validates every value at startup.

Oracle Linux 8 deployment notes
────────────────────────────────
  No code changes needed for OL8.  Run with:
    python3.11 -m uvicorn threatos.main:app --host 0.0.0.0 --port 8000
    python3.11 -m threatos.workers.ingest_worker
    python3.11 -m threatos.workers.coverage_worker
  All env vars are identical — only the Python binary name differs from Ubuntu.
"""
from __future__ import annotations

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ───────────────────────────────────────────────────────────
    app_env:   str  = "development"
    app_debug: bool = True

    # ── Database ──────────────────────────────────────────────────────────────
    database_url:         str = "postgresql+asyncpg://threatos:secret@localhost:5432/threatos"
    database_pool_size:   int = 10
    database_max_overflow:int = 20

    # ── Redis ─────────────────────────────────────────────────────────────────
    redis_url:          str = "redis://localhost:6379/0"
    redis_stream_name:  str = "threatos:events:normalized"
    redis_stream_maxlen:int = 100_000

    # Stream consumer group and consumer identity
    redis_consumer_group: str = "detection-workers"
    redis_consumer_name:  str = "worker-1"

    # ── Worker tuning ─────────────────────────────────────────────────────────
    # Number of stream messages to read per XREADGROUP call
    worker_batch_size: int = 500

    # How long (ms) to block waiting for new stream messages before re-polling
    worker_block_ms: int = 200

    # Asset criticality TTL in Redis (seconds).
    # Avoids a DB query per event for the same host.
    asset_criticality_ttl: int = 300   # 5 minutes

    # ── Coverage worker ───────────────────────────────────────────────────────
    coverage_refresh_interval_seconds: int = 3600   # 1 hour

    # ── ATT&CK bundle ─────────────────────────────────────────────────────────
    attck_bundle_url: str = (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "enterprise-attack/enterprise-attack.json"
    )

    # ── Nmap ──────────────────────────────────────────────────────────────────
    # OL8: dnf install nmap  → same binary path as Ubuntu
    nmap_binary_path:    str = "/usr/bin/nmap"
    nmap_default_timeout:int = 300

    @property
    def is_development(self) -> bool:
        return self.app_env == "development"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
