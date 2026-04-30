from __future__ import annotations
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8",
        case_sensitive=False, extra="ignore",
    )
    app_env:   str  = "development"
    app_debug: bool = True
    database_url:          str = "postgresql+asyncpg://threatos:threatos_secret@localhost:5432/threatos"
    database_pool_size:    int = 10
    database_max_overflow: int = 20
    redis_url:             str = "redis://localhost:6379/0"
    redis_stream_name:     str = "threatos:events:normalized"
    redis_stream_maxlen:   int = 100_000
    redis_consumer_group:  str = "detection-workers"
    redis_consumer_name:   str = "worker-1"
    worker_batch_size:     int = 500
    worker_block_ms:       int = 200
    asset_criticality_ttl: int = 300
    coverage_refresh_interval_seconds: int = 3600
    attck_bundle_url: str = (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "enterprise-attack/enterprise-attack.json"
    )
    nmap_binary_path:     str = "/usr/bin/nmap"
    nmap_default_timeout: int = 300

@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()

settings = get_settings()
