"""ARGUS Backend — configuration from environment."""

import os

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings from env vars."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "postgresql+asyncpg://argus:argus@localhost:5432/argus"

    @field_validator("database_url", mode="after")
    @classmethod
    def ensure_asyncpg(cls, v: str) -> str:
        if v.startswith("postgresql://") and "+asyncpg" not in v:
            return v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v
    jwt_secret: str = ""
    jwt_expiry: str = "15m"
    jwt_algorithm: str = "HS256"
    cors_origins: str = "*"
    vercel_frontend_url: str = ""
    debug: bool = False
    log_level: str = "INFO"
    version: str = "0.1.0"
    default_tenant_id: str = "00000000-0000-0000-0000-000000000001"

    # LLM Providers (Phase 6) — at least one required for AI orchestration
    openai_api_key: str | None = None
    deepseek_api_key: str | None = None
    openrouter_api_key: str | None = None
    google_api_key: str | None = None
    kimi_api_key: str | None = None
    perplexity_api_key: str | None = None

    # Data Sources (Phase 6) — optional
    censys_api_key: str | None = None
    securitytrails_api_key: str | None = None
    virustotal_api_key: str | None = None
    hibp_api_key: str | None = None

    # MinIO/S3 (Phase 7 — reports, screenshots). Env: MINIO_ENDPOINT, MINIO_ACCESS_KEY, etc.
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "argus"
    minio_secret_key: str = "argussecret"
    minio_bucket: str = "argus"
    minio_secure: bool = False

    # Redis & Celery (Phase 5)
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str | None = None  # Defaults to redis_url if unset
    sandbox_container_name: str = "argus-sandbox"
    sandbox_enabled: bool = False  # Enable docker exec into sandbox when True

    # Admin API — when set, admin endpoints require X-Admin-Key header
    admin_api_key: str | None = None

    # Recon Module (Phase 8)
    recon_tools_timeout: int = 300
    recon_max_concurrent_jobs: int = 5
    recon_artifact_bucket: str = "argus-recon"
    recon_default_dns_resolver: str = "8.8.8.8"
    recon_scope_strict: bool = True
    recon_rate_limit_per_second: int = 10
    recon_max_subdomains: int = 10000
    recon_output_base_dir: str = "./recon_output"
    stage1_artifacts_bucket: str = "stage1-artifacts"
    stage2_artifacts_bucket: str = "stage2-artifacts"
    stage3_artifacts_bucket: str = "stage3-artifacts"
    stage4_artifacts_bucket: str = "stage4-artifacts"
    exploitation_timeout_minutes: int = 10
    exploitation_max_concurrent: int = 3
    exploitation_approval_timeout_minutes: int = 60

    @property
    def celery_broker(self) -> str:
        return self.celery_broker_url or self.redis_url

    def get_cors_origins_list(self) -> list[str]:
        """Merge VERCEL_FRONTEND_URL, CORS_ORIGINS, and localhost dev origins (deduped)."""
        dev_defaults = [
            "http://localhost:5000",
            "http://127.0.0.1:5000",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:5800",
            "http://127.0.0.1:5800",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
            "http://localhost:3001",
            "http://127.0.0.1:3001",
        ]
        seen: set[str] = set()
        out: list[str] = []

        def add(origin: str) -> None:
            o = origin.strip().rstrip("/")
            if o and o not in seen:
                seen.add(o)
                out.append(o)

        vf = (self.vercel_frontend_url or "").strip()
        if vf:
            add(vf)

        raw = (self.cors_origins or "").strip()
        if raw and raw != "*":
            for part in raw.split(","):
                add(part)

        include_dev = self.debug or os.getenv("CORS_INCLUDE_DEV_ORIGINS", "true").lower() == "true"
        if not out:
            return list(dev_defaults) if include_dev else []

        if include_dev:
            for d in dev_defaults:
                add(d)
        return out


settings = Settings()
