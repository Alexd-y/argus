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
    # Dedicated bucket for generated report files (presigned/download); stage artifacts stay in minio_bucket / stage buckets.
    minio_reports_bucket: str = "argus-reports"
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
    # Optional path to xsstrike.py on the host (see plugins/tools/xsstrike). Env: XSSTRIKE_SCRIPT_PATH
    xsstrike_script_path: str | None = None
    recon_max_concurrent_jobs: int = 5
    # VA active scan / sandbox (OWASP-002): max concurrent async tool runs
    active_scan_max_concurrent_jobs: int = 3
    active_scan_max_capture_bytes: int = 4 * 1024 * 1024
    # OWASP-004 — VA active scan phase (dalfox/ffuf/sqlmap); sqlmap off by default
    sqlmap_va_enabled: bool = False
    # VA-007 — after vuln findings, exploitation phase may enqueue Celery sqlmap (policy + approval)
    va_exploit_aggressive_enabled: bool = False
    # VA-002 — append LLM-suggested active-scan argv after deterministic plan (requires LLM keys)
    va_ai_plan_enabled: bool = False
    va_active_scan_tool_timeout_sec: float = 120.0
    ffuf_va_wordlist_path: str = ""
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

    # WEB-006 — destructive tools requiring explicit per-scan approval
    destructive_tool_names: str = "sqlmap,commix"

    # RPT-004 — AI report section text cache (Redis)
    ai_text_cache_ttl_seconds: int = 604800

    @property
    def celery_broker(self) -> str:
        return self.celery_broker_url or self.redis_url

    @property
    def destructive_tools(self) -> frozenset[str]:
        """Parse DESTRUCTIVE_TOOL_NAMES into a deduplicated frozenset of canonical names."""
        return frozenset(
            t.strip().lower()
            for t in self.destructive_tool_names.split(",")
            if t.strip()
        )

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


def _sync_llm_api_keys_to_environ() -> None:
    """Copy LLM keys from Pydantic-loaded ``backend/.env`` into ``os.environ``.

    Pydantic Settings reads ``.env`` into ``settings`` fields but does not populate
    ``os.environ``. Code in ``src.llm.adapters`` and ``src.core.llm_config`` only
    reads ``os.environ``. Values already set in the real environment win.
    """
    pairs: list[tuple[str, str | None]] = [
        ("OPENAI_API_KEY", settings.openai_api_key),
        ("DEEPSEEK_API_KEY", settings.deepseek_api_key),
        ("OPENROUTER_API_KEY", settings.openrouter_api_key),
        ("GOOGLE_API_KEY", settings.google_api_key),
        ("KIMI_API_KEY", settings.kimi_api_key),
        ("PERPLEXITY_API_KEY", settings.perplexity_api_key),
    ]
    for env_key, val in pairs:
        if not val or not str(val).strip():
            continue
        if (os.environ.get(env_key) or "").strip():
            continue
        os.environ[env_key] = str(val).strip()


_sync_llm_api_keys_to_environ()
