"""ARGUS Backend — configuration from environment."""

import os

from typing import Literal

from pydantic import AliasChoices, Field, field_validator
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
    llm_primary_provider: str = Field(
        default="",
        validation_alias=AliasChoices("LLM_PRIMARY_PROVIDER", "llm_primary_provider"),
    )
    max_cost_per_scan_usd: float = Field(
        default=10.0,
        validation_alias=AliasChoices("MAX_COST_PER_SCAN_USD", "max_cost_per_scan_usd"),
    )

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
    # External URL for presigned links in reports (replaces internal Docker hostname).
    # When unset, presigned URLs are returned as-is (dev mode).
    minio_public_url: str | None = None

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
    # Aggressive argv merge from ``data/tool_configs.json`` (extra flags / payload wordlists).
    # Default false so unit tests and CI keep stable argv; set VA_AGGRESSIVE_SCAN=true in prod.
    va_aggressive_scan: bool = False
    # Worker-side reflected XSS probe (httpx); runs after VA active scan when sandbox + target.
    va_custom_xss_poc_enabled: bool = True
    # XSS-006 — dedicated XSS engine (payload repos, headless verification, caps). Env: XSS_*.
    xss_payload_repos: str = ""
    # Optional JSON array of payload strings (HTTP GET once, merged into all context buckets). Env: XSS_PAYLOAD_COLLECTION_URL
    xss_payload_collection_url: str = ""
    # Legacy seconds-based cap; prefer xss_playwright_timeout_ms for Playwright navigation.
    xss_verification_headless_timeout: int = 15
    xss_max_payloads_per_param: int = 50
    # XSS_VERIFICATION_ENABLED — headless Playwright XSS verification (T3).
    xss_verification_enabled: bool = True
    # XSS_PLAYWRIGHT_TIMEOUT or XSS_PLAYWRIGHT_TIMEOUT_MS (milliseconds).
    xss_playwright_timeout_ms: int = Field(
        default=5000,
        validation_alias=AliasChoices(
            "XSS_PLAYWRIGHT_TIMEOUT",
            "XSS_PLAYWRIGHT_TIMEOUT_MS",
        ),
    )
    # Deprecated: use xss_verification_enabled. Kept for backward-compatible env parsing only.
    xss_browser_verification_enabled: bool = False
    xss_context_detection_enabled: bool = True
    # Optional Playwright PNG + response_snippet enrichment for XSS / open-redirect PoCs (POC-003).
    # Requires ``playwright`` + browser install; off by default. Env: VA_POC_PLAYWRIGHT_SCREENSHOT_ENABLED.
    va_poc_playwright_screenshot_enabled: bool = False
    # POC-004 — embed PoC screenshot as <img> in tier HTML/PDF (inflates size); link-only by default.
    # Env: REPORT_POC_EMBED_SCREENSHOT_INLINE
    report_poc_embed_screenshot_inline: bool = False
    # RPT / Valhalla — отображаемое имя исполнителя на титульном листе отчёта.
    # Env: REPORT_EXECUTOR_DISPLAY_NAME
    report_executor_display_name: str = "Svalbard Security Inc."
    # VA-007 — after vuln findings, exploitation phase may enqueue Celery sqlmap (policy + approval)
    va_exploit_aggressive_enabled: bool = False
    # VA-002 — append LLM-suggested active-scan argv after deterministic plan (requires LLM keys)
    va_ai_plan_enabled: bool = False
    va_active_scan_tool_timeout_sec: float = 120.0
    # KAL-004 — recon hooks (whatweb / nikto / TLS probe); ssl probe needs headroom
    va_whatweb_timeout_sec: float = 90.0
    va_nikto_timeout_sec: float = 180.0
    va_ssl_probe_timeout_sec: float = 300.0
    ffuf_va_wordlist_path: str = ""
    # KAL-005 — feroxbuster (time cap + operator-chosen small wordlists in sandbox)
    va_ferox_time_limit_sec: int = 90
    va_ferox_wordlist_max_lines: int = 5000
    # KAL-005 — recon DNS sandbox (max apex domains = 1 by default; max parsed subdomain intel lines)
    kal_recon_dns_max_domains: int = 1
    kal_recon_dns_max_lines: int = 200
    # KAL-005 — tcpdump (allowlist interface names, comma-separated)
    va_tcpdump_allowed_interfaces: str = "eth0,lo"
    va_tcpdump_interface: str = "eth0"
    va_tcpdump_max_packets: int = 200
    va_tcpdump_timeout_sec: float = 45.0
    va_mitmdump_listen_port: int = 8899
    va_mitmdump_timeout_sec: float = 25.0
    va_capture_max_upload_bytes: int = 5_000_000
    recon_artifact_bucket: str = "argus-recon"
    recon_default_dns_resolver: str = "8.8.8.8"
    recon_scope_strict: bool = True
    recon_rate_limit_per_second: int = 10
    # RECON-001 — optional override for pipeline throttling (when unset, use recon_rate_limit_per_second).
    recon_rate_limit: int | None = None
    recon_max_subdomains: int = 10000
    # RECON-002 — optional cap for passive subdomain CLI bundle (falls back to RECON_TOOLS_TIMEOUT if unset)
    recon_passive_subdomain_timeout_sec: int | None = None
    # RECON-002 — theHarvester -b sources (comma-separated, subset of policy allowlist)
    recon_theharvester_sources: str = "crtsh,anubis,urlscan"
    recon_theharvester_recon_limit: int = 300
    recon_theharvester_passive_enabled: bool = True
    # RECON-001 — pipeline mode (passive / active / full). Default full preserves legacy behavior.
    recon_mode: Literal["passive", "active", "full"] = "full"
    # When true, forces passive mode regardless of recon_mode.
    recon_passive_only: bool = False
    recon_active_depth: int = 1
    recon_enable_content_discovery: bool = False
    recon_deep_port_scan: bool = False
    # RECON-005 — optional naabu + nmap -sV deep scan (full mode + RECON_DEEP_PORT_SCAN only)
    recon_deep_naabu_enabled: bool = True
    recon_deep_naabu_top_ports: int = 500
    recon_deep_max_hosts: int = 5
    recon_deep_max_ports_per_host: int = 40
    recon_deep_timeout_sec: int | None = None
    recon_js_analysis: bool = False
    # RECON-007 — JS / query-param harvest (caps + optional linkfinder / unfurl CLI)
    recon_js_max_merged_urls: int = 20000
    recon_js_max_js_urls: int = 200
    recon_js_max_downloads: int = 15
    recon_js_max_response_bytes: int = 1_048_576
    recon_js_linkfinder_enabled: bool = True
    recon_js_unfurl_enabled: bool = False
    recon_js_unfurl_max_urls: int = 10
    recon_screenshots: bool = False
    # RECON-008 — asnmap (apex) + gowitness caps (full mode + flags; passive has no optional steps)
    recon_asnmap_enabled: bool = True
    recon_gowitness_max_urls: int = 25
    recon_gowitness_timeout_sec: int | None = None
    recon_gowitness_concurrency: int = 3
    recon_tool_selection: str = ""
    recon_wordlist_path: str = ""
    # RECON-003 — dnsx multi-type probe, optional dig ANY, MinIO dns_records + raw; heuristic takeover hints
    recon_dns_depth_enabled: bool = True
    recon_dns_depth_dig_deep: bool = False
    recon_dns_depth_takeover_hints: bool = True
    recon_dnsx_record_types: str = "a,aaaa,cname,mx,txt,ns"
    recon_dnsx_include_resp: bool = False
    recon_dnsx_silent: bool = False
    recon_dns_depth_timeout_sec: int | None = None
    recon_dnsx_extra_flags: str = ""
    # RECON-004 — httpx / whatweb / nuclei tech recon (nuclei: -tags or comma -t list from env)
    recon_nuclei_tech_tags: str = "tech"
    recon_nuclei_tech_templates: str = ""

    # ENH-V2 — Feature flags for new enrichment modules
    shodan_enrichment_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("SHODAN_ENRICHMENT_ENABLED", "shodan_enrichment_enabled"),
    )
    perplexity_intel_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("PERPLEXITY_INTEL_ENABLED", "perplexity_intel_enabled"),
    )
    adversarial_score_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("ADVERSARIAL_SCORE_ENABLED", "adversarial_score_enabled"),
    )
    exploitability_validation_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("EXPLOITABILITY_VALIDATION_ENABLED", "exploitability_validation_enabled"),
    )
    poc_generation_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("POC_GENERATION_ENABLED", "poc_generation_enabled"),
    )

    #: Scan mode: quick | standard | deep (Strix-style). Controls category scope and reasoning effort.
    scan_mode: str = Field(
        default="standard",
        validation_alias=AliasChoices("SCAN_MODE", "scan_mode"),
    )
    #: LLM dedup during enrichment pipeline.
    llm_dedup_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("LLM_DEDUP_ENABLED", "llm_dedup_enabled"),
    )
    #: Memory compression for long scans (>40 LLM calls).
    memory_compression_enabled: bool = Field(
        default=True,
        validation_alias=AliasChoices("MEMORY_COMPRESSION_ENABLED", "memory_compression_enabled"),
    )

    @field_validator(
        "recon_rate_limit",
        "recon_passive_subdomain_timeout_sec",
        "recon_deep_timeout_sec",
        "recon_dns_depth_timeout_sec",
        "recon_gowitness_timeout_sec",
        mode="before",
    )
    @classmethod
    def empty_str_to_none_int(cls, v: object) -> object:
        if isinstance(v, str) and v.strip() == "":
            return None
        return v

    @field_validator("recon_mode", mode="before")
    @classmethod
    def normalize_recon_mode(cls, v: object) -> str:
        if v is None or (isinstance(v, str) and not str(v).strip()):
            return "full"
        s = str(v).strip().lower()
        if s in ("passive", "active", "full"):
            return s
        return "full"

    @field_validator("recon_active_depth", mode="after")
    @classmethod
    def clamp_recon_active_depth(cls, v: int) -> int:
        return max(0, int(v))

    @field_validator("recon_rate_limit", mode="after")
    @classmethod
    def validate_recon_rate_limit(cls, v: int | None) -> int | None:
        if v is None:
            return None
        return max(1, int(v))

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

    # KAL-002 — MCP password-audit tools (hydra/medusa): server-side gate in addition to request opt-in.
    # Env: KAL_ALLOW_PASSWORD_AUDIT=true
    kal_allow_password_audit: bool = False

    # KAL-006 — searchsploit from recon service/version strings (bounded queries).
    # Env: SEARCHSPLOIT_ENABLED, SEARCHSPLOIT_MAX_QUERIES
    searchsploit_enabled: bool = True
    searchsploit_max_queries: int = 8

    # KAL-006 — optional Trivy filesystem scan when recon collected requirements.txt / package.json.
    # Env: TRIVY_ENABLED
    trivy_enabled: bool = False

    # VDF-005 — theHarvester in VA sandbox (emails → masked Valhalla context). Env: HARVESTER_ENABLED
    harvester_enabled: bool = False

    # VDF-008 — optional gospider/parsero after robots/sitemap fetch. Env: VA_ROBOTS_EXTENDED_PIPELINE
    va_robots_extended_pipeline: bool = False

    # KAL-006 — Pwned Passwords k-anonymity API during reporting only; requires explicit opt-in.
    # Never log plaintext passwords. Env: HIBP_PASSWORD_CHECK_OPT_IN
    hibp_password_check_opt_in: bool = False

    # KAL-003 — Multi-phase nmap recon (sandbox + KAL network_scanning policy).
    nmap_recon_cycle: bool = True  # env NMAP_RECON_CYCLE
    nmap_full_tcp: bool = False  # env NMAP_FULL_TCP
    nmap_udp_top50: bool = False  # env NMAP_UDP_TOP50
    nmap_recon_phase_timeout_sec: int = 600  # env NMAP_RECON_PHASE_TIMEOUT_SEC

    # RPT-004 — language for AI-generated report sections (ISO 639-1). Env: REPORT_LANGUAGE
    report_language: str = Field(
        default="ru",
        validation_alias=AliasChoices("REPORT_LANGUAGE", "report_language"),
    )

    # RPT-004 — AI report section text cache (Redis)
    ai_text_cache_ttl_seconds: int = 604800
    # T9 — replace executive AI text with grounded fallback when prose disagrees with structured counts/HIBP.
    # Env: AI_TEXT_EXECUTIVE_FACT_CHECK_REPLACE (default true)
    ai_text_executive_fact_check_replace: bool = True

    # OWASP-001 — Russian OWASP Top 10:2025 reference JSON for reports/templates. Env: OWASP_JSON_PATH
    # Relative paths resolve from backend package root (directory containing ``src/``).
    owasp_json_path: str = "data/owasp_top_10_2025_ru.json"

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

    if settings.llm_primary_provider:
        os.environ.setdefault("LLM_PRIMARY_PROVIDER", settings.llm_primary_provider)

    flag_pairs = [
        ("SHODAN_ENRICHMENT_ENABLED", str(settings.shodan_enrichment_enabled).lower()),
        ("PERPLEXITY_INTEL_ENABLED", str(settings.perplexity_intel_enabled).lower()),
        ("ADVERSARIAL_SCORE_ENABLED", str(settings.adversarial_score_enabled).lower()),
        ("EXPLOITABILITY_VALIDATION_ENABLED", str(settings.exploitability_validation_enabled).lower()),
        ("POC_GENERATION_ENABLED", str(settings.poc_generation_enabled).lower()),
        ("SCAN_MODE", settings.scan_mode),
        ("LLM_DEDUP_ENABLED", str(settings.llm_dedup_enabled).lower()),
        ("MEMORY_COMPRESSION_ENABLED", str(settings.memory_compression_enabled).lower()),
        ("LLM_PRIMARY_PROVIDER", settings.llm_primary_provider),
    ]
    for env_key, val in flag_pairs:
        if val:
            os.environ.setdefault(env_key, val)


_sync_llm_api_keys_to_environ()
