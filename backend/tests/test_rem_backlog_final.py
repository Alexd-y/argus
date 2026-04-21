"""REM-001..REM-008: Backlog-final remediation regression tests."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from pydantic import ValidationError

BACKEND_ROOT = Path(__file__).resolve().parent.parent
BACKEND_SRC = BACKEND_ROOT / "src"
ARGUS_ROOT = BACKEND_ROOT.parent


# ---------------------------------------------------------------------------
# REM-001: No more `app.` imports in src/
# ---------------------------------------------------------------------------

class TestRem001NoAppImports:
    """All `from app.` / `import app.` references must be gone from backend/src/."""

    def test_no_app_imports_in_src(self) -> None:
        violations: list[str] = []
        for py in BACKEND_SRC.rglob("*.py"):
            for i, line in enumerate(py.read_text(encoding="utf-8").splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("from app.") or stripped.startswith("import app."):
                    violations.append(f"{py.relative_to(BACKEND_SRC)}:{i}: {stripped}")
        assert violations == [], "Found app.* imports:\n" + "\n".join(violations)


# ---------------------------------------------------------------------------
# REM-001: src.schemas package importable
# ---------------------------------------------------------------------------

class TestRem001SchemasPackage:
    """The new src.schemas package must be importable and expose key types."""

    def test_schemas_package_importable(self) -> None:
        from src.schemas.ai.common import TaskMetadata, build_task_metadata
        from src.schemas.exploitation.requests import ApprovalActionRequest
        from src.schemas.threat_modeling.schemas import ThreatModelInputBundle
        from src.schemas.vulnerability_analysis.schemas import (
            FindingStatus,
            VulnerabilityAnalysisInputBundle,
        )

        assert TaskMetadata is not None
        assert build_task_metadata is not None
        assert VulnerabilityAnalysisInputBundle is not None
        assert ThreatModelInputBundle is not None
        assert ApprovalActionRequest is not None
        assert FindingStatus.CONFIRMED.value == "confirmed"


# ---------------------------------------------------------------------------
# REM-001: FindingStatus has all required members
# ---------------------------------------------------------------------------

class TestRem001FindingStatusMembers:
    """FindingStatus enum must contain every expected status value."""

    def test_finding_status_has_all_members(self) -> None:
        from src.schemas.vulnerability_analysis.schemas import FindingStatus

        expected = {
            "confirmed", "suspected", "unconfirmed", "false_positive",
            "duplicate", "hypothesis", "partially_confirmed", "rejected",
        }
        actual = {s.value for s in FindingStatus}
        assert expected.issubset(actual), f"Missing: {expected - actual}"


# ---------------------------------------------------------------------------
# REM-002: JWT secret validation
# ---------------------------------------------------------------------------

class TestRem002JwtSecret:
    """JWT_SECRET must be required in production (debug=False) and optional in dev."""

    def test_jwt_secret_empty_prod_raises(self) -> None:
        from src.core.config import Settings

        with pytest.raises(ValidationError, match="(?i)jwt"):
            Settings(_env_file=None, jwt_secret="", debug=False)

    def test_jwt_secret_empty_dev_ok(self) -> None:
        from src.core.config import Settings

        s = Settings(_env_file=None, jwt_secret="", debug=True)
        assert s.jwt_secret == ""

    def test_jwt_secret_set_prod_ok(self) -> None:
        from src.core.config import Settings

        s = Settings(
            _env_file=None,
            jwt_secret="super-secret-key-123",
            database_url="postgresql+asyncpg://test:test@localhost/test",
            minio_secret_key="test-secret",
            debug=False,
        )
        assert s.jwt_secret == "super-secret-key-123"


# ---------------------------------------------------------------------------
# REM-002: docker-compose CORS no wildcard default
# ---------------------------------------------------------------------------

class TestRem002DockerComposeCors:
    """docker-compose.yml must not fall back to wildcard '*' CORS default."""

    COMPOSE_PATH = ARGUS_ROOT / "infra" / "docker-compose.yml"

    def test_docker_compose_cors_no_wildcard(self) -> None:
        if not self.COMPOSE_PATH.exists():
            pytest.skip("docker-compose.yml not found")
        text = self.COMPOSE_PATH.read_text(encoding="utf-8")
        assert ":-*}" not in text, "docker-compose.yml still uses wildcard CORS default"
        assert ":-http://localhost:3000}" in text or "CORS_ORIGINS" not in text


# ---------------------------------------------------------------------------
# REM-003: No Russian / Cyrillic in reporting.py
# ---------------------------------------------------------------------------

CYRILLIC_RE = re.compile(r"[а-яА-ЯёЁ]+")


class TestRem003NoCyrillicReporting:
    """reporting.py must not contain Cyrillic string literals."""

    REPORTING_PATH = BACKEND_SRC / "services" / "reporting.py"

    def test_no_russian_in_reporting(self) -> None:
        if not self.REPORTING_PATH.exists():
            pytest.skip("reporting.py not found")
        text = self.REPORTING_PATH.read_text(encoding="utf-8")
        cyrillic = CYRILLIC_RE.findall(text)
        assert cyrillic == [], f"Found Cyrillic text in reporting.py: {cyrillic[:10]}"


# ---------------------------------------------------------------------------
# REM-004 reverted: the seven packages REM-004 removed are ALL in active use.
#
# Audit trail (verified at module-import / first-call time):
#   * tldextract, netaddr      → src.recon.scope.validator (module-level imports;
#                                pulled in transitively by the FastAPI app at startup
#                                via src.api.routers.recon.targets).
#   * dnspython                → src.policy.ownership (lazy import for DNS TXT
#                                ownership challenges).
#   * typer, rich              → src.recon.cli.* (module-level imports — used by
#                                operator CLI tools shipped in the same image).
#   * shodan                   → src.intel.shodan_enricher (lazy import gated by
#                                SHODAN_ENRICHMENT_ENABLED, default true).
#   * beautifulsoup4 (bs4)     → src.recon.vulnerability_analysis.active_scan.
#                                context_detector (module-level import; required by
#                                the active-scan VA pipeline).
#
# Removing them caused ImportError at FastAPI startup and broke `docker compose up`
# (see git history of infra/backend/Dockerfile and backend/requirements.txt).
# This test now enforces the *opposite* invariant: those packages MUST stay
# declared so the regression cannot reappear.
# ---------------------------------------------------------------------------

class TestRem004RequiredDeps:
    """Packages previously misclassified as unused — must remain declared."""

    REQUIRED_PACKAGES = [
        "typer", "tldextract", "dnspython", "netaddr",
        "rich", "beautifulsoup4", "shodan",
    ]

    def test_required_deps_present(self) -> None:
        req = BACKEND_ROOT / "requirements.txt"
        if not req.exists():
            pytest.skip("requirements.txt not found")
        text = req.read_text(encoding="utf-8").lower()
        missing = [pkg for pkg in self.REQUIRED_PACKAGES if pkg not in text]
        assert missing == [], (
            f"Required packages missing from requirements.txt (REM-004 regression): {missing}. "
            "Regenerate via: python backend/scripts/sync_requirements.py"
        )


# ---------------------------------------------------------------------------
# REM-005: Settings exposes all env API-key fields
# ---------------------------------------------------------------------------

class TestRem005SettingsApiKeys:
    """Settings model must declare every external-service API key field."""

    EXPECTED_KEYS = [
        "censys_api_secret", "nvd_api_key", "exploitdb_api_key",
        "urlscan_api_key", "abuseipdb_api_key", "greynoise_api_key",
        "otx_api_key", "github_token", "shodan_api_key",
    ]

    def test_settings_has_env_api_keys(self) -> None:
        from src.core.config import Settings

        fields = Settings.model_fields
        missing = [k for k in self.EXPECTED_KEYS if k not in fields]
        assert missing == [], f"Missing Settings fields: {missing}"


# ---------------------------------------------------------------------------
# REM-006: No duplicate backend/Dockerfile
# ---------------------------------------------------------------------------

class TestRem006NoDuplicateDockerfile:
    """backend/Dockerfile must not exist; the canonical one lives in infra/."""

    def test_no_duplicate_backend_dockerfile(self) -> None:
        dupe = BACKEND_ROOT / "Dockerfile"
        assert not dupe.exists(), "backend/Dockerfile should not exist (use infra/backend/Dockerfile)"


# ---------------------------------------------------------------------------
# REM-007: Email validation on ScanCreateRequest
# ---------------------------------------------------------------------------

class TestRem007EmailValidation:
    """ScanCreateRequest.email field must reject invalid addresses."""

    def test_invalid_email_rejected(self) -> None:
        from src.api.schemas import ScanCreateRequest

        with pytest.raises(ValidationError):
            ScanCreateRequest(
                target="https://example.com",
                email="not-an-email",
            )

    def test_valid_email_accepted(self) -> None:
        from src.api.schemas import ScanCreateRequest

        req = ScanCreateRequest(
            target="https://example.com",
            email="user@example.com",
        )
        assert req.email == "user@example.com"


# ---------------------------------------------------------------------------
# REM-007: Severity whitelist uses Literal type
# ---------------------------------------------------------------------------

class TestRem007SeverityWhitelist:
    """scans.py must use Literal[...] for the severity filter parameter."""

    SCANS_PATH = BACKEND_SRC / "api" / "routers" / "scans.py"

    def test_severity_literal_type(self) -> None:
        if not self.SCANS_PATH.exists():
            pytest.skip("scans.py not found")
        text = self.SCANS_PATH.read_text(encoding="utf-8")
        assert "Literal[" in text and "severity" in text.lower(), (
            "scans.py must use a Literal type for severity filtering"
        )


# ---------------------------------------------------------------------------
# REM-008: Dead variable removed from va_active_scan_phase.py
# ---------------------------------------------------------------------------

class TestRem008DeadVariableRemoved:
    """The dead `_ = float(settings...)` assignment must be gone."""

    VA_PATH = (
        BACKEND_SRC / "recon" / "vulnerability_analysis"
        / "active_scan" / "va_active_scan_phase.py"
    )

    def test_no_dead_float_settings_var(self) -> None:
        if not self.VA_PATH.exists():
            pytest.skip("va_active_scan_phase.py not found")
        text = self.VA_PATH.read_text(encoding="utf-8")
        assert "_ = float(settings" not in text, (
            "Dead variable _ = float(settings...) still present"
        )


# ---------------------------------------------------------------------------
# REM-008: FindingNote CRUD endpoints exist
# ---------------------------------------------------------------------------

class TestRem008FindingNoteCrud:
    """findings.py router must expose PUT and DELETE endpoints for notes."""

    FINDINGS_PATH = BACKEND_SRC / "api" / "routers" / "findings.py"

    def test_put_endpoint_exists(self) -> None:
        if not self.FINDINGS_PATH.exists():
            pytest.skip("findings.py not found")
        text = self.FINDINGS_PATH.read_text(encoding="utf-8")
        assert "@router.put(" in text and "note" in text.lower(), (
            "PUT endpoint for notes missing in findings.py"
        )

    def test_delete_endpoint_exists(self) -> None:
        if not self.FINDINGS_PATH.exists():
            pytest.skip("findings.py not found")
        text = self.FINDINGS_PATH.read_text(encoding="utf-8")
        assert "@router.delete(" in text and "note" in text.lower(), (
            "DELETE endpoint for notes missing in findings.py"
        )
