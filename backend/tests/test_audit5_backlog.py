"""Audit-5 backlog closure tests.

Covers H-1 (auth bypass double guard), H-2 (MCP auth contract), H-4 (notes field migration),
M-1 (MinIO default creds), M-2 (CORS headers), M-13 (candidates_count None),
M-14 (memory_compression setting), M-16/M-17 (schema_export), Config fields, L-17 (STUB_STEPS).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _patch_login_db_no_user(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stub async_session_factory so login queries see no user (no real DB)."""

    class _Sess:
        async def execute(self, *_a, **_kw):
            class _R:
                def scalar_one_or_none(self):
                    return None
            return _R()

    class _CM:
        async def __aenter__(self):
            return _Sess()

        async def __aexit__(self, *_a):
            return None

    monkeypatch.setattr("src.api.routers.auth.async_session_factory", lambda: _CM())


_JWT_SECRET = "test-secret-key-min-32-chars-long-for-hs256"


def _set_jwt_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.core.config.settings.jwt_secret", _JWT_SECRET)


# ---------------------------------------------------------------------------
# H-1: Auth bypass double guard
# ---------------------------------------------------------------------------


class TestH1AuthBypass:
    """Login bypass requires BOTH debug=True AND dev_login_bypass_enabled=True."""

    def test_bypass_disabled_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """debug=True + dev_login_bypass_enabled=False (default) → 401."""
        monkeypatch.setattr("src.core.config.settings.debug", True)
        monkeypatch.setattr("src.core.config.settings.dev_login_bypass_enabled", False)
        _set_jwt_secret(monkeypatch)
        _patch_login_db_no_user(monkeypatch)

        from main import app
        from starlette.testclient import TestClient

        client = TestClient(app)
        resp = client.post("/api/v1/auth/login", json={"mail": "x@x.com", "password": "p"})
        assert resp.status_code == 401

    def test_bypass_works_when_both_flags_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """debug=True + dev_login_bypass_enabled=True → 200 with dev_mode."""
        monkeypatch.setattr("src.core.config.settings.debug", True)
        monkeypatch.setattr("src.core.config.settings.dev_login_bypass_enabled", True)
        _set_jwt_secret(monkeypatch)
        _patch_login_db_no_user(monkeypatch)

        from main import app
        from starlette.testclient import TestClient

        client = TestClient(app)
        resp = client.post("/api/v1/auth/login", json={"mail": "x@x.com", "password": "p"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["dev_mode"] is True
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_bypass_needs_debug_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """debug=False + dev_login_bypass_enabled=True → 401."""
        monkeypatch.setattr("src.core.config.settings.debug", False)
        monkeypatch.setattr("src.core.config.settings.dev_login_bypass_enabled", True)
        _set_jwt_secret(monkeypatch)
        _patch_login_db_no_user(monkeypatch)

        from main import app
        from starlette.testclient import TestClient

        client = TestClient(app)
        resp = client.post("/api/v1/auth/login", json={"mail": "x@x.com", "password": "p"})
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# H-2: MCP auth contract (X-API-Key, not Authorization Bearer)
# ---------------------------------------------------------------------------


class TestH2McpAuthContract:
    """_get_auth_headers must use X-API-Key header, not Bearer token."""

    @pytest.fixture(autouse=True)
    def _mcp_path(self) -> None:
        mcp_dir = str(BACKEND_DIR.parent / "mcp-server")
        if mcp_dir not in sys.path:
            sys.path.insert(0, mcp_dir)

    def test_auth_header_uses_api_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """With ARGUS_API_KEY set, header is X-API-Key (not Authorization: Bearer)."""
        monkeypatch.setenv("ARGUS_API_KEY", "test-key-123")
        argus_mcp = pytest.importorskip("argus_mcp")
        headers = argus_mcp._get_auth_headers()
        assert headers == {"X-API-Key": "test-key-123"}
        assert "Authorization" not in headers

    def test_auth_header_empty_without_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without ARGUS_API_KEY env var, returns empty dict."""
        monkeypatch.delenv("ARGUS_API_KEY", raising=False)
        argus_mcp = pytest.importorskip("argus_mcp")
        headers = argus_mcp._get_auth_headers()
        assert headers == {}


# ---------------------------------------------------------------------------
# H-4: notes field migration (notes_ru → notes backward compat)
# ---------------------------------------------------------------------------


class TestH4NotesField:
    """RobotsSitemapMergedSummaryModel notes / notes_ru migration."""

    def test_notes_field_exists(self) -> None:
        from src.reports.valhalla_report_context import RobotsSitemapMergedSummaryModel

        m = RobotsSitemapMergedSummaryModel()
        assert hasattr(m, "notes")
        assert hasattr(m, "notes_ru")

    def test_notes_ru_migrates_to_notes(self) -> None:
        from src.reports.valhalla_report_context import RobotsSitemapMergedSummaryModel

        m = RobotsSitemapMergedSummaryModel(notes_ru="test content")
        assert m.notes == "test content"

    def test_notes_takes_priority(self) -> None:
        from src.reports.valhalla_report_context import RobotsSitemapMergedSummaryModel

        m = RobotsSitemapMergedSummaryModel(notes="English", notes_ru="Russian")
        assert m.notes == "English"


# ---------------------------------------------------------------------------
# M-1: MinIO default credentials
# ---------------------------------------------------------------------------


class TestM1MinioDefaults:
    """Default minio_access_key should not be a hardcoded credential in non-debug."""

    def test_minio_access_key_default_value(self) -> None:
        from src.core.config import Settings

        s = Settings(debug=True, jwt_secret=_JWT_SECRET)
        assert isinstance(s.minio_access_key, str)

    def test_minio_warn_on_default_creds_non_debug(self, caplog: pytest.LogCaptureFixture) -> None:
        """In non-debug mode, using default 'argus' key logs a warning (model_validator)."""
        import logging

        from src.core.config import Settings

        with caplog.at_level(logging.WARNING, logger="src.core.config"):
            Settings(
                debug=False,
                jwt_secret=_JWT_SECRET,
                database_url="postgresql+asyncpg://u:p@host/db",
                minio_secret_key="real-secret",
            )
        assert any("MinIO" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# M-2: CORS headers
# ---------------------------------------------------------------------------


class TestM2CorsHeaders:
    """CORSMiddleware must include X-API-Key, X-Tenant-ID, X-Admin-Key."""

    def test_cors_includes_custom_headers(self) -> None:
        from main import app

        cors_mw = None
        for mw in app.user_middleware:
            if "CORSMiddleware" in str(mw):
                cors_mw = mw
                break
        assert cors_mw is not None, "CORSMiddleware not found in app middleware"
        headers = cors_mw.kwargs.get("allow_headers", [])
        assert "X-API-Key" in headers
        assert "X-Tenant-ID" in headers
        assert "X-Admin-Key" in headers


# ---------------------------------------------------------------------------
# M-13: candidates_count allows None
# ---------------------------------------------------------------------------


class TestM13CandidatesCount:
    """Stage4ReadinessResult.candidates_count accepts None and int."""

    def test_candidates_count_allows_none(self) -> None:
        from src.recon.exploitation.dependency_check import Stage4ReadinessResult

        r = Stage4ReadinessResult(ready=True, candidates_count=None)
        assert r.candidates_count is None

    def test_candidates_count_accepts_int(self) -> None:
        from src.recon.exploitation.dependency_check import Stage4ReadinessResult

        r = Stage4ReadinessResult(ready=True, candidates_count=5)
        assert r.candidates_count == 5

    def test_candidates_count_defaults_none(self) -> None:
        from src.recon.exploitation.dependency_check import Stage4ReadinessResult

        r = Stage4ReadinessResult(ready=False)
        assert r.candidates_count is None


# ---------------------------------------------------------------------------
# M-14: memory_compression_enabled in Settings
# ---------------------------------------------------------------------------


class TestM14MemorySettings:
    """Settings must expose memory_compression_enabled boolean."""

    def test_memory_compression_in_settings(self) -> None:
        from src.core.config import Settings

        s = Settings(debug=True, jwt_secret=_JWT_SECRET)
        assert hasattr(s, "memory_compression_enabled")
        assert isinstance(s.memory_compression_enabled, bool)

    def test_memory_compression_default_true(self) -> None:
        from src.core.config import Settings

        s = Settings(debug=True, jwt_secret=_JWT_SECRET)
        assert s.memory_compression_enabled is True


# ---------------------------------------------------------------------------
# M-16 / M-17: schema_export (task definitions + payload validation)
# ---------------------------------------------------------------------------


class TestM16SchemaExport:
    """get_recon_ai_task_definitions and validate_recon_ai_payload contract."""

    def test_task_definitions_non_empty(self) -> None:
        from src.schemas.ai.schema_export import get_recon_ai_task_definitions

        defs = get_recon_ai_task_definitions()
        assert len(defs) > 0
        for _k, v in defs.items():
            assert "task_name" in v
            assert "description" in v

    def test_task_definitions_have_required_keys_field(self) -> None:
        from src.schemas.ai.schema_export import get_recon_ai_task_definitions

        defs = get_recon_ai_task_definitions()
        for _k, v in defs.items():
            assert "required_input_keys" in v
            assert isinstance(v["required_input_keys"], list)

    def test_validate_payload_missing_input(self) -> None:
        from src.schemas.ai.schema_export import validate_recon_ai_payload

        result = validate_recon_ai_payload("route_discovery", {}, {})
        assert result["input"]["is_valid"] is False

    def test_validate_payload_unknown_task(self) -> None:
        from src.schemas.ai.schema_export import validate_recon_ai_payload

        result = validate_recon_ai_payload("nonexistent_task", {}, {})
        assert result["input"]["is_valid"] is False
        assert result["output"]["is_valid"] is False

    def test_validate_payload_valid_output(self) -> None:
        from src.schemas.ai.schema_export import validate_recon_ai_payload

        result = validate_recon_ai_payload(
            "route_discovery",
            {"meta": {}, "bundle": {}},
            {"routes": []},
        )
        assert result["input"]["is_valid"] is True
        assert result["output"]["is_valid"] is True


# ---------------------------------------------------------------------------
# Config fields: dev_login_bypass, mcp_timeout, va_redirect_target
# ---------------------------------------------------------------------------


class TestConfigFields:
    """Verify default values for critical config knobs."""

    def test_dev_login_bypass_default_false(self) -> None:
        from src.core.config import Settings

        s = Settings(debug=True, jwt_secret=_JWT_SECRET)
        assert s.dev_login_bypass_enabled is False

    def test_mcp_timeout_default(self) -> None:
        from src.core.config import Settings

        s = Settings(debug=True, jwt_secret=_JWT_SECRET)
        assert s.mcp_timeout == 10.0

    def test_va_redirect_target_default(self) -> None:
        from src.core.config import Settings

        s = Settings(debug=True, jwt_secret=_JWT_SECRET)
        assert "evil.example.com" in s.va_redirect_test_target


# ---------------------------------------------------------------------------
# L-17: STUB_STEPS removed from step_registry
# ---------------------------------------------------------------------------


class TestL17StubStepsRemoved:
    """STUB_STEPS export removed; DEPRECATED_STEPS exists instead."""

    def test_no_stub_steps_export(self) -> None:
        import src.recon.step_registry as sr

        assert not hasattr(sr, "STUB_STEPS") or getattr(sr, "STUB_STEPS") is sr.DEPRECATED_STEPS
        assert hasattr(sr, "DEPRECATED_STEPS")

    def test_deprecated_steps_is_frozenset(self) -> None:
        import src.recon.step_registry as sr

        assert isinstance(sr.DEPRECATED_STEPS, frozenset)
