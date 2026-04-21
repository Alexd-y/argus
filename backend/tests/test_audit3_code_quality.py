"""Tests for code quality improvements (M-15, M-16, M-18, M-19, M-20, M-22, M-25)."""

from __future__ import annotations

import re
from pathlib import Path

BACKEND_SRC = Path(__file__).resolve().parent.parent / "src"


class TestAdminHealthLogging:
    """M-15: admin.py should not swallow exceptions."""

    def test_no_except_pass_in_admin(self) -> None:
        text = (BACKEND_SRC / "api" / "routers" / "admin.py").read_text(
            encoding="utf-8"
        )
        lines = text.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("except") and i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                assert next_line != "pass", (
                    f"admin.py:{i + 2} has bare 'pass' after except"
                )


class TestHealthLogging:
    """M-16: health.py should log DB failures."""

    def test_no_except_pass_in_health(self) -> None:
        text = (BACKEND_SRC / "api" / "routers" / "health.py").read_text(
            encoding="utf-8"
        )
        lines = text.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith("except") and i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                assert next_line != "pass", (
                    f"health.py:{i + 2} has bare 'pass' after except"
                )

    def test_health_logs_db_failure(self) -> None:
        """health.py exception handlers should log warnings."""
        text = (BACKEND_SRC / "api" / "routers" / "health.py").read_text(
            encoding="utf-8"
        )
        assert "logger.warning" in text


class TestNoRussianComments:
    """M-18, M-19: No Russian comments in config.py and planner.py."""

    _CYRILLIC = re.compile(r"[а-яА-ЯёЁ]+")

    def test_no_russian_in_config(self) -> None:
        text = (BACKEND_SRC / "core" / "config.py").read_text(encoding="utf-8")
        found = self._CYRILLIC.findall(text)
        assert found == [], f"Cyrillic in config.py: {found[:5]}"

    def test_no_russian_in_planner(self) -> None:
        planner = (
            BACKEND_SRC
            / "recon"
            / "vulnerability_analysis"
            / "active_scan"
            / "planner.py"
        )
        assert planner.exists(), "planner.py must exist in the project"
        text = planner.read_text(encoding="utf-8")
        found = self._CYRILLIC.findall(text)
        assert found == [], f"Cyrillic in planner.py: {found[:5]}"


class TestSchemasComment:
    """M-20: schemas.py should not say 'no active router yet'."""

    def test_no_stale_comment(self) -> None:
        text = (BACKEND_SRC / "api" / "schemas.py").read_text(encoding="utf-8")
        assert "no active router yet" not in text.lower()


class TestReportPipelineExceptions:
    """M-22: report_pipeline.py should have specific exception handling."""

    def test_has_report_generation_error(self) -> None:
        rp = BACKEND_SRC / "reports" / "report_pipeline.py"
        assert rp.exists(), "report_pipeline.py must exist in the project"
        text = rp.read_text(encoding="utf-8")
        assert "ReportGenerationError" in text

    def test_has_template_error_handling(self) -> None:
        rp = BACKEND_SRC / "reports" / "report_pipeline.py"
        assert rp.exists(), "report_pipeline.py must exist in the project"
        text = rp.read_text(encoding="utf-8")
        assert "TemplateError" in text or "jinja2" in text


class TestAiTextCacheEviction:
    """M-25: ai_text_generation.py should log + evict on cache corruption."""

    def test_cache_logs_corruption(self) -> None:
        ai_text = BACKEND_SRC / "reports" / "ai_text_generation.py"
        assert ai_text.exists(), "ai_text_generation.py must exist in the project"
        text = ai_text.read_text(encoding="utf-8")
        assert "cache corrupted" in text.lower() or "evict" in text.lower()

    def test_cache_deletes_corrupt_key(self) -> None:
        """On cache corruption, the key should be deleted."""
        ai_text = BACKEND_SRC / "reports" / "ai_text_generation.py"
        assert ai_text.exists(), "ai_text_generation.py must exist in the project"
        text = ai_text.read_text(encoding="utf-8")
        assert "r.delete" in text or "delete(cache_key)" in text
