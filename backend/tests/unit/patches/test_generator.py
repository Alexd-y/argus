"""Tests for Patch Generation Worker."""

import json

import pytest
from unittest.mock import AsyncMock, patch

from src.workers.patches.generator import (
    generate_patch,
    validate_patch,
    PatchResult,
    PatchType,
    PatchStatus,
)


class TestPatchResult:
    def test_default_values(self):
        r = PatchResult()
        assert r.status == PatchStatus.PENDING
        assert r.patch_type == PatchType.MINIMAL
        assert r.original_code == ""

    def test_patch_type_enum(self):
        assert PatchType.MINIMAL.value == "minimal"
        assert PatchType.HARDENING.value == "hardening"


class TestPatchGeneration:
    @pytest.mark.asyncio
    async def test_no_code_returns_error(self):
        finding = {"title": "Test", "severity": "high"}
        result = await generate_patch(finding, "")
        assert result.status == PatchStatus.FAILED_VALIDATION
        assert result.error == "No code to patch"

    @pytest.mark.asyncio
    async def test_generates_patch_from_wrb(self):
        finding = {
            "title": "SQL Injection", "severity": "critical",
            "cwe": "CWE-89", "file_path": "app.py", "line_start": 42,
            "description": "Unsanitized user input in SQL query",
        }
        code = 'query = "SELECT * FROM users WHERE id = " + user_input'

        # generate_patch routes through the unified LLM facade, which returns
        # the model's content string (JSON) — not a raw provider envelope.
        wrb_content = json.dumps({
            "patched_code": "query = SELECT * FROM users WHERE id = %s",
            "diff": "- + user_input\n+ %s",
            "rationale": "Use parameterized queries",
            "secure_alternative": "Use ORM",
            "blast_radius": "Only this function",
            "backward_compat_risk": "low",
            "regression_test": "def test(): pass",
        })

        with patch(
            "src.llm.facade.call_llm_unified",
            new=AsyncMock(return_value=wrb_content),
        ):
            result = await generate_patch(finding, code)

        assert result.status == PatchStatus.GENERATED
        assert result.patched_code != ""
        assert "parameterized" in result.rationale.lower() or result.rationale != ""


class TestPatchValidation:
    @pytest.mark.asyncio
    async def test_empty_patch_fails(self):
        r = PatchResult(patched_code="")
        result = await validate_patch(r)
        assert result.lint_passed is False
        assert result.status == PatchStatus.FAILED_VALIDATION

    @pytest.mark.asyncio
    async def test_valid_syntax_passes_lint(self):
        r = PatchResult(patched_code="def fixed(): return 'ok'")
        result = await validate_patch(r)
        assert result.lint_passed is True

    @pytest.mark.asyncio
    async def test_syntax_error_fails(self):
        r = PatchResult(patched_code="def broken( {{{ ")
        result = await validate_patch(r)
        assert result.lint_passed is False
        assert result.status == PatchStatus.FAILED_VALIDATION
