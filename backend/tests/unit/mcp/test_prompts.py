"""Unit tests for MCP prompt templates.

The prompts are pure-Python helpers that build a list of MCP messages —
they never call the live API. The tests assert that:

* All three prompts register without errors.
* Required arguments are honoured (FastMCP exposes them via ``list_prompts``).
* The system / user message split round-trips through ``get_prompt``.
* Long inputs are truncated server-side to bound prompt size.
"""

from __future__ import annotations

import asyncio

from mcp.server.fastmcp import FastMCP

from src.mcp.prompts import register_all
from src.mcp.prompts.remediation_advisor import _render_remediation_block
from src.mcp.prompts.severity_normalizer import register as register_normalizer
from src.mcp.prompts.vulnerability_explainer import (
    _render_finding_block,
    register as register_explainer,
)


class TestRegisterAll:
    def test_all_three_prompts_registered(self) -> None:
        app = FastMCP(name="test")
        register_all(app)
        prompts = asyncio.run(app.list_prompts())
        names = {p.name for p in prompts}
        assert "vulnerability.explainer" in names
        assert "remediation.advisor" in names
        assert "severity.normalizer" in names

    def test_explainer_arguments_metadata(self) -> None:
        app = FastMCP(name="test")
        register_explainer(app)
        prompts = asyncio.run(app.list_prompts())
        explainer = next(p for p in prompts if p.name == "vulnerability.explainer")
        arg_names = {a.name for a in explainer.arguments or ()}
        assert {"title", "severity"} <= arg_names


class TestVulnerabilityExplainerBlock:
    def test_minimum_block(self) -> None:
        block = _render_finding_block(
            title="SQL injection in /login",
            severity="HIGH",
            description=None,
            cwe=None,
            owasp_category=None,
        )
        assert "SQL injection in /login" in block
        assert "high" in block.lower()
        assert "FINDING" in block

    def test_full_block(self) -> None:
        block = _render_finding_block(
            title="Stored XSS",
            severity="medium",
            description="A reflected payload in /search.",
            cwe="CWE-79",
            owasp_category="A03",
        )
        assert "CWE-79" in block
        assert "A03" in block
        assert "/search" in block

    def test_long_description_truncated_to_4k(self) -> None:
        long_desc = "X" * 8_000
        block = _render_finding_block(
            title="t",
            severity="LOW",
            description=long_desc,
            cwe=None,
            owasp_category=None,
        )
        # The slicing keeps exactly the first 4 000 X's; longer runs do not appear.
        assert "X" * 4_000 in block
        assert "X" * 5_000 not in block


class TestRemediationAdvisorBlock:
    def test_required_fields_only(self) -> None:
        block = _render_remediation_block(
            title="t", severity="HIGH", stack=None, evidence_summary=None, cwe=None
        )
        assert "REMEDIATION REQUEST" in block
        assert "Severity: high" in block
        assert "primary fix" in block

    def test_stack_truncated_to_200(self) -> None:
        block = _render_remediation_block(
            title="t",
            severity="HIGH",
            stack="A" * 1_000,
            evidence_summary=None,
            cwe=None,
        )
        assert "A" * 200 in block
        assert "A" * 201 not in block

    def test_cwe_emitted(self) -> None:
        block = _render_remediation_block(
            title="t", severity="HIGH", stack=None, evidence_summary=None, cwe="CWE-89"
        )
        assert "CWE-89" in block


class TestSeverityNormalizerRegistration:
    def test_registration_creates_prompt(self) -> None:
        app = FastMCP(name="test")
        register_normalizer(app)
        prompts = asyncio.run(app.list_prompts())
        names = {p.name for p in prompts}
        assert "severity.normalizer" in names


class TestPromptMessageContract:
    def test_explainer_round_trip(self) -> None:
        app = FastMCP(name="test")
        register_explainer(app)
        result = asyncio.run(
            app.get_prompt(
                "vulnerability.explainer",
                {"title": "Stored XSS", "severity": "HIGH"},
            )
        )
        assert len(result.messages) == 2
        # First message is system guidance, second is the rendered finding block.
        # Roles in MCP protocol space are "user" / "assistant".
        roles = {m.role for m in result.messages}
        assert roles == {"user", "assistant"}
        # Rendered content should mention the finding details.
        joined = " ".join(getattr(m.content, "text", "") for m in result.messages)
        assert "Stored XSS" in joined
        assert "high" in joined.lower()
