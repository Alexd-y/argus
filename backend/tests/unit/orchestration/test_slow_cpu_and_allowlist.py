"""Regression tests for Full-Surface allowlist, slow-CPU timeout scaling, and
robust phase-review JSON extraction.

Covers three fixes landed together:

* ``recon/mcp/policy.py`` — deep/Full-Surface profile tool_ids (``nuclei_ssrf``,
  ``ffuf_lfi``, ``corscanner``) and real binaries (``arjun``/``wafw00f``/
  ``whatwaf``) must pass ``evaluate_va_active_scan_tool_policy`` instead of
  failing with ``active_scan_tool_not_allowlisted``.
* ``llm/json_extract.py`` — tolerant extraction of a JSON object from
  prose/fenced/truncated LLM output (fixes ``phase_review`` parse_error).
* ``adversarial_critic`` — malformed model output degrades to a non-alarming
  ``review_unavailable`` status, never a ``parse_error`` report defect.
"""

from __future__ import annotations

import asyncio

from src.llm.json_extract import extract_json_object
from src.orchestration.adversarial_critic import run_adversarial_critic
from src.recon.mcp.policy import (
    evaluate_va_active_scan_tool_policy,
    resolve_va_active_scan_tool_canonical,
)


class TestActiveScanAllowlist:
    def test_profile_nuclei_variants_resolve_to_base_binary(self) -> None:
        for tool_id in ("nuclei_ssrf", "nuclei_csrf", "nuclei_sqli", "nuclei_rce", "nuclei_idor"):
            assert resolve_va_active_scan_tool_canonical(tool_id) == "nuclei", tool_id
            assert evaluate_va_active_scan_tool_policy(tool_name=tool_id).allowed, tool_id

    def test_ffuf_lfi_resolves_to_ffuf(self) -> None:
        assert resolve_va_active_scan_tool_canonical("ffuf_lfi") == "ffuf"
        assert evaluate_va_active_scan_tool_policy(tool_name="ffuf_lfi").allowed

    def test_newly_allowlisted_binaries(self) -> None:
        for tool in ("arjun", "wafw00f", "whatwaf"):
            assert evaluate_va_active_scan_tool_policy(tool_name=tool).allowed, tool

    def test_corscanner_and_curl_cors_resolve(self) -> None:
        assert resolve_va_active_scan_tool_canonical("corscanner") == "cors"
        assert evaluate_va_active_scan_tool_policy(tool_name="corscanner").allowed
        assert resolve_va_active_scan_tool_canonical("curl_cors") == "curl"

    def test_unknown_tool_still_denied(self) -> None:
        decision = evaluate_va_active_scan_tool_policy(tool_name="totally_made_up_tool")
        assert not decision.allowed
        assert decision.reason == "active_scan_tool_not_allowlisted"


class TestExtractJsonObject:
    def test_plain_json(self) -> None:
        assert extract_json_object('{"a": 1}') == {"a": 1}

    def test_fenced_json_block(self) -> None:
        text = "Here is the result:\n```json\n{\"critiques\": [], \"ok\": true}\n```\nDone."
        assert extract_json_object(text) == {"critiques": [], "ok": True}

    def test_prose_prefix_then_object(self) -> None:
        text = 'Thought: I will now answer.\n{"overall_assessment": "fine"} trailing prose'
        assert extract_json_object(text) == {"overall_assessment": "fine"}

    def test_braces_inside_strings_do_not_break_balance(self) -> None:
        text = 'prefix {"note": "use { and } carefully", "n": 2} suffix'
        assert extract_json_object(text) == {"note": "use { and } carefully", "n": 2}

    def test_truncated_json_returns_none(self) -> None:
        # max_tokens cut-off — unbalanced, unrecoverable.
        assert extract_json_object('{"critiques": [{"finding_id": "x"') is None

    def test_empty_and_non_object(self) -> None:
        assert extract_json_object("") is None
        assert extract_json_object("   ") is None
        assert extract_json_object("[1, 2, 3]") is None


class TestAdversarialCriticGracefulDegrade:
    def _findings(self) -> list[dict[str, object]]:
        return [{"finding_id": "f1", "title": "TLS", "severity": "medium", "vuln_type": "tls_probe"}]

    def test_malformed_response_degrades_not_parse_error(self) -> None:
        async def _bad_executor(_s: str, _u: str) -> dict[str, str]:
            return {"content": "I cannot produce JSON right now, sorry."}

        result = asyncio.run(run_adversarial_critic(self._findings(), llm_executor=_bad_executor))
        assert result.findings_reviewed == 1
        assert result.overall_assessment.startswith("review_unavailable")
        assert "parse_error" not in result.overall_assessment

    def test_fenced_response_is_parsed(self) -> None:
        async def _good_executor(_s: str, _u: str) -> dict[str, str]:
            return {
                "content": '```json\n{"critiques": [{"finding_id": "f1", '
                '"critique_type": "bypass", "description": "d", "suggested_action": "a", '
                '"severity": "low"}], "blind_spots": ["bs"], "overall_assessment": "ok"}\n```'
            }

        result = asyncio.run(run_adversarial_critic(self._findings(), llm_executor=_good_executor))
        assert result.overall_assessment == "ok"
        assert len(result.critiques) == 1
        assert result.blind_spots == ["bs"]
