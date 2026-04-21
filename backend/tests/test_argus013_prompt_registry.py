"""Tests for ARGUS-013 prompt registry and JSON schemas."""

import json
from unittest.mock import AsyncMock, patch

import pytest
from src.orchestration.prompt_registry import (
    EXPLOITATION,
    FIXER_SYSTEM_PROMPT,
    PHASE_PROMPTS,
    PHASE_SCHEMAS,
    POST_EXPLOITATION,
    RECON,
    REPORTING,
    THREAT_MODELING,
    VULN_ANALYSIS,
    get_fixer_prompt,
    get_prompt,
    get_schema,
)


class TestPromptRegistry:
    """Prompt registry structure and get_prompt."""

    def test_phase_prompts_has_all_phases(self) -> None:
        phases = {RECON, THREAT_MODELING, VULN_ANALYSIS, EXPLOITATION, POST_EXPLOITATION, REPORTING}
        assert set(PHASE_PROMPTS.keys()) == phases

    def test_each_phase_has_system_and_template(self) -> None:
        for phase, entry in PHASE_PROMPTS.items():
            assert isinstance(entry, tuple), f"{phase} should be (system, template)"
            assert len(entry) == 2, f"{phase} should have system and template"
            system, template = entry
            assert isinstance(system, str) and len(system) > 0
            assert isinstance(template, str) and len(template) > 0

    def test_get_prompt_recon(self) -> None:
        system, user = get_prompt(RECON, target="https://x.com", options={"depth": 1})
        assert "https://x.com" in user
        assert "depth" in user or "1" in user
        assert "assets" in user and "subdomains" in user and "ports" in user

    def test_get_prompt_threat_modeling(self) -> None:
        system, user = get_prompt(THREAT_MODELING, assets=["a1", "a2"])
        assert "a1" in user
        assert "threat_model" in user

    def test_get_prompt_reporting(self) -> None:
        summary = {"target": "x.com", "recon": None}
        system, user = get_prompt(REPORTING, summary=summary)
        assert "x.com" in user
        assert "report" in user

    def test_get_prompt_unknown_phase_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown phase"):
            get_prompt("unknown_phase", target="x")


class TestPhaseSchemas:
    """JSON schemas per phase."""

    def test_phase_schemas_has_all_phases(self) -> None:
        phases = {RECON, THREAT_MODELING, VULN_ANALYSIS, EXPLOITATION, POST_EXPLOITATION, REPORTING}
        assert set(PHASE_SCHEMAS.keys()) == phases

    def test_recon_schema_structure(self) -> None:
        schema = get_schema(RECON)
        assert schema["type"] == "object"
        assert "assets" in schema["properties"]
        assert "subdomains" in schema["properties"]
        assert "ports" in schema["properties"]

    def test_exploitation_schema_has_exploits_and_evidence(self) -> None:
        schema = get_schema(EXPLOITATION)
        assert "exploits" in schema["properties"]
        assert "evidence" in schema["properties"]

    def test_get_schema_unknown_phase_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown phase"):
            get_schema("unknown")

    @pytest.mark.parametrize(
        "phase",
        [RECON, THREAT_MODELING, VULN_ANALYSIS, EXPLOITATION, POST_EXPLOITATION, REPORTING],
    )
    def test_get_schema_and_fixer_prompt_for_each_phase(self, phase: str) -> None:
        """Each phase in registry has valid schema and get_fixer_prompt works with it."""
        schema = get_schema(phase)
        assert isinstance(schema, dict)
        assert schema.get("type") == "object"
        assert "properties" in schema or "required" in schema

        invalid_json = '{"incomplete": '
        system, user = get_fixer_prompt(invalid_json, schema)
        assert system == FIXER_SYSTEM_PROMPT
        assert invalid_json in user
        schema_str = json.dumps(schema, indent=2)
        assert schema_str in user


class TestFixerPrompt:
    """Fixer prompt for JSON retry."""

    def test_get_fixer_prompt_includes_invalid_json_and_schema(self) -> None:
        invalid = '{"assets": ["a1"], "subdomains":'
        schema = get_schema(RECON)
        system, user = get_fixer_prompt(invalid, schema)
        assert invalid in user
        assert "assets" in user
        assert "subdomains" in user
        assert system == FIXER_SYSTEM_PROMPT

    def test_fixer_schema_is_valid_json(self) -> None:
        schema = get_schema(RECON)
        schema_str = json.dumps(schema)
        parsed = json.loads(schema_str)
        assert parsed == schema

    def test_get_fixer_prompt_with_empty_schema(self) -> None:
        """Empty schema should not crash; prompt still contains schema string."""
        empty_schema: dict[str, object] = {}
        invalid = "not json"
        system, user = get_fixer_prompt(invalid, empty_schema)
        assert system == FIXER_SYSTEM_PROMPT
        assert invalid in user
        assert "Expected schema:" in user
        assert "{}" in user


class TestAiPromptsRetryWithFixer:
    """ai_recon retries with fixer when first response is invalid JSON."""

    @pytest.mark.asyncio
    async def test_retry_fixer_produces_valid_json(self) -> None:
        """First call returns invalid JSON, fixer call returns valid JSON."""
        invalid_response = "not valid json at all"
        valid_response = '{"assets": ["a1","a2"], "subdomains": ["s1.com"], "ports": [80,443]}'

        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"}):
            with patch("src.orchestration.ai_prompts.call_llm_unified", new_callable=AsyncMock) as mock_call:
                mock_call.side_effect = [invalid_response, valid_response]
                from src.orchestration.ai_prompts import ai_recon
                from src.orchestration.phases import ReconInput

                out = await ai_recon(ReconInput(target="https://x.com", options={}))

                assert mock_call.call_count == 2
                assert out.assets == ["a1", "a2"]
                assert out.subdomains == ["s1.com"]
                assert out.ports == [80, 443]

    @pytest.mark.asyncio
    async def test_no_retry_when_first_response_valid(self) -> None:
        """When first call returns valid JSON, fixer is not called."""
        valid_response = '{"assets": ["x1"], "subdomains": ["y.com"], "ports": [443]}'

        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"}):
            with patch("src.orchestration.ai_prompts.call_llm_unified", new_callable=AsyncMock) as mock_call:
                mock_call.return_value = valid_response
                from src.orchestration.ai_prompts import ai_recon
                from src.orchestration.phases import ReconInput

                out = await ai_recon(ReconInput(target="x.com", options={}))

                assert mock_call.call_count == 1
                assert out.assets == ["x1"]

    @pytest.mark.asyncio
    async def test_fixer_still_invalid_json_raises(self) -> None:
        """When initial and all fixer retries return invalid JSON, ai_recon raises."""
        invalid_responses = [
            "not valid json at all",
            '{"assets": ["broken", ',
            "still not json",
            "{bad}",
        ]

        with patch.dict("os.environ", {"OPENAI_API_KEY": "sk-test"}):
            with patch("src.orchestration.ai_prompts.call_llm_unified", new_callable=AsyncMock) as mock_call:
                mock_call.side_effect = invalid_responses
                from src.orchestration.ai_prompts import ai_recon
                from src.orchestration.phases import ReconInput

                with pytest.raises(RuntimeError, match="LLM returned invalid response"):
                    await ai_recon(ReconInput(target="x.com", options={}))

                assert mock_call.call_count == 4
