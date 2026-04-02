"""RPT-004 — Prompt registry sections, cache key, Celery task; cache hit skips LLM."""

from __future__ import annotations

import hashlib
import json
from unittest.mock import MagicMock

import pytest

from src.orchestration.prompt_registry import (
    REPORT_AI_SECTION_EXECUTIVE_SUMMARY,
    REPORT_AI_SECTION_KEYS,
    get_report_ai_section_prompt,
)
from src.reports.ai_text_generation import (
    REPORT_AI_SKIPPED_GENERATION_FAILED,
    REPORT_AI_SKIPPED_NO_LLM,
    build_ai_text_cache_key,
    canonical_payload_hash,
    run_ai_text_generation,
)
from src.services.reporting import ReportGenerator


class TestRpt004PromptRegistry:
    """All section keys registered with templates and versions."""

    def test_all_section_keys_present(self) -> None:
        expected = {
            "executive_summary",
            "vulnerability_description",
            "remediation_step",
            "business_risk",
            "compliance_check",
            "prioritization_roadmap",
            "hardening_recommendations",
            "executive_summary_valhalla",
            "attack_scenarios",
            "exploit_chains",
            "remediation_stages",
            "zero_day_potential",
        }
        assert REPORT_AI_SECTION_KEYS == expected

    def test_get_prompt_returns_tuple(self) -> None:
        system, user, version = get_report_ai_section_prompt(
            REPORT_AI_SECTION_EXECUTIVE_SUMMARY,
            {"finding": "xss", "severity": "high"},
        )
        assert "penetration testing report" in system.lower()
        assert "finding" in user and "xss" in user
        assert version.startswith("vhq009-")


class TestRpt004CacheKey:
    def test_payload_hash_deterministic(self) -> None:
        p = {"b": 2, "a": 1}
        assert canonical_payload_hash(p) == canonical_payload_hash({"a": 1, "b": 2})

    def test_cache_key_components(self) -> None:
        h = "ab" * 32
        components = {
            "tenant_id": "t1",
            "scan_id": "s1",
            "tier": "full",
            "section_key": "executive_summary",
            "payload_hash": h,
            "prompt_version": "v1",
        }
        expected = "argus:ai_text:" + hashlib.sha256(
            json.dumps(components, sort_keys=True).encode("utf-8")
        ).hexdigest()
        key = build_ai_text_cache_key("t1", "s1", "full", "executive_summary", h, "v1")
        assert key == expected
        assert key.startswith("argus:ai_text:")
        assert len(key) == len("argus:ai_text:") + 64

    def test_cache_key_colon_in_values_no_collision_with_joined_form(self) -> None:
        """Distinct tenant/scan values that would merge if colon-joined must not share a key."""
        h = "ab" * 32
        k1 = build_ai_text_cache_key("a:b", "c", "full", "executive_summary", h, "v1")
        k2 = build_ai_text_cache_key("a", "b:c", "full", "executive_summary", h, "v1")
        assert k1 != k2


class TestRpt004CacheSkipsLlm:
    def test_cache_hit_skips_llm(self) -> None:
        mock_redis = MagicMock()
        mock_redis.get.return_value = json.dumps({"text": "cached body"})
        llm = MagicMock(return_value="should not run")

        out = run_ai_text_generation(
            "tenant-a",
            "scan-b",
            "standard",
            "executive_summary",
            {"k": "v"},
            redis_client=mock_redis,
            llm_callable=llm,
            cache_ttl_seconds=60,
        )

        assert out["status"] == "ok"
        assert out["cache_hit"] is True
        assert out["text"] == "cached body"
        llm.assert_not_called()
        mock_redis.get.assert_called_once()

    def test_llm_empty_response_returns_generation_failed_placeholder(self) -> None:
        mock_redis = MagicMock()
        mock_redis.get.return_value = None
        llm = MagicMock(return_value="   ")

        out = run_ai_text_generation(
            "tenant-a",
            "scan-b",
            "midgard",
            "executive_summary",
            {"k": "v"},
            redis_client=mock_redis,
            llm_callable=llm,
            cache_ttl_seconds=60,
        )

        assert out["status"] == "failed"
        assert out.get("text") == REPORT_AI_SKIPPED_GENERATION_FAILED
        mock_redis.set.assert_not_called()

    def test_cache_miss_calls_llm_and_sets_cache(self) -> None:
        mock_redis = MagicMock()
        mock_redis.get.return_value = None
        llm = MagicMock(return_value="fresh text")

        out = run_ai_text_generation(
            "tenant-a",
            "scan-b",
            "standard",
            "executive_summary",
            {"k": "v"},
            redis_client=mock_redis,
            llm_callable=llm,
            cache_ttl_seconds=60,
        )

        assert out["status"] == "ok"
        assert out["cache_hit"] is False
        assert out["text"] == "fresh text"
        llm.assert_called_once()
        mock_redis.set.assert_called_once()


class TestRpt004ExecutiveFactGate:
    def test_mismatched_severity_replaced_when_config_enabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            "src.reports.ai_text_generation.settings.ai_text_executive_fact_check_replace",
            True,
        )
        out = run_ai_text_generation(
            "t1",
            "s1",
            "valhalla",
            "executive_summary",
            {
                "executive_severity_totals": {
                    "critical": 0,
                    "high": 1,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
                "finding_count": 1,
            },
            redis_client=None,
            llm_callable=lambda *a, **k: "There are 99 critical findings.",
        )
        assert out["status"] == "ok"
        assert "99" not in out["text"]
        assert "critical: 0" in out["text"]

    def test_mismatched_keeps_llm_when_replace_disabled(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "src.reports.ai_text_generation.settings.ai_text_executive_fact_check_replace",
            False,
        )
        out = run_ai_text_generation(
            "t1",
            "s1",
            "valhalla",
            "executive_summary",
            {
                "executive_severity_totals": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "info": 0,
                },
                "finding_count": 0,
            },
            redis_client=None,
            llm_callable=lambda *a, **k: "There are 99 critical findings.",
        )
        assert out["status"] == "ok"
        assert "99" in out["text"]


class TestRpt004NoLlmPlaceholders:
    def test_run_ai_text_generation_no_keys_returns_placeholder_text(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for k in (
            "OPENAI_API_KEY",
            "DEEPSEEK_API_KEY",
            "OPENROUTER_API_KEY",
            "GOOGLE_API_KEY",
            "KIMI_API_KEY",
            "PERPLEXITY_API_KEY",
        ):
            monkeypatch.delenv(k, raising=False)
        out = run_ai_text_generation(
            "t1",
            "s1",
            "midgard",
            "executive_summary",
            {"finding_count": 0},
            redis_client=None,
            llm_callable=None,
        )
        assert out["status"] == "skipped_no_llm"
        assert out.get("text") == REPORT_AI_SKIPPED_NO_LLM

    def test_ai_results_to_text_map_includes_skipped_no_llm(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for k in (
            "OPENAI_API_KEY",
            "DEEPSEEK_API_KEY",
            "OPENROUTER_API_KEY",
            "GOOGLE_API_KEY",
            "KIMI_API_KEY",
            "PERPLEXITY_API_KEY",
        ):
            monkeypatch.delenv(k, raising=False)
        raw = run_ai_text_generation(
            "t1", "s1", "midgard", "remediation_step", {"finding_count": 1}, redis_client=None
        )
        mapped = ReportGenerator.ai_results_to_text_map({"remediation_step": raw})
        assert mapped["remediation_step"] == REPORT_AI_SKIPPED_NO_LLM


class TestRpt004CeleryRegistration:
    def test_task_registered_and_routed(self) -> None:
        import src.tasks  # noqa: F401 — registers Celery tasks on the app
        from src.celery_app import app as celery_app

        assert "argus.ai_text_generation" in celery_app.tasks
        routes = celery_app.conf.task_routes or {}
        assert routes.get("argus.ai_text_generation", {}).get("queue") == "argus.reports"
