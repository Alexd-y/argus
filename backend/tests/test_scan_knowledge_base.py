"""Unit tests for ScanKnowledgeBase (mocked Redis via patch get_redis; no real Redis)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from src.agents.va_orchestrator import VAMultiAgentOrchestrator
from src.cache import scan_knowledge_base as skb_module
from src.cache.scan_knowledge_base import ScanKnowledgeBase


@pytest.fixture(autouse=True)
def reset_kb_singleton() -> None:
    prev = skb_module._kb_instance
    skb_module._kb_instance = None
    yield
    skb_module._kb_instance = prev


@pytest.fixture
def mock_redis() -> MagicMock:
    r = MagicMock()
    r.get.return_value = None
    pipe = MagicMock()
    r.pipeline.return_value = pipe
    pipe.execute.return_value = []
    r.scan_iter.return_value = iter([])
    return r


@pytest.fixture
def kb(mock_redis: MagicMock) -> ScanKnowledgeBase:
    with patch.object(skb_module, "get_redis", return_value=mock_redis):
        return ScanKnowledgeBase()


def test_get_skills_for_owasp_a05(kb: ScanKnowledgeBase, mock_redis: MagicMock) -> None:
    skills = kb.get_skills_for_owasp("OWASP A05 — Injection")
    assert skills == ["sql_injection", "xss", "rce", "path_traversal"]
    mock_redis.setex.assert_called()
    call_kw = mock_redis.setex.call_args[0]
    assert call_kw[0] == "argus:kb:owasp:A05"


def test_get_skills_for_cwe_79(kb: ScanKnowledgeBase, mock_redis: MagicMock) -> None:
    for raw in ("CWE-79", "cwe-79", "79"):
        skills = kb.get_skills_for_cwe(raw)
        assert skills == ["xss"]
    mock_redis.setex.assert_called()


def test_get_scan_strategy_merges_owasp_and_cwe_dedupes_skills(
    kb: ScanKnowledgeBase,
) -> None:
    strat = kb.get_scan_strategy(["A05"], ["CWE-79"])
    assert strat["owasp_ids"] == ["A05"]
    assert strat["cwe_ids"] == ["CWE-79"]
    assert strat["skills"] == ["sql_injection", "xss", "rce", "path_traversal"]
    assert strat["priority"] == ["A05", "CWE-79"]
    assert strat["tools"] == ["sqlmap", "dalfox", "nuclei", "semgrep", "ffuf"]


def test_warm_cache_no_crash_with_mock_redis(
    kb: ScanKnowledgeBase, mock_redis: MagicMock
) -> None:
    kb.warm_cache()
    mock_redis.pipeline.assert_called_once()
    pipe = mock_redis.pipeline.return_value
    assert pipe.setex.call_count >= 1
    pipe.execute.assert_called_once()


def test_warm_cache_no_crash_memory_only() -> None:
    with patch.object(skb_module, "get_redis", return_value=None):
        kb = ScanKnowledgeBase()
    kb.warm_cache()


def test_stats_structure_redis_backend(kb: ScanKnowledgeBase, mock_redis: MagicMock) -> None:
    mock_redis.get.return_value = None
    mock_redis.scan_iter.return_value = iter([])
    st = kb.stats()
    assert set(st.keys()) == {
        "hits",
        "misses",
        "key_count",
        "memory_usage_estimate_bytes",
        "backend",
    }
    assert st["backend"] == "redis"
    assert isinstance(st["hits"], int)
    assert isinstance(st["misses"], int)
    assert isinstance(st["key_count"], int)
    assert isinstance(st["memory_usage_estimate_bytes"], int)


def test_enrich_from_recon_va_orchestrator_sample_findings(mock_redis: MagicMock) -> None:
    skb_module._kb_instance = None
    findings: list[dict] = [
        {
            "title": "Reflected XSS",
            "owasp": "Top10 A05",
            "cwe": "CWE-79",
            "evidence": "param=q",
        },
        {
            "metadata": {
                "owasp_top10": ["A05"],
                "cwe_id": 89,
            },
        },
        {
            "notes": "Plain text mentions A07 and CWE-352 for parser coverage",
        },
    ]
    with patch.object(skb_module, "get_redis", return_value=mock_redis):
        out = VAMultiAgentOrchestrator.enrich_from_recon(findings)

    assert out["owasp_ids"] == ["A05", "A07"]
    assert set(out["cwe_ids"]) == {"CWE-352", "CWE-79", "CWE-89"}
    strat = out["strategy"]
    assert isinstance(strat, dict)
    assert strat["owasp_ids"] == ["A05", "A07"]
    assert set(strat["cwe_ids"]) == {"CWE-352", "CWE-79", "CWE-89"}
    assert isinstance(out["skills"], list)
    assert isinstance(out["tools"], list)
    assert "xss" in out["skills"]
    assert len(out["tools"]) >= 1
