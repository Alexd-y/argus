"""Wave 5 / R-9.1 — unified LLM telemetry seam.

The PRIMARY WhiteRabbitNeo path (``src/llm/facade.py``) must land in the SAME
single telemetry writer as the cloud gateway. These tests pin the recorder's
contract offline (no DB / no event loop): it funnels into
``src.llm_gateway.usage_ledger.record_usage`` with the scope's tenant/scan/phase
and sha256 hashes of the prompt/response, and never raises into the call path.
"""

from __future__ import annotations

import hashlib

import pytest
from src.llm.telemetry import (
    current_telemetry_scope,
    llm_telemetry_scope,
    record_llm_invocation,
)
from src.llm_gateway import usage_ledger


@pytest.fixture(autouse=True)
def _clear_ledger():
    """Isolate the process-global in-memory ledger per test."""
    usage_ledger._ledger.clear()
    yield
    usage_ledger._ledger.clear()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_scope_default_is_empty_and_restores():
    assert current_telemetry_scope() == {"tenant_id": "", "scan_id": "", "phase": ""}
    with llm_telemetry_scope(tenant_id="t1", scan_id="s1", phase="vuln_analysis"):
        assert current_telemetry_scope() == {
            "tenant_id": "t1",
            "scan_id": "s1",
            "phase": "vuln_analysis",
        }
        with llm_telemetry_scope(tenant_id="t2", scan_id="s2", phase="exploitation"):
            assert current_telemetry_scope()["tenant_id"] == "t2"
        # inner scope restored to the outer one
        assert current_telemetry_scope()["tenant_id"] == "t1"
    assert current_telemetry_scope() == {"tenant_id": "", "scan_id": "", "phase": ""}


def test_record_inherits_scope_and_hashes_texts():
    with llm_telemetry_scope(tenant_id="tenant-a", scan_id="scan-a", phase="vuln_analysis"):
        record_llm_invocation(
            task="VULN_ANALYSIS",
            provider="whiterabbitneo",
            model="taico-ai/WhiteRabbitNeo-v3-7B",
            prompt_text="system\nuser-prompt",
            response_text="model-answer",
            prompt_tokens=11,
            completion_tokens=7,
            latency_ms=42,
        )

    assert len(usage_ledger._ledger) == 1
    entry = usage_ledger._ledger[0]
    assert entry["tenant_id"] == "tenant-a"
    assert entry["scan_id"] == "scan-a"
    assert entry["phase"] == "vuln_analysis"
    assert entry["task"] == "VULN_ANALYSIS"
    assert entry["provider"] == "whiterabbitneo"
    assert entry["prompt_tokens"] == 11
    assert entry["completion_tokens"] == 7
    assert entry["total_tokens"] == 18


def test_explicit_scan_and_phase_override_scope():
    with llm_telemetry_scope(tenant_id="tenant-a", scan_id="scope-scan", phase="recon"):
        record_llm_invocation(
            task="DEDUP_ANALYSIS",
            provider="cloud",
            model="deepseek",
            prompt_text="p",
            response_text="r",
            scan_id="explicit-scan",
            phase="reporting",
        )
    entry = usage_ledger._ledger[0]
    # explicit args win; tenant still comes from the scope
    assert entry["scan_id"] == "explicit-scan"
    assert entry["phase"] == "reporting"
    assert entry["tenant_id"] == "tenant-a"


def test_hashes_match_sha256_and_empty_text_is_empty_hash(monkeypatch):
    captured = {}

    def _fake_record_usage(**kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(usage_ledger, "record_usage", _fake_record_usage)

    record_llm_invocation(
        task="THREAT_MODELING",
        provider="whiterabbitneo",
        model="wrb",
        prompt_text="hello",
        response_text=None,
    )
    assert captured["prompt_hash"] == _sha("hello")
    assert captured["response_hash"] == ""  # None/empty text → empty hash, not a hash of ""


def test_enum_task_is_coerced_to_value():
    class _Task:
        value = "EXPLOIT_GENERATION"

    record_llm_invocation(task=_Task(), provider="wrb", model="wrb", prompt_text="x")
    assert usage_ledger._ledger[0]["task"] == "EXPLOIT_GENERATION"


def test_recorder_never_raises(monkeypatch):
    def _boom(**kwargs):
        raise RuntimeError("ledger exploded")

    monkeypatch.setattr(usage_ledger, "record_usage", _boom)
    # Must be swallowed — telemetry can never break the LLM call path.
    record_llm_invocation(task="VALIDATION_ONESHOT", provider="wrb", model="wrb", prompt_text="x")
