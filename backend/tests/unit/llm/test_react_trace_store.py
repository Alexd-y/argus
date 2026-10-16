"""Wave 5 / R-9.4 — full ReAct reasoning-trace persistence.

Pins: off by default; when on, scalar metadata is written and the full ordered
steps go through the redact-then-store path; no tenant in scope → noop; the
react_agent.run wrapper persists best-effort without altering the result.
"""

from __future__ import annotations

import asyncio
import hashlib
import json

from src.core.config import settings
from src.llm import react_trace_store
from src.llm.react_trace_store import persist_react_trace
from src.llm.telemetry import llm_telemetry_scope


class _Step:
    def __init__(self, step_type, content):
        self.step_type = step_type
        self.content = content
        self.tool_name = None
        self.tool_args = None
        self.tool_result = None
        self.timestamp = "2026-01-01T00:00:00+00:00"


class _Result:
    def __init__(self):
        self.answer = "the answer"
        self.iterations = 3
        self.confidence = 0.9
        self.total_duration_seconds = 1.5
        self.stop_reason = "final_answer"
        self.evidence_backed = True
        self.error = ""
        self.steps = [_Step("thought", "t1"), _Step("action", "a1")]


class _FakeSession:
    def __init__(self):
        self.added = []
        self.committed = False
        self.tenant = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.committed = True


def test_steps_to_json_roundtrips_fields():
    payload = json.loads(react_trace_store._steps_to_json(_Result()))
    assert [p["step_type"] for p in payload] == ["thought", "action"]
    assert payload[0]["content"] == "t1"


def test_steps_to_json_redacts_multiline_secret_in_fields():
    """Regression: redaction runs on RAW fields, not the JSON blob, so a
    multi-line PEM in a tool result is caught (no parser-differential bypass)."""
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEAsecretkeymaterialDONOTLEAK1234567890\n"
        "-----END RSA PRIVATE KEY-----"
    )

    class _Step:
        step_type = "observation"
        content = "tool output follows"
        tool_name = "curl"
        tool_args = None
        tool_result = pem
        timestamp = "ts"

    class _R:
        steps = [_Step()]

    blob = react_trace_store._steps_to_json(_R())
    assert "MIIEpAIBAAKCAQEAsecretkeymaterialDONOTLEAK1234567890" not in blob
    assert "REDACTED" in blob


def test_steps_to_json_redacts_secret_nested_in_dict_result():
    """The differential also closes for STRUCTURED tool results: a PEM nested in
    a dict/list must be redacted at the string leaf, not after json.dumps."""
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEpAIBAAKCAQEAnestedSECRETkeyDONOTLEAK9876543210\n"
        "-----END RSA PRIVATE KEY-----"
    )

    class _Step:
        step_type = "observation"
        content = "ok"
        tool_name = "reader"
        tool_args = {"paths": ["/etc/key.pem"]}
        tool_result = {"files": [{"name": "key.pem", "body": pem}]}
        timestamp = "ts"

    class _R:
        steps = [_Step()]

    blob = react_trace_store._steps_to_json(_R())
    assert "MIIEpAIBAAKCAQEAnestedSECRETkeyDONOTLEAK9876543210" not in blob
    assert "REDACTED" in blob


def test_disabled_by_default_is_noop(monkeypatch):
    monkeypatch.setattr(settings, "react_trace_persist", False, raising=False)
    with llm_telemetry_scope(tenant_id="t", scan_id="s", phase="exploitation"):
        assert asyncio.run(persist_react_trace(result=_Result())) is None


def test_no_tenant_in_scope_is_noop(monkeypatch):
    monkeypatch.setattr(settings, "react_trace_persist", True, raising=False)
    # no scope set → tenant resolves empty → noop
    assert asyncio.run(persist_react_trace(result=_Result())) is None


def test_persists_scalar_metadata_and_steps_key(monkeypatch):
    monkeypatch.setattr(settings, "react_trace_persist", True, raising=False)
    session = _FakeSession()

    async def _set_tenant(sess, tenant_id):
        sess.tenant = tenant_id

    monkeypatch.setattr("src.db.session.async_session_factory", lambda: session)
    monkeypatch.setattr("src.db.session.set_session_tenant", _set_tenant)
    monkeypatch.setattr(
        "src.llm.telemetry_text_store.store_redacted_text",
        lambda **kw: "tn/sc/llm_telemetry/react_trace-abc.txt",
    )

    with llm_telemetry_scope(tenant_id="tn", scan_id="sc", phase="exploitation"):
        row_id = asyncio.run(persist_react_trace(result=_Result(), task="EXPLOIT_GENERATION"))

    assert row_id is not None
    assert session.committed is True
    assert session.tenant == "tn"
    row = session.added[0]
    assert row.tenant_id == "tn"
    assert row.scan_id == "sc"
    assert row.phase == "exploitation"
    assert row.task == "EXPLOIT_GENERATION"
    assert row.iterations == 3
    assert row.steps_count == 2
    assert row.evidence_backed is True
    assert row.stop_reason == "final_answer"
    assert row.steps_object_key == "tn/sc/llm_telemetry/react_trace-abc.txt"
    assert row.answer_hash == hashlib.sha256(b"the answer").hexdigest()


def test_best_effort_swallows_errors(monkeypatch):
    monkeypatch.setattr(settings, "react_trace_persist", True, raising=False)

    def _boom():
        raise RuntimeError("db down")

    monkeypatch.setattr("src.db.session.async_session_factory", _boom)
    monkeypatch.setattr("src.llm.telemetry_text_store.store_redacted_text", lambda **kw: "")
    with llm_telemetry_scope(tenant_id="tn", scan_id="sc", phase="x"):
        assert asyncio.run(persist_react_trace(result=_Result())) is None


def test_agent_run_wrapper_returns_result_and_persist_is_noop_by_default():
    from src.orchestration.react_agent import ReActAgent, ReActStopReason

    agent = ReActAgent(task_description="probe")
    # llm_caller=None → the loop stops immediately with NO_LLM; the wrapper must
    # still return that result unchanged (persist is off by default → noop).
    result = asyncio.run(agent.run(llm_caller=None))
    assert result.stop_reason == ReActStopReason.NO_LLM.value
