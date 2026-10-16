"""Wave 5 / R-9.9 — structured-output enforcement on the primary WRB path.

The exact request field is server-dependent (WRB may be vLLM or a llama.cpp
server), so the dialect is explicit and defaults to "off" — a schema never
changes the payload until the deployment opts into a dialect its server accepts.
"""

from __future__ import annotations

from src.core.config import settings
from src.llm.whiterabbitneo_adapter import _apply_structured_output

_SCHEMA = {"type": "object", "properties": {"ok": {"type": "boolean"}}}


def _base_payload() -> dict:
    return {"model": "wrb", "messages": [], "temperature": 0.2, "max_tokens": 128}


def test_no_schema_is_noop(monkeypatch):
    monkeypatch.setattr(settings, "llm_structured_output_mode", "guided_json", raising=False)
    p = _base_payload()
    _apply_structured_output(p, None)
    assert "response_format" not in p and "guided_json" not in p


def test_off_mode_is_noop_even_with_schema(monkeypatch):
    monkeypatch.setattr(settings, "llm_structured_output_mode", "off", raising=False)
    p = _base_payload()
    _apply_structured_output(p, _SCHEMA)
    assert "response_format" not in p and "guided_json" not in p


def test_json_object_mode(monkeypatch):
    monkeypatch.setattr(settings, "llm_structured_output_mode", "json_object", raising=False)
    p = _base_payload()
    _apply_structured_output(p, _SCHEMA)
    assert p["response_format"] == {"type": "json_object"}
    assert "guided_json" not in p


def test_guided_json_mode_vllm(monkeypatch):
    monkeypatch.setattr(settings, "llm_structured_output_mode", "guided_json", raising=False)
    p = _base_payload()
    _apply_structured_output(p, _SCHEMA)
    assert p["response_format"] == {"type": "json_object"}
    assert p["guided_json"] == _SCHEMA


def test_llama_schema_mode(monkeypatch):
    monkeypatch.setattr(settings, "llm_structured_output_mode", "llama_schema", raising=False)
    p = _base_payload()
    _apply_structured_output(p, _SCHEMA)
    assert p["response_format"] == {"type": "json_object", "schema": _SCHEMA}


def test_unknown_mode_is_noop(monkeypatch):
    monkeypatch.setattr(settings, "llm_structured_output_mode", "nonsense", raising=False)
    p = _base_payload()
    _apply_structured_output(p, _SCHEMA)
    assert p == _base_payload()
