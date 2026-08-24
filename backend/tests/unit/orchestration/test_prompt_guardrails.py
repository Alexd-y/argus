"""Prompt guardrail integrity — forbidden coercive/fabrication instructions are gone,
and untrusted-data guardrails are present (Requirements R6, R8.5/R8.6)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.agents.va_orchestrator import DISCOVERY_SYSTEM_PROMPT
from src.orchestration.prompt_registry import SYSTEM_PROMPT_BASE, UNTRUSTED_DATA_GUARDRAILS

_PROMPTS_DIR = Path(__file__).resolve().parents[3] / "src" / "orchestration" / "prompts"

# Phrases that must never reappear in prompt sources.
_FORBIDDEN = [
    "go hard",
    "$500",
    "at least 10 different approaches",
    "never leave evidence fields empty",
    "generate tool commands and payloads to fill",
    "generate commands to fill missing data",
]


def _all_prompt_texts() -> list[tuple[str, str]]:
    texts: list[tuple[str, str]] = [
        ("SYSTEM_PROMPT_BASE", SYSTEM_PROMPT_BASE),
        ("DISCOVERY_SYSTEM_PROMPT", DISCOVERY_SYSTEM_PROMPT),
    ]
    for path in _PROMPTS_DIR.rglob("*.j2"):
        texts.append((str(path.relative_to(_PROMPTS_DIR)), path.read_text(encoding="utf-8")))
    return texts


@pytest.mark.parametrize("forbidden", _FORBIDDEN)
def test_no_forbidden_phrase_in_any_prompt(forbidden: str) -> None:
    for name, text in _all_prompt_texts():
        assert forbidden not in text.lower(), f"forbidden phrase {forbidden!r} found in {name}"


def test_system_base_contains_untrusted_data_guardrails() -> None:
    lowered = SYSTEM_PROMPT_BASE.lower()
    assert "untrusted data" in lowered
    assert "not_assessed" in lowered
    assert "never fabricate" in lowered
    assert "signed registry" in lowered
    assert "abstain" in lowered


def test_shared_guardrail_block_is_complete() -> None:
    lowered = UNTRUSTED_DATA_GUARDRAILS.lower()
    for needle in (
        "untrusted data",
        "abstain",
        "evidence ids",
        "never fabricate",
        "cve",
        "raw shell commands",
        "scope, profile and budget",
        "secrets",
    ):
        assert needle in lowered, needle


def test_system_base_template_is_sanitized() -> None:
    text = (_PROMPTS_DIR / "system_base.j2").read_text(encoding="utf-8").lower()
    assert "untrusted data" in text
    assert "never leave evidence fields empty" not in text
