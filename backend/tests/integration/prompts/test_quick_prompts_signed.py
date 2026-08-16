"""QUICK-006 — signed Quick prompt catalog loads without mutating SIGNATURES.

Mirrors ``tests/integration/orchestrator_runtime/test_signed_prompts_load.py``
and the payloads drift guard in ``tests/integration/payloads/test_signatures_no_drift.py``.
This module is read-only against ``backend/config/prompts/``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Final

import pytest

from src.llm_orchestrator.prompt_registry import PromptRegistry, PromptRegistryError
from src.orchestration.prompt_registry import QUICK_PROMPT_IDS

_QUICK_PROMPT_FILES: Final[tuple[str, ...]] = (
    "quick_planner_v1.yaml",
    "quick_fingerprint_classifier_v1.yaml",
    "quick_finding_triage_v1.yaml",
    "quick_security_critic_v1.yaml",
    "quick_reporter_v1.yaml",
)

_SCHEMA_BY_PROMPT: Final[dict[str, str]] = {
    "quick_planner_v1": "quick_scan_plan_v1",
    "quick_fingerprint_classifier_v1": "asset_fingerprint_v1",
    "quick_finding_triage_v1": "finding_triage_v1",
    "quick_security_critic_v1": "security_critique_v1",
    "quick_reporter_v1": "quick_report_v1",
}


def _backend_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _hash_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="module")
def real_prompts_dir() -> Path:
    prompts = _backend_root() / "config" / "prompts"
    assert prompts.is_dir(), f"expected prompts dir at {prompts}"
    return prompts


@pytest.fixture(scope="module")
def initial_hashes(real_prompts_dir: Path) -> dict[str, str]:
    hashes: dict[str, str] = {
        "SIGNATURES": _hash_file(real_prompts_dir / "SIGNATURES"),
    }
    for name in _QUICK_PROMPT_FILES:
        path = real_prompts_dir / name
        assert path.is_file(), f"missing signed quick prompt {path}"
        hashes[name] = _hash_file(path)
    return hashes


@pytest.fixture(scope="module")
def loaded_registry(real_prompts_dir: Path) -> PromptRegistry:
    registry = PromptRegistry(prompts_dir=real_prompts_dir)
    try:
        registry.load()
    except PromptRegistryError as exc:  # pragma: no cover - reproducible failure
        pytest.fail(
            f"real prompt catalog failed to load: {exc!s}; "
            "check backend/config/prompts/SIGNATURES and _keys/."
        )
    return registry


def test_quick_prompt_ids_are_signed_and_loadable(
    loaded_registry: PromptRegistry,
) -> None:
    for prompt_id in sorted(QUICK_PROMPT_IDS):
        assert prompt_id in loaded_registry, f"missing signed prompt {prompt_id}"
        definition = loaded_registry.get(prompt_id)
        assert definition.prompt_id == prompt_id
        assert "Do not create shell commands." in definition.system_prompt
        expected_schema = _SCHEMA_BY_PROMPT[prompt_id]
        assert definition.expected_schema_ref == expected_schema
        assert definition.response_schema_id == expected_schema


def test_quick_planner_forbids_shell_in_system_prompt(
    loaded_registry: PromptRegistry,
) -> None:
    planner = loaded_registry.get("quick_planner_v1")
    lowered = planner.system_prompt.lower()
    assert "shell" in lowered
    assert "tool_id" in lowered or "capability" in lowered


def test_loading_registry_does_not_mutate_quick_prompt_signatures(
    real_prompts_dir: Path,
    initial_hashes: dict[str, str],
    loaded_registry: PromptRegistry,
) -> None:
    del loaded_registry  # registry already loaded; this asserts the catalog stayed put
    PromptRegistry(prompts_dir=real_prompts_dir).load()
    actual_sig = _hash_file(real_prompts_dir / "SIGNATURES")
    assert actual_sig == initial_hashes["SIGNATURES"], (
        "prompts SIGNATURES mutated by registry load — signing drift"
    )
    drift: list[str] = []
    for name in _QUICK_PROMPT_FILES:
        actual = _hash_file(real_prompts_dir / name)
        if actual != initial_hashes[name]:
            drift.append(name)
    assert not drift, f"quick prompt YAML mutated by registry load: {drift}"


def test_repeated_prompt_load_is_idempotent(real_prompts_dir: Path) -> None:
    hashes: set[str] = set()
    for _ in range(3):
        PromptRegistry(prompts_dir=real_prompts_dir).load()
        hashes.add(_hash_file(real_prompts_dir / "SIGNATURES"))
    assert len(hashes) == 1
