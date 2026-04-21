"""Integration tests: load the real signed prompt catalog (ARG-008).

Mirror of ``tests/integration/payloads/test_signed_payloads_load.py``.
Loads ``backend/config/prompts/`` against the bundled ``SIGNATURES``
manifest and the matching public keys under ``_keys/`` and asserts:

* All five prompt roles are present (planner / critic / verifier /
  reporter / fixer).
* No tampering has occurred since the catalog was last signed.
* The Pydantic schema matches the YAML payload (the loader runs every
  validator on every prompt).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.orchestrator.prompt_registry import (
    AgentRole,
    PromptRegistry,
    PromptRegistryError,
)


def _backend_root() -> Path:
    """Return ``backend/`` regardless of the test runner's CWD."""
    return Path(__file__).resolve().parents[3]


@pytest.fixture(scope="module")
def real_prompts_dir() -> Path:
    return _backend_root() / "config" / "prompts"


@pytest.fixture(scope="module")
def loaded_registry(real_prompts_dir: Path) -> PromptRegistry:
    if not real_prompts_dir.is_dir():
        pytest.skip(f"prompts dir not present: {real_prompts_dir}")
    registry = PromptRegistry(prompts_dir=real_prompts_dir)
    try:
        registry.load()
    except PromptRegistryError as exc:  # pragma: no cover - reproducible failure
        pytest.fail(
            f"real prompt catalog failed to load: {exc!s}; "
            "check backend/config/prompts/SIGNATURES and _keys/."
        )
    return registry


def test_all_five_roles_present(loaded_registry: PromptRegistry) -> None:
    summary = loaded_registry.load()  # idempotent
    assert summary.total >= 5
    role_counts = summary.by_role
    for role in (
        AgentRole.PLANNER,
        AgentRole.CRITIC,
        AgentRole.VERIFIER,
        AgentRole.REPORTER,
        AgentRole.FIXER,
    ):
        assert role_counts.get(role.value, 0) >= 1, (
            f"missing prompt for role={role.value}"
        )


def test_canonical_prompt_ids_present(loaded_registry: PromptRegistry) -> None:
    for prompt_id in (
        "planner_v1",
        "critic_v1",
        "verifier_v1",
        "reporter_v1",
        "fixer_v1",
    ):
        assert prompt_id in loaded_registry, (
            f"prompt_id={prompt_id!r} missing from real catalog"
        )


def test_planner_expected_schema_ref(loaded_registry: PromptRegistry) -> None:
    planner = loaded_registry.get("planner_v1")
    assert planner.expected_schema_ref == "validation_plan_v1"


def test_critic_expected_schema_ref(loaded_registry: PromptRegistry) -> None:
    critic = loaded_registry.get("critic_v1")
    assert critic.expected_schema_ref in {"critic_verdict_v1", None}


def test_fixer_has_no_schema_ref(loaded_registry: PromptRegistry) -> None:
    """Fixer's output is the *target* agent's contract, not its own."""
    fixer = loaded_registry.get("fixer_v1")
    assert fixer.expected_schema_ref is None


def test_models_are_within_token_budget(loaded_registry: PromptRegistry) -> None:
    for prompt in loaded_registry.list_all():
        assert 1 <= prompt.default_max_tokens <= 8192
        assert 0.0 <= prompt.default_temperature <= 1.0
