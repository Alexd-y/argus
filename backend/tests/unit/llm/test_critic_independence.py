"""Wave 5 / R-9.14 — independent-review audit.

R-9.14 requires verifying that the second-pass review is a GENUINELY independent
check, not a formality. The author (planner), the critic, and the verifier are
separate signed prompts; this test encodes the independence invariant so it
cannot silently regress into "the critic just restates the plan":

* the three roles are distinct (``agent_role``);
* their system prompts are pairwise distinct (not copy-paste);
* the critic's prompt carries an adversarial posture (it can REJECT), which the
  author's does not — i.e. the critic is positioned to disagree, not to rubber-stamp.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

_PROMPTS = Path(__file__).resolve().parents[3] / "config" / "prompts"


def _load(name: str) -> dict:
    return yaml.safe_load((_PROMPTS / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def roles():
    return {
        "planner": _load("planner_v1.yaml"),
        "critic": _load("critic_v1.yaml"),
        "verifier": _load("verifier_v1.yaml"),
    }


def test_three_roles_exist_with_distinct_agent_role(roles):
    agent_roles = {name: r.get("agent_role") for name, r in roles.items()}
    assert agent_roles["planner"] == "planner"
    assert agent_roles["critic"] == "critic"
    assert agent_roles["verifier"] == "verifier"
    assert len(set(agent_roles.values())) == 3  # genuinely distinct roles


def test_system_prompts_are_pairwise_distinct(roles):
    prompts = {name: (r.get("system_prompt") or "").strip() for name, r in roles.items()}
    assert all(prompts.values()), "every role must carry a non-empty system prompt"
    assert prompts["planner"] != prompts["critic"]
    assert prompts["planner"] != prompts["verifier"]
    assert prompts["critic"] != prompts["verifier"]


def test_critic_has_adversarial_posture_the_author_lacks(roles):
    critic = (roles["critic"].get("system_prompt") or "").lower()
    planner = (roles["planner"].get("system_prompt") or "").lower()
    # The critic must be able to reject/block — an independent gate, not a restate.
    assert any(w in critic for w in ("reject", "approve or reject", "block", "deny"))
    # The author is a constructive role; it does not frame itself as the rejecter.
    assert "reject the plan" not in planner
