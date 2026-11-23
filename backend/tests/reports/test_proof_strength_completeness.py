"""WP B — three-state honesty enforced at the Valhalla completeness gate.

Pure/unit. The gate must make the ARTEX invariant a *release rule*: a finding whose
proof-strength lookup is UNAVAILABLE has to be printed as such; it may never be
silently dropped or rendered as "not vulnerable".
"""

from __future__ import annotations

from src.reports.valhalla_completeness import proof_state_release_blockers


def test_unavailable_proof_requires_explicit_marker() -> None:
    blockers = proof_state_release_blockers(
        proof_states=["present", "unavailable", "present"],
        report_text="Finding A: proof strength: proven. Finding B: (marker dropped).",
    )
    assert blockers
    assert any("unavailable" in b.lower() for b in blockers)


def test_unavailable_proof_with_marker_is_clean() -> None:
    blockers = proof_state_release_blockers(
        proof_states=["present", "unavailable"],
        report_text="Finding B: proof strength unavailable — evidence lookup error.",
    )
    assert blockers == []


def test_no_unavailable_states_is_clean() -> None:
    blockers = proof_state_release_blockers(
        proof_states=["present", "missing", "present"],
        report_text="nothing special here",
    )
    assert blockers == []


def test_unavailable_never_rendered_as_not_vulnerable() -> None:
    blockers = proof_state_release_blockers(
        proof_states=["unavailable"],
        report_text="Finding is not vulnerable.",  # the forbidden conflation
    )
    assert any("not vulnerable" in b.lower() for b in blockers)
