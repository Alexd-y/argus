"""WP B — ARTEX honesty-semantics ported into Valhalla proof-strength.

Pure/unit; no Postgres, WeasyPrint or LLM required. Covers the three-state
honesty contract (present / missing / unavailable), the counterevidence and
bound-evidence accounting, and the single stale-evidence predicate shared by the
report and the exporters.

The invariant under test is ARTEX ``report/quality.go``: a *lookup error* must
never be rendered as "not vulnerable" or "unverified"; an honest gap (zero bound
evidence, no quality row) is printed explicitly rather than silently omitted.
"""

from __future__ import annotations

from src.reports.proof_strength import (
    ProofState,
    ProofStrength,
    build_finding_proof_strength,
    compute_proof_strength,
    evidence_version_is_stale,
    stale_banner,
)
from src.reports.report_document import ReportFinding, ReportPoC


def _finding(**kw) -> ReportFinding:
    base: dict = {"finding_id": "F-1", "title": "SQL injection in /login", "severity": "high"}
    base.update(kw)
    return ReportFinding(**base)


# --------------------------------------------------------------------------- #
# Three-state honesty — the central ARTEX contract
# --------------------------------------------------------------------------- #


def test_lookup_error_is_unavailable_not_not_vulnerable() -> None:
    """A DB/lookup error → UNAVAILABLE, never 'not vulnerable' / 'unverified'."""
    ps = compute_proof_strength(
        _finding(verification_status="confirmed", evidence_ids=["E-1"]),
        known_evidence_ids={"E-1"},
        lookup_error=RuntimeError("evidence store unreachable"),
    )
    assert ps.state is ProofState.UNAVAILABLE
    blob = (ps.label + " " + ps.verification_note + " " + ps.poe_level).lower()
    assert "unavailable" in blob
    assert "not vulnerable" not in blob
    assert "unverified" not in blob


def test_bare_finding_is_missing_quality_row() -> None:
    """A finding with no assessment / evidence / poc has no quality row → MISSING."""
    ps = compute_proof_strength(_finding())
    assert ps.state is ProofState.MISSING
    assert "not recorded" in ps.label.lower()


def test_assessed_finding_is_present() -> None:
    """A finding carrying a real verification signal yields a PRESENT quality row."""
    ps = compute_proof_strength(
        _finding(verification_status="confirmed", evidence_ids=["E-1"], tool_run_id="T-1"),
        known_evidence_ids={"E-1"},
    )
    assert ps.state is ProofState.PRESENT
    assert ps.poe_level  # non-empty PoE label
    assert isinstance(ps, ProofStrength)


# --------------------------------------------------------------------------- #
# Counterevidence + bound-evidence accounting
# --------------------------------------------------------------------------- #


def test_counterevidence_collects_downgrade_reason_and_explicit_list() -> None:
    ps = compute_proof_strength(
        _finding(
            verification_status="observed",
            evidence_ids=["E-1"],
            downgrade_reason="discriminator did not reproduce under negative control",
            counterevidence=["time-based payload timed out at 30s"],
        ),
        known_evidence_ids={"E-1"},
    )
    joined = " | ".join(ps.counterevidence).lower()
    assert "discriminator did not reproduce" in joined
    assert "time-based payload timed out" in joined


def test_bound_evidence_count_is_referential() -> None:
    """Only evidence ids that resolve in the snapshot count as bound."""
    ps = compute_proof_strength(
        _finding(verification_status="confirmed", evidence_ids=["E-1", "E-ghost"]),
        known_evidence_ids={"E-1"},
    )
    assert ps.bound_evidence_count == 1


def test_zero_bound_evidence_is_printed_not_hidden() -> None:
    """Honest gap: a confirmed claim with zero bound evidence says so explicitly."""
    ps = compute_proof_strength(
        _finding(verification_status="suspected", evidence_ids=["E-ghost"]),
        known_evidence_ids={"E-1"},
    )
    assert ps.bound_evidence_count == 0
    assert "zero bound evidence" in ps.confidence_rationale.lower()


def test_raw_artifact_ref_counts_as_bound_evidence() -> None:
    ps = compute_proof_strength(
        _finding(verification_status="confirmed", raw_artifact_ref="minio://raw/abc"),
        known_evidence_ids=set(),
    )
    assert ps.bound_evidence_count == 1


def test_poc_negative_control_is_not_counterevidence() -> None:
    """A passing negative control proves the finding; it is not counterevidence."""
    ps = compute_proof_strength(
        _finding(
            verification_status="confirmed",
            evidence_ids=["E-1"],
            poc=ReportPoC(
                discriminator="sleep(5) observed", negative_control="no sleep without payload"
            ),
        ),
        known_evidence_ids={"E-1"},
    )
    joined = " | ".join(ps.counterevidence).lower()
    assert "no sleep without payload" not in joined


# --------------------------------------------------------------------------- #
# Stale-evidence predicate — ONE function for report + export surfaces
# --------------------------------------------------------------------------- #


def test_stale_predicate_true_on_version_mismatch() -> None:
    assert evidence_version_is_stale("v7", "v9") is True


def test_stale_predicate_false_on_match() -> None:
    assert evidence_version_is_stale("v9", "v9") is False


def test_stale_predicate_false_when_current_unknown() -> None:
    """Unknown current version is not a false 'stale' claim (honest, not alarmist)."""
    assert evidence_version_is_stale("v9", None) is False
    assert evidence_version_is_stale(None, None) is False


def test_stale_banner_present_on_mismatch_absent_on_match() -> None:
    banner = stale_banner("v7", "v9")
    assert banner is not None
    assert banner["built_against"] == "v7"
    assert banner["current"] == "v9"
    assert "older evidence" in banner["message"].lower()
    assert stale_banner("v9", "v9") is None


# --------------------------------------------------------------------------- #
# build_finding_proof_strength — adapter over the legacy template-row shape
# (evidence_classification / evidence_refs / unconfirmed_reason) → canonical
# --------------------------------------------------------------------------- #


def test_legacy_validated_row_maps_to_present_proven() -> None:
    ps = build_finding_proof_strength(
        {
            "evidence_classification": "validated",
            "evidence_refs": ["E-1"],
            "confidence": "confirmed",
        },
        known_evidence_ids={"E-1"},
    )
    assert ps.state is ProofState.PRESENT
    assert ps.poe_level == "proven"
    assert ps.bound_evidence_count == 1


def test_legacy_candidate_row_maps_to_suspected() -> None:
    ps = build_finding_proof_strength({"evidence_classification": "candidate"})
    assert ps.state is ProofState.PRESENT
    assert ps.poe_level == "partial"


def test_legacy_unconfirmed_reason_becomes_counterevidence() -> None:
    ps = build_finding_proof_strength(
        {
            "evidence_classification": "candidate",
            "unconfirmed_reason": "payload blocked by WAF; no reflection observed",
        }
    )
    assert any("blocked by waf" in c.lower() for c in ps.counterevidence)


def test_exploit_demonstrated_row_maps_to_exploitable() -> None:
    ps = build_finding_proof_strength(
        {"exploit_demonstrated": True, "evidence_refs": ["E-1"]},
        known_evidence_ids={"E-1"},
    )
    assert ps.poe_level == "proven-exploitable"


def test_build_finding_proof_strength_is_unavailable_on_attribute_error() -> None:
    """A finding whose field access raises must degrade to UNAVAILABLE, never blank."""

    class Exploding:
        @property
        def verification_status(self):  # noqa: D401 - test double
            raise RuntimeError("row store unreachable")

    ps = build_finding_proof_strength(Exploding())
    assert ps.state is ProofState.UNAVAILABLE
    assert "unavailable" in ps.label.lower()
