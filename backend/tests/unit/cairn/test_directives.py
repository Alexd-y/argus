"""Phase 14 — directive schemas, intrusiveness cap, deterministic priority, dedup."""

from __future__ import annotations

from src.cairn.directives.dedup import dedupe_focuses, normalize_focus
from src.cairn.directives.priority import compute_priority_score
from src.cairn.directives.schemas import (
    JSON_SCHEMA_PENTEST_DIRECTIVE_BATCH,
    DirectiveFocus,
    DirectiveKind,
    FocusType,
    Intrusiveness,
    PentestDirective,
    ProofRequirement,
    allowed_intrusiveness_for,
    clamp_intrusiveness,
    exceeds_allowed,
)

# --- intrusiveness safety (§18.6 #1) -----------------------------------------


def test_production_caps_at_active_safe() -> None:
    allowed = allowed_intrusiveness_for("production", has_target_lease=True)
    assert allowed == Intrusiveness.ACTIVE_SAFE


def test_lab_with_lease_allows_active_intrusive() -> None:
    allowed = allowed_intrusiveness_for("lab_unrestricted", has_target_lease=True)
    assert allowed == Intrusiveness.ACTIVE_INTRUSIVE


def test_lab_without_lease_caps_at_active_safe() -> None:
    allowed = allowed_intrusiveness_for("lab_unrestricted", has_target_lease=False)
    assert allowed == Intrusiveness.ACTIVE_SAFE


def test_model_cannot_escalate_intrusiveness() -> None:
    allowed = allowed_intrusiveness_for("production", has_target_lease=False)
    clamped = clamp_intrusiveness(Intrusiveness.ACTIVE_INTRUSIVE, allowed)
    assert clamped == Intrusiveness.ACTIVE_SAFE
    assert exceeds_allowed(Intrusiveness.ACTIVE_INTRUSIVE, allowed) is True


def test_destructive_never_allowed() -> None:
    allowed = allowed_intrusiveness_for("lab_unrestricted", has_target_lease=True)
    assert exceeds_allowed(Intrusiveness.DESTRUCTIVE_FORBIDDEN, allowed) is True
    assert clamp_intrusiveness(Intrusiveness.DESTRUCTIVE_FORBIDDEN, allowed) == allowed


# --- deterministic priority (§18.7) ------------------------------------------


def test_priority_is_deterministic() -> None:
    kw = {"severity": "high", "cvss": 8.1, "epss": 0.6, "kev_listed": True, "public_poc": True}
    assert compute_priority_score(**kw) == compute_priority_score(**kw)


def test_priority_kev_and_poc_raise_score() -> None:
    low = compute_priority_score(severity="medium", cvss=5.0)
    high = compute_priority_score(
        severity="medium", cvss=5.0, kev_listed=True, public_poc=True, epss=0.9
    )
    assert high > low
    assert 0.0 <= low <= 1.0 and 0.0 <= high <= 1.0


def test_priority_penalty_lowers_score() -> None:
    base = compute_priority_score(severity="high", cvss=8.0)
    penalized = compute_priority_score(severity="high", cvss=8.0, already_explored_penalty=1.0)
    assert penalized < base


# --- dedup (§18.7) -----------------------------------------------------------


def test_normalize_focus_keys() -> None:
    assert (
        normalize_focus(DirectiveFocus(type=FocusType.CVE, value="CVE-2026-34486"))
        == "cve:cve-2026-34486"
    )
    assert (
        normalize_focus(DirectiveFocus(type=FocusType.PORT, value="4000", port=4000)) == "port:4000"
    )
    assert (
        normalize_focus(DirectiveFocus(type=FocusType.SERVICE, value="Tomcat", service_version="9"))
        == "service:tomcat@9"
    )


def test_dedupe_focuses_keeps_first() -> None:
    focuses = [
        DirectiveFocus(type=FocusType.SERVICE, value="Tomcat"),
        DirectiveFocus(type=FocusType.SERVICE, value="tomcat"),
        DirectiveFocus(type=FocusType.PORT, value="4000", port=4000),
    ]
    kept = dedupe_focuses(focuses)
    assert len(kept) == 2


# --- schema ------------------------------------------------------------------


def test_directive_schema_roundtrip() -> None:
    directive = PentestDirective(
        kind=DirectiveKind.SERVICE_DEEP_DIVE,
        title="Zoom in on Tomcat",
        directive_text="Focus on the Tomcat service and its CVEs; validate with a PoC.",
        focus=DirectiveFocus(type=FocusType.SERVICE, value="Tomcat"),
        success_criterion="A working PoC executes a command on the target.",
        proof_requirement=ProofRequirement.COMMAND_EXECUTION,
        intrusiveness=Intrusiveness.ACTIVE_SAFE,
        priority_score=0.7,
    )
    dumped = directive.model_dump()
    assert dumped["kind"] == "service_deep_dive"
    assert PentestDirective(**dumped).focus.value == "Tomcat"


def test_batch_json_schema_exported() -> None:
    assert "properties" in JSON_SCHEMA_PENTEST_DIRECTIVE_BATCH
    assert "directives" in JSON_SCHEMA_PENTEST_DIRECTIVE_BATCH["properties"]
