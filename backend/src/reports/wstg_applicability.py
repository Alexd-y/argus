"""Structured, surface-driven WSTG applicability (ARGUS-WSTG-COV-1 §Applicability).

This replaces the previous heuristic that excluded whole test groups whenever the
scanner happened to run unauthenticated. That was wrong:

* the *scanner* lacking a session does not prove the *application* lacks an auth
  mechanism (spec §3.1);
* ``manual_required`` / ``unsupported`` mean "we could not automate it", not "the
  target is out of applicability scope" (spec §3.2).

The honest model: a test's applicability derives from **structured surface
observations** (:mod:`src.reports.wstg_surface`), and defaults to ``unknown``
(which stays in the denominator) whenever the required feature has not been
positively observed. A test is excluded (``not_applicable``) only when the
required feature is *confirmed absent in scope* with evidence.

A confirmed finding mapped to a test always forces ``applicable`` and, if a prior
N/A existed, records a contradiction for the gate to surface.
"""

from __future__ import annotations

from datetime import UTC, datetime

from src.reports.wstg_coverage import _WSTG_TESTS
from src.reports.wstg_model import Applicability, ApplicabilityDecision, ReasonCode
from src.reports.wstg_surface import (
    SurfaceFeature,
    SurfaceObservation,
    build_surface_index,
)

RULE_VERSION = "argus-wstg-cov-1"

# Categories whose tests apply to essentially any reachable web target and thus
# carry no surface precondition (they are never blanket-excluded).
_UNIVERSAL_CATEGORIES: frozenset[str] = frozenset(
    {
        "Information Gathering",
        "Configuration and Deployment",
        "Error Handling",
        "Cryptography",
    }
)

# Category → the surface features a test needs (any-of). Absence of *all* of them
# (confirmed) makes the test not-applicable; an unknown feature keeps it unknown.
_CATEGORY_REQUIREMENTS: dict[str, tuple[SurfaceFeature, ...]] = {
    "Identity Management": (SurfaceFeature.AUTH_MECHANISM,),
    "Authentication": (SurfaceFeature.AUTH_MECHANISM,),
    "Authorization": (SurfaceFeature.AUTH_MECHANISM, SurfaceFeature.CONFIRMED_ROLES),
    "Session Management": (SurfaceFeature.AUTH_MECHANISM, SurfaceFeature.COOKIES),
    "Input Validation": (
        SurfaceFeature.FORMS,
        SurfaceFeature.QUERY_PARAMS,
        SurfaceFeature.BODY_INPUTS,
    ),
    "Business Logic Testing": (
        SurfaceFeature.FORMS,
        SurfaceFeature.BODY_INPUTS,
        SurfaceFeature.API,
    ),
    "Client-side Testing": (SurfaceFeature.CLIENT_INPUT,),
    "API Testing": (SurfaceFeature.API,),
}

# Per-test overrides for tests whose requirement differs from their category.
_TEST_REQUIREMENTS: dict[str, tuple[SurfaceFeature, ...]] = {
    "WSTG-SESS-02": (SurfaceFeature.COOKIES,),  # cookie attributes need a cookie
    "WSTG-ATHZ-01": (SurfaceFeature.QUERY_PARAMS, SurfaceFeature.PATH_PARAMS),
    "WSTG-BUSL-08": (SurfaceFeature.FILE_UPLOAD,),
    "WSTG-BUSL-09": (SurfaceFeature.FILE_UPLOAD,),
    "WSTG-CLNT-10": (SurfaceFeature.WEBSOCKETS,),
}

# Tests that need human judgement and cannot be fully automated by ARGUS today.
# CRITICAL (spec §3.2, §16): ``manual_required`` is NOT ``not_applicable`` — these
# stay ``unknown`` and remain in the denominator; the reason_code just makes the
# limitation explicit in the report instead of silently excluding them.
_MANUAL_REQUIRED_TESTS: frozenset[str] = frozenset(
    {
        "WSTG-IDNT-02",  # user registration process — workflow judgement
        "WSTG-IDNT-03",  # account provisioning — workflow judgement
        "WSTG-ATHN-08",  # weak security question answers — content judgement
        "WSTG-BUSL-01",  # business logic data validation
        "WSTG-BUSL-02",  # ability to forge requests
        "WSTG-BUSL-03",  # integrity checks
        "WSTG-BUSL-04",  # process timing
        "WSTG-BUSL-05",  # function-use limits
        "WSTG-BUSL-06",  # circumvention of workflows
        "WSTG-BUSL-07",  # defenses against application misuse
    }
)

# Tests with no automated executor wired in the current toolset. Still in scope
# and in the denominator; surfaced with an ``unsupported`` reason_code.
_UNSUPPORTED_TESTS: frozenset[str] = frozenset(
    {
        "WSTG-INPV-13",  # format string injection — no automated executor
        "WSTG-INPV-14",  # incubated vulnerabilities — no automated executor
        "WSTG-INPV-16",  # HTTP incoming requests — no automated executor
        "WSTG-CRYP-02",  # padding oracle — no automated executor
    }
)


def _requirements_for(test_id: str, category: str) -> tuple[SurfaceFeature, ...]:
    if test_id in _TEST_REQUIREMENTS:
        return _TEST_REQUIREMENTS[test_id]
    if category in _UNIVERSAL_CATEGORIES:
        return ()
    return _CATEGORY_REQUIREMENTS.get(category, ())


def _execution_limitation(test_id: str) -> tuple[ReasonCode, str] | None:
    """Return an execution-limitation ``reason_code`` for manual/unsupported tests.

    Returns ``None`` for tests ARGUS can automate. The limitation never changes
    applicability (it stays ``unknown``/``applicable`` and in the denominator) —
    it only records *why* the test is unlikely to auto-complete.
    """
    if test_id in _MANUAL_REQUIRED_TESTS:
        return (
            ReasonCode.MANUAL_REQUIRED,
            "Requires manual analyst execution; not fully automatable by ARGUS.",
        )
    if test_id in _UNSUPPORTED_TESTS:
        return (
            ReasonCode.UNSUPPORTED,
            "No automated executor is wired for this test in the current toolset.",
        )
    return None


def decide_applicability(
    *,
    surface: list[SurfaceObservation] | None = None,
    finding_test_ids: frozenset[str] = frozenset(),
    scope_version: str | None = None,
    now: str | None = None,
) -> dict[str, ApplicabilityDecision]:
    """Produce one :class:`ApplicabilityDecision` per catalog test.

    ``finding_test_ids`` are tests with a confirmed finding — they are always
    applicable (a finding proves the surface exists) and override any N/A.
    """
    index = build_surface_index(surface or [])
    decided_at = now or datetime.now(UTC).isoformat()
    out: dict[str, ApplicabilityDecision] = {}

    for tc in _WSTG_TESTS:
        reqs = _requirements_for(tc.id, tc.category)
        rule_id = f"req:{tc.id}" if tc.id in _TEST_REQUIREMENTS else f"cat:{tc.category}"
        limitation = _execution_limitation(tc.id)

        if tc.id in finding_test_ids:
            out[tc.id] = ApplicabilityDecision(
                test_id=tc.id,
                state=Applicability.APPLICABLE,
                rationale="A confirmed finding maps to this test; the feature exists.",
                rule_id=rule_id,
                rule_version=RULE_VERSION,
                scope_version=scope_version,
                decided_at=decided_at,
                source="finding_reconsideration",
            )
            continue

        if not reqs:
            reason = limitation[0] if limitation else None
            rationale = (
                limitation[1]
                if limitation
                else "Applies to any reachable web target (no surface precondition)."
            )
            out[tc.id] = ApplicabilityDecision(
                test_id=tc.id,
                state=Applicability.APPLICABLE,
                reason_code=reason,
                rationale=rationale,
                rule_id=rule_id,
                rule_version=RULE_VERSION,
                scope_version=scope_version,
                decided_at=decided_at,
                source="catalog_rule",
            )
            continue

        observed = [index.get(f) for f in reqs]
        if any(o is not None and o.confirms_present() for o in observed):
            state, reason, rationale, ev = (
                Applicability.APPLICABLE,
                limitation[0] if limitation else None,
                (
                    limitation[1]
                    if limitation
                    else "A required input/feature was positively observed on the target."
                ),
                _collect_evidence(observed, present=True),
            )
        elif observed and all(o is not None and o.confirms_absent() for o in observed):
            feats = ", ".join(f.value for f in reqs)
            state, reason, rationale, ev = (
                Applicability.NOT_APPLICABLE,
                ReasonCode.FEATURE_ABSENT,
                f"Required feature(s) confirmed absent in scope by completed discovery: {feats}.",
                _collect_evidence(observed, present=False),
            )
        elif limitation is not None:
            # No conclusive surface, but the test is known-manual/unsupported:
            # keep it in the denominator (unknown) and surface the real reason.
            state, reason, rationale, ev = (
                Applicability.UNKNOWN,
                limitation[0],
                limitation[1],
                (),
            )
        else:
            feats = ", ".join(f.value for f in reqs)
            state, reason, rationale, ev = (
                Applicability.UNKNOWN,
                ReasonCode.DISCOVERY_INCOMPLETE,
                f"Required feature(s) not conclusively observed ({feats}); kept in scope.",
                (),
            )

        out[tc.id] = ApplicabilityDecision(
            test_id=tc.id,
            state=state,
            reason_code=reason,
            rationale=rationale,
            evidence_refs=ev,
            rule_id=rule_id,
            rule_version=RULE_VERSION,
            scope_version=scope_version,
            decided_at=decided_at,
            source="surface_rule",
        )
    return out


def _collect_evidence(
    observed: list[SurfaceObservation | None], *, present: bool
) -> tuple[str, ...]:
    refs: list[str] = []
    for o in observed:
        if o is None:
            continue
        if (present and o.confirms_present()) or (not present and o.confirms_absent()):
            refs.extend(o.evidence_refs)
    return tuple(dict.fromkeys(refs))


__all__ = [
    "RULE_VERSION",
    "_MANUAL_REQUIRED_TESTS",
    "_UNSUPPORTED_TESTS",
    "decide_applicability",
]
