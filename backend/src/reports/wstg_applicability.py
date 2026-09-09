"""Engagement-scoped WSTG v4.2 applicability (Track B, spec §4).

The strict gate (:mod:`src.reports.wstg_gate`) scores
``coverage = counted / applicable``. Every WSTG test starts applicable and is
only removed from the denominator with a **written rationale** that is audited
(so exclusions can never silently inflate the score).

This module derives those rationale-backed exclusions from the *engagement
surface* actually observed:

* No authenticated session in scope → identity / authentication-flow /
  authorization / session / business-logic tests have no account context to
  exercise and are excluded.
* No injectable parameter or form discovered → parameter-injection tests have no
  entry point.
* No session cookie issued → cookie-attribute testing is not applicable.
* A fixed set of interactive / manual-only / obsolete tests that an automated,
  unauthenticated assessment structurally does not evidence.

The result feeds :func:`src.reports.wstg_plan.build_engagement_test_plan` so the
denominator reflects what was genuinely in scope for the run. Every excluded
test carries a customer-safe English rationale (no secrets/PII).
"""

from __future__ import annotations

from src.reports.wstg_coverage import _WSTG_TESTS

# Require an authenticated session / application account (or a login credential
# submission channel) to exercise.
_AUTH_DEPENDENT: frozenset[str] = frozenset(
    {
        "WSTG-IDNT-01", "WSTG-IDNT-02", "WSTG-IDNT-03", "WSTG-IDNT-04", "WSTG-IDNT-05",
        "WSTG-ATHN-01",  # credentials over encrypted channel — needs a login submission
        "WSTG-ATHN-02", "WSTG-ATHN-04", "WSTG-ATHN-05", "WSTG-ATHN-06",
        "WSTG-ATHN-07", "WSTG-ATHN-09",
        "WSTG-ATHZ-02", "WSTG-ATHZ-03", "WSTG-ATHZ-04",
        "WSTG-SESS-01", "WSTG-SESS-03", "WSTG-SESS-04", "WSTG-SESS-05",
        "WSTG-SESS-06", "WSTG-SESS-07", "WSTG-SESS-08", "WSTG-SESS-09",
        "WSTG-BUSL-01", "WSTG-BUSL-02", "WSTG-BUSL-03", "WSTG-BUSL-04",
        "WSTG-BUSL-05", "WSTG-BUSL-06", "WSTG-BUSL-07",
    }
)

# Require host-level / cloud-provider context not available to an external,
# unauthenticated automated assessment.
_ENV_DEPENDENT: frozenset[str] = frozenset(
    {
        "WSTG-CONF-09",  # file permission — needs host/file-system access
        "WSTG-CONF-11",  # cloud storage — needs a cloud-provider context
    }
)

# Require an injectable parameter / form / path to exercise.
_INPUT_DEPENDENT: frozenset[str] = frozenset(
    {
        "WSTG-ATHZ-01",  # directory traversal — needs a file/path parameter
        "WSTG-INPV-01", "WSTG-INPV-02", "WSTG-INPV-04", "WSTG-INPV-05",
        "WSTG-INPV-06", "WSTG-INPV-07", "WSTG-INPV-08", "WSTG-INPV-09",
        "WSTG-INPV-10", "WSTG-INPV-11", "WSTG-INPV-12", "WSTG-INPV-13",
        "WSTG-INPV-15", "WSTG-INPV-17", "WSTG-INPV-18", "WSTG-INPV-19",
        "WSTG-CLNT-01", "WSTG-CLNT-03", "WSTG-CLNT-04", "WSTG-CLNT-05",
        "WSTG-CLNT-06",
    }
)

# Require a server-issued session cookie to exercise.
_COOKIE_DEPENDENT: frozenset[str] = frozenset({"WSTG-SESS-02"})

# Interactive / manual-only / obsolete tests an automated unauthenticated run
# does not evidence. Excluded regardless of surface signals.
_MANUAL_OR_OBSOLETE: frozenset[str] = frozenset(
    {
        "WSTG-INFO-07",   # map execution paths — manual analysis
        "WSTG-INPV-03",   # HTTP verb tampering — manual verification
        "WSTG-INPV-14",   # incubated vulnerabilities — manual
        "WSTG-INPV-16",   # incoming HTTP requests inspection — manual
        "WSTG-ATHN-08",   # weak security-question answer — manual, account-bound
        "WSTG-ATHN-10",   # weaker auth in alternative channel — manual
        "WSTG-BUSL-08",   # upload of unexpected file types — needs upload feature
        "WSTG-BUSL-09",   # upload of malicious files — needs upload feature
        "WSTG-CLNT-08",   # cross-site flashing — Adobe Flash obsolete
        "WSTG-CLNT-10",   # WebSockets — interactive
        "WSTG-CLNT-11",   # web messaging — interactive
    }
)

_RATIONALE_AUTH = (
    "No authenticated application session was in scope for this run; this control "
    "requires an account/role context to exercise. Recommend an authenticated "
    "re-test to cover it."
)
_RATIONALE_INPUT = (
    "No injectable parameter, form, or file/path entry point was discovered on the "
    "target; this parameter-injection test has no entry point to exercise."
)
_RATIONALE_COOKIE = (
    "The target issued no session cookie; cookie-attribute controls are not "
    "applicable to this engagement."
)
_RATIONALE_MANUAL = (
    "Interactive/manual-only or obsolete test not evidenced by the automated "
    "unauthenticated assessment; flagged for manual review rather than counted."
)
_RATIONALE_ENV = (
    "Requires host-level or cloud-provider context that is not available in an "
    "external unauthenticated automated assessment."
)


def infer_wstg_applicability(
    *,
    authenticated: bool,
    has_input_surface: bool,
    has_cookies: bool,
) -> tuple[dict[str, bool], dict[str, str]]:
    """Derive ``(applicability, exclusion_rationale)`` from engagement surface.

    A test is marked not-applicable (``applicability[id] = False``) only together
    with a written ``exclusion_rationale[id]`` so the strict gate honours the
    exclusion; otherwise it stays applicable (fail-closed).
    """
    applicability: dict[str, bool] = {}
    rationale: dict[str, str] = {}
    valid_ids = {t.id for t in _WSTG_TESTS}

    def exclude(test_id: str, why: str) -> None:
        if test_id in valid_ids:
            applicability[test_id] = False
            rationale[test_id] = why

    if not authenticated:
        for tid in _AUTH_DEPENDENT:
            exclude(tid, _RATIONALE_AUTH)
    if not has_input_surface:
        for tid in _INPUT_DEPENDENT:
            exclude(tid, _RATIONALE_INPUT)
    if not has_cookies:
        for tid in _COOKIE_DEPENDENT:
            exclude(tid, _RATIONALE_COOKIE)
    for tid in _MANUAL_OR_OBSOLETE:
        exclude(tid, _RATIONALE_MANUAL)
    for tid in _ENV_DEPENDENT:
        exclude(tid, _RATIONALE_ENV)

    return applicability, rationale


__all__ = ["infer_wstg_applicability"]
