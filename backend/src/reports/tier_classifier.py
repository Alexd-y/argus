"""ARG-024 / ARG-025 — Pure tier filter for ``ReportData``.

The classifier takes the *full* ``ReportData`` collected by the report
pipeline and projects it to the subset visible at a given ``ReportTier``:

* **Midgard** (CISO / exec): only summary counts, severity rollup, top-N
  critical findings, and OWASP alignment. AI text, exploit chains, raw
  artefact dumps, evidence and screenshots are **stripped**.
* **Asgard** (security team — ARG-025): adds full findings, remediation
  hints and **sanitised** reproducer recipes — every reproducer ``argv``
  embedded in a finding's PoC is run through
  :func:`src.reports.replay_command_sanitizer.sanitize_replay_command`
  before the projected data leaves this function.
* **Valhalla** (leadership-technical, Cycle 4): adds AI exploit chains,
  hardening roadmap and zero-day potential.

Why a separate module?
    The classifier is pure (input → output, no I/O, no DB) and fully
    deterministic. Wiring it as a separate function keeps
    :class:`ReportService` thin and lets us assert tier guarantees in unit
    tests without standing up the full Jinja pipeline.

Security guardrails
    * The classifier never *adds* fields to ``ReportData``; it only redacts.
      A bug here cannot leak data the caller did not already pass in.
    * Midgard projection drops ``evidence``, ``screenshots``,
      ``raw_artifacts``, ``timeline``, ``phase_outputs`` — those are the
      most likely carriers of secrets / credentials and are NEVER required
      for an executive summary.
    * Asgard projection sanitises every reproducer command and every
      reproducer string sitting inside a finding's PoC payload — the
      sanitiser strips bearer tokens, AWS keys, NT/LM hashes, destructive
      flags and reverse-shell payloads (NIST SP 800-204D §5.1.4).
    * The function returns a *new* ``ReportData`` instance; the input is
      never mutated. Frozen dataclasses are not used here because
      ``ReportData`` is itself a mutable dataclass — so we explicitly
      ``replace(...)`` every field we touch.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from typing import Any, Final

from src.api.schemas import Finding
from src.reports.generators import ReportData
from src.reports.replay_command_sanitizer import (
    SanitizeContext,
    sanitize_replay_command,
)
from src.reports.report_bundle import ReportTier

# Midgard "top-N critical" cap. Backlog/dev1_md §15 says top-10; we keep the
# constant here so Asgard / Valhalla can raise it without touching tests.
MIDGARD_TOP_FINDINGS: Final[int] = 10


# Severity rank used to surface only the most urgent findings on the
# Midgard cover page. Matches ``generators._SEVERITY_RANK`` byte-for-byte —
# duplicated here to avoid importing private symbols across modules.
_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}


def _finding_priority_key(f: Finding) -> tuple[int, float, str, str]:
    """Sort key for "most urgent first": severity → CVSS → title → CWE."""
    sev_rank = _SEVERITY_RANK.get((f.severity or "").lower().strip(), 99)
    cvss = -float(f.cvss) if f.cvss is not None else 0.0
    title = (f.title or "").lower()
    cwe = f.cwe or ""
    return (sev_rank, cvss, title, cwe)


def _top_n_findings(findings: list[Finding], n: int) -> list[Finding]:
    """Return the ``n`` most urgent findings (deterministic ordering)."""
    if n <= 0 or not findings:
        return []
    return sorted(findings, key=_finding_priority_key)[:n]


def classify_for_tier(
    data: ReportData,
    tier: ReportTier,
    *,
    sanitize_context: SanitizeContext | None = None,
) -> ReportData:
    """Project ``data`` to the subset visible at the requested ``tier``.

    Pure function: no I/O, no DB, no logging of payload contents. The
    result is a *new* ``ReportData``; ``data`` is never mutated.

    ``sanitize_context`` is forwarded to the Asgard projection so the
    sanitiser can honour operator-supplied canary tokens, additional
    endpoints and an explicit asset URL. When ``None`` we fall back to
    a minimal context built from ``data.target``.
    """
    if tier is ReportTier.MIDGARD:
        return _project_midgard(data, sanitize_context=sanitize_context)
    if tier is ReportTier.ASGARD:
        return _project_asgard(data, sanitize_context=sanitize_context)
    if tier is ReportTier.VALHALLA:
        return _project_valhalla(data, sanitize_context=sanitize_context)
    raise ValueError(f"Unknown ReportTier: {tier!r}")


def _project_midgard(
    data: ReportData,
    *,
    sanitize_context: SanitizeContext | None = None,
) -> ReportData:
    """Strip everything beyond exec-summary essentials.

    ARG-031 — also runs the sanitiser over reproducer fields as a
    defence-in-depth measure: even though the Midgard view collapses
    to a top-N findings list, the JSON / SARIF / JUnit emissions still
    surface ``proof_of_concept`` blocks. Sanitising at the classifier
    keeps the secret-leak contract uniform across all three tiers.
    The sanitiser is idempotent so the change is purely additive.
    """
    ctx = sanitize_context or SanitizeContext(target=data.target or "")
    top = _top_n_findings(list(data.findings), MIDGARD_TOP_FINDINGS)
    sanitised = [_sanitise_finding(f, sanitize_ctx=ctx) for f in top]
    return replace(
        data,
        findings=sanitised,
        timeline=[],
        phase_outputs=[],
        evidence=[],
        screenshots=[],
        ai_insights=[],
        executive_summary=data.executive_summary,
        remediation=[],
        raw_artifacts=[],
        hibp_pwned_password_summary=None,
    )


def _project_asgard(
    data: ReportData, *, sanitize_context: SanitizeContext | None = None
) -> ReportData:
    """Asgard tier — full findings + remediation + sanitised reproducer + timeline.

    ARG-025: every reproducer command embedded in a finding's PoC payload
    is passed through :func:`sanitize_replay_command`. Both shapes are
    handled:

    * ``proof_of_concept["replay_command"]`` (``list[str]``) — sanitised
      element-wise and re-stored.
    * ``proof_of_concept["reproducer"]`` (``str``) — split on whitespace
      so the sanitiser sees per-token spans, sanitised, then re-joined
      with single spaces. The string form is best-effort only; callers
      that care about exact quoting MUST use the list form.

    Raw artefact dumps and HIBP password summaries remain stripped — the
    Asgard tier is for the security team, not for incident-response /
    forensic export (those live in Valhalla and a separate IR pipeline).

    ``sanitize_context`` lets callers thread operator-supplied canary
    tokens / extra endpoints through to the sanitiser. When omitted, a
    minimal context derived from ``data.target`` is used.
    """
    ctx = sanitize_context or SanitizeContext(target=data.target or "")
    sanitised_findings = [_sanitise_finding(f, sanitize_ctx=ctx) for f in data.findings]
    return replace(
        data,
        findings=sanitised_findings,
        timeline=list(data.timeline),
        phase_outputs=list(data.phase_outputs),
        evidence=list(data.evidence),
        screenshots=list(data.screenshots),
        ai_insights=data.ai_insights
        if isinstance(data.ai_insights, list)
        else [data.ai_insights],
        executive_summary=data.executive_summary,
        remediation=data.remediation
        if isinstance(data.remediation, list)
        else [data.remediation],
        raw_artifacts=[],
        hibp_pwned_password_summary=None,
    )


def _sanitise_finding(f: Finding, *, sanitize_ctx: SanitizeContext) -> Finding:
    """Return a copy of ``f`` whose reproducer fields have been sanitised.

    The sanitiser is **idempotent**: a Finding that has already been
    processed will round-trip with byte-identical output. Findings
    without a PoC payload are returned unchanged (no allocation).
    """
    poc = f.proof_of_concept
    needs_clone = False
    new_poc: dict[str, Any] | None = None

    if isinstance(poc, dict):
        new_poc = deepcopy(poc)
        replay = new_poc.get("replay_command")
        if isinstance(replay, list) and all(isinstance(t, str) for t in replay):
            sanitised = sanitize_replay_command(list(replay), sanitize_ctx)
            if sanitised != replay:
                new_poc["replay_command"] = sanitised
                needs_clone = True
        text = new_poc.get("reproducer")
        if isinstance(text, str) and text.strip():
            argv = text.split()
            sanitised_argv = sanitize_replay_command(argv, sanitize_ctx)
            new_text = " ".join(sanitised_argv)
            if new_text != text:
                new_poc["reproducer"] = new_text
                needs_clone = True

    if not needs_clone:
        return f
    return f.model_copy(update={"proof_of_concept": new_poc})


def _project_valhalla(
    data: ReportData,
    *,
    sanitize_context: SanitizeContext | None = None,
) -> ReportData:
    """Valhalla tier (ARG-031) — executive / business-impact lens.

    Same data envelope as the legacy pass-through (AI exploit chains,
    zero-day, hardening, raw artefacts, HIBP summary all preserved) BUT
    we now run every reproducer ``argv`` through
    :func:`sanitize_replay_command` mirroring Asgard. Rationale:

    * Valhalla is consumed by C-suite / Board readers who must NOT see
      raw secrets or destructive flags even in supporting evidence.
    * Defence-in-depth: ARG-030's secret-leak contract test is being
      extended to cover Valhalla (660 → 990 cases). Sanitising at the
      classifier ensures callers cannot bypass the contract by skipping
      :func:`assemble_valhalla_sections`.

    The sanitiser is idempotent so this is safe to chain after
    Asgard-style projections without introducing drift.
    """
    ctx = sanitize_context or SanitizeContext(target=data.target or "")
    sanitised_findings = [_sanitise_finding(f, sanitize_ctx=ctx) for f in data.findings]
    return replace(
        data,
        findings=sanitised_findings,
        timeline=list(data.timeline),
        phase_outputs=list(data.phase_outputs),
        evidence=list(data.evidence),
        screenshots=list(data.screenshots),
        ai_insights=data.ai_insights
        if isinstance(data.ai_insights, list)
        else [data.ai_insights],
        executive_summary=data.executive_summary,
        remediation=data.remediation
        if isinstance(data.remediation, list)
        else [data.remediation],
        raw_artifacts=list(data.raw_artifacts),
        hibp_pwned_password_summary=data.hibp_pwned_password_summary,
    )


__all__ = [
    "MIDGARD_TOP_FINDINGS",
    "classify_for_tier",
]
