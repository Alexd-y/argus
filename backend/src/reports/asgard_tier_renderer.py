"""ARG-025 — Asgard tier renderer (full findings + remediation + sanitized
reproducer + timeline + presigned evidence URLs).

The Midgard tier (ARG-024) gives a CISO-grade exec summary with severity
counts and a Top-N finding list. **Asgard** is the working-level brief
delivered to the security team; it adds:

* every finding (no Top-N cap), with description / CWE / CVSS / OWASP
  category;
* remediation guidance (one bullet per finding);
* a sanitized **replay command** for each finding — the live ``argv``
  passed through :func:`src.reports.replay_command_sanitizer.sanitize_replay_command`
  so the report never embeds raw secrets, destructive flags, or
  reverse-shell payloads;
* a chronological timeline of pipeline phases;
* presigned URLs for screenshot / artefact evidence (so the security
  team can pull the raw artefacts from S3 / MinIO without exposing the
  bucket credentials).

The renderer is **pure**: it produces a structured
:class:`AsgardSectionAssembly` from a tier-projected ``ReportData``. The
service layer then either:

* serialises the assembly into a Jinja context (for HTML / PDF), or
* embeds it inside JSON / CSV / SARIF / JUnit emissions via a
  ``"asgard_report"`` key — keeping the contract observable from any
  format and trivially diffable in snapshot tests.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, Final, TypeAlias

from pydantic import BaseModel, ConfigDict, Field

from src.api.schemas import Finding
from src.reports.generators import (
    EvidenceEntry,
    ReportData,
    ScreenshotEntry,
    TimelineEntry,
)
from src.reports.replay_command_sanitizer import (
    SanitizeContext,
    sanitize_replay_command,
)

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------


# Optional callback that turns an S3 / MinIO object key into a presigned
# URL. The callback may return ``None`` (presigning disabled) and may
# raise — the renderer catches and downgrades to ``None`` so a presigning
# bug never breaks report assembly.
PresignFn: TypeAlias = Callable[[str], str | None]


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


# Fixed section ordering — the API contract for the Asgard report. Adding a
# section requires a CHANGELOG entry and a snapshot regeneration.
ASGARD_SECTION_ORDER: Final[tuple[str, ...]] = (
    "title_meta",
    "executive_summary_counts",
    "owasp_compliance",
    "findings",
    "remediation",
    "reproducer",
    "timeline",
    "evidence",
    "screenshots",
)


# Severity rank — duplicated locally so this module does not pull in any
# private symbols from ``generators`` or ``tier_classifier`` (keeps the
# import graph cycle-free).
_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}


# ---------------------------------------------------------------------------
# Section payload models
# ---------------------------------------------------------------------------


class AsgardFindingSection(BaseModel):
    """One row of the Asgard findings table."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    severity: str
    title: str
    description: str
    cwe: str | None = None
    cvss: float | None = None
    owasp_category: str | None = None
    confidence: str | None = None
    evidence_type: str | None = None


class AsgardRemediationSection(BaseModel):
    """Remediation guidance for a finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_title: str
    severity: str
    guidance: str


class AsgardReproducerSection(BaseModel):
    """Sanitised reproducer command for a finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_title: str
    severity: str
    command: tuple[str, ...]


class AsgardTimelineSection(BaseModel):
    """One phase entry in the timeline."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    order_index: int
    phase: str
    snippet: str
    created_at: str | None = None


class AsgardEvidenceSection(BaseModel):
    """Evidence (presigned URL or object key) attached to a finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    object_key: str
    description: str | None = None
    presigned_url: str | None = None


class AsgardScreenshotSection(BaseModel):
    """Screenshot reference with optional presigned URL."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    object_key: str
    url_or_email: str | None = None
    presigned_url: str | None = None


class AsgardSectionAssembly(BaseModel):
    """Full Asgard tier section assembly — serialisable into any format."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    title_meta: dict[str, Any] = Field(default_factory=dict)
    executive_summary_counts: dict[str, int] = Field(default_factory=dict)
    owasp_compliance: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[AsgardFindingSection] = Field(default_factory=list)
    remediation: list[AsgardRemediationSection] = Field(default_factory=list)
    reproducer: list[AsgardReproducerSection] = Field(default_factory=list)
    timeline: list[AsgardTimelineSection] = Field(default_factory=list)
    evidence: list[AsgardEvidenceSection] = Field(default_factory=list)
    screenshots: list[AsgardScreenshotSection] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers — finding → section translators
# ---------------------------------------------------------------------------


def _finding_priority_key(f: Finding) -> tuple[int, float, str, str]:
    sev_rank = _SEVERITY_RANK.get((f.severity or "").lower().strip(), 99)
    cvss = -float(f.cvss) if f.cvss is not None else 0.0
    title = (f.title or "").lower()
    cwe = f.cwe or ""
    return (sev_rank, cvss, title, cwe)


def _ordered_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=_finding_priority_key)


def _findings_to_sections(findings: list[Finding]) -> list[AsgardFindingSection]:
    return [
        AsgardFindingSection(
            severity=f.severity,
            title=f.title or "",
            description=f.description or "",
            cwe=f.cwe,
            cvss=f.cvss,
            owasp_category=f.owasp_category,
            confidence=f.confidence,
            evidence_type=f.evidence_type,
        )
        for f in findings
    ]


def _remediation_for_finding(f: Finding) -> str:
    """Best-effort remediation guidance from ``applicability_notes`` /
    ``description``.

    The generator keeps this advisory local to the tier renderer so we
    never reach back into the LLM layer at render time.
    """
    notes = (f.applicability_notes or "").strip()
    if notes:
        return notes
    poc = f.proof_of_concept or {}
    if isinstance(poc, dict):
        rem = poc.get("remediation") or poc.get("mitigation")
        if isinstance(rem, str) and rem.strip():
            return rem.strip()
    return (
        "Review the finding and apply vendor-provided patches or compensating controls."
    )


def _reproducer_argv(f: Finding) -> list[str] | None:
    """Extract the raw replay-command argv from a finding's PoC payload.

    Supported PoC shapes:

    * ``{"replay_command": ["curl", "…"]}``  — preferred (already a list).
    * ``{"reproducer": "curl …"}``           — fallback (single string).
    * ``{"reproducible_steps": "curl …"}``   — fallback for the old DTO key.

    The function returns ``None`` when no usable argv is present so the
    renderer can suppress the row entirely (we never emit an empty
    ``[]`` reproducer that an operator might mistake for a sanitisation
    bug).
    """
    poc = f.proof_of_concept
    if isinstance(poc, dict):
        argv = poc.get("replay_command")
        if isinstance(argv, list) and all(isinstance(t, str) for t in argv):
            return list(argv)
        text = poc.get("reproducer")
        if isinstance(text, str) and text.strip():
            return text.strip().split()
    if f.reproducible_steps and f.reproducible_steps.strip():
        return f.reproducible_steps.strip().split()
    return None


def _reproducers_for_findings(
    findings: list[Finding],
    *,
    context: SanitizeContext,
) -> list[AsgardReproducerSection]:
    out: list[AsgardReproducerSection] = []
    for f in findings:
        argv = _reproducer_argv(f)
        if argv is None:
            continue
        sanitized = sanitize_replay_command(argv, context)
        if not sanitized:
            continue
        out.append(
            AsgardReproducerSection(
                finding_title=f.title or "",
                severity=f.severity,
                command=tuple(sanitized),
            )
        )
    return out


def _remediation_for_findings(
    findings: list[Finding],
) -> list[AsgardRemediationSection]:
    return [
        AsgardRemediationSection(
            finding_title=f.title or "",
            severity=f.severity,
            guidance=_remediation_for_finding(f),
        )
        for f in findings
    ]


def _timeline_to_sections(
    timeline: list[TimelineEntry],
    *,
    snippet_limit: int = 480,
) -> list[AsgardTimelineSection]:
    rows = sorted(
        timeline, key=lambda t: (t.order_index, t.phase or "", t.created_at or "")
    )
    out: list[AsgardTimelineSection] = []
    for t in rows:
        snippet = ""
        if t.entry is not None:
            try:
                snippet = json.dumps(t.entry, ensure_ascii=False, sort_keys=True)
            except (TypeError, ValueError):
                snippet = str(t.entry)
            snippet = snippet[:snippet_limit]
        out.append(
            AsgardTimelineSection(
                order_index=t.order_index,
                phase=t.phase or "",
                snippet=snippet,
                created_at=t.created_at,
            )
        )
    return out


def _evidence_to_sections(
    evidence: list[EvidenceEntry],
    *,
    presigner: PresignFn | None,
) -> list[AsgardEvidenceSection]:
    rows = sorted(evidence, key=lambda e: (e.finding_id, e.object_key))
    out: list[AsgardEvidenceSection] = []
    for e in rows:
        url: str | None = None
        if presigner is not None and e.object_key:
            try:
                url = presigner(e.object_key)
            except Exception:
                # Defensive: a presigner blow-up MUST NOT break report
                # generation. We log nothing here (pure module); the
                # caller logs at the dispatch layer.
                url = None
        out.append(
            AsgardEvidenceSection(
                finding_id=e.finding_id,
                object_key=e.object_key,
                description=e.description,
                presigned_url=url,
            )
        )
    return out


def _screenshots_to_sections(
    screenshots: list[ScreenshotEntry],
    *,
    presigner: PresignFn | None,
) -> list[AsgardScreenshotSection]:
    rows = sorted(screenshots, key=lambda s: (s.object_key, s.url_or_email or ""))
    out: list[AsgardScreenshotSection] = []
    for s in rows:
        url: str | None = None
        if presigner is not None and s.object_key:
            try:
                url = presigner(s.object_key)
            except Exception:
                url = None
        out.append(
            AsgardScreenshotSection(
                object_key=s.object_key,
                url_or_email=s.url_or_email,
                presigned_url=url,
            )
        )
    return out


def _executive_counts(findings: list[Finding]) -> dict[str, int]:
    """Severity totals across the full Asgard finding set."""
    counts = dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)
    for f in findings:
        sev = (f.severity or "").lower().strip()
        if sev == "informational":
            sev = "info"
        if sev in counts:
            counts[sev] += 1
    return counts


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def assemble_asgard_sections(
    data: ReportData,
    *,
    sanitize_context: SanitizeContext | None = None,
    presigner: PresignFn | None = None,
) -> AsgardSectionAssembly:
    """Build a deterministic :class:`AsgardSectionAssembly` from ``data``.

    Parameters
    ----------
    data:
        Tier-projected report data (already passed through
        :func:`tier_classifier.classify_for_tier`).
    sanitize_context:
        Asset / endpoint / canary metadata for the replay-command
        sanitiser. Defaults to a context derived from ``data.target``.
    presigner:
        Optional ``object_key -> presigned URL`` callback. Implementation
        is free to consult the storage layer (S3 / MinIO) and return
        ``None`` if presigning is disabled or the object is missing. The
        callback may raise; the caller swallows exceptions to keep the
        renderer pure-output.
    """
    ctx = sanitize_context or SanitizeContext(
        target=data.target or "",
        endpoints=tuple(),
        canaries=tuple(),
    )
    findings = _ordered_findings(list(data.findings))
    title_meta: dict[str, Any] = {
        "report_id": data.report_id,
        "target": data.target or "",
        "scan_id": data.scan_id or "",
        "tenant_id": data.tenant_id or "",
        "tier": "asgard",
        "created_at": data.created_at,
    }
    return AsgardSectionAssembly(
        title_meta=title_meta,
        executive_summary_counts=_executive_counts(findings),
        owasp_compliance=_owasp_rows_for_findings(findings),
        findings=_findings_to_sections(findings),
        remediation=_remediation_for_findings(findings),
        reproducer=_reproducers_for_findings(findings, context=ctx),
        timeline=_timeline_to_sections(list(data.timeline)),
        evidence=_evidence_to_sections(list(data.evidence), presigner=presigner),
        screenshots=_screenshots_to_sections(
            list(data.screenshots), presigner=presigner
        ),
    )


def asgard_assembly_to_jinja_context(
    assembly: AsgardSectionAssembly,
    *,
    base_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Project an :class:`AsgardSectionAssembly` into a Jinja context.

    Existing midgard / valhalla templates already consume a context with
    ``tier``, ``findings`` (list of dicts) and ``recon_summary`` keys; we
    splice an ``"asgard_report"`` slot into that context so the Asgard
    template can read assembly data without a second translation layer.
    """
    base = dict(base_context or {})
    base["tier"] = "asgard"
    base["asgard_report"] = assembly.model_dump(mode="json")
    return base


# Local OWASP-rollup helper. We deliberately do NOT import
# :func:`src.reports.generators.build_owasp_compliance_rows` because it
# expects ``list[dict]`` rows; the Asgard renderer produces sections
# directly from ``Finding`` objects.
def _owasp_rows_for_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    """Return a stable, A01..A10 ordered OWASP rollup."""
    from src.owasp_top10_2025 import (
        OWASP_TOP10_2025_CATEGORY_IDS,
        OWASP_TOP10_2025_CATEGORY_TITLES,
    )

    counts: dict[str, int] = dict.fromkeys(OWASP_TOP10_2025_CATEGORY_IDS, 0)
    for f in findings:
        oc = (f.owasp_category or "").strip()
        if oc and oc in counts:
            counts[oc] += 1
    rows: list[dict[str, Any]] = []
    for cid in OWASP_TOP10_2025_CATEGORY_IDS:
        n = counts[cid]
        rows.append(
            {
                "category_id": cid,
                "title": OWASP_TOP10_2025_CATEGORY_TITLES.get(cid, cid),
                "count": n,
                "has_findings": n > 0,
            }
        )
    return rows


__all__ = [
    "ASGARD_SECTION_ORDER",
    "AsgardEvidenceSection",
    "AsgardFindingSection",
    "AsgardRemediationSection",
    "AsgardReproducerSection",
    "AsgardScreenshotSection",
    "AsgardSectionAssembly",
    "AsgardTimelineSection",
    "asgard_assembly_to_jinja_context",
    "assemble_asgard_sections",
]
