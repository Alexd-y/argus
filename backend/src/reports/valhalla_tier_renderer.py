"""ARG-031 — Valhalla tier renderer (executive / CISO / Board lens).

Mirrors :mod:`asgard_tier_renderer` (ARG-025) but raises the audience to the
**executive** layer:

* Risk-quantification per asset — composite score
  ``max(cvss_v3) × business_value_weight × exploitability_factor``;
* OWASP Top-10 rollup matrix (categories × severity bins);
* Top-N findings ranked by composite ``severity × exploitability × business_value``;
* Auto-generated executive summary paragraph (deterministic template-fill;
  the LLM path is intentionally NOT the default — it would defeat the
  byte-stable snapshot contract);
* Remediation roadmap bucketed into four phases (P0 ≤ 7d, P1 ≤ 30d,
  P2 ≤ 90d, P3 backlog);
* Evidence references with optional presigned URLs;
* Pipeline timeline (chronological).

The renderer is **pure**: it produces a structured
:class:`ValhallaSectionAssembly` from a tier-projected ``ReportData`` plus
a :class:`BusinessContext`. The service layer then either:

* serialises the assembly into a Jinja context (HTML / PDF), or
* embeds it inside JSON / CSV / SARIF / JUnit emissions via a
  ``"valhalla_executive_report"`` slot — keeping the contract observable
  from any format and trivially diffable in snapshot tests.

Why a separate slot from the legacy ``valhalla_report`` (built at JSON
time by :func:`generators.build_valhalla_report_payload`)?
    The legacy payload reads from ``valhalla_context`` (recon / threat-
    model / tech-stack tables) and is shaped for the operator-facing
    Valhalla view introduced earlier. The new business-impact lens is
    additive — emitting it under a distinct key keeps backward
    compatibility intact and lets templates / API consumers opt in.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any, Final, TypeAlias

from pydantic import BaseModel, ConfigDict, Field

from src.api.schemas import Finding
from src.findings.prioritizer import FindingPrioritizer
from src.owasp_top10_2025 import (
    OWASP_TOP10_2025_CATEGORY_IDS,
    OWASP_TOP10_2025_CATEGORY_TITLES,
)
from src.reports.generators import (
    EvidenceEntry,
    ReportData,
    TimelineEntry,
)
from src.reports.replay_command_sanitizer import (
    SanitizeContext,
    sanitize_replay_command,
)

# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------


PresignFn: TypeAlias = Callable[[str], str | None]


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


# Fixed section ordering — the API contract for the Valhalla executive
# report. Adding a section requires a CHANGELOG entry and a snapshot
# regeneration.
VALHALLA_EXECUTIVE_SECTION_ORDER: Final[tuple[str, ...]] = (
    "title_meta",
    "executive_summary",
    "executive_summary_counts",
    "risk_quantification_per_asset",
    "owasp_rollup_matrix",
    "top_findings_by_business_impact",
    "kev_listed_findings",
    "remediation_roadmap",
    "evidence_refs",
    "timeline_entries",
)


# Top-N cap for business-impact findings list. Caps the table footprint
# in HTML/PDF and keeps JSON snapshots tractable.
VALHALLA_TOP_FINDINGS_CAP: Final[int] = 25
VALHALLA_TOP_ASSETS_CAP: Final[int] = 50
# ARG-044 — KEV-listed section cap. KEV catalogue is small per scan; the
# cap exists to keep PDF render time bounded if a particularly noisy
# scan returns hundreds of vulnerable hosts.
VALHALLA_KEV_LISTED_CAP: Final[int] = 25


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


# Severity bins used in OWASP rollup matrix and counts. ``info`` and
# ``informational`` collapse into a single ``info`` bin.
_SEVERITY_BINS: Final[tuple[str, ...]] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
)


# Exploitability factor by ``Finding.confidence`` — bounded ``[0, 1]``.
# ``confirmed`` (PoC reproduced) carries the full weight; ``advisory``
# (purely heuristic) is heavily down-weighted so risk quantification
# does not drown in noise.
_CONFIDENCE_EXPLOITABILITY: Final[dict[str, float]] = {
    "confirmed": 1.0,
    "likely": 0.75,
    "possible": 0.5,
    "advisory": 0.25,
}


# Severity-weighted contribution to the per-finding business-impact score.
# Used so a "critical" finding outranks a "low" finding even when CVSS
# is missing — defensive default for unfunded callers.
_SEVERITY_WEIGHT: Final[dict[str, float]] = {
    "critical": 10.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 1.0,
    "informational": 1.0,
}


# OWASP "other" bucket id used when a finding's CWE / owasp_category does
# not match a Top-10 category. Kept short so the rollup table stays
# narrow.
_OWASP_OTHER_BUCKET: Final[str] = "A00"
_OWASP_OTHER_TITLE: Final[str] = "Other / Unmapped"


# Conservative CWE → OWASP-2025 mapping. We only embed mappings that are
# unambiguously defensible per the OWASP Top 10 2025 mapping table; a
# finding with a CWE we do not recognise falls through to its
# ``owasp_category`` field (when populated) and finally to
# :data:`_OWASP_OTHER_BUCKET`.
_CWE_TO_OWASP_2025: Final[dict[str, str]] = {
    # A01 — Broken Access Control
    "CWE-22": "A01",  # Path traversal
    "CWE-23": "A01",
    "CWE-35": "A01",
    "CWE-59": "A01",
    "CWE-200": "A01",
    "CWE-201": "A01",
    "CWE-219": "A01",
    "CWE-264": "A01",
    "CWE-275": "A01",
    "CWE-276": "A01",
    "CWE-284": "A01",
    "CWE-285": "A01",
    "CWE-352": "A01",  # CSRF
    "CWE-359": "A01",
    "CWE-377": "A01",
    "CWE-402": "A01",
    "CWE-425": "A01",
    "CWE-441": "A01",
    "CWE-497": "A01",
    "CWE-538": "A01",
    "CWE-540": "A01",
    "CWE-552": "A01",
    "CWE-566": "A01",
    "CWE-601": "A01",
    "CWE-639": "A01",  # IDOR
    "CWE-651": "A01",
    "CWE-668": "A01",
    "CWE-706": "A01",
    "CWE-862": "A01",
    "CWE-863": "A01",
    "CWE-913": "A01",
    "CWE-922": "A01",
    "CWE-1275": "A01",
    # A02 — Security Misconfiguration
    "CWE-2": "A02",
    "CWE-11": "A02",
    "CWE-13": "A02",
    "CWE-15": "A02",
    "CWE-16": "A02",
    "CWE-260": "A02",
    "CWE-315": "A02",
    "CWE-520": "A02",
    "CWE-526": "A02",
    "CWE-537": "A02",
    "CWE-541": "A02",
    "CWE-547": "A02",
    "CWE-611": "A02",  # XXE
    "CWE-614": "A02",
    "CWE-756": "A02",
    "CWE-776": "A02",
    "CWE-942": "A02",
    "CWE-1004": "A02",
    "CWE-1032": "A02",
    "CWE-1174": "A02",
    "CWE-693": "A02",
    # A03 — Software Supply Chain Failures
    "CWE-829": "A03",
    "CWE-830": "A03",
    "CWE-937": "A03",
    "CWE-1104": "A03",
    "CWE-1357": "A03",
    # A04 — Cryptographic Failures
    "CWE-261": "A04",
    "CWE-296": "A04",
    "CWE-310": "A04",
    "CWE-319": "A04",
    "CWE-321": "A04",
    "CWE-322": "A04",
    "CWE-323": "A04",
    "CWE-324": "A04",
    "CWE-325": "A04",
    "CWE-326": "A04",
    "CWE-327": "A04",
    "CWE-328": "A04",
    "CWE-329": "A04",
    "CWE-330": "A04",
    "CWE-331": "A04",
    "CWE-335": "A04",
    "CWE-336": "A04",
    "CWE-337": "A04",
    "CWE-338": "A04",
    "CWE-340": "A04",
    "CWE-347": "A04",
    "CWE-523": "A04",
    "CWE-720": "A04",
    "CWE-757": "A04",
    "CWE-759": "A04",
    "CWE-760": "A04",
    "CWE-780": "A04",
    "CWE-818": "A04",
    "CWE-916": "A04",
    # A05 — Injection
    "CWE-20": "A05",
    "CWE-74": "A05",
    "CWE-75": "A05",
    "CWE-77": "A05",  # Command injection
    "CWE-78": "A05",  # OS command injection
    "CWE-79": "A05",  # XSS
    "CWE-80": "A05",
    "CWE-83": "A05",
    "CWE-87": "A05",
    "CWE-88": "A05",
    "CWE-89": "A05",  # SQL injection
    "CWE-90": "A05",
    "CWE-91": "A05",
    "CWE-93": "A05",
    "CWE-94": "A05",  # Code injection
    "CWE-95": "A05",
    "CWE-96": "A05",
    "CWE-97": "A05",
    "CWE-98": "A05",
    "CWE-99": "A05",
    "CWE-113": "A05",
    "CWE-116": "A05",
    "CWE-138": "A05",
    "CWE-184": "A05",
    "CWE-470": "A05",
    "CWE-471": "A05",
    "CWE-564": "A05",
    "CWE-610": "A05",
    "CWE-643": "A05",
    "CWE-644": "A05",
    "CWE-652": "A05",
    "CWE-917": "A05",
    # A06 — Insecure Design
    "CWE-73": "A06",
    "CWE-183": "A06",
    "CWE-209": "A06",
    "CWE-213": "A06",
    "CWE-235": "A06",
    "CWE-256": "A06",
    "CWE-257": "A06",
    "CWE-266": "A06",
    "CWE-269": "A06",
    "CWE-280": "A06",
    "CWE-311": "A06",
    "CWE-312": "A06",
    "CWE-313": "A06",
    "CWE-316": "A06",
    "CWE-419": "A06",
    "CWE-430": "A06",
    "CWE-434": "A06",
    "CWE-444": "A06",
    "CWE-451": "A06",
    "CWE-472": "A06",
    "CWE-501": "A06",
    "CWE-522": "A06",
    "CWE-525": "A06",
    "CWE-539": "A06",
    "CWE-579": "A06",
    "CWE-598": "A06",
    "CWE-602": "A06",
    "CWE-642": "A06",
    "CWE-646": "A06",
    "CWE-650": "A06",
    "CWE-653": "A06",
    "CWE-656": "A06",
    "CWE-657": "A06",
    "CWE-799": "A06",
    "CWE-840": "A06",
    "CWE-841": "A06",
    "CWE-927": "A06",
    "CWE-1021": "A06",
    "CWE-1173": "A06",
    # A07 — Authentication Failures
    "CWE-255": "A07",
    "CWE-259": "A07",  # Hardcoded password
    "CWE-287": "A07",  # Improper authentication
    "CWE-288": "A07",
    "CWE-290": "A07",
    "CWE-294": "A07",
    "CWE-295": "A07",  # Improper cert validation
    "CWE-297": "A07",
    "CWE-300": "A07",
    "CWE-302": "A07",
    "CWE-304": "A07",
    "CWE-306": "A07",
    "CWE-307": "A07",
    "CWE-346": "A07",
    "CWE-384": "A07",  # Session fixation
    "CWE-521": "A07",
    "CWE-613": "A07",
    "CWE-620": "A07",
    "CWE-640": "A07",
    "CWE-798": "A07",  # Hardcoded credentials
    "CWE-940": "A07",
    "CWE-1216": "A07",
    # A08 — Software or Data Integrity Failures
    "CWE-345": "A08",
    "CWE-353": "A08",
    "CWE-426": "A08",
    "CWE-494": "A08",
    "CWE-502": "A08",  # Insecure deserialization
    "CWE-565": "A08",
    "CWE-784": "A08",
    "CWE-915": "A08",
    # A09 — Security Logging & Alerting Failures
    "CWE-117": "A09",
    "CWE-223": "A09",
    "CWE-532": "A09",
    "CWE-778": "A09",
    # A10 — Mishandling of Exceptional Conditions (was SSRF in 2021; now broader in 2025)
    "CWE-754": "A10",
    "CWE-755": "A10",
    "CWE-918": "A10",  # SSRF
    "CWE-1295": "A10",
}


# ---------------------------------------------------------------------------
# Business context (input parameters for risk quantification)
# ---------------------------------------------------------------------------


class BusinessContext(BaseModel):
    """Operator-supplied business-impact lens parameters.

    The renderer treats each finding's ``cvss`` as the technical severity
    and multiplies it by the asset's :attr:`default_business_value` (or a
    per-asset override from :attr:`asset_business_values`) and the
    finding's exploitability factor. The result is a composite score we
    rank the top-N business-impact list against.

    Attributes are immutable so the renderer's pure-function contract
    extends transitively to its inputs.

    Parameters
    ----------
    asset_business_values:
        Tuple of ``(asset_url, weight)`` pairs. ``asset_url`` is matched
        case-sensitively against either ``ReportData.target`` or the URL
        embedded in a finding's PoC (whichever the renderer derives per
        finding). Weight is bounded ``[0, 10]`` — a value > 1 inflates
        risk for high-value assets, < 1 deflates it. Default ``1.0`` is
        applied when no per-asset override matches.
    default_business_value:
        Fallback weight (default ``1.0``). Same bounds as the per-asset
        override.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    asset_business_values: tuple[tuple[str, float], ...] = Field(default_factory=tuple)
    default_business_value: float = Field(default=1.0, ge=0.0, le=10.0)

    def value_for(self, asset: str) -> float:
        """Return the business-value weight for ``asset`` (case-sensitive)."""
        for key, weight in self.asset_business_values:
            if key == asset:
                return float(weight)
        return float(self.default_business_value)


# ---------------------------------------------------------------------------
# Section payload models
# ---------------------------------------------------------------------------


class AssetRiskRow(BaseModel):
    """One row of the per-asset risk-quantification table."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    asset: str
    finding_count: int = Field(ge=0)
    max_cvss: float = Field(ge=0.0)
    business_value: float = Field(ge=0.0)
    exploitability_factor: float = Field(ge=0.0, le=1.0)
    composite_score: float = Field(ge=0.0)
    top_severity: str


class OwaspRollupRow(BaseModel):
    """One row of the OWASP Top-10 × severity rollup matrix."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    category_id: str
    title: str
    critical: int = Field(ge=0)
    high: int = Field(ge=0)
    medium: int = Field(ge=0)
    low: int = Field(ge=0)
    info: int = Field(ge=0)
    total: int = Field(ge=0)


class BusinessImpactFindingRow(BaseModel):
    """One row of the top-N business-impact findings list."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    rank: int = Field(ge=1)
    severity: str
    title: str
    description: str
    cwe: str | None = None
    cvss: float | None = None
    owasp_category: str
    business_value: float = Field(ge=0.0)
    exploitability_factor: float = Field(ge=0.0, le=1.0)
    composite_score: float = Field(ge=0.0)
    asset: str
    sanitized_command: tuple[str, ...] = Field(default_factory=tuple)
    # ARG-044 — intel signals propagated for executive visibility.
    epss_score: float | None = Field(default=None, ge=0.0, le=1.0)
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    kev_listed: bool = False
    ssvc_decision: str | None = None


class KevListedFindingRow(BaseModel):
    """ARG-044 — one row of the dedicated KEV-listed findings section.

    Surfaces actively-exploited vulnerabilities (per CISA's Known
    Exploited Vulnerabilities catalogue) at the top of the executive
    report so the CISO sees them even if the business-value lens
    deprioritises the host.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    rank: int = Field(ge=1)
    severity: str
    title: str
    cwe: str | None = None
    cvss: float | None = None
    owasp_category: str
    asset: str
    kev_added_date: str | None = None
    epss_percentile: float | None = Field(default=None, ge=0.0, le=1.0)
    ssvc_decision: str | None = None


class RemediationPhaseRow(BaseModel):
    """One row of the remediation roadmap (P0..P3)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    phase_id: str  # "P0".."P3"
    sla_days: int = Field(ge=0)
    severity_bucket: str
    finding_count: int = Field(ge=0)
    top_finding_titles: tuple[str, ...] = Field(default_factory=tuple)


class ValhallaEvidenceRef(BaseModel):
    """Evidence (presigned URL or object key) attached to a finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    object_key: str
    description: str | None = None
    presigned_url: str | None = None


class ValhallaTimelineEntry(BaseModel):
    """One phase entry in the timeline."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    order_index: int
    phase: str
    snippet: str
    created_at: str | None = None


class ValhallaSectionAssembly(BaseModel):
    """Full Valhalla executive tier section assembly — serialisable into any format."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    title_meta: dict[str, Any] = Field(default_factory=dict)
    executive_summary: str = ""
    executive_summary_counts: dict[str, int] = Field(default_factory=dict)
    risk_quantification_per_asset: tuple[AssetRiskRow, ...] = Field(
        default_factory=tuple
    )
    owasp_rollup_matrix: tuple[OwaspRollupRow, ...] = Field(default_factory=tuple)
    top_findings_by_business_impact: tuple[BusinessImpactFindingRow, ...] = Field(
        default_factory=tuple
    )
    kev_listed_findings: tuple[KevListedFindingRow, ...] = Field(
        default_factory=tuple
    )
    remediation_roadmap: tuple[RemediationPhaseRow, ...] = Field(default_factory=tuple)
    evidence_refs: tuple[ValhallaEvidenceRef, ...] = Field(default_factory=tuple)
    timeline_entries: tuple[ValhallaTimelineEntry, ...] = Field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


_URL_HOST_RE: Final[re.Pattern[str]] = re.compile(
    r"^[a-zA-Z][a-zA-Z0-9+.\-]*://([^/\s\"']+)"
)


def _normalise_severity(sev: str | None) -> str:
    """Return one of ``critical|high|medium|low|info`` (defaults to ``info``)."""
    s = (sev or "").strip().lower()
    if s == "informational":
        return "info"
    if s in _SEVERITY_BINS:
        return s
    return "info"


def _exploitability_for(f: Finding) -> float:
    return _CONFIDENCE_EXPLOITABILITY.get(
        (f.confidence or "likely").strip().lower(), 0.5
    )


def _owasp_category_for(f: Finding) -> str:
    """Map a finding to an OWASP-2025 bucket (``A01``..``A10`` / ``A00``)."""
    direct = (f.owasp_category or "").strip()
    if direct in OWASP_TOP10_2025_CATEGORY_IDS:
        return direct
    cwe = (f.cwe or "").strip()
    if cwe:
        normalised = cwe.upper()
        mapped = _CWE_TO_OWASP_2025.get(normalised)
        if mapped is not None:
            return mapped
    return _OWASP_OTHER_BUCKET


def _asset_for_finding(f: Finding, *, fallback_target: str) -> str:
    """Best-effort asset extraction from PoC / evidence_refs / fallback target."""
    poc = f.proof_of_concept
    if isinstance(poc, dict):
        for key in ("url", "endpoint", "asset", "target"):
            value = poc.get(key)
            if isinstance(value, str) and value.strip():
                return _to_host(value.strip()) or value.strip()
        replay = poc.get("replay_command")
        if isinstance(replay, list):
            for token in replay:
                if isinstance(token, str):
                    host = _to_host(token)
                    if host:
                        return host
        text = poc.get("reproducer")
        if isinstance(text, str):
            for token in text.split():
                host = _to_host(token)
                if host:
                    return host
    if f.evidence_refs:
        for ref in f.evidence_refs:
            if isinstance(ref, str):
                host = _to_host(ref)
                if host:
                    return host
    if fallback_target:
        return _to_host(fallback_target) or fallback_target
    return ""


def _to_host(candidate: str) -> str | None:
    match = _URL_HOST_RE.match(candidate or "")
    if match:
        return match.group(1)
    return None


def _composite_score(
    f: Finding,
    *,
    business_value: float,
    exploitability: float,
) -> float:
    cvss = (
        float(f.cvss)
        if f.cvss is not None
        else _SEVERITY_WEIGHT.get(_normalise_severity(f.severity), 1.0)
    )
    return float(cvss) * float(business_value) * float(exploitability)


def _reproducer_argv(f: Finding) -> list[str] | None:
    """Extract the raw replay-command argv from a finding's PoC payload."""
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


def _executive_counts(findings: list[Finding]) -> dict[str, int]:
    counts = dict.fromkeys(_SEVERITY_BINS, 0)
    for f in findings:
        counts[_normalise_severity(f.severity)] += 1
    return counts


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------


def _build_asset_risk_rows(
    findings: list[Finding],
    *,
    business_context: BusinessContext,
    fallback_target: str,
) -> tuple[AssetRiskRow, ...]:
    """Group findings by asset, compute per-asset composite score."""
    bucket: dict[str, dict[str, Any]] = {}
    for f in findings:
        asset = _asset_for_finding(f, fallback_target=fallback_target) or "(unknown)"
        bv = business_context.value_for(asset)
        expl = _exploitability_for(f)
        cvss = float(f.cvss) if f.cvss is not None else 0.0
        composite = _composite_score(f, business_value=bv, exploitability=expl)
        entry = bucket.setdefault(
            asset,
            {
                "finding_count": 0,
                "max_cvss": 0.0,
                "business_value": bv,
                "max_exploitability": 0.0,
                "max_composite": 0.0,
                "top_sev_rank": 99,
                "top_severity": "info",
            },
        )
        entry["finding_count"] += 1
        if cvss > entry["max_cvss"]:
            entry["max_cvss"] = cvss
        if expl > entry["max_exploitability"]:
            entry["max_exploitability"] = expl
        if composite > entry["max_composite"]:
            entry["max_composite"] = composite
        sev = _normalise_severity(f.severity)
        sev_rank = _SEVERITY_RANK[sev]
        if sev_rank < entry["top_sev_rank"]:
            entry["top_sev_rank"] = sev_rank
            entry["top_severity"] = sev
    rows = [
        AssetRiskRow(
            asset=asset,
            finding_count=int(entry["finding_count"]),
            max_cvss=round(float(entry["max_cvss"]), 4),
            business_value=round(float(entry["business_value"]), 4),
            exploitability_factor=round(float(entry["max_exploitability"]), 4),
            composite_score=round(float(entry["max_composite"]), 4),
            top_severity=str(entry["top_severity"]),
        )
        for asset, entry in bucket.items()
    ]
    rows.sort(key=lambda r: (-r.composite_score, r.asset))
    return tuple(rows[:VALHALLA_TOP_ASSETS_CAP])


def _build_owasp_rollup_matrix(findings: list[Finding]) -> tuple[OwaspRollupRow, ...]:
    """Return a stable ``A01..A10`` (+ ``A00``) × severity rollup matrix."""
    counts: dict[str, dict[str, int]] = {
        cid: dict.fromkeys(_SEVERITY_BINS, 0)
        for cid in (*OWASP_TOP10_2025_CATEGORY_IDS, _OWASP_OTHER_BUCKET)
    }
    for f in findings:
        cat = _owasp_category_for(f)
        sev = _normalise_severity(f.severity)
        counts[cat][sev] += 1
    rows: list[OwaspRollupRow] = []
    for cid in (*OWASP_TOP10_2025_CATEGORY_IDS, _OWASP_OTHER_BUCKET):
        c = counts[cid]
        title = OWASP_TOP10_2025_CATEGORY_TITLES.get(cid, _OWASP_OTHER_TITLE)
        rows.append(
            OwaspRollupRow(
                category_id=cid,
                title=title,
                critical=c["critical"],
                high=c["high"],
                medium=c["medium"],
                low=c["low"],
                info=c["info"],
                total=sum(c.values()),
            )
        )
    return tuple(rows)


def _build_top_business_impact(
    findings: list[Finding],
    *,
    business_context: BusinessContext,
    sanitize_context: SanitizeContext,
    fallback_target: str,
) -> tuple[BusinessImpactFindingRow, ...]:
    """Top-N business-impact findings sorted by composite score.

    ARG-044 — the deterministic intel-aware
    :meth:`FindingPrioritizer.rank_objects` is consulted **first** so
    KEV-listed and SSVC ``Act`` findings always land at the top of the
    business-impact list, even if their composite (CVSS × business
    value × exploitability) score is lower than a less-actionable
    high-CVSS finding. Within each intel-priority bucket the legacy
    composite score still drives ordering, so executives keep the
    business lens for tie-breaks.
    """
    composite_lookup: dict[int, float] = {}
    for f in findings:
        asset = _asset_for_finding(f, fallback_target=fallback_target) or "(unknown)"
        bv = business_context.value_for(asset)
        expl = _exploitability_for(f)
        composite_lookup[id(f)] = _composite_score(
            f, business_value=bv, exploitability=expl
        )

    intel_ranked = FindingPrioritizer.rank_objects(findings)

    rows: list[BusinessImpactFindingRow] = []
    for rank, f in enumerate(intel_ranked[:VALHALLA_TOP_FINDINGS_CAP], start=1):
        asset = _asset_for_finding(f, fallback_target=fallback_target) or "(unknown)"
        bv = business_context.value_for(asset)
        expl = _exploitability_for(f)
        composite = composite_lookup.get(id(f), 0.0)
        argv = _reproducer_argv(f)
        sanitized: tuple[str, ...] = ()
        if argv:
            sanitized = tuple(sanitize_replay_command(argv, sanitize_context))
        rows.append(
            BusinessImpactFindingRow(
                rank=rank,
                severity=_normalise_severity(f.severity),
                title=f.title or "",
                description=f.description or "",
                cwe=f.cwe,
                cvss=f.cvss,
                owasp_category=_owasp_category_for(f),
                business_value=round(float(bv), 4),
                exploitability_factor=round(float(expl), 4),
                composite_score=round(float(composite), 4),
                asset=asset,
                sanitized_command=sanitized,
                epss_score=getattr(f, "epss_score", None),
                epss_percentile=getattr(f, "epss_percentile", None),
                kev_listed=bool(getattr(f, "kev_listed", False)),
                ssvc_decision=getattr(f, "ssvc_decision", None),
            )
        )
    return tuple(rows)


def _build_kev_listed_findings(
    findings: list[Finding],
    *,
    fallback_target: str,
) -> tuple[KevListedFindingRow, ...]:
    """ARG-044 — surface CISA KEV-listed findings into a dedicated section.

    Order matches :meth:`FindingPrioritizer.rank_objects` so the KEV
    section's row order agrees with the executive top-N table.
    """
    kev_only = [f for f in findings if bool(getattr(f, "kev_listed", False))]
    if not kev_only:
        return ()
    ranked = FindingPrioritizer.rank_objects(kev_only)
    rows: list[KevListedFindingRow] = []
    for rank, f in enumerate(ranked[:VALHALLA_KEV_LISTED_CAP], start=1):
        asset = _asset_for_finding(f, fallback_target=fallback_target) or "(unknown)"
        rows.append(
            KevListedFindingRow(
                rank=rank,
                severity=_normalise_severity(f.severity),
                title=f.title or "",
                cwe=f.cwe,
                cvss=f.cvss,
                owasp_category=_owasp_category_for(f),
                asset=asset,
                kev_added_date=getattr(f, "kev_added_date", None),
                epss_percentile=getattr(f, "epss_percentile", None),
                ssvc_decision=getattr(f, "ssvc_decision", None),
            )
        )
    return tuple(rows)


def _build_remediation_roadmap(
    findings: list[Finding],
) -> tuple[RemediationPhaseRow, ...]:
    """Bucket findings into four SLA phases (P0/P1/P2/P3)."""
    phases: dict[str, dict[str, Any]] = {
        "P0": {"sla_days": 7, "severity_bucket": "critical", "items": []},
        "P1": {"sla_days": 30, "severity_bucket": "high", "items": []},
        "P2": {"sla_days": 90, "severity_bucket": "medium", "items": []},
        "P3": {"sla_days": 0, "severity_bucket": "low/info (backlog)", "items": []},
    }
    for f in findings:
        sev = _normalise_severity(f.severity)
        if sev == "critical":
            phases["P0"]["items"].append(f)
        elif sev == "high":
            phases["P1"]["items"].append(f)
        elif sev == "medium":
            phases["P2"]["items"].append(f)
        else:
            phases["P3"]["items"].append(f)
    rows: list[RemediationPhaseRow] = []
    for pid in ("P0", "P1", "P2", "P3"):
        items: list[Finding] = phases[pid]["items"]
        items_sorted = sorted(
            items, key=lambda x: ((x.title or "").lower(), x.cwe or "")
        )
        rows.append(
            RemediationPhaseRow(
                phase_id=pid,
                sla_days=int(phases[pid]["sla_days"]),
                severity_bucket=str(phases[pid]["severity_bucket"]),
                finding_count=len(items_sorted),
                top_finding_titles=tuple(f.title or "" for f in items_sorted[:5]),
            )
        )
    return tuple(rows)


def _build_evidence_refs(
    evidence: list[EvidenceEntry],
    *,
    presigner: PresignFn | None,
) -> tuple[ValhallaEvidenceRef, ...]:
    rows = sorted(evidence, key=lambda e: (e.finding_id, e.object_key))
    out: list[ValhallaEvidenceRef] = []
    for e in rows:
        url: str | None = None
        if presigner is not None and e.object_key:
            try:
                url = presigner(e.object_key)
            except Exception:
                # Presigner failure MUST NOT break report generation.
                url = None
        out.append(
            ValhallaEvidenceRef(
                finding_id=e.finding_id,
                object_key=e.object_key,
                description=e.description,
                presigned_url=url,
            )
        )
    return tuple(out)


def _build_timeline_entries(
    timeline: list[TimelineEntry],
    *,
    snippet_limit: int = 480,
) -> tuple[ValhallaTimelineEntry, ...]:
    rows = sorted(
        timeline, key=lambda t: (t.order_index, t.phase or "", t.created_at or "")
    )
    out: list[ValhallaTimelineEntry] = []
    for t in rows:
        snippet = ""
        if t.entry is not None:
            try:
                snippet = json.dumps(t.entry, ensure_ascii=False, sort_keys=True)
            except (TypeError, ValueError):
                snippet = str(t.entry)
            snippet = snippet[:snippet_limit]
        out.append(
            ValhallaTimelineEntry(
                order_index=t.order_index,
                phase=t.phase or "",
                snippet=snippet,
                created_at=t.created_at,
            )
        )
    return tuple(out)


def _build_executive_summary(
    *,
    data: ReportData,
    counts: dict[str, int],
    asset_rows: tuple[AssetRiskRow, ...],
    roadmap: tuple[RemediationPhaseRow, ...],
) -> str:
    """Deterministic template-fill executive summary paragraph.

    LLM enrichment is intentionally out of scope of this default path —
    the byte-stable snapshot contract requires a deterministic builder.
    Operators wanting LLM phrasing should run the AI rewrite *after*
    Valhalla rendering.
    """
    scan_id = data.scan_id or data.report_id or "unknown-scan"
    tenant = data.tenant_id or "unspecified-tenant"
    when = data.created_at or "unknown timestamp"
    total = sum(counts.values())
    severity_part = ", ".join(
        f"{counts.get(b, 0)} {b.upper()}"
        for b in _SEVERITY_BINS
        if counts.get(b, 0) > 0
    )
    if not severity_part:
        severity_part = "0 actionable"
    if asset_rows:
        top_asset = asset_rows[0]
        top_asset_part = (
            f"Top business risk: {top_asset.asset} "
            f"(composite score {top_asset.composite_score:.2f})."
        )
    else:
        top_asset_part = "No assets ranked (no findings)."
    next_phase = next((p for p in roadmap if p.finding_count > 0), None)
    if next_phase is not None:
        if next_phase.sla_days > 0:
            phase_part = (
                f"Recommended priority: {next_phase.phase_id} "
                f"({next_phase.severity_bucket}, SLA ≤ {next_phase.sla_days} days, "
                f"{next_phase.finding_count} item(s))."
            )
        else:
            phase_part = (
                f"Recommended priority: {next_phase.phase_id} "
                f"({next_phase.severity_bucket}, {next_phase.finding_count} item(s))."
            )
    else:
        phase_part = "No remediation actions required."
    return (
        f"During scan {scan_id} for tenant {tenant} as of {when}, "
        f"ARGUS identified {total} finding(s) ({severity_part}). "
        f"{top_asset_part} {phase_part}"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def assemble_valhalla_sections(
    data: ReportData,
    *,
    business_context: BusinessContext | None = None,
    sanitize_context: SanitizeContext | None = None,
    presigner: PresignFn | None = None,
) -> ValhallaSectionAssembly:
    """Build a deterministic :class:`ValhallaSectionAssembly` from ``data``.

    Parameters
    ----------
    data:
        Tier-projected report data (already passed through
        :func:`tier_classifier.classify_for_tier`).
    business_context:
        Per-asset business-value lens. ``None`` defaults to a context
        where every asset weighs ``1.0``.
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
    bctx = business_context or BusinessContext()
    sctx = sanitize_context or SanitizeContext(
        target=data.target or "",
        endpoints=tuple(),
        canaries=tuple(),
    )
    findings = list(data.findings)
    fallback_target = data.target or ""

    counts = _executive_counts(findings)
    asset_rows = _build_asset_risk_rows(
        findings, business_context=bctx, fallback_target=fallback_target
    )
    owasp_rows = _build_owasp_rollup_matrix(findings)
    top_findings = _build_top_business_impact(
        findings,
        business_context=bctx,
        sanitize_context=sctx,
        fallback_target=fallback_target,
    )
    kev_rows = _build_kev_listed_findings(
        findings, fallback_target=fallback_target
    )
    roadmap = _build_remediation_roadmap(findings)
    evidence_rows = _build_evidence_refs(list(data.evidence), presigner=presigner)
    timeline_rows = _build_timeline_entries(list(data.timeline))
    summary = _build_executive_summary(
        data=data, counts=counts, asset_rows=asset_rows, roadmap=roadmap
    )

    title_meta: dict[str, Any] = {
        "report_id": data.report_id,
        "target": data.target or "",
        "scan_id": data.scan_id or "",
        "tenant_id": data.tenant_id or "",
        "tier": "valhalla",
        "created_at": data.created_at,
    }

    return ValhallaSectionAssembly(
        title_meta=title_meta,
        executive_summary=summary,
        executive_summary_counts=counts,
        risk_quantification_per_asset=asset_rows,
        owasp_rollup_matrix=owasp_rows,
        top_findings_by_business_impact=top_findings,
        kev_listed_findings=kev_rows,
        remediation_roadmap=roadmap,
        evidence_refs=evidence_rows,
        timeline_entries=timeline_rows,
    )


def valhalla_assembly_to_jinja_context(
    assembly: ValhallaSectionAssembly,
    *,
    base_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Project a :class:`ValhallaSectionAssembly` into a Jinja context.

    The new business-impact lens lands under the
    ``valhalla_executive_report`` slot to avoid colliding with the
    pre-existing ``valhalla_report`` payload built by
    :func:`generators.build_valhalla_report_payload`. Templates and JSON
    consumers see both blobs and can opt into the executive lens
    independently.
    """
    base = dict(base_context or {})
    base["tier"] = "valhalla"
    base["valhalla_executive_report"] = assembly.model_dump(mode="json")
    # Same ordering as the assembly model — HTML/PDF/JSON all stay in lockstep.
    base["valhalla_executive_section_order"] = list(VALHALLA_EXECUTIVE_SECTION_ORDER)
    return base


__all__ = [
    "VALHALLA_EXECUTIVE_SECTION_ORDER",
    "VALHALLA_KEV_LISTED_CAP",
    "VALHALLA_TOP_ASSETS_CAP",
    "VALHALLA_TOP_FINDINGS_CAP",
    "AssetRiskRow",
    "BusinessContext",
    "BusinessImpactFindingRow",
    "KevListedFindingRow",
    "OwaspRollupRow",
    "RemediationPhaseRow",
    "ValhallaEvidenceRef",
    "ValhallaSectionAssembly",
    "ValhallaTimelineEntry",
    "assemble_valhalla_sections",
    "valhalla_assembly_to_jinja_context",
]
