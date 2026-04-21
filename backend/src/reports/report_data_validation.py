"""RPT — Validate ``ReportData`` after build, before render/upload (T3)."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

from src.reports.data_collector import executive_severity_totals_from_severity_strings
from src.reports.generators import ReportData

logger = logging.getLogger(__name__)

_REPORT_TIERS: frozenset[str] = frozenset({"midgard", "asgard", "valhalla"})

# Minimal Valhalla shape: keys present on ``ValhallaReportContext.model_dump()`` (VHL-001).
_VALHALLA_VC_REQUIRED_KEYS: frozenset[str] = frozenset(
    {
        "risk_matrix",
        "critical_vulns",
        "robots_txt_analysis",
        "sitemap_analysis",
        "ssl_tls_analysis",
        "security_headers_analysis",
        "tech_stack_table",
        "tech_stack_structured",
        "dependency_analysis",
        "outdated_components",
        "robots_sitemap_merged",
        "robots_sitemap_analysis",
        "leaked_emails",
        "mandatory_sections",
        "coverage",
    }
)


def _normalize_tier(tier: str | None) -> str:
    t = (tier or "").strip().lower()
    return t if t in _REPORT_TIERS else "midgard"


@dataclass
class ReportDataValidationResult:
    ok: bool
    reason_codes: list[str] = field(default_factory=list)


def report_validation_failure_payload(
    *,
    report_id: str,
    tenant_id: str,
    tier: str,
    reason_codes: list[str],
) -> dict[str, Any]:
    """Structured fields for JSON logging (no findings text, no HIBP notes)."""
    return {
        "event": "report_data_validation_failed",
        "report_id": report_id,
        "tenant_id": tenant_id,
        "tier": tier,
        "reason_codes": list(reason_codes),
    }


def log_report_validation_failure(payload: dict[str, Any]) -> None:
    logger.error(json.dumps(payload, ensure_ascii=False))


def validate_report_data(
    report_data: ReportData,
    *,
    tier: str | None = None,
    template_context: dict[str, Any] | None = None,
) -> ReportDataValidationResult:
    """
    Pre-render checks: severity totals vs findings, degenerate findings, HIBP sanity, Valhalla context.

    Policy: findings with empty title, empty description, and unknown/empty severity are rejected
    (``finding_unknown_empty``).
    """
    reasons: list[str] = []
    tier_norm = _normalize_tier(tier)

    expected = executive_severity_totals_from_severity_strings(f.severity for f in report_data.findings)
    sm = report_data.summary
    for key in ("critical", "high", "medium", "low", "info"):
        if int(getattr(sm, key, 0) or 0) != int(expected.get(key, 0)):
            reasons.append("severity_summary_mismatch")
            break

    for f in report_data.findings:
        title = (f.title or "").strip()
        desc = (f.description or "").strip()
        sev_raw = (f.severity or "").strip().lower()
        unknown_sev = not sev_raw or sev_raw == "unknown"
        if not title and not desc and unknown_sev:
            reasons.append("finding_unknown_empty")
            break

    hibp = report_data.hibp_pwned_password_summary
    if isinstance(hibp, dict) and hibp:
        try:
            checks_run = max(0, int(hibp.get("checks_run") or 0))
            pwned = max(0, int(hibp.get("pwned_count") or 0))
            if "checks_attempted" in hibp and hibp["checks_attempted"] is not None:
                attempted = max(0, int(hibp["checks_attempted"]))
                if attempted < checks_run:
                    reasons.append("hibp_checks_attempted_lt_run")
                elif pwned > checks_run:
                    reasons.append("hibp_pwned_gt_checks_run")
            else:
                if pwned > checks_run:
                    reasons.append("hibp_pwned_gt_checks_run")
        except (TypeError, ValueError):
            reasons.append("hibp_coercion_failed")

    if tier_norm == "valhalla":
        ctx = template_context or {}
        vc = ctx.get("valhalla_context")
        if not isinstance(vc, dict):
            reasons.append("valhalla_context_missing")
        else:
            missing = sorted(k for k in _VALHALLA_VC_REQUIRED_KEYS if k not in vc)
            if missing:
                reasons.append("valhalla_context_incomplete")
        scan_art = ctx.get("scan_artifacts")
        if not isinstance(scan_art, dict) or "status" not in scan_art:
            reasons.append("valhalla_scan_artifacts_meta_missing")

    uniq = list(dict.fromkeys(reasons))
    return ReportDataValidationResult(ok=len(uniq) == 0, reason_codes=uniq)


_EXEC_SEV_SECTION_KEYS: frozenset[str] = frozenset(
    {"executive_summary", "executive_summary_valhalla"}
)

_SEV_PATTERNS_EN: list[tuple[str, str]] = [
    (r"\b(\d{1,4})\s+critical\b", "critical"),
    (r"\b(\d{1,4})\s+critically\b", "critical"),
    (r"\b(\d{1,4})\s+high[\s-]severity\b", "high"),
    (r"\b(\d{1,4})\s+medium\b", "medium"),
    (r"\b(\d{1,4})\s+low\b", "low"),
    (r"\b(\d{1,4})\s+informational\b", "info"),
    (r"\b(\d{1,4})\s+info\b", "info"),
]

# Backward compat: RU severity labels from legacy scanner tools that emit Russian output.
_SEV_PATTERNS_RU: list[tuple[str, str]] = [
    (r"\b(\d{1,4})\s+\u043a\u0440\u0438\u0442\u0438\u0447", "critical"),
    (r"\b(\d{1,4})\s+\u0432\u044b\u0441\u043e\u043a", "high"),
    (r"\b(\d{1,4})\s+\u0441\u0440\u0435\u0434\u043d", "medium"),
    (r"\b(\d{1,4})\s+\u043d\u0438\u0437\u043a", "low"),
]

# Combined for backward compat (used in quality gate text extraction).
_SEV_PATTERNS: list[tuple[str, str]] = _SEV_PATTERNS_EN + _SEV_PATTERNS_RU


def _int_totals_from_payload(payload: dict[str, Any]) -> dict[str, int]:
    raw = payload.get("executive_severity_totals")
    if not isinstance(raw, dict):
        return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    out: dict[str, int] = {}
    for k in ("critical", "high", "medium", "low", "info"):
        try:
            out[k] = max(0, int(raw.get(k) or 0))
        except (TypeError, ValueError):
            out[k] = 0
    return out


def _finding_count_from_payload(payload: dict[str, Any]) -> int:
    try:
        return max(0, int(payload.get("finding_count") or 0))
    except (TypeError, ValueError):
        return 0


def validate_executive_ai_text_against_payload(
    section_key: str,
    payload: dict[str, Any],
    text: str,
) -> tuple[bool, list[str]]:
    """
    T9 — Compare executive-summary prose counts to structured ``executive_severity_totals``,
    ``finding_count``, and HIBP aggregates. Conservative: only flags explicit numeric claims.
    """
    if section_key not in _EXEC_SEV_SECTION_KEYS:
        return True, []
    reasons: list[str] = []
    t = (text or "").strip()
    if not t:
        return True, []
    totals = _int_totals_from_payload(payload)
    tl = t.lower()

    mentioned: dict[str, list[int]] = {k: [] for k in totals}
    for pat, bucket in _SEV_PATTERNS:
        for m in re.finditer(pat, tl, flags=re.IGNORECASE):
            try:
                mentioned[bucket].append(int(m.group(1)))
            except (ValueError, IndexError):
                continue
    for bucket, nums in mentioned.items():
        if not nums:
            continue
        exp = totals[bucket]
        for n in nums:
            if n != exp:
                reasons.append("executive_ai_severity_count_mismatch")
                break
        if reasons:
            break

    fc = _finding_count_from_payload(payload)
    # EN labels; union with RU patterns for legacy scanner output support
    for m in re.finditer(r"\b(\d{1,4})\s+(?:findings?|vulnerabilit(?:y|ies)|уязвимост|находок)\b", tl, re.IGNORECASE):
        try:
            n = int(m.group(1))
        except ValueError:
            continue
        if n != fc:
            reasons.append("executive_ai_finding_count_mismatch")
            break

    hibp = payload.get("hibp_pwned_password_summary")
    hibp_context = "pwned" in tl or "hibp" in tl or "breach" in tl or "password" in tl
    if isinstance(hibp, dict) and hibp and hibp_context:
        try:
            pwned = max(0, int(hibp.get("pwned_count") or 0))
            checks = max(0, int(hibp.get("checks_run") or 0))
        except (TypeError, ValueError):
            pwned, checks = 0, 0
        for m in re.finditer(r"\b(\d{1,4})\s+pwned\b", tl):
            try:
                if int(m.group(1)) != pwned:
                    reasons.append("executive_ai_hibp_count_mismatch")
                    break
            except ValueError:
                continue
        if "executive_ai_hibp_count_mismatch" not in reasons:
            for m in re.finditer(
                r"\b(\d{1,4})\s+(?:of\s+)?(?:the\s+)?(\d{1,4})\s+(?:checked|checks|samples)\b",
                tl,
            ):
                try:
                    a, b = int(m.group(1)), int(m.group(2))
                except ValueError:
                    continue
                if (a, b) != (pwned, checks) and (a, b) != (checks, pwned):
                    reasons.append("executive_ai_hibp_count_mismatch")
                    break

    uniq = list(dict.fromkeys(reasons))
    return len(uniq) == 0, uniq


def grounded_executive_summary_fallback_text(payload: dict[str, Any]) -> str:
    """Safe replacement when generated executive text fails structured fact checks."""
    totals = _int_totals_from_payload(payload)
    fc = _finding_count_from_payload(payload)
    parts = [
        f"Structured results: {fc} finding(s) recorded. "
        f"Severity totals — critical: {totals['critical']}, high: {totals['high']}, "
        f"medium: {totals['medium']}, low: {totals['low']}, informational: {totals['info']}."
    ]
    hibp = payload.get("hibp_pwned_password_summary")
    if isinstance(hibp, dict) and hibp:
        try:
            pwned = max(0, int(hibp.get("pwned_count") or 0))
            checks = max(0, int(hibp.get("checks_run") or 0))
        except (TypeError, ValueError):
            pwned, checks = 0, 0
        parts.append(
            f" Credential sample checks (HIBP): {pwned} hit(s) in {checks} check(s) "
            "where sampling was performed."
        )
    parts.append(" Narrative aligned to verified metrics above.")
    return " ".join(parts)
