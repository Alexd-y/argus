"""ARG-024 — SARIF v2.1.0 generator.

Renders a :class:`ReportData` as a single-run SARIF v2.1.0 document
suitable for GitHub Code Scanning, GitLab, Sonar, Defect Dojo, and any
other consumer of the OASIS standard.

Specification
    Schema (canonical): ``https://json.schemastore.org/sarif-2.1.0.json``
    Spec (PDF / HTML):  ``https://docs.oasis-open.org/sarif/sarif/v2.1.0/``

Mapping (FindingDTO / Finding-API → SARIF)
    severity  → result.level (error|warning|note)
    title     → result.message.text
    cwe       → rule.properties.cwe + rule.helpUri (cwe.mitre.org/CWE-N)
    cvss      → rule.properties.{cvss_v3_score,cvss_v3_vector}
    target    → result.locations[].physicalLocation.artifactLocation.uri
    url       → same (PoC/recon evidence is treated as artifactLocation)
    sha256    → result.fingerprints["primaryFinding/v1"] (stable across runs)
    owasp     → result.properties.owasp_top10_2025

Determinism
    The generator emits keys in lexicographic order at every level
    (``json.dumps(sort_keys=True)`` is unsuitable because we want a stable
    ``runs[]`` order regardless of finding insertion order). Findings are
    sorted by the same priority key the JSON/CSV generators use, so a
    repeat run on the same input is byte-identical.

Security
    SARIF outputs are typically published into CI logs / dashboards. We
    therefore:
        * never embed raw PoC bodies (they may contain secrets/cookies);
          only ``description`` text and structured ``proof_of_concept``
          fields the normaliser already redacted are passed through;
        * never embed evidence file paths (they live in the redacted
          MinIO ``evidence_refs`` list — surfaced as
          ``properties.evidence_refs`` rather than as a physical
          artefact).
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Final

from src.api.schemas import Finding
from src.owasp_top10_2025 import (
    OWASP_TOP10_2025_CATEGORY_TITLES,
    parse_owasp_category,
)
from src.reports.generators import ReportData

SARIF_SCHEMA_URL: Final[str] = (
    "https://json.schemastore.org/sarif-2.1.0.json"
)
SARIF_VERSION: Final[str] = "2.1.0"

# Tool driver name shown to consumers (GitHub Code Scanning displays this
# verbatim). Backlog/dev1_md §15 — branded "ARGUS" capital, semver.
ARGUS_TOOL_NAME: Final[str] = "ARGUS"
ARGUS_TOOL_INFORMATION_URI: Final[str] = "https://github.com/argus-security/argus"

# Fingerprint kind id; consumers use this to dedup across re-runs.
PRIMARY_FINGERPRINT_KEY: Final[str] = "primaryFinding/v1"

# Severity → SARIF level (per spec §3.27.10). ``critical``/``high`` → error
# so they fail the CI gate; ``medium`` → warning; everything else → note.
_SEVERITY_TO_LEVEL: Final[dict[str, str]] = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
}

# Mapping reused by tier_classifier — kept in sync deliberately. SARIF spec
# does not define a "rank" for non-numeric severities, so we surface CVSS
# (when available) via ``properties`` instead.
_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}

# Conservative regex for valid SARIF rule ids (no whitespace, no slashes).
_RULE_ID_SANITIZER = re.compile(r"[^A-Za-z0-9._\-+]")
_MAX_RULE_ID_LEN: Final[int] = 128
_MAX_MESSAGE_LEN: Final[int] = 4096
_MAX_DESCRIPTION_LEN: Final[int] = 8192
_DEFAULT_RULE_ID: Final[str] = "ARGUS-FINDING"


def _severity_level(sev: str | None) -> str:
    """Map an internal severity string to a SARIF level."""
    return _SEVERITY_TO_LEVEL.get((sev or "").strip().lower(), "warning")


def _severity_rank(sev: str | None) -> int:
    """Stable rank for sorting (lower → more urgent)."""
    return _SEVERITY_RANK.get((sev or "").strip().lower(), 99)


def _truncate(value: str | None, limit: int) -> str:
    """Bounded truncation; returns empty string for ``None``."""
    if not value:
        return ""
    s = str(value)
    return s if len(s) <= limit else s[: limit - 1] + "\u2026"


def _sanitize_rule_id(raw: str | None) -> str:
    """Coerce a rule id (CWE-79, custom string, or empty) into SARIF-safe shape."""
    candidate = (raw or "").strip()
    if not candidate:
        return _DEFAULT_RULE_ID
    cleaned = _RULE_ID_SANITIZER.sub("-", candidate)
    cleaned = cleaned.strip("-")
    return cleaned[:_MAX_RULE_ID_LEN] or _DEFAULT_RULE_ID


def _cwe_id(raw: str | None) -> str | None:
    """Extract a CWE numeric id from strings like ``CWE-79`` or ``79``."""
    if not raw:
        return None
    s = str(raw).strip().upper()
    if s.startswith("CWE-"):
        s = s[4:]
    if s.isdigit():
        return s
    return None


def _rule_id_for_finding(f: Finding) -> str:
    """Stable rule id derived from CWE; falls back to title-hash when absent."""
    cwe = _cwe_id(f.cwe)
    if cwe:
        return f"ARGUS-CWE-{cwe}"
    title = (f.title or "").strip()
    if title:
        digest = hashlib.sha256(title.encode("utf-8")).hexdigest()[:12]
        return f"ARGUS-RULE-{digest}"
    return _DEFAULT_RULE_ID


def _help_uri_for_cwe(cwe: str | None) -> str | None:
    """Return the canonical CWE help URI for ``cwe`` (None when unparseable)."""
    cwe_num = _cwe_id(cwe)
    if cwe_num:
        return f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
    return None


def _finding_priority_key(f: Finding) -> tuple[int, float, str, str]:
    """Same key used by tier_classifier — keep determinism stable."""
    sev_rank = _severity_rank(f.severity)
    cvss = -float(f.cvss) if f.cvss is not None else 0.0
    title = (f.title or "").lower()
    cwe = f.cwe or ""
    return (sev_rank, cvss, title, cwe)


def _physical_location(uri: str | None) -> dict[str, Any] | None:
    """Build a SARIF ``physicalLocation`` from a target URI (when present)."""
    if not uri:
        return None
    safe_uri = _truncate(uri, 2048)
    return {
        "artifactLocation": {"uri": safe_uri},
    }


def _result_message(f: Finding) -> dict[str, Any]:
    """Build a SARIF ``message`` object from finding title/description.

    SARIF requires a ``text`` field on every result — we always populate
    it with the finding's title (truncated). The description (when set)
    becomes ``markdown`` so consumers that render markdown (GitHub) can
    show formatting; consumers that do not still see ``text``.
    """
    msg: dict[str, Any] = {
        "text": _truncate(f.title or "Untitled finding", _MAX_MESSAGE_LEN),
    }
    description = (f.description or "").strip()
    if description:
        msg["markdown"] = _truncate(description, _MAX_MESSAGE_LEN)
    return msg


def _build_rule(rule_id: str, sample: Finding) -> dict[str, Any]:
    """Build a ``runs[].tool.driver.rules[]`` entry for a unique rule id."""
    cwe_num = _cwe_id(sample.cwe)
    short = _truncate(sample.title or rule_id, 256)
    full = _truncate(sample.description or sample.title or rule_id, _MAX_DESCRIPTION_LEN)
    properties: dict[str, Any] = {
        "tags": ["security", "argus"],
    }
    if cwe_num:
        properties["cwe"] = f"CWE-{cwe_num}"
    if sample.cvss is not None:
        properties["security-severity"] = f"{float(sample.cvss):.1f}"
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": rule_id,
        "shortDescription": {"text": short},
        "fullDescription": {"text": full},
        "defaultConfiguration": {"level": _severity_level(sample.severity)},
        "properties": properties,
    }
    help_uri = _help_uri_for_cwe(sample.cwe)
    if help_uri:
        rule["helpUri"] = help_uri
    return rule


def _result_properties(f: Finding) -> dict[str, Any]:
    """Surface auxiliary metadata as ``result.properties`` (security-severity, OWASP)."""
    props: dict[str, Any] = {}
    if f.cvss is not None:
        props["cvss_v3_score"] = float(f.cvss)
        props["security-severity"] = f"{float(f.cvss):.1f}"
    cwe_num = _cwe_id(f.cwe)
    if cwe_num:
        props["cwe"] = f"CWE-{cwe_num}"
    owasp = parse_owasp_category(getattr(f, "owasp_category", None))
    if owasp:
        props["owasp_top10_2025"] = owasp
        title = OWASP_TOP10_2025_CATEGORY_TITLES.get(owasp)
        if title:
            props["owasp_top10_2025_title"] = title
    confidence = getattr(f, "confidence", None)
    if confidence:
        props["confidence"] = str(confidence)
    evidence_refs = getattr(f, "evidence_refs", None)
    if evidence_refs:
        props["evidence_refs"] = sorted(str(x) for x in evidence_refs if x)
    if f.severity:
        props["severity"] = str(f.severity).lower().strip()
    return props


def _result_fingerprint(f: Finding, target: str | None) -> str:
    """Stable per-finding fingerprint for cross-run dedup.

    The fingerprint is SHA-256 over a canonical tuple ``(target, rule_id,
    severity, title, cwe, cvss)`` — independent of finding ordering and
    immune to whitespace differences in the source data.
    """
    key = "|".join([
        (target or "").strip().lower(),
        _rule_id_for_finding(f),
        (f.severity or "").lower().strip(),
        (f.title or "").strip().lower(),
        (f.cwe or "").strip().upper(),
        f"{float(f.cvss):.1f}" if f.cvss is not None else "",
    ])
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _build_result(f: Finding, *, target: str | None) -> dict[str, Any]:
    """Build a ``runs[].results[]`` entry for one finding."""
    rule_id = _rule_id_for_finding(f)
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": _severity_level(f.severity),
        "message": _result_message(f),
    }
    physical = _physical_location(target)
    if physical is not None:
        result["locations"] = [{"physicalLocation": physical}]
    result["fingerprints"] = {PRIMARY_FINGERPRINT_KEY: _result_fingerprint(f, target)}
    properties = _result_properties(f)
    if properties:
        result["properties"] = properties
    return result


def _ordered(obj: Any) -> Any:
    """Return ``obj`` with all dict keys recursively sorted (deterministic JSON).

    SARIF arrays preserve order intentionally (rules appear before they are
    referenced; results are ordered by priority); only object keys are
    canonicalised.
    """
    if isinstance(obj, dict):
        return {k: _ordered(obj[k]) for k in sorted(obj.keys())}
    if isinstance(obj, list):
        return [_ordered(x) for x in obj]
    return obj


def _ordered_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Type-narrowed wrapper around ``_ordered`` for top-level payloads."""
    ordered = _ordered(payload)
    assert isinstance(ordered, dict)  # noqa: S101 — invariant maintained by _ordered for dict input
    return ordered


def build_sarif_payload(
    data: ReportData,
    *,
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Build a SARIF v2.1.0 dict from ``data`` (no I/O, no JSON encoding)."""
    findings_sorted = sorted(list(data.findings or []), key=_finding_priority_key)

    rules_by_id: dict[str, dict[str, Any]] = {}
    for f in findings_sorted:
        rid = _rule_id_for_finding(f)
        if rid not in rules_by_id:
            rules_by_id[rid] = _build_rule(rid, f)

    rules = [rules_by_id[rid] for rid in sorted(rules_by_id)]

    results = [_build_result(f, target=data.target) for f in findings_sorted]

    driver: dict[str, Any] = {
        "name": ARGUS_TOOL_NAME,
        "informationUri": ARGUS_TOOL_INFORMATION_URI,
        "rules": rules,
    }
    if tool_version:
        driver["version"] = tool_version

    automation_id = (data.scan_id or data.report_id or "").strip()

    run: dict[str, Any] = {
        "tool": {"driver": driver},
        "results": results,
    }
    if automation_id:
        run["automationDetails"] = {"id": automation_id}

    artifacts: list[dict[str, Any]] = []
    if data.target:
        artifacts.append({
            "location": {"uri": _truncate(data.target, 2048)},
            "description": {"text": "Scan target"},
        })
    if artifacts:
        run["artifacts"] = artifacts

    payload: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URL,
        "version": SARIF_VERSION,
        "runs": [run],
    }
    return _ordered_payload(payload)


def generate_sarif(
    data: ReportData,
    *,
    tool_version: str | None = None,
) -> bytes:
    """Render ``data`` as a UTF-8 SARIF v2.1.0 byte stream."""
    payload = build_sarif_payload(data, tool_version=tool_version)
    return json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")


__all__ = [
    "ARGUS_TOOL_INFORMATION_URI",
    "ARGUS_TOOL_NAME",
    "PRIMARY_FINGERPRINT_KEY",
    "SARIF_SCHEMA_URL",
    "SARIF_VERSION",
    "build_sarif_payload",
    "generate_sarif",
]
