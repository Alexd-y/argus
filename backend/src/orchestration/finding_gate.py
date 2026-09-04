"""Evidence gating and deduplication for pipeline findings (Block 1.2 / 1.3).

The vuln_analysis phase aggregates findings from many producers (active-scan
tool parsers, LLM agents, SAST, fuzzing). Historically this produced two
classes of report noise observed on real scans:

* ``unknown finding`` / fingerprint-only records with empty
  ``evidence`` / ``poc`` / ``tool_output`` (e.g. WhatWeb plugin hits with no
  specific vulnerability). These are *coverage* signals, not vulnerabilities,
  and must not be emitted as findings.
* Exact duplicates (two identical TLS_PROBE records, two identical
  rate-limiting records) that inflate the finding count.

This module centralizes both concerns so the fix applies to every producer:

* :class:`EvidenceQuality` — unified none/weak/moderate/strong scale.
* :func:`evidence_quality_of` — derive quality from a finding dict.
* :func:`gate_findings` — drop evidence-less placeholder findings.
* :func:`dedupe_findings` — collapse duplicates by a stable ``finding_key``,
  recording ``occurrences`` and merged evidence.
* :func:`gate_and_dedupe_findings` — the composed entry point used by the
  vuln_analysis handler.

The gate is a correctness fix, not a behavior removal, but per the "never
remove behavior silently" rule it is guarded by
``settings.finding_evidence_gate_enabled`` (default ``True``) and every drop /
merge is logged with structured context so it can be audited or disabled.
"""

from __future__ import annotations

import hashlib
import logging
import re
from enum import IntEnum
from typing import Any

logger = logging.getLogger(__name__)


class EvidenceQuality(IntEnum):
    """Unified evidence-quality scale for findings.

    Ordered so ``a >= b`` comparisons work (STRONG is the highest bar).
    """

    NONE = 0
    WEAK = 1
    MODERATE = 2
    STRONG = 3


# Placeholder / non-informative titles that, on their own, never constitute a
# vulnerability. Matched case-insensitively against the normalized title.
_PLACEHOLDER_TITLES: frozenset[str] = frozenset(
    {
        "unknown finding",
        "unknown",
        "unknown vulnerability",
        "untitled",
        "n/a",
        "none",
        "finding",
        "test",
        "placeholder",
    }
)

# Titles that are pure fingerprint/coverage signals (a tool ran and matched)
# but carry no specific vulnerability. Matched as a prefix on the normalized,
# URL-stripped title.
_COVERAGE_TITLE_PREFIXES: tuple[str, ...] = (
    "whatweb_plugin",
    "whatweb plugin",
    "unknown finding",
)

_MIN_MEANINGFUL_DESC = 15

# Strip a trailing " — <url/target>" or " on <target>" qualifier so duplicate
# records that differ only by their rendered target collapse together.
_TITLE_SUFFIX_RE = re.compile(r"\s+(?:—|-|on|for|at)\s+https?://\S+.*$", re.IGNORECASE)


def _s(value: Any) -> str:
    return value.strip() if isinstance(value, str) else ""


def _normalize_title(title: Any) -> str:
    raw = _s(title).lower()
    if not raw:
        return ""
    stripped = _TITLE_SUFFIX_RE.sub("", raw).strip()
    return stripped or raw


def _has_proof_of_concept(finding: dict[str, Any]) -> bool:
    poc = finding.get("proof_of_concept")
    if isinstance(poc, dict):
        return any(
            _s(poc.get(k))
            for k in (
                "curl_command",
                "javascript_code",
                "raw_request",
                "raw_response",
                "payload",
                "url",
            )
        )
    return bool(_s(poc))


def _has_evidence(finding: dict[str, Any]) -> bool:
    return bool(
        _s(finding.get("evidence"))
        or _s(finding.get("tool_output"))
        or finding.get("screenshot_urls")
        or finding.get("evidence_refs")
    )


def evidence_quality_of(finding: dict[str, Any]) -> EvidenceQuality:
    """Derive the :class:`EvidenceQuality` of a finding dict.

    Rules (highest wins):

    * STRONG  — a working payload / PoC with request+response or curl, or an
      explicit ``payload_successful`` flag.
    * MODERATE — a proof_of_concept object or tool evidence is attached.
    * WEAK    — a meaningful (>= 15 char) description from an identified
      source tool, but no attached PoC/evidence.
    * NONE    — placeholder title or nothing evidence-bearing at all.
    """
    if not isinstance(finding, dict):
        return EvidenceQuality.NONE

    title_norm = _normalize_title(finding.get("title"))
    if title_norm in _PLACEHOLDER_TITLES:
        return EvidenceQuality.NONE
    # Fingerprint/coverage signal (e.g. WhatWeb plugin hit): only real evidence
    # keeps it as a finding; otherwise it is coverage, not a vulnerability.
    if any(title_norm.startswith(p) for p in _COVERAGE_TITLE_PREFIXES) and not (
        _has_proof_of_concept(finding) or _has_evidence(finding)
    ):
        return EvidenceQuality.NONE

    has_poc = _has_proof_of_concept(finding)
    has_evidence = _has_evidence(finding)
    payload_ok = bool(finding.get("payload_successful"))
    description = _s(finding.get("description"))
    source_tool = _s(finding.get("source_tool")) or _s(finding.get("source"))

    if payload_ok:
        return EvidenceQuality.STRONG
    if has_poc and has_evidence:
        return EvidenceQuality.STRONG
    if has_poc or has_evidence:
        return EvidenceQuality.MODERATE
    if len(description) >= _MIN_MEANINGFUL_DESC and source_tool:
        return EvidenceQuality.WEAK
    if len(description) >= _MIN_MEANINGFUL_DESC:
        return EvidenceQuality.WEAK
    return EvidenceQuality.NONE


def _finding_target(finding: dict[str, Any]) -> str:
    poc = finding.get("proof_of_concept")
    if isinstance(poc, dict):
        for key in ("url", "matched_at", "target"):
            val = _s(poc.get(key))
            if val:
                return val.lower()
    for key in ("url", "target", "asset", "matched_at"):
        val = _s(finding.get(key))
        if val:
            return val.lower()
    return ""


def _finding_port(finding: dict[str, Any]) -> str:
    port = finding.get("port")
    if port not in (None, ""):
        return str(port)
    target = _finding_target(finding)
    match = re.search(r":(\d{1,5})(?:/|$)", target)
    return match.group(1) if match else ""


def _finding_param(finding: dict[str, Any]) -> str:
    poc = finding.get("proof_of_concept")
    if isinstance(poc, dict) and _s(poc.get("parameter")):
        return _s(poc.get("parameter")).lower()
    return _s(finding.get("param")).lower()


def finding_key(finding: dict[str, Any]) -> str:
    """Stable dedup key: ``hash(normalized_title + cwe + target + port + param)``.

    The target host is used (not the full URL) so records differing only by a
    trailing slash or query string collapse together, matching the observed
    duplicate TLS_PROBE / rate-limiting cases.
    """
    title = _normalize_title(finding.get("title"))
    cwe = _s(finding.get("cwe")).upper()
    target = _finding_target(finding)
    host = target.split("/")[0] if target else ""
    port = _finding_port(finding)
    param = _finding_param(finding)
    basis = f"{title}|{cwe}|{host}|{port}|{param}"
    return hashlib.sha256(basis.encode("utf-8", "replace")).hexdigest()[:16]


def gate_findings(
    findings: list[dict[str, Any]],
    *,
    scan_id: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split findings into (kept, dropped).

    A finding is *dropped* (routed to coverage/informational, not the
    vulnerability list) when its :class:`EvidenceQuality` is ``NONE`` — i.e. a
    placeholder title or no evidence/poc/tool_output at all. LLM/normalizer
    output is never allowed to invent a vulnerability out of nothing.
    """
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        quality = evidence_quality_of(finding)
        finding["evidence_quality"] = quality.name.lower()
        if quality == EvidenceQuality.NONE:
            dropped.append(finding)
        else:
            kept.append(finding)
    if dropped:
        logger.info(
            "finding_gate_dropped",
            extra={
                "scan_id": scan_id,
                "dropped": len(dropped),
                "kept": len(kept),
                "titles": [(_s(f.get("title")) or "<empty>")[:60] for f in dropped[:20]],
            },
        )
    return kept, dropped


def _merge_duplicate(primary: dict[str, Any], other: dict[str, Any]) -> None:
    """Fold ``other`` into ``primary``: bump occurrences, keep strongest data."""
    primary["occurrences"] = int(primary.get("occurrences", 1)) + 1

    occ_evidence = primary.setdefault("evidence_occurrences", [])
    other_evidence = _s(other.get("evidence")) or _s(other.get("description"))
    if other_evidence:
        occ_evidence.append(
            {
                "source_tool": _s(other.get("source_tool")) or _s(other.get("source")),
                "evidence": other_evidence[:2000],
            }
        )

    # Keep the strongest severity / CVSS / evidence quality across duplicates.
    _severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    if _severity_rank.get(_s(other.get("severity")).lower(), -1) > _severity_rank.get(
        _s(primary.get("severity")).lower(), -1
    ):
        primary["severity"] = other.get("severity")
    if (other.get("cvss") or 0.0) > (primary.get("cvss") or 0.0):
        primary["cvss"] = other.get("cvss")
    if not _has_proof_of_concept(primary) and _has_proof_of_concept(other):
        primary["proof_of_concept"] = other.get("proof_of_concept")


def dedupe_findings(
    findings: list[dict[str, Any]],
    *,
    scan_id: str | None = None,
) -> list[dict[str, Any]]:
    """Collapse duplicate findings by :func:`finding_key`.

    The first occurrence is kept and annotated with ``occurrences: n`` and an
    ``evidence_occurrences`` list holding the merged evidence of the folded
    duplicates.
    """
    by_key: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    collapsed = 0
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = finding_key(finding)
        primary = by_key.get(key)
        if primary is None:
            finding.setdefault("occurrences", 1)
            by_key[key] = finding
            order.append(key)
        else:
            _merge_duplicate(primary, finding)
            collapsed += 1
    if collapsed:
        logger.info(
            "finding_dedupe_collapsed",
            extra={"scan_id": scan_id, "collapsed": collapsed, "unique": len(order)},
        )
    return [by_key[k] for k in order]


def gate_and_dedupe_findings(
    findings: list[dict[str, Any]],
    *,
    scan_id: str | None = None,
    enabled: bool = True,
) -> list[dict[str, Any]]:
    """Compose evidence gating (1.2) and deduplication (1.3).

    When ``enabled`` is ``False`` the findings are returned unchanged (each
    still annotated with ``evidence_quality`` for downstream consumers).
    """
    if not findings:
        return findings
    if not enabled:
        for finding in findings:
            if isinstance(finding, dict):
                finding.setdefault(
                    "evidence_quality", evidence_quality_of(finding).name.lower()
                )
        return findings
    kept, _dropped = gate_findings(findings, scan_id=scan_id)
    return dedupe_findings(kept, scan_id=scan_id)


__all__ = [
    "EvidenceQuality",
    "dedupe_findings",
    "evidence_quality_of",
    "finding_key",
    "gate_and_dedupe_findings",
    "gate_findings",
]
