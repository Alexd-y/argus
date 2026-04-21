"""TEXT_LINES SQLi / SSTi / NoSQLi probe parsers — Cycle 6 T05.

Four approval-gated scanners (``ghauri``, ``tplmap``, ``nosqlmap``,
``arachni``) previously hit the heartbeat path.  Extraction is
intentionally heuristic — real runs are noisy; we emit bounded
:class:`FindingDTO` rows only when a line matches high-signal patterns
and always redact passwords embedded in log lines.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Final

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import make_finding_dto, stable_hash_12
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar
from src.sandbox.parsers._text_base import (
    load_canonical_or_stdout_text,
    redact_password_in_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)

EVIDENCE_SIDECAR: Final[str] = "t05_sqli_probe_findings.jsonl"
_MAX_FINDINGS: Final[int] = 500

_CANONICAL: Final[dict[str, tuple[str, ...]]] = {
    "ghauri": ("ghauri.log",),
    "tplmap": ("tplmap.txt",),
    "nosqlmap": ("nosqlmap.txt",),
    "arachni": ("arachni.afr",),
}

_SQLI_LINE: Final[re.Pattern[str]] = re.compile(
    r"(?i)sql\s*injection|injectable|parameter\s+[^\s]+\s+is\s+vulnerable|"
    r"banner:\s*(mysql|mariadb|postgres|microsoft)|\bunion\s+select\b",
)
_SSTI_LINE: Final[re.Pattern[str]] = re.compile(
    r"(?i)template\s+inject|ssti|\bjinja2\b|\bvelocity\b|tplmap|erb\s+inject",
)
_NOSQL_LINE: Final[re.Pattern[str]] = re.compile(
    r"(?i)nosql|mongo(db)?\s+inject|auth\s+bypass|nosqlmap|\$where",
)
_ARACHNI_LINE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(critical|high)\b.*\b(severity|vulnerability)\b|CVE-\d{4}-\d+|\[\*+\]|\[!+\]",
)


def parse_sqli_probe_text(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate heuristic probe logs into findings (T05)."""
    del stderr
    canonical = _CANONICAL.get(tool_id)
    if canonical is None:
        _logger.warning(
            "sqli_probe_text_parser.unregistered_tool",
            extra={
                "event": "sqli_probe_text_parser_unregistered_tool",
                "tool_id": tool_id,
            },
        )
        return []

    text = load_canonical_or_stdout_text(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_names=canonical,
        tool_id=tool_id,
    )
    if not text.strip():
        return []

    pattern = _pattern_for_tool(tool_id)
    category, cwes, cvss = _category_for_tool(tool_id)

    seen: set[str] = set()
    findings: list[FindingDTO] = []
    blobs: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or not pattern.search(line):
            continue
        safe = redact_password_in_text(line[:1200]) or line[:1200]
        fp = stable_hash_12(safe)
        if fp in seen:
            continue
        seen.add(fp)
        finding = make_finding_dto(
            category=category,
            cwe=list(cwes),
            cvss_v3_score=cvss,
            confidence=ConfidenceLevel.LIKELY,
            owasp_wstg=["WSTG-INPV-05"],
        )
        findings.append(finding)
        evidence = scrub_evidence_strings(
            {"tool_id": tool_id, "line": safe, "fingerprint_hash": fp}
        )
        blobs.append(json.dumps(evidence, sort_keys=True, ensure_ascii=False))
        if len(findings) >= _MAX_FINDINGS:
            _logger.warning(
                "sqli_probe_text_parser.cap_reached",
                extra={
                    "event": "sqli_probe_text_parser_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
            break

    if blobs:
        persist_jsonl_sidecar(
            artifacts_dir,
            sidecar_name=EVIDENCE_SIDECAR,
            evidence_records=blobs,
            tool_id=tool_id,
        )
    return findings


def _pattern_for_tool(tool_id: str) -> re.Pattern[str]:
    if tool_id == "tplmap":
        return _SSTI_LINE
    if tool_id == "nosqlmap":
        return _NOSQL_LINE
    if tool_id == "arachni":
        return _ARACHNI_LINE
    return _SQLI_LINE


def _category_for_tool(
    tool_id: str,
) -> tuple[FindingCategory, tuple[int, ...], float]:
    if tool_id == "tplmap":
        return FindingCategory.SSTI, (94, 1336), 7.5
    if tool_id == "nosqlmap":
        return FindingCategory.NOSQLI, (943, 89), 8.0
    if tool_id == "arachni":
        return FindingCategory.MISCONFIG, (200, 89), 6.5
    return FindingCategory.SQLI, (89,), 8.5


__all__ = ["parse_sqli_probe_text", "EVIDENCE_SIDECAR"]
