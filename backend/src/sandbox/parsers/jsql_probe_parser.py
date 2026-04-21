"""Parser for jsql-injection JSON export — Cycle 6 T05."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Final

from src.pipeline.contracts.finding_dto import ConfidenceLevel, FindingCategory, FindingDTO
from src.sandbox.parsers._base import make_finding_dto, stable_hash_12
from src.sandbox.parsers._jsonl_base import load_canonical_or_stdout_json, persist_jsonl_sidecar
from src.sandbox.parsers._text_base import redact_password_in_text, scrub_evidence_strings

EVIDENCE_SIDECAR: Final[str] = "jsql_findings.jsonl"
_CANONICAL: Final[str] = "jsql.json"
_DEFAULT_CVSS: Final[float] = 8.5


def parse_jsql_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Emit a confirmed SQLi finding when JSON shows exfiltrated schema/data."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL,
        tool_id=tool_id,
    )
    if not isinstance(payload, dict):
        return []

    if payload.get("error") or payload.get("exception"):
        return []

    signal_keys = (
        "database",
        "databases",
        "tables",
        "columns",
        "data",
        "rows",
        "records",
        "vendor",
        "dbms",
    )
    if not any(k in payload for k in signal_keys):
        return []

    url = str(payload.get("url") or payload.get("target") or "")
    url_safe = redact_password_in_text(url) if url else ""

    finding = make_finding_dto(
        category=FindingCategory.SQLI,
        cwe=[89],
        cvss_v3_score=_DEFAULT_CVSS,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-INPV-05"],
    )
    fp = stable_hash_12(json.dumps(payload, sort_keys=True, default=str)[:8000])
    evidence = scrub_evidence_strings(
        {
            "tool_id": tool_id,
            "url": url_safe,
            "fingerprint_hash": fp,
            "vendor": str(payload.get("vendor") or payload.get("dbms") or ""),
        }
    )
    persist_jsonl_sidecar(
        artifacts_dir,
        sidecar_name=EVIDENCE_SIDECAR,
        evidence_records=[json.dumps(evidence, sort_keys=True, ensure_ascii=False)],
        tool_id=tool_id,
    )
    return [finding]


__all__ = ["parse_jsql_json", "EVIDENCE_SIDECAR"]
