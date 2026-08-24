"""Parser for ``host -a`` DNS all-records output (ARG-048).

``host -a {domain}`` writes name/termcap-style DNS records to
``/out/host.txt``::

    Trying "example.com"
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0

    ;; QUESTION SECTION:
    ;example.com.               IN      ANY

    ;; ANSWER SECTION:
    example.com.        3600    IN      A       93.184.216.34
    example.com.        3600    IN      AAAA    2606:2800:220:1:248:1893:25c8:1946
    example.com.        3600    IN      MX      10 mail.example.com.
    example.com.        3600    IN      NS      ns1.example.com.
    example.com.        3600    IN      SOA     ns1.example.com. admin.example.com. ...

Findings:

* One INFO finding per ``(domain, record_type, value)`` tuple.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Final, TypeAlias

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
    stable_hash_12,
)
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar
from src.sandbox.parsers._text_base import (
    load_canonical_or_stdout_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)

EVIDENCE_SIDECAR_NAME: Final[str] = "host_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("host.txt", "host.log")
_MAX_FINDINGS: Final[int] = 5_000

# Matches: <domain>. <ttl> IN <type> <value>
_ANSWER_LINE_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<domain>[^\s]+?\.?)\s+"
    r"\d+\s+"
    r"(?:IN|in)\s+"
    r"(?P<type>[A-Z]{1,6})\s+"
    r"(?P<value>.+)$",
)

_DedupKey: TypeAlias = tuple[str, str, str]


def parse_host(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate ``host -a`` text output into FindingDTOs."""
    del stderr
    text = load_canonical_or_stdout_text(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_names=_CANONICAL_NAMES,
        tool_id=tool_id,
    )
    if not text:
        return []

    in_answer_section = False
    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith(";;") and "ANSWER SECTION:" in line:
            in_answer_section = True
            continue
        # host uses ;; for all zone section markers; detect any other section
        if line.startswith(";;"):
            if any(
                s in line
                for s in (
                    "QUESTION SECTION:",
                    "AUTHORITY SECTION:",
                    "ADDITIONAL SECTION:",
                    "MSG SIZE",
                )
            ):
                in_answer_section = False
                continue
            continue
        # Lines starting with "Trying" are meta
        if line.startswith("Trying"):
            continue
        if not in_answer_section:
            continue

        match = _ANSWER_LINE_RE.match(line)
        if not match:
            continue

        domain = match.group("domain").rstrip(".").lower()
        record_type = match.group("type").upper()
        raw_value = match.group("value").strip().rstrip(".")
        value = _clean_txt_value(record_type, raw_value)

        if not domain or not value:
            continue

        key: _DedupKey = (domain, record_type, value)
        if key in seen:
            continue
        seen.add(key)

        finding = _build_finding()
        evidence: dict[str, object] = {
            "tool_id": tool_id,
            "domain": domain,
            "record_type": record_type,
            "value": value,
            "fingerprint_hash": stable_hash_12(f"host|{domain}|{record_type}|{value}"),
        }
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "host.cap_reached",
                extra={
                    "event": "host_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
            break

    keyed.sort(key=lambda item: item[0])
    if keyed:
        persist_jsonl_sidecar(
            artifacts_dir,
            sidecar_name=EVIDENCE_SIDECAR_NAME,
            evidence_records=[blob for _, _, blob in keyed],
            tool_id=tool_id,
        )
    return [finding for _, finding, _ in keyed]


def _clean_txt_value(record_type: str, raw: str) -> str:
    """Strip surrounding quotes and normalise TXT records."""
    cleaned = raw.strip('"').strip("'").strip()
    if record_type == "TXT":
        if cleaned.startswith('"') and cleaned.endswith('"'):
            cleaned = cleaned[1:-1]
    return cleaned


def _build_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200, 668],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-INFO-01", "WSTG-INFO-02"],
    )


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_host",
]
