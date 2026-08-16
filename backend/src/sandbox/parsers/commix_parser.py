"""Parser for commix command-injection output (Backlog/dev1_md §4.9 — F-M03).

commix (``--batch --level 1``) probes a URL for OS command injection and
writes a line-based text log to ``/out/commix_output.txt`` (see
``config/tools/commix.yaml``; also mirrored on stdout). When a parameter
is injectable commix prints a confirmation line, e.g.::

    [+] The (GET) 'addr' parameter is vulnerable to (results-based) command injection technique.
    [+] The ('id') POST parameter appears to be injectable via (time-based) command injection technique.
    [+] The target URL appears to be vulnerable to command injection attacks.

Only these positive detections yield findings; the surrounding progress
chatter (``[*] Testing ...``, ``[!] ...`` warnings) is ignored.

Translation rules
-----------------

* **Category** — every emitted finding is
  :class:`FindingCategory.CMDI` (OS command injection).

* **Confidence** — :class:`ConfidenceLevel.CONFIRMED`. commix flags an
  injection point only after a positive payload round-trip, so the
  detection is a real exploit primitive, not a heuristic.

* **CWE** — ``[77, 78]`` (Command Injection + OS Command Injection),
  matching ``cwe_hints`` in ``config/tools/commix.yaml``.

* **CVSS** — sentinel vector with a representative critical base score
  (:data:`_CVSS_CMDI`); the real vector is re-derived downstream from
  the CWE-78 + CVE lookup path.

Dedup
-----

Stable key: ``(param, method)``. commix can print the same injectable
parameter across several techniques (results-based, time-based, …); they
are the same underlying vulnerability, so they collapse to one finding
while every observed technique is preserved in the evidence sidecar.

A URL-level detection (no parameter named) collapses under the sentinel
key ``("", "")`` and is only emitted when no parameter-level finding was
seen, so a specific per-parameter finding always wins over the generic
"target URL is vulnerable" line.

Cap
---

Hard-limited to :data:`_MAX_FINDINGS = 1_000`.

Sidecar
-------

Mirrored into ``artifacts_dir / "commix_findings.jsonl"``.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    SSVCDecision,
)
from src.sandbox.parsers._base import (
    make_finding_dto,
    stable_hash_12,
)
from src.sandbox.parsers._text_base import (
    load_canonical_or_stdout_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "commix_findings.jsonl"
_CANONICAL_FILENAMES: Final[tuple[str, ...]] = ("commix_output.txt",)
_MAX_FINDINGS: Final[int] = 1_000
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


_CWE_CMDI: Final[tuple[int, ...]] = (77, 78)
_CVSS_CMDI: Final[float] = 9.8
_OWASP_WSTG_DEFAULT: Final[tuple[str, ...]] = ("WSTG-INPV-12",)
_MITRE_ATTACK_DEFAULT: Final[tuple[str, ...]] = ("T1059",)


# ---------------------------------------------------------------------------
# Regex catalogue
# ---------------------------------------------------------------------------


# A line is a positive detection when it says something is
# "vulnerable to" / "injectable" AND mentions command / code injection.
_DETECT_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:vulnerable to|injectable)",
    re.IGNORECASE,
)
_INJECTION_KIND_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:command|code)\s+injection",
    re.IGNORECASE,
)
# HTTP method commix annotates in parentheses, e.g. ``(GET)`` / ``(POST)``.
_METHOD_RE: Final[re.Pattern[str]] = re.compile(
    r"\((?P<method>GET|POST|PUT|DELETE|PATCH|HEAD|Cookie|HTTP Header)\)",
    re.IGNORECASE,
)
# Injection technique commix annotates in parentheses, e.g.
# ``(results-based)`` / ``(time-based)`` / ``(classic)``.
_TECHNIQUE_RE: Final[re.Pattern[str]] = re.compile(
    r"\((?P<technique>[^)]*?"
    r"(?:results-based|time-based|file-based|semi-blind|blind|classic|dynamic)"
    r"[^)]*)\)",
    re.IGNORECASE,
)
# Parameter name — tried in priority order. Tolerates commix's several
# phrasings: ``'id' parameter``, ``'id') POST parameter`` (paren-wrapped
# quote + trailing bare method), and ``'id' (GET) parameter``.
_PARAM_QUOTED_BEFORE_RE: Final[re.Pattern[str]] = re.compile(
    r"'(?P<param>[^']{1,120})'\)?\s+"
    r"(?:\(?(?P<method_bare>GET|POST|PUT|DELETE|PATCH|HEAD|Cookie|HTTP Header)\)?\s+)?"
    r"parameter",
    re.IGNORECASE,
)
_PARAM_QUOTED_AFTER_RE: Final[re.Pattern[str]] = re.compile(
    r"parameter\s+'(?P<param>[^']{1,120})'",
    re.IGNORECASE,
)
_URL_LEVEL_RE: Final[re.Pattern[str]] = re.compile(
    r"target url.*?(?:vulnerable|injectable)",
    re.IGNORECASE,
)


DedupKey: TypeAlias = tuple[str, str]
_URL_LEVEL_KEY: Final[DedupKey] = ("", "")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_commix(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate commix output into CMDI findings."""
    del stderr
    text = load_canonical_or_stdout_text(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_names=_CANONICAL_FILENAMES,
        tool_id=tool_id,
    )
    if not text:
        return []
    records = list(_iter_records(text))
    if not records:
        return []
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Record extraction
# ---------------------------------------------------------------------------


def _iter_records(text: str) -> Iterator[dict[str, Any]]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if not _DETECT_RE.search(line):
            continue
        param_match = _PARAM_QUOTED_BEFORE_RE.search(
            line
        ) or _PARAM_QUOTED_AFTER_RE.search(line)
        is_url_level = _URL_LEVEL_RE.search(line) is not None
        # Require an injection-kind mention unless a parameter is explicitly
        # named on a detection line (some commix builds omit the phrase on
        # the per-parameter confirmation line).
        if not _INJECTION_KIND_RE.search(line) and param_match is None:
            continue
        if param_match is None and not is_url_level:
            continue
        method_match = _METHOD_RE.search(line)
        technique_match = _TECHNIQUE_RE.search(line)
        param = param_match.group("param").strip() if param_match else ""
        if method_match:
            method = method_match.group("method").upper()
        else:
            # commix also prints the method as a bare word right after the
            # quoted parameter (``'user') POST parameter``); recover it from
            # the param regex's optional capture when no ``(METHOD)`` token is
            # present on the line.
            bare_method = (
                param_match.groupdict().get("method_bare") if param_match else None
            )
            method = bare_method.upper() if bare_method else ""
        technique = (
            technique_match.group("technique").strip() if technique_match else ""
        )
        yield {
            "param": param,
            "method": method,
            "technique": technique,
            "url_level": param == "" and is_url_level,
            "line": line,
        }


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    param_level_seen = any(not rec["url_level"] for rec in records)
    seen: set[DedupKey] = set()
    keyed: list[tuple[tuple[int, str, str], FindingDTO, str]] = []
    for record in records:
        # A specific per-parameter finding always supersedes the generic
        # "target URL is vulnerable" line.
        if record["url_level"] and param_level_seen:
            continue
        key: DedupKey = (
            (record["param"] or "").lower(),
            (record["method"] or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding()
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            0 if not record["url_level"] else 1,
            key[0],
            key[1],
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "commix_parser.cap_reached",
                extra={
                    "event": "commix_parser_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
            break
    keyed.sort(key=lambda item: item[0])
    if keyed:
        _persist_sidecar(
            artifacts_dir,
            tool_id=tool_id,
            evidence_records=[blob for _, _, blob in keyed],
        )
    return [finding for _, finding, _ in keyed]


def _build_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.CMDI,
        cwe=list(_CWE_CMDI),
        cvss_v3_score=_CVSS_CMDI,
        confidence=ConfidenceLevel.CONFIRMED,
        ssvc_decision=SSVCDecision.ACT,
        owasp_wstg=list(_OWASP_WSTG_DEFAULT),
        mitre_attack=list(_MITRE_ATTACK_DEFAULT),
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "commix_cmdi",
        "param": record.get("param"),
        "method": record.get("method"),
        "technique": record.get("technique"),
        "url_level": bool(record.get("url_level")),
        "line": _truncate_text(record.get("line")),
        "synthetic_id": stable_hash_12(
            f"{(record.get('param') or '').lower()}::{record.get('method') or ''}"
        ),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value in (None, "") and key != "url_level":
            continue
        cleaned[key] = value
    return json.dumps(
        scrub_evidence_strings(cleaned), sort_keys=True, ensure_ascii=False
    )


def _persist_sidecar(
    artifacts_dir: Path,
    *,
    tool_id: str,
    evidence_records: list[str],
) -> None:
    try:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        sidecar_path = artifacts_dir / EVIDENCE_SIDECAR_NAME
        with sidecar_path.open("w", encoding="utf-8") as fh:
            for blob in evidence_records:
                fh.write(blob)
                fh.write("\n")
    except OSError as exc:
        _logger.warning(
            "commix_parser.evidence_sidecar_write_failed",
            extra={
                "event": "commix_parser_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _truncate_text(text: str | None) -> str | None:
    if text is None or text == "":
        return None
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_EVIDENCE_BYTES:
        return text
    truncated = encoded[:_MAX_EVIDENCE_BYTES].decode("utf-8", errors="replace")
    return truncated + "...[truncated]"


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_commix",
]
