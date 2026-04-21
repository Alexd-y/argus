"""Parser for Semgrep ``--json`` output (Backlog/dev1_md §4.16 — ARG-018).

§4.16 ships eight Code / secrets scanners; this module covers the
flagship multi-language SAST engine that emits the canonical r2c
``semgrep --json --output /out/semgrep.json`` envelope on disk:

* **semgrep** (``semgrep scan --config p/owasp-top-ten --config p/ci
  --json --output /out/semgrep.json --metrics off --quiet --timeout 300
  {path}``) — multi-language static analysis; supports Python, JavaScript,
  TypeScript, Java, Go, Ruby, PHP, Scala, Kotlin, C/C++, Bash, YAML,
  Terraform, etc. The two rule packs (``p/owasp-top-ten`` + ``p/ci``)
  are pre-bundled inside ``argus-kali-cloud:latest`` (no live registry
  pull) because the wrapper runs under the ``offline-no-egress``
  network policy; ``--metrics off`` disables r2c telemetry; per-file
  timeout is 300 s.

The remaining seven §4.16 tools (``terrascan``, ``tfsec``, ``kics``,
``bandit``, ``gitleaks``, ``trufflehog``, ``detect_secrets``) emit
distinct JSON shapes and either:

* Have their own dedicated parser (added in follow-up cycles), or
* Ship as ``parse_strategy=text_lines`` / ``json_object`` without a
  per-tool parser (the dispatch layer logs ``unmapped_tool`` until the
  Cycle 3 SAST follow-up wires a small adapter family).

Semgrep envelope shape (semgrep v1.50+):

.. code-block:: json

    {
      "version":   "1.59.0",
      "results": [
        {
          "check_id":  "python.lang.security.audit.dangerous-subprocess",
          "path":      "src/utils.py",
          "start":     {"line": 42, "col": 9, "offset": 1234},
          "end":       {"line": 44, "col": 35, "offset": 1300},
          "extra": {
            "message":  "subprocess called with shell=True permits OS injection.",
            "severity": "ERROR",
            "metadata": {
              "cwe":         ["CWE-78: Improper Neutralization of OS Command"],
              "owasp":       ["A03:2021 — Injection"],
              "category":    "security",
              "technology":  ["python"],
              "subcategory": ["audit"],
              "confidence":  "HIGH",
              "likelihood":  "HIGH",
              "impact":      "HIGH",
              "references":  ["https://...", "https://owasp.org/Top10/A03_2021-Injection/"]
            },
            "lines":     "subprocess.run(cmd, shell=True)",
            "fingerprint": "<stable hash>",
            "metavars":  {...}
          }
        }
      ],
      "errors": [],
      "paths":  {"scanned": [...], "skipped": [...]}
    }

Translation rules
-----------------

* **Severity** — Semgrep emits three buckets: ``ERROR`` / ``WARNING`` /
  ``INFO``. The parser maps them onto ARGUS's five-level severity by
  combining the Semgrep ``severity`` with metadata ``confidence`` /
  ``likelihood`` / ``impact`` (Semgrep Pro ships these on the public
  registry rules):

  - ``ERROR``   + (any of confidence/likelihood/impact ∈ {HIGH}) → ``critical``
  - ``ERROR``                                                    → ``high``
  - ``WARNING`` + (any of confidence/likelihood/impact ∈ {HIGH}) → ``high``
  - ``WARNING``                                                  → ``medium``
  - ``INFO``                                                     → ``low``
  - everything else                                              → ``info``

* **Category** — driven by metadata + check_id substrings:

  1. metadata ``cwe`` list → CWE IDs → category lookup (matches the §4.10
     XSS / §4.9 SQLi / §4.11 SSRF / §4.16 secret-leak / §4.17 LDAP
     classes).
  2. metadata ``category`` (``security`` / ``best-practice`` /
     ``correctness`` / ``maintainability``) — only ``security`` keeps
     the CWE-derived bucket; everything else collapses to ``INFO``
     (Semgrep is also a code-quality engine; non-security findings
     should not pollute the SUPPLY_CHAIN / MISCONFIG buckets).
  3. ``check_id`` substring scan (``sql``, ``xss``, ``ssrf``, ``rce``,
     ``injection``, ``secret``, …) as a final fallback when neither CWE
     nor category land a verdict.
  4. Default: :class:`FindingCategory.MISCONFIG`.

* **Confidence** — derived from Semgrep severity + CWE presence:

  - ``ERROR``   with metadata ``confidence=HIGH`` → ``LIKELY``.
  - ``ERROR``   without it                       → ``LIKELY``.
  - ``WARNING`` with metadata ``confidence=HIGH`` → ``LIKELY``.
  - ``WARNING``                                  → ``SUSPECTED``.
  - ``INFO``                                      → ``SUSPECTED``.

* **CVSS score** — Semgrep does not emit a CVSS vector; we lift a
  severity-bucket sentinel from :data:`_SEVERITY_TO_CVSS` so the
  downstream Prioritiser can place ``ERROR``-class findings above
  ``INFO`` without waiting for the Normaliser.

* **CWE list** — pulled from ``extra.metadata.cwe`` (canonical Semgrep
  registry shape: ``["CWE-78: ...", "CWE-89: ..."]``) and normalised to
  positive integers. Defaults to the per-category fallback when missing.

* **OWASP-WSTG** — derived from category via :data:`_OWASP_BY_CATEGORY`
  (consistent with the Nuclei + Trivy mapping).

* **References** — folded into evidence under ``references[]``;
  ``OWASP A0X:202Y`` strings from ``extra.metadata.owasp`` land in a
  separate ``owasp_top10`` evidence field.

Dedup
-----

Stable key: ``(check_id, path, start_line, end_line)``. Two distinct
rules matching the same line are two findings; the same rule
re-matching the exact same span (start_line + end_line) is one. The
``end_line`` component is what disambiguates two AST-node hits that
collapse to the same start_line but cover different spans (e.g. two
semicolon-separated statements on the same physical line).

Sorting is deterministic on (severity desc → check_id → path → start_line).

Cap
---

Hard-limited to :data:`_MAX_FINDINGS = 10_000` so a Semgrep run over a
mono-repo with thousands of low-confidence rules cannot exhaust worker
memory. ``errors[]`` (parse failures, rule exceptions) are surfaced as
a single ``WARNING semgrep_parser.scan_errors`` log event and dropped
from the FindingDTO list (they are tool diagnostics, not findings).

Sidecar
-------

Every emitted record is mirrored into
``artifacts_dir / "semgrep_findings.jsonl"``. Each record carries its
source ``tool_id`` (``semgrep``).

Failure model
-------------

Fail-soft by contract:

* Missing ``semgrep.json`` falls back to stdout parsing.
* Malformed JSON returns ``[]`` after a structured warning.
* Records missing ``check_id`` or ``path`` are skipped with a
  structured ``WARNING semgrep_parser.result_missing_field`` log.
* OS errors writing the sidecar are logged and swallowed.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
    safe_load_json,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants — surfaced for tests + downstream evidence pipeline.
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "semgrep_findings.jsonl"


# Hard cap on emitted findings. A semgrep run with ``--config auto``
# over a 200k-LOC repo legitimately produces 5–9k records; 10k stays
# bounded against a misconfigured rule pack (e.g. a "match every
# function" custom rule).
_MAX_FINDINGS: Final[int] = 10_000


# Hard cap on evidence text bytes (message / lines snippet).
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


# Severity bucket → CVSS v3.1 anchor. Semgrep does not emit a CVSS
# vector (it's a SAST tool, not a CVE database), so we lift these
# sentinels so the prioritiser does not flatten ERROR-class to P4.
# Anchored on Backlog/dev1_md §11 priority weighting.
_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 3.5,
    "info": 0.0,
}


# Severity rank for deterministic descending sort.
_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


# Severity → ConfidenceLevel base map. Combined with metadata
# ``confidence`` to potentially escalate WARNING-with-HIGH-confidence
# above SUSPECTED.
_SEVERITY_CONFIDENCE: Final[dict[str, ConfidenceLevel]] = {
    "critical": ConfidenceLevel.LIKELY,
    "high": ConfidenceLevel.LIKELY,
    "medium": ConfidenceLevel.SUSPECTED,
    "low": ConfidenceLevel.SUSPECTED,
    "info": ConfidenceLevel.SUSPECTED,
}


# Per-category CWE backstop.
_CATEGORY_DEFAULT_CWE: Final[dict[FindingCategory, tuple[int, ...]]] = {
    FindingCategory.RCE: (78, 94),
    FindingCategory.CMDI: (78,),
    FindingCategory.SQLI: (89,),
    FindingCategory.NOSQLI: (943,),
    FindingCategory.LDAPI: (90,),
    FindingCategory.SSTI: (1336, 94),
    FindingCategory.SSRF: (918,),
    FindingCategory.XXE: (611,),
    FindingCategory.XSS: (79,),
    FindingCategory.LFI: (22, 73),
    FindingCategory.OPEN_REDIRECT: (601,),
    FindingCategory.AUTH: (287,),
    FindingCategory.IDOR: (639,),
    FindingCategory.JWT: (345, 287),
    FindingCategory.CRYPTO: (327,),
    FindingCategory.SECRET_LEAK: (798, 200),
    FindingCategory.DOS: (400,),
    FindingCategory.CORS: (942,),
    FindingCategory.CSRF: (352,),
    FindingCategory.SUPPLY_CHAIN: (1395,),
    FindingCategory.MISCONFIG: (16, 1032),
    FindingCategory.INFO: (200,),
}


# Per-category OWASP-WSTG hints (mirrors nuclei_parser._OWASP_BY_CATEGORY).
_OWASP_BY_CATEGORY: Final[dict[FindingCategory, tuple[str, ...]]] = {
    FindingCategory.RCE: ("WSTG-INPV-12",),
    FindingCategory.CMDI: ("WSTG-INPV-12",),
    FindingCategory.SQLI: ("WSTG-INPV-05",),
    FindingCategory.NOSQLI: ("WSTG-INPV-05",),
    FindingCategory.LDAPI: ("WSTG-INPV-06",),
    FindingCategory.SSTI: ("WSTG-INPV-18",),
    FindingCategory.SSRF: ("WSTG-INPV-19",),
    FindingCategory.XXE: ("WSTG-INPV-07",),
    FindingCategory.XSS: ("WSTG-INPV-01", "WSTG-INPV-02"),
    FindingCategory.LFI: ("WSTG-ATHZ-01",),
    FindingCategory.OPEN_REDIRECT: ("WSTG-CLNT-04",),
    FindingCategory.AUTH: ("WSTG-ATHN-01",),
    FindingCategory.IDOR: ("WSTG-ATHZ-04",),
    FindingCategory.JWT: ("WSTG-SESS-09",),
    FindingCategory.CRYPTO: ("WSTG-CRYP-01",),
    FindingCategory.SECRET_LEAK: ("WSTG-ATHN-06", "WSTG-INFO-08"),
    FindingCategory.DOS: ("WSTG-BUSL-01",),
    FindingCategory.CORS: ("WSTG-CLNT-07",),
    FindingCategory.CSRF: ("WSTG-SESS-05",),
    FindingCategory.SUPPLY_CHAIN: ("WSTG-INFO-08",),
    FindingCategory.MISCONFIG: ("WSTG-CONF-04",),
    FindingCategory.INFO: ("WSTG-INFO-08",),
}


# CWE id → ARGUS category. Picked to match the most-common Semgrep
# registry rule families. Entries marked ``# top-25`` come from the
# 2024 CWE Top-25 list; the rest are common SAST findings.
_CWE_TO_CATEGORY: Final[dict[int, FindingCategory]] = {
    78: FindingCategory.RCE,  # OS command injection (top-25).
    79: FindingCategory.XSS,  # XSS (top-25).
    89: FindingCategory.SQLI,  # SQLi (top-25).
    90: FindingCategory.LDAPI,
    94: FindingCategory.RCE,  # Code injection.
    91: FindingCategory.XXE,
    611: FindingCategory.XXE,
    918: FindingCategory.SSRF,
    98: FindingCategory.LFI,  # PHP file inclusion.
    22: FindingCategory.LFI,  # Path traversal.
    73: FindingCategory.LFI,
    287: FindingCategory.AUTH,
    284: FindingCategory.AUTH,
    295: FindingCategory.CRYPTO,
    297: FindingCategory.CRYPTO,
    310: FindingCategory.CRYPTO,
    326: FindingCategory.CRYPTO,
    327: FindingCategory.CRYPTO,
    330: FindingCategory.CRYPTO,
    345: FindingCategory.JWT,
    352: FindingCategory.CSRF,
    400: FindingCategory.DOS,
    502: FindingCategory.RCE,  # Insecure deserialization.
    601: FindingCategory.OPEN_REDIRECT,
    639: FindingCategory.IDOR,
    798: FindingCategory.SECRET_LEAK,  # Hard-coded credentials.
    532: FindingCategory.SECRET_LEAK,  # Information exposure via log.
    693: FindingCategory.MISCONFIG,
    830: FindingCategory.SUPPLY_CHAIN,
    915: FindingCategory.IDOR,
    916: FindingCategory.CRYPTO,
    943: FindingCategory.NOSQLI,
    1336: FindingCategory.SSTI,
    1395: FindingCategory.SUPPLY_CHAIN,
}


# Substring → category fallback when neither CWE nor metadata category
# resolves a clear bucket. Walked in priority order so a check_id like
# ``python.django.injection.sql.tainted-sql-string`` lands as SQLI
# even though "injection" appears first.
_CHECK_ID_TO_CATEGORY: Final[tuple[tuple[str, FindingCategory], ...]] = (
    ("sqli", FindingCategory.SQLI),
    (".sql", FindingCategory.SQLI),
    ("nosql", FindingCategory.NOSQLI),
    ("xss", FindingCategory.XSS),
    ("ssrf", FindingCategory.SSRF),
    ("ssti", FindingCategory.SSTI),
    ("xxe", FindingCategory.XXE),
    ("rce", FindingCategory.RCE),
    ("command-injection", FindingCategory.RCE),
    ("os-command", FindingCategory.RCE),
    ("ldap", FindingCategory.LDAPI),
    ("path-traversal", FindingCategory.LFI),
    ("file-inclusion", FindingCategory.LFI),
    ("open-redirect", FindingCategory.OPEN_REDIRECT),
    ("idor", FindingCategory.IDOR),
    ("authn", FindingCategory.AUTH),
    ("auth-bypass", FindingCategory.AUTH),
    ("jwt", FindingCategory.JWT),
    ("csrf", FindingCategory.CSRF),
    ("crypto", FindingCategory.CRYPTO),
    ("hardcoded", FindingCategory.SECRET_LEAK),
    ("secret", FindingCategory.SECRET_LEAK),
    ("token", FindingCategory.SECRET_LEAK),
    ("password", FindingCategory.SECRET_LEAK),
    ("dependency", FindingCategory.SUPPLY_CHAIN),
    ("misconfig", FindingCategory.MISCONFIG),
    ("config", FindingCategory.MISCONFIG),
    ("dos", FindingCategory.DOS),
    ("cors", FindingCategory.CORS),
)


# Stable dedup key shape: ``(check_id, path, start_line, end_line)``.
# The ``end_line`` component disambiguates two findings of the same
# rule that share a ``start_line`` but cover different AST node spans
# (e.g. a single physical line carrying two semicolon-separated
# statements where Semgrep emits one finding per AST node). Without
# ``end_line`` such legitimate distinct findings would silently
# collapse to one.
DedupKey: TypeAlias = tuple[str, str, int, int]


# ---------------------------------------------------------------------------
# Public entry point — signature mandated by the dispatch layer:
# ``(stdout, stderr, artifacts_dir, tool_id) -> list[FindingDTO]``.
# ---------------------------------------------------------------------------


def parse_semgrep_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate Semgrep ``--json`` output into FindingDTOs.

    Resolution order for the JSON blob:

    1. ``artifacts_dir / "semgrep.json"`` (canonical: the ``semgrep``
       YAML invokes ``-o /out/semgrep.json``).
    2. ``stdout`` fallback — ``semgrep --json`` without ``-o`` streams
       to stdout instead.

    ``stderr`` is accepted for parser dispatch signature symmetry but
    intentionally not consumed (Semgrep uses stderr for progress /
    rule-load banners only).
    """
    del stderr
    payload = _load_payload(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        tool_id=tool_id,
    )
    if payload is None:
        return []
    if not isinstance(payload, dict):
        _logger.warning(
            "semgrep_parser.envelope_not_dict",
            extra={
                "event": "semgrep_parser_envelope_not_dict",
                "tool_id": tool_id,
            },
        )
        return []
    _surface_scan_errors(payload, tool_id=tool_id)
    raw_results = payload.get("results")
    if not isinstance(raw_results, list):
        return []
    records = list(_iter_normalised(raw_results, tool_id=tool_id))
    if not records:
        return []
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Pipeline — dedup + sort + sidecar persistence
# ---------------------------------------------------------------------------


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Common pipeline: dedup → cap → sort → build FindingDTO + sidecar."""

    seen: set[DedupKey] = set()
    keyed: list[tuple[tuple[int, str, str, int], DedupKey, FindingDTO, str]] = []

    for record in records:
        key = _dedup_key(record)
        if key in seen:
            continue
        seen.add(key)

        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = _sort_key(record)
        keyed.append((sort_key, key, finding, evidence_blob))

        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "semgrep_parser.cap_reached",
                extra={
                    "event": "semgrep_parser_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
            break

    keyed.sort(key=lambda item: item[0])
    if keyed:
        _persist_evidence_sidecar(
            artifacts_dir,
            tool_id=tool_id,
            evidence_records=[blob for _, _, _, blob in keyed],
        )

    return [finding for _, _, finding, _ in keyed]


def _dedup_key(record: dict[str, Any]) -> DedupKey:
    """Stable dedup key: ``(check_id, path, start_line, end_line)``.

    ``end_line`` is included so two findings of the same rule that share
    a ``start_line`` but cover different AST node spans stay distinct
    (Semgrep emits per-AST-node findings, e.g. two statements on the
    same physical line each get their own record). A 3-tuple key would
    silently collapse them.
    """
    return (
        str(record.get("check_id") or ""),
        str(record.get("path") or ""),
        int(record.get("start_line") or 0),
        int(record.get("end_line") or 0),
    )


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str, int]:
    """Deterministic sort key (severity desc → check_id → path → start_line)."""
    severity = str(record.get("severity") or "info")
    rank = _SEVERITY_RANK.get(severity, 0)
    return (
        -rank,
        str(record.get("check_id") or ""),
        str(record.get("path") or ""),
        int(record.get("start_line") or 0),
    )


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    """Map a normalised semgrep record onto a :class:`FindingDTO`."""
    category: FindingCategory = record["category"]
    cwe_list = list(record.get("cwe") or ())
    if not cwe_list:
        cwe_list = list(_CATEGORY_DEFAULT_CWE.get(category, (200,)))
    confidence: ConfidenceLevel = record["confidence"]
    cvss_score: float = record.get("cvss_v3_score") or 0.0
    cvss_vector: str = record.get("cvss_v3_vector") or SENTINEL_CVSS_VECTOR
    owasp_wstg = list(record.get("owasp_wstg") or ())
    return make_finding_dto(
        category=category,
        cwe=cwe_list,
        cvss_v3_vector=cvss_vector,
        cvss_v3_score=cvss_score,
        confidence=confidence,
        owasp_wstg=owasp_wstg,
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    """Build a compact evidence JSON for downstream redaction + persistence."""
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "semgrep",
        "check_id": record.get("check_id"),
        "path": record.get("path"),
        "start_line": record.get("start_line"),
        "end_line": record.get("end_line"),
        "start_col": record.get("start_col"),
        "end_col": record.get("end_col"),
        "severity": record.get("severity"),
        "semgrep_severity": record.get("semgrep_severity"),
        "confidence_meta": record.get("confidence_meta"),
        "likelihood": record.get("likelihood"),
        "impact": record.get("impact"),
        "category_meta": record.get("category_meta"),
        "technology": list(record.get("technology") or ()),
        "subcategory": list(record.get("subcategory") or ()),
        "cwe": list(record.get("cwe") or ()),
        "owasp_top10": list(record.get("owasp_top10") or ()),
        "references": list(record.get("references") or ()),
        "message": _truncate_text(record.get("message")),
        "lines_snippet": _truncate_text(record.get("lines_snippet")),
        "fingerprint": record.get("fingerprint"),
        "synthetic_id": _stable_hash(
            f"{record.get('check_id', '')}::{record.get('path', '')}::"
            f"{record.get('start_line', 0)}"
        ),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None:
            continue
        if isinstance(value, list | tuple) and not value:
            continue
        if value == "":
            continue
        cleaned[key] = value
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _persist_evidence_sidecar(
    artifacts_dir: Path,
    *,
    tool_id: str,
    evidence_records: list[str],
) -> None:
    """Best-effort write of the per-finding evidence sidecar JSONL."""
    try:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        sidecar_path = artifacts_dir / EVIDENCE_SIDECAR_NAME
        with sidecar_path.open("w", encoding="utf-8") as fh:
            for blob in evidence_records:
                fh.write(blob)
                fh.write("\n")
    except OSError as exc:
        _logger.warning(
            "semgrep_parser.evidence_sidecar_write_failed",
            extra={
                "event": "semgrep_parser_evidence_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


def _surface_scan_errors(payload: dict[str, Any], *, tool_id: str) -> None:
    """Log Semgrep ``errors[]`` (parse failures / rule errors) once per scan."""
    errors = payload.get("errors")
    if not isinstance(errors, list) or not errors:
        return
    error_types: list[str] = []
    for err in errors:
        if isinstance(err, dict):
            error_type = err.get("type")
            if isinstance(error_type, str):
                error_types.append(error_type)
    _logger.warning(
        "semgrep_parser.scan_errors",
        extra={
            "event": "semgrep_parser_scan_errors",
            "tool_id": tool_id,
            "error_count": len(errors),
            "error_types": sorted(set(error_types))[:10],
        },
    )


# ---------------------------------------------------------------------------
# Payload resolution
# ---------------------------------------------------------------------------


def _load_payload(
    *,
    stdout: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> Any:
    """Resolve the canonical ``semgrep.json`` blob or fall back to stdout."""
    canonical = _safe_join(artifacts_dir, "semgrep.json")
    if canonical is not None and canonical.is_file():
        try:
            raw = canonical.read_bytes()
        except OSError as exc:
            _logger.warning(
                "semgrep_parser.canonical_read_failed",
                extra={
                    "event": "semgrep_parser_canonical_read_failed",
                    "tool_id": tool_id,
                    "path": "semgrep.json",
                    "error_type": type(exc).__name__,
                },
            )
            raw = b""
        if raw.strip():
            payload = safe_load_json(raw, tool_id=tool_id)
            if payload is not None:
                return payload
    if stdout and stdout.strip():
        return safe_load_json(stdout, tool_id=tool_id)
    return None


def _safe_join(base: Path, name: str) -> Path | None:
    """Defensive ``base / name`` that refuses path-traversal segments."""
    if "/" in name or "\\" in name or ".." in name:
        return None
    return base / name


# ---------------------------------------------------------------------------
# Record normalisation
# ---------------------------------------------------------------------------


def _iter_normalised(
    raw_results: list[Any],
    *,
    tool_id: str,
) -> Iterable[dict[str, Any]]:
    """Yield normalised records from a Semgrep ``results[]`` block."""
    for raw in raw_results:
        if not isinstance(raw, dict):
            continue
        check_id = _string_field(raw, "check_id")
        path = _string_field(raw, "path")
        if check_id is None or path is None:
            _logger.warning(
                "semgrep_parser.result_missing_field",
                extra={
                    "event": "semgrep_parser_result_missing_field",
                    "tool_id": tool_id,
                    "missing": "check_id" if check_id is None else "path",
                },
            )
            continue
        raw_start = raw.get("start")
        start: dict[str, Any] = raw_start if isinstance(raw_start, dict) else {}
        raw_end = raw.get("end")
        end: dict[str, Any] = raw_end if isinstance(raw_end, dict) else {}
        start_line = _coerce_int(start.get("line")) or 0
        end_line = _coerce_int(end.get("line")) or start_line
        start_col = _coerce_int(start.get("col"))
        end_col = _coerce_int(end.get("col"))
        raw_extra = raw.get("extra")
        extra: dict[str, Any] = raw_extra if isinstance(raw_extra, dict) else {}
        raw_meta = extra.get("metadata")
        metadata: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
        semgrep_severity = (_string_field(extra, "severity") or "INFO").upper()
        confidence_meta = (_string_field(metadata, "confidence") or "").upper()
        likelihood = (_string_field(metadata, "likelihood") or "").upper()
        impact = (_string_field(metadata, "impact") or "").upper()
        category_meta = (_string_field(metadata, "category") or "").lower()
        cwe_list = _extract_cwe_list(metadata.get("cwe"))
        owasp_top10 = _extract_strings(metadata.get("owasp"))
        references = _extract_strings(metadata.get("references"))
        technology = _extract_strings(metadata.get("technology"))
        subcategory = _extract_strings(metadata.get("subcategory"))
        category = _classify_category(
            cwe_list=cwe_list,
            category_meta=category_meta,
            check_id=check_id,
        )
        severity = _map_severity(
            semgrep_severity=semgrep_severity,
            confidence_meta=confidence_meta,
            likelihood=likelihood,
            impact=impact,
        )
        confidence = _classify_confidence(
            semgrep_severity=semgrep_severity,
            confidence_meta=confidence_meta,
        )
        cvss_score = _SEVERITY_TO_CVSS.get(severity, 0.0)
        owasp_wstg = _OWASP_BY_CATEGORY.get(category, ("WSTG-INFO-08",))
        message = _string_field(extra, "message")
        lines_snippet = _string_field(extra, "lines")
        fingerprint = _string_field(extra, "fingerprint")
        yield {
            "check_id": check_id,
            "path": path,
            "start_line": start_line,
            "end_line": end_line,
            "start_col": start_col,
            "end_col": end_col,
            "severity": severity,
            "semgrep_severity": semgrep_severity,
            "confidence_meta": confidence_meta or None,
            "likelihood": likelihood or None,
            "impact": impact or None,
            "category_meta": category_meta or None,
            "technology": technology,
            "subcategory": subcategory,
            "category": category,
            "confidence": confidence,
            "cwe": cwe_list,
            "owasp_top10": owasp_top10,
            "references": references,
            "message": message,
            "lines_snippet": lines_snippet,
            "fingerprint": fingerprint,
            "owasp_wstg": owasp_wstg,
            "cvss_v3_score": cvss_score,
            "cvss_v3_vector": SENTINEL_CVSS_VECTOR,
        }


# ---------------------------------------------------------------------------
# Helpers — severity / category / confidence classifiers
# ---------------------------------------------------------------------------


def _map_severity(
    *,
    semgrep_severity: str,
    confidence_meta: str,
    likelihood: str,
    impact: str,
) -> str:
    """Combine Semgrep severity + metadata into the canonical bucket."""
    has_high_signal = "HIGH" in {confidence_meta, likelihood, impact}
    if semgrep_severity == "ERROR":
        return "critical" if has_high_signal else "high"
    if semgrep_severity == "WARNING":
        return "high" if has_high_signal else "medium"
    if semgrep_severity == "INFO":
        return "low"
    return "info"


def _classify_category(
    *,
    cwe_list: list[int],
    category_meta: str,
    check_id: str,
) -> FindingCategory:
    """Pick the most specific :class:`FindingCategory` for a record.

    Precedence: CWE → security-only category lift via metadata + check_id
    → MISCONFIG fallback.

    Non-security ``category`` values (best-practice / correctness /
    maintainability) collapse to :class:`FindingCategory.INFO` because
    Semgrep is also a code-quality engine and those records should not
    inflate the SUPPLY_CHAIN / MISCONFIG buckets.
    """
    if category_meta and category_meta != "security":
        return FindingCategory.INFO
    for cwe_id in cwe_list:
        bucket = _CWE_TO_CATEGORY.get(cwe_id)
        if bucket is not None:
            return bucket
    lowered = check_id.lower()
    for substring, bucket in _CHECK_ID_TO_CATEGORY:
        if substring in lowered:
            return bucket
    return FindingCategory.MISCONFIG


def _classify_confidence(
    *,
    semgrep_severity: str,
    confidence_meta: str,
) -> ConfidenceLevel:
    """Map Semgrep severity + metadata.confidence onto ConfidenceLevel."""
    if semgrep_severity == "ERROR":
        return ConfidenceLevel.LIKELY
    if semgrep_severity == "WARNING" and confidence_meta == "HIGH":
        return ConfidenceLevel.LIKELY
    return ConfidenceLevel.SUSPECTED


# ---------------------------------------------------------------------------
# Helpers — field accessors / coercers
# ---------------------------------------------------------------------------


def _string_field(record: dict[str, Any], key: str) -> str | None:
    """Return ``record[key]`` if it is a non-empty string, else ``None``."""
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _extract_cwe_list(raw: Any) -> list[int]:
    """Return a sorted, deduplicated list of CWE ids (positive integers)."""
    collected: list[int] = []
    if isinstance(raw, list):
        for item in raw:
            cwe_id = _coerce_cwe(item)
            if cwe_id is not None:
                collected.append(cwe_id)
    elif isinstance(raw, str | int):
        cwe_id = _coerce_cwe(raw)
        if cwe_id is not None:
            collected.append(cwe_id)
    return sorted(set(collected))


def _coerce_cwe(value: Any) -> int | None:
    """Coerce a CWE token into a positive integer.

    Accepts ``"CWE-78: Improper Neutralization"`` (Semgrep registry
    canonical), ``"CWE-78"``, ``"78"``, and ``78``.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str):
        candidate = value.strip().upper()
        if candidate.startswith("CWE-"):
            candidate = candidate[4:]
        digits: list[str] = []
        for ch in candidate:
            if ch.isdigit():
                digits.append(ch)
            else:
                break
        if not digits:
            return None
        cwe_id = int("".join(digits))
        return cwe_id if cwe_id > 0 else None
    return None


def _extract_strings(raw: Any) -> tuple[str, ...]:
    """Return a sorted tuple of unique non-empty string values."""
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, list):
        items = [v for v in raw if isinstance(v, str)]
    else:
        return ()
    cleaned = {v.strip() for v in items if v.strip()}
    return tuple(sorted(cleaned))


def _coerce_int(value: Any) -> int | None:
    """Coerce ``value`` into a positive int (or ``None``)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        candidate = int(value.strip())
        return candidate if candidate >= 0 else None
    return None


def _truncate_text(text: str | None) -> str | None:
    """Cap a single string at :data:`_MAX_EVIDENCE_BYTES` UTF-8 bytes."""
    if text is None or text == "":
        return None
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_EVIDENCE_BYTES:
        return text
    truncated = encoded[:_MAX_EVIDENCE_BYTES].decode("utf-8", errors="replace")
    return truncated + "...[truncated]"


def _stable_hash(text: str) -> str:
    """Return a cross-process deterministic 12-char hex digest of ``text``."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_semgrep_json",
]
