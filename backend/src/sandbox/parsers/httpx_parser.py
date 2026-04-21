"""Parser for ProjectDiscovery `httpx` JSONL output (Backlog/dev1_md §4.4).

`httpx -json` (or `-jsonl`) emits one JSON object per probed target with a
fairly stable schema::

    {
      "url": "https://example.com",
      "status_code": 200,
      "title": "Example Domain",
      "tech": ["Nginx", "Cloudflare"],
      "tls": {"subject_cn": "example.com", "tls_version": "tls13", ...},
      "favicon": "0x12345678",
      "jarm": "...",
      "webserver": "nginx/1.21.6",
      "content_type": "text/html",
      "host": "93.184.216.34",
      ...
    }

Each non-trivial record becomes one :class:`FindingDTO` of category
:attr:`FindingCategory.INFO` (tech-disclosure semantics) with severity held
implicitly via the sentinel ``cvss_v3_score == 0.0`` from
:func:`make_finding_dto`. The original record is folded into a compact
JSON evidence blob and persisted as a JSONL sidecar under
``artifacts_dir / "httpx_findings.jsonl"`` so the downstream evidence
pipeline can hash and attach it without re-walking the raw stdout.

Contract
--------
* Records without a ``url`` field are skipped (logged once at WARNING).
* Records with the same ``(url, tech_tuple)`` are deduplicated — httpx may
  emit several rows for the same URL when probing both http+https.
* Malformed JSONL lines are skipped (logged at WARNING by the JSONL helper).
* Output ordering is deterministic: sorted by ``url`` then by tech tuple so
  snapshot tests stay stable across reruns.
* Sidecar file write is best-effort: any :class:`OSError` is logged at
  WARNING and swallowed (the FindingDTOs are still returned). This keeps
  the parser pure-deterministic for in-memory test paths that pass
  ``Path("/dev/null")`` or a non-writable directory.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Final

from src.pipeline.contracts.finding_dto import FindingCategory, FindingDTO
from src.sandbox.parsers._base import (
    ParserContext,
    make_finding_dto,
    safe_load_jsonl,
)

_logger = logging.getLogger(__name__)


# Tech disclosure findings are an "Information Exposure" class (CWE-200).
# Backlog/dev1_md §4.4 (HTTP fingerprinting) aligns with WSTG-INFO-02 (Web
# server fingerprint) and WSTG-INFO-08 (App framework fingerprint).
_HTTPX_DEFAULT_CWE: tuple[int, ...] = (200,)
_HTTPX_DEFAULT_WSTG: tuple[str, ...] = ("WSTG-INFO-02", "WSTG-INFO-08")


EVIDENCE_SIDECAR_NAME: Final[str] = "httpx_findings.jsonl"


def parse_httpx_jsonl(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
) -> list[FindingDTO]:
    """Translate httpx JSONL output into a deduplicated list of findings.

    Side-effect: writes one compact JSON evidence record per emitted
    finding to ``artifacts_dir / EVIDENCE_SIDECAR_NAME`` (best-effort —
    OSErrors are logged and swallowed). ``stderr`` is accepted for parser
    dispatch signature symmetry but not consumed.
    """
    del stderr

    DedupKey = tuple[str, tuple[str, ...]]
    seen_keys: set[DedupKey] = set()
    keyed_findings: list[tuple[DedupKey, FindingDTO]] = []
    keyed_evidence: list[tuple[DedupKey, str]] = []

    for record in safe_load_jsonl(stdout, tool_id="httpx"):
        url = _string_field(record, "url")
        if not url:
            _logger.warning(
                "httpx_parser.skip_no_url",
                extra={
                    "event": "httpx_parser_skip_no_url",
                    "tool_id": "httpx",
                },
            )
            continue

        tech_list = _normalise_tech(record.get("tech"))
        dedup_key: DedupKey = (url, tech_list)
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)

        evidence_blob = _build_evidence(record, url=url, tech_list=tech_list)
        keyed_evidence.append((dedup_key, evidence_blob))
        finding = make_finding_dto(
            category=FindingCategory.INFO,
            cwe=list(_HTTPX_DEFAULT_CWE),
            owasp_wstg=list(_HTTPX_DEFAULT_WSTG),
        )
        keyed_findings.append((dedup_key, finding))
        _logger.debug(
            "httpx_parser.record_emitted",
            extra={
                "event": "httpx_parser_record_emitted",
                "tool_id": "httpx",
                "url": url,
                "status_code": _int_field(record, "status_code"),
                "tech_count": len(tech_list),
                "evidence_bytes": len(evidence_blob),
            },
        )

    # Sort by the dedup key (url, tech_tuple) so the output is deterministic
    # across reruns regardless of the order httpx happened to emit the rows
    # (and independent of file-system iteration ordering for snapshot tests).
    # The sentinel UUID + same-millisecond timestamps on FindingDTOs make a
    # post-hoc sort by FindingDTO fields a no-op, so we sort on the upstream
    # key we still have in scope. Sidecar JSONL stays aligned with the
    # returned findings list — both are sorted by the same key.
    keyed_findings.sort(key=lambda item: item[0])
    keyed_evidence.sort(key=lambda item: item[0])

    if keyed_evidence:
        _persist_evidence_sidecar(artifacts_dir, [blob for _, blob in keyed_evidence])

    return [finding for _, finding in keyed_findings]


def _persist_evidence_sidecar(artifacts_dir: Path, evidence_records: list[str]) -> None:
    """Best-effort write of the per-finding evidence sidecar JSONL.

    Failure is non-fatal: any :class:`OSError` is logged and swallowed so
    that the parser stays pure-deterministic for in-memory test paths and
    so a transient disk error never aborts the worker run.
    """
    try:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        sidecar_path = artifacts_dir / EVIDENCE_SIDECAR_NAME
        with sidecar_path.open("w", encoding="utf-8") as fh:
            for blob in evidence_records:
                fh.write(blob)
                fh.write("\n")
    except OSError as exc:
        _logger.warning(
            "httpx_parser.evidence_sidecar_write_failed",
            extra={
                "event": "httpx_parser_evidence_sidecar_write_failed",
                "tool_id": "httpx",
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


def parse_httpx_for_dispatch(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    context: ParserContext,
) -> list[FindingDTO]:
    """Dispatch-friendly adapter that ignores ``context``.

    Kept as a separate symbol so the dispatch registry can register a
    uniform 4-arg callable without forcing every tool-specific parser to
    accept (and silently drop) a context argument it does not need.
    """
    del context
    return parse_httpx_jsonl(stdout, stderr, artifacts_dir)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _string_field(record: dict[str, Any], key: str) -> str | None:
    """Return ``record[key]`` if it is a non-empty string, else ``None``."""
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _int_field(record: dict[str, Any], key: str) -> int | None:
    """Return ``record[key]`` if it is an int, else ``None``."""
    value = record.get(key)
    if isinstance(value, bool):  # bool is a subclass of int — exclude.
        return None
    if isinstance(value, int):
        return value
    return None


def _normalise_tech(value: Any) -> tuple[str, ...]:
    """Coerce a heterogeneous ``tech`` field into a sorted unique tuple.

    httpx normally emits ``tech`` as ``list[str]`` but older versions and
    custom wrappers occasionally produce a comma-separated string or a dict
    keyed by tech name. The parser is liberal in what it accepts so the
    catalog is not held hostage to one upstream version.
    """
    if value is None:
        return ()
    if isinstance(value, str):
        items = [t.strip() for t in value.split(",")]
    elif isinstance(value, list):
        items = [str(t).strip() for t in value if isinstance(t, (str, int))]
    elif isinstance(value, dict):
        items = [str(t).strip() for t in value.keys() if isinstance(t, str)]
    else:
        items = []
    cleaned = sorted({t for t in items if t})
    return tuple(cleaned)


def _build_evidence(
    record: dict[str, Any], *, url: str, tech_list: tuple[str, ...]
) -> str:
    """Build a compact evidence JSON for downstream redaction + persistence.

    Keeps only the fields that have probative value for a tech-disclosure
    finding (URL, status, tech stack, page title, TLS handshake summary).
    Unknown keys are intentionally dropped to avoid leaking sensitive
    headers / cookies that might appear in a verbose httpx run.
    """
    payload: dict[str, Any] = {
        "url": url,
        "status_code": _int_field(record, "status_code"),
        "title": _string_field(record, "title"),
        "tech": list(tech_list),
        "webserver": _string_field(record, "webserver"),
        "content_type": _string_field(record, "content_type"),
        "host": _string_field(record, "host"),
        "favicon": _string_field(record, "favicon"),
        "jarm": _string_field(record, "jarm"),
        "tls": _summarise_tls(record.get("tls")),
    }
    cleaned = {k: v for k, v in payload.items() if v not in (None, [], {})}
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


_TLS_KEEP_KEYS: tuple[str, ...] = (
    "subject_cn",
    "subject_dn",
    "issuer_cn",
    "issuer_dn",
    "tls_version",
    "cipher",
    "fingerprint_hash",
    "not_before",
    "not_after",
)


def _summarise_tls(value: Any) -> dict[str, Any] | None:
    """Project the most useful TLS fields from a httpx record.

    The full ``tls`` block from httpx can include certificate chains and
    raw extensions; we keep the canonical identity / version fields only.
    """
    if not isinstance(value, dict):
        return None
    out: dict[str, Any] = {}
    for key in _TLS_KEEP_KEYS:
        sub_value = value.get(key)
        if isinstance(sub_value, (str, int, float)) and sub_value not in (None, ""):
            out[key] = sub_value
        elif isinstance(sub_value, dict) and sub_value:
            inner = {
                k: v
                for k, v in sub_value.items()
                if isinstance(v, (str, int, float)) and v not in (None, "")
            }
            if inner:
                out[key] = inner
    return out or None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_httpx_for_dispatch",
    "parse_httpx_jsonl",
]
