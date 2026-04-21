"""Parser for Playwright runner JSON + HAR output (ARG-032 batch 4a).

The catalog ``playwright_runner`` tool persists its artifacts at
``/out/playwright/`` — typically ``index.har`` for the HTTP archive,
plus a sidecar JSON envelope (``result.json`` or stdout) describing
script execution status, console messages, and uncaught errors.

Translation rules
-----------------

* One INFO finding per unique ``(method, status_class, hostname,
  path-prefix)`` HTTP exchange surfaced from the HAR (CWE-200 / -668),
  capped at :data:`_MAX_REQUEST_FINDINGS` to avoid fan-out on JS-
  heavy single-page apps.
* One MISCONFIG finding per HTTP 5xx response (CWE-755) — server-side
  errors observed during the scripted browser session.
* One MISCONFIG finding per uncaught script error / page error
  reported by Playwright (``errors[]`` / ``console[].type=='error'``)
  with CWE-1059 (Insufficient Technical Documentation — surfaces
  client-side breakage that needs operator follow-up).

CRITICAL security gate
----------------------

Every HAR entry passes through :func:`iter_har_entries` which masks
``Cookie`` / ``Set-Cookie`` / ``Authorization`` / ``Proxy-Authorization``
headers and inline URL credentials BEFORE the parser ever sees them.
URLs themselves are run through :func:`redact_password_in_text` to
catch any ``https://user:pw@host`` embeds, and every evidence string
is finally scrubbed by :func:`scrub_evidence_strings` so any residual
secret pattern (PEM block, AWS key, JWT) is zeroed before sidecar
persistence.
"""

from __future__ import annotations

import json
import logging
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
    stable_hash_12,
)
from src.sandbox.parsers._browser_base import (
    browse_artifact_dir,
    iter_har_entries,
    load_first_existing,
    load_har_payload,
    safe_url_parts,
)
from src.sandbox.parsers._jsonl_base import (
    persist_jsonl_sidecar,
    safe_join_artifact,
)
from src.sandbox.parsers._text_base import scrub_evidence_strings

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "playwright_runner_findings.jsonl"
_CANONICAL_DIR: Final[str] = "playwright"
_HAR_CANDIDATES: Final[tuple[str, ...]] = ("index.har", "playwright.har")
_RESULT_CANDIDATES: Final[tuple[str, ...]] = (
    "result.json",
    "playwright.json",
    "report.json",
)
_MAX_REQUEST_FINDINGS: Final[int] = 250
_MAX_ERROR_FINDINGS: Final[int] = 100


_REQUEST_DEDUP_KEY: TypeAlias = tuple[str, str, str, str]


def parse_playwright_runner(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate Playwright runner output into FindingDTOs."""
    del stderr
    artifact_dir = browse_artifact_dir(artifacts_dir, _CANONICAL_DIR)
    har_payload = _load_har(artifact_dir, tool_id=tool_id)
    result_payload = _load_result(artifact_dir, stdout=stdout, tool_id=tool_id)

    findings: list[FindingDTO] = []
    evidence_blobs: list[str] = []

    findings.extend(
        _emit_request_findings(
            har_payload, evidence_blobs=evidence_blobs, tool_id=tool_id
        )
    )
    findings.extend(
        _emit_error_findings(
            result_payload, evidence_blobs=evidence_blobs, tool_id=tool_id
        )
    )

    if evidence_blobs:
        persist_jsonl_sidecar(
            artifacts_dir,
            sidecar_name=EVIDENCE_SIDECAR_NAME,
            evidence_records=evidence_blobs,
            tool_id=tool_id,
        )
    return findings


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------


def _load_har(artifact_dir: Path | None, *, tool_id: str) -> Any:
    if artifact_dir is None:
        return None
    candidates = [
        path
        for name in _HAR_CANDIDATES
        if (path := safe_join_artifact(artifact_dir, name)) is not None
    ]
    return load_har_payload(candidates, tool_id=tool_id)


def _load_result(artifact_dir: Path | None, *, stdout: bytes, tool_id: str) -> Any:
    candidates: list[Path] = []
    if artifact_dir is not None:
        candidates = [
            path
            for name in _RESULT_CANDIDATES
            if (path := safe_join_artifact(artifact_dir, name)) is not None
        ]
    raw = load_first_existing(candidates, tool_id=tool_id)
    if raw.strip():
        from src.sandbox.parsers._base import safe_load_json

        decoded = safe_load_json(raw, tool_id=tool_id)
        if decoded is not None:
            return decoded
    if stdout and stdout.strip():
        from src.sandbox.parsers._base import safe_load_json

        return safe_load_json(stdout, tool_id=tool_id)
    return None


# ---------------------------------------------------------------------------
# HAR → findings
# ---------------------------------------------------------------------------


def _status_class(status: int) -> str:
    if status <= 0:
        return "0xx"
    bucket = (status // 100) * 100
    return f"{bucket}xx"


def _path_prefix(path: str, depth: int = 2) -> str:
    raw_path = path or "/"
    segments = [seg for seg in raw_path.split("/") if seg]
    prefix = "/" + "/".join(segments[:depth]) if segments else "/"
    return prefix


def _emit_request_findings(
    har_payload: Any,
    *,
    evidence_blobs: list[str],
    tool_id: str,
) -> list[FindingDTO]:
    seen: set[_REQUEST_DEDUP_KEY] = set()
    keyed: list[tuple[_REQUEST_DEDUP_KEY, FindingDTO, str]] = []
    for entry in iter_har_entries(har_payload, tool_id=tool_id):
        method = str(entry.get("method") or "")
        url = str(entry.get("url") or "")
        raw_status = entry.get("status") or 0
        try:
            status = int(raw_status) if isinstance(raw_status, (int, float, str)) else 0
        except (TypeError, ValueError):
            status = 0
        if not method or not url:
            continue
        raw_host = entry.get("host")
        raw_path = entry.get("path")
        if isinstance(raw_host, str) and isinstance(raw_path, str):
            host = raw_host
            path = _path_prefix(raw_path)
        else:
            extracted_host, extracted_path = safe_url_parts(url)
            host = extracted_host
            path = _path_prefix(extracted_path)
        key: _REQUEST_DEDUP_KEY = (method, _status_class(status), host, path)
        if key in seen:
            continue
        seen.add(key)
        is_error = 500 <= status < 600
        finding = _build_request_finding(is_error=is_error)
        evidence = _build_request_evidence(
            entry,
            tool_id=tool_id,
            host=host,
            path=path,
            is_error=is_error,
        )
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_REQUEST_FINDINGS:
            _logger.warning(
                "playwright_runner.request_cap_reached",
                extra={
                    "event": "playwright_runner_request_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_REQUEST_FINDINGS,
                },
            )
            break
    keyed.sort(key=lambda item: item[0])
    findings: list[FindingDTO] = []
    for key, finding, blob in keyed:
        findings.append(finding)
        evidence_blobs.append(blob)
        del key
    return findings


def _build_request_finding(*, is_error: bool) -> FindingDTO:
    if is_error:
        return make_finding_dto(
            category=FindingCategory.MISCONFIG,
            cwe=[755],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=0.0,
            confidence=ConfidenceLevel.LIKELY,
            owasp_wstg=["WSTG-ERRH-01", "WSTG-CLNT-01"],
        )
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200, 668],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-INFO-02", "WSTG-CLNT-09"],
    )


def _build_request_evidence(
    entry: dict[str, object],
    *,
    tool_id: str,
    host: str,
    path: str,
    is_error: bool,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "tool_id": tool_id,
        "method": entry.get("method"),
        "host": host,
        "path_prefix": path,
        "status": entry.get("status"),
        "url_hash": stable_hash_12(str(entry.get("url") or "")),
        "is_server_error": is_error,
    }
    request_headers = entry.get("request_headers")
    if isinstance(request_headers, list) and request_headers:
        payload["request_header_count"] = len(request_headers)
    response_headers = entry.get("response_headers")
    if isinstance(response_headers, list) and response_headers:
        payload["response_header_count"] = len(response_headers)
    post_data = entry.get("post_data")
    if isinstance(post_data, dict):
        payload["post_data"] = post_data
    return payload


# ---------------------------------------------------------------------------
# Result JSON → findings
# ---------------------------------------------------------------------------


def _emit_error_findings(
    result_payload: Any,
    *,
    evidence_blobs: list[str],
    tool_id: str,
) -> list[FindingDTO]:
    if not isinstance(result_payload, dict):
        return []
    raw_errors = list(_iter_error_messages(result_payload))
    if not raw_errors:
        return []
    seen: set[str] = set()
    keyed: list[tuple[str, FindingDTO, str]] = []
    for error_text in raw_errors:
        cleaned = error_text.strip()
        if not cleaned:
            continue
        key = stable_hash_12(cleaned)
        if key in seen:
            continue
        seen.add(key)
        finding = make_finding_dto(
            category=FindingCategory.MISCONFIG,
            cwe=[1059],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=0.0,
            confidence=ConfidenceLevel.SUSPECTED,
            owasp_wstg=["WSTG-ERRH-02", "WSTG-CLNT-01"],
        )
        evidence: dict[str, object] = {
            "tool_id": tool_id,
            "error_hash": key,
            "error_length": len(cleaned),
            "error_kind": "playwright_console_or_script",
        }
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_ERROR_FINDINGS:
            _logger.warning(
                "playwright_runner.error_cap_reached",
                extra={
                    "event": "playwright_runner_error_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_ERROR_FINDINGS,
                },
            )
            break
    keyed.sort(key=lambda item: item[0])
    findings: list[FindingDTO] = []
    for _, finding, blob in keyed:
        findings.append(finding)
        evidence_blobs.append(blob)
    return findings


def _iter_error_messages(payload: dict[str, Any]) -> list[str]:
    out: list[str] = []
    errors = payload.get("errors")
    if isinstance(errors, list):
        for item in errors:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                msg = item.get("message") or item.get("text")
                if isinstance(msg, str):
                    out.append(msg)
    console = payload.get("console")
    if isinstance(console, list):
        for entry in console:
            if not isinstance(entry, dict):
                continue
            level = str(entry.get("type") or entry.get("level") or "").lower()
            if level not in {"error", "warning"}:
                continue
            text = entry.get("text") or entry.get("message")
            if isinstance(text, str):
                out.append(text)
    page_errors = payload.get("pageErrors")
    if isinstance(page_errors, list):
        for item in page_errors:
            if isinstance(item, str):
                out.append(item)
    return out


# ---------------------------------------------------------------------------
# Serialisation
# ---------------------------------------------------------------------------


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_playwright_runner",
]
