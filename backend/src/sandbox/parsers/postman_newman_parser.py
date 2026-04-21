"""Parser for ``newman`` (Postman runner) JSON output (Backlog §4.14 — ARG-029).

``newman run --reporter-json-export newman.json`` produces a verbose
JSON envelope that captures the entire collection run.  We focus on
two failure surfaces — operationally meaningful and security-adjacent:

* ``run.failures[]``    — assertion failures emitted during script
  execution.  These usually encode contract violations (status codes,
  schema mismatches, presence of secrets in responses, etc.).
* ``run.executions[].response`` — every executed request whose
  response status is ``>= 500`` is treated as a server-side error
  (potential WAF / DoS / mis-routing surface).

Auth tokens are aggressively redacted from the persisted sidecar
because operator-supplied collections embed bearer tokens, basic auth
strings and API keys directly in the headers.

Translation rules
-----------------

* **Assertion failures**:

  - severity = ``medium`` by default; bumped to ``high`` for any
    assertion mentioning ``security``, ``auth``, ``token``, ``leak``,
    ``credential``.
  - category = ``OTHER`` when the message is generic; ``AUTH`` /
    ``SECRET_LEAK`` when the keyword table fires.

* **HTTP 5xx responses** → ``OTHER`` finding tagged with CWE-755
  (improper-error-handling) at severity ``low`` (CVSS 3.0).

Sidecar lives at ``artifacts_dir / "postman_newman_findings.jsonl"``.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Iterator
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
    redact_secret,
)
from src.sandbox.parsers._jsonl_base import (
    load_canonical_or_stdout_json,
    persist_jsonl_sidecar,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "postman_newman_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "newman.json"
_MAX_FINDINGS: Final[int] = 5_000
_MAX_BODY_PREVIEW: Final[int] = 200


_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "critical": 9.0,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
}


_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


_AUTH_KEYWORDS: Final[tuple[str, ...]] = (
    "auth",
    "token",
    "credential",
    "login",
    "session",
    "jwt",
    "bearer",
)


_SECRET_KEYWORDS: Final[tuple[str, ...]] = (
    "leak",
    "exposed secret",
    "secret value",
    "api key",
    "private key",
)


_SECURITY_KEYWORDS: Final[tuple[str, ...]] = (
    "security",
    "csrf",
    "xss",
    "sqli",
)


_TOKEN_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(r"Bearer\s+[A-Za-z0-9._\-/+=]+", re.IGNORECASE),
    re.compile(r"Basic\s+[A-Za-z0-9+/=]+", re.IGNORECASE),
    re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    re.compile(r"sk_[A-Za-z0-9]{16,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
)


DedupKey: TypeAlias = tuple[str, str, str, str]


def parse_postman_newman_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate newman's run report into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    if not isinstance(payload, dict):
        if payload is not None:
            _logger.warning(
                "postman_newman_parser.envelope_not_object",
                extra={
                    "event": "postman_newman_parser_envelope_not_object",
                    "tool_id": tool_id,
                    "actual_type": type(payload).__name__,
                },
            )
        return []
    run = payload.get("run")
    if not isinstance(run, dict):
        return []
    records = list(_iter_records(run, tool_id=tool_id))
    if not records:
        return []
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    seen: set[DedupKey] = set()
    keyed: list[tuple[tuple[int, str, str, str, str], FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (
            str(record.get("kind") or ""),
            str(record.get("request_name") or ""),
            str(record.get("status") or ""),
            str(record.get("message") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            -_SEVERITY_RANK.get(str(record.get("severity") or "info"), 0),
            str(record.get("kind") or ""),
            str(record.get("request_name") or ""),
            str(record.get("status") or ""),
            str(record.get("message") or ""),
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "postman_newman_parser.cap_reached",
                extra={
                    "event": "postman_newman_parser_cap_reached",
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


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    category: FindingCategory = record.get("_category", FindingCategory.OTHER)
    cwes = record.get("_cwes") or [710]
    severity = str(record.get("severity") or "low")
    return make_finding_dto(
        category=category,
        cwe=list(cwes),
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=_SEVERITY_TO_CVSS.get(severity, 3.0),
        confidence=ConfidenceLevel.LIKELY,
        owasp_wstg=["WSTG-INFO-08", "WSTG-CONF-04"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": record.get("kind"),
        "request_name": record.get("request_name"),
        "method": record.get("method"),
        "url": record.get("url"),
        "status": record.get("status"),
        "severity": record.get("severity"),
        "category": record.get("category"),
        "message": record.get("message"),
        "test_name": record.get("test_name"),
        "response_preview": record.get("response_preview"),
    }
    cleaned: dict[str, Any] = {
        key: value
        for key, value in payload.items()
        if value is not None and value != ""
    }
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _iter_records(run: dict[str, Any], *, tool_id: str) -> Iterable[dict[str, Any]]:
    yield from _iter_assertion_failures(run, tool_id=tool_id)
    yield from _iter_server_errors(run, tool_id=tool_id)


def _iter_assertion_failures(
    run: dict[str, Any], *, tool_id: str
) -> Iterable[dict[str, Any]]:
    failures = run.get("failures")
    if not isinstance(failures, list):
        return
    for index, failure in enumerate(failures):
        if not isinstance(failure, dict):
            _logger.debug(
                "postman_newman_parser.failure_not_object",
                extra={
                    "event": "postman_newman_parser_failure_not_object",
                    "tool_id": tool_id,
                    "index": index,
                },
            )
            continue
        source = failure.get("source")
        request_name = (
            _string_field(source, "name") if isinstance(source, dict) else None
        )
        error = failure.get("error")
        if not isinstance(error, dict):
            continue
        message = _string_field(error, "message")
        test_name = _string_field(error, "test")
        if message is None and test_name is None:
            continue
        composite = " ".join(filter(None, (test_name, message))).lower()
        category, cwes, severity = _classify_assertion(composite)
        yield {
            "kind": "assertion",
            "request_name": request_name,
            "method": _extract_request_method(failure),
            "url": _extract_request_url(failure),
            "status": None,
            "severity": severity,
            "category": category.name.lower(),
            "message": message,
            "test_name": test_name,
            "response_preview": None,
            "_category": category,
            "_cwes": cwes,
        }


def _iter_server_errors(
    run: dict[str, Any], *, tool_id: str
) -> Iterable[dict[str, Any]]:
    executions = run.get("executions")
    if not isinstance(executions, list):
        return
    for index, execution in enumerate(executions):
        if not isinstance(execution, dict):
            _logger.debug(
                "postman_newman_parser.execution_not_object",
                extra={
                    "event": "postman_newman_parser_execution_not_object",
                    "tool_id": tool_id,
                    "index": index,
                },
            )
            continue
        item = execution.get("item")
        request_name = _string_field(item, "name") if isinstance(item, dict) else None
        request = execution.get("request") if isinstance(execution, dict) else None
        method = _string_field(request, "method") if isinstance(request, dict) else None
        url = _extract_url(request) if isinstance(request, dict) else None
        response = execution.get("response")
        if not isinstance(response, dict):
            continue
        status = response.get("code")
        if not isinstance(status, int) or status < 500:
            continue
        body = _string_field(response, "stream") or _string_field(response, "body")
        if body and len(body) > _MAX_BODY_PREVIEW:
            body = body[:_MAX_BODY_PREVIEW] + "…"
        yield {
            "kind": "server_error",
            "request_name": request_name,
            "method": method,
            "url": url,
            "status": status,
            "severity": "low",
            "category": "error_handling",
            "message": f"HTTP {status} response",
            "test_name": None,
            "response_preview": _redact_token_payload(body),
            "_category": FindingCategory.OTHER,
            "_cwes": [755],
        }


def _classify_assertion(
    text: str,
) -> tuple[FindingCategory, tuple[int, ...], str]:
    if any(keyword in text for keyword in _SECRET_KEYWORDS):
        return FindingCategory.SECRET_LEAK, (200, 532), "high"
    if any(keyword in text for keyword in _AUTH_KEYWORDS):
        return FindingCategory.AUTH, (287, 285), "high"
    if any(keyword in text for keyword in _SECURITY_KEYWORDS):
        return FindingCategory.MISCONFIG, (16,), "medium"
    return FindingCategory.OTHER, (710,), "medium"


def _extract_request_method(failure: dict[str, Any]) -> str | None:
    cursor = failure.get("cursor")
    if isinstance(cursor, dict):
        method = _string_field(cursor, "httpRequest")
        if method is not None:
            return method
    parent = failure.get("parent")
    if isinstance(parent, dict):
        method = _string_field(parent, "method")
        if method is not None:
            return method
    return None


def _extract_request_url(failure: dict[str, Any]) -> str | None:
    parent = failure.get("parent")
    if isinstance(parent, dict):
        url = _extract_url(parent)
        if url is not None:
            return url
    source = failure.get("source")
    if isinstance(source, dict):
        request = source.get("request")
        if isinstance(request, dict):
            return _extract_url(request)
    return None


def _extract_url(request: dict[str, Any]) -> str | None:
    url = request.get("url")
    if isinstance(url, str):
        return url
    if isinstance(url, dict):
        raw = url.get("raw")
        if isinstance(raw, str):
            return raw
    return None


def _redact_token_payload(value: str | None) -> str | None:
    if value is None:
        return None
    redacted = value
    for pattern in _TOKEN_PATTERNS:
        redacted = pattern.sub("<REDACTED-TOKEN>", redacted)
    if "secret" in redacted.lower() and len(redacted) > 32:
        redacted = redact_secret(redacted) or "<REDACTED-TOKEN>"
    return redacted


def _string_field(record: Any, key: str) -> str | None:
    if not isinstance(record, dict):
        return None
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_postman_newman_json",
]


def _typecheck_iterator() -> None:  # pragma: no cover - mypy seam
    _: Iterator[dict[str, Any]] = iter([])
    del _
