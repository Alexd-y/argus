"""JSON_OBJECT XSS auxiliary parsers — Cycle 6 T05 (xsstrike / xsser / playwright)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Final

from src.pipeline.contracts.finding_dto import ConfidenceLevel, FindingCategory, FindingDTO
from src.sandbox.parsers._base import make_finding_dto, stable_hash_12
from src.sandbox.parsers._jsonl_base import load_canonical_or_stdout_json, persist_jsonl_sidecar
from src.sandbox.parsers._text_base import redact_password_in_text, scrub_evidence_strings

_logger = logging.getLogger(__name__)

EVIDENCE_SIDECAR: Final[str] = "t05_xss_aux_findings.jsonl"
_MAX_FINDINGS: Final[int] = 2_000

_CANONICAL_BY_TOOL: Final[dict[str, str]] = {
    "xsstrike": "xsstrike.json",
    "xsser": "xsser.json",
    "playwright_xss_verify": "playwright.json",
}

_OWASP: Final[tuple[str, ...]] = ("WSTG-INPV-01", "WSTG-INPV-02")


def parse_xss_auxiliary_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Normalise XSStrike / XSSer / Playwright verifier JSON exports."""
    del stderr
    canonical = _CANONICAL_BY_TOOL.get(tool_id)
    if canonical is None:
        _logger.warning(
            "xss_auxiliary_json.unregistered_tool",
            extra={"event": "xss_auxiliary_json_unregistered_tool", "tool_id": tool_id},
        )
        return []

    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=canonical,
        tool_id=tool_id,
    )
    if payload is None:
        return []

    if tool_id == "playwright_xss_verify":
        return _parse_playwright_verdict(payload, artifacts_dir, tool_id)
    return _parse_xss_scan_json(payload, artifacts_dir, tool_id)


def _parse_playwright_verdict(
    payload: Any,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    if not isinstance(payload, dict):
        return []
    fired = payload.get("canaryExecuted")
    if fired is None:
        fired = payload.get("xssDetected")
    if fired is None:
        fired = payload.get("executed")
    if fired not in (True, "true", 1, "1"):
        return []

    url = str(payload.get("url") or payload.get("target") or "")
    finding = make_finding_dto(
        category=FindingCategory.XSS,
        cwe=[79],
        cvss_v3_score=7.5,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=list(_OWASP),
    )
    evidence = scrub_evidence_strings(
        {
            "tool_id": tool_id,
            "url": redact_password_in_text(url) if url else "",
            "fingerprint_hash": stable_hash_12(json.dumps(payload, sort_keys=True, default=str)),
        }
    )
    persist_jsonl_sidecar(
        artifacts_dir,
        sidecar_name=EVIDENCE_SIDECAR,
        evidence_records=[json.dumps(evidence, sort_keys=True, ensure_ascii=False)],
        tool_id=tool_id,
    )
    return [finding]


def _parse_xss_scan_json(
    payload: Any,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    records = _flatten_url_records(payload)
    if not records:
        return []

    seen: set[tuple[str, str]] = set()
    findings: list[FindingDTO] = []
    blobs: list[str] = []

    for rec in records:
        url = rec.get("url", "")
        param = rec.get("param", "")
        key = (url, param)
        if key in seen:
            continue
        seen.add(key)
        finding = make_finding_dto(
            category=FindingCategory.XSS,
            cwe=[79],
            cvss_v3_score=6.1,
            confidence=ConfidenceLevel.LIKELY,
            owasp_wstg=list(_OWASP),
        )
        findings.append(finding)
        evidence = scrub_evidence_strings(
            {
                "tool_id": tool_id,
                "url": redact_password_in_text(url) if url else "",
                "param": param,
                "fingerprint_hash": stable_hash_12(f"{url}|{param}"),
            }
        )
        blobs.append(json.dumps(evidence, sort_keys=True, ensure_ascii=False))
        if len(findings) >= _MAX_FINDINGS:
            _logger.warning(
                "xss_auxiliary_json.cap_reached",
                extra={"event": "xss_auxiliary_json_cap_reached", "tool_id": tool_id},
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


def _flatten_url_records(payload: Any) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    _walk(payload, out)
    return out


def _walk(node: Any, acc: list[dict[str, str]]) -> None:
    if isinstance(node, dict):
        url = node.get("url") or node.get("target") or node.get("uri")
        param = node.get("param") or node.get("parameter") or node.get("parameter_name")
        if isinstance(url, str) and url.startswith("http"):
            acc.append(
                {
                    "url": url,
                    "param": str(param) if param is not None else "",
                }
            )
        for v in node.values():
            _walk(v, acc)
    elif isinstance(node, list):
        for v in node:
            _walk(v, acc)


__all__ = ["parse_xss_auxiliary_json", "EVIDENCE_SIDECAR"]
