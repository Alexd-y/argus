"""TEXT_LINES discovery parsers — Cycle 6 T05 (heartbeat → mapped batch).

Twelve catalog tools emit unstructured text (URLs, scanner banners, or
JSON on stdout) but previously had no :data:`_TOOL_TO_PARSER` entry, so
``dispatch_parse`` fell through to the ARG-020 heartbeat path.

This module centralises the shared extraction logic:

* **URL / endpoint discovery** — gobuster, crawlers, link extractors,
  passive archives, CMS text reports.
* **SecretFinder** — one :class:`FindingCategory.SECRET_LEAK` per
  non-empty line with redacted evidence (no raw tokens hit disk).
* **MageScan** — tolerates JSON on stdout (catalog ``evidence_artifacts``
  is empty) and emits inventory / patch-gap findings defensively.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import (
    make_finding_dto,
    redact_secret,
    stable_hash_12,
)
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar
from src.sandbox.parsers._subdomain_base import build_subdomain_finding, is_valid_hostname
from src.sandbox.parsers._text_base import (
    load_canonical_or_stdout_text,
    redact_password_in_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)

EVIDENCE_SIDECAR: Final[str] = "t05_discovery_findings.jsonl"
_MAX_FINDINGS: Final[int] = 2_000
_URL_RE: Final[re.Pattern[str]] = re.compile(
    r"https?://[^\s<>\]\"'`,;)]+",
    re.IGNORECASE,
)
_GOBUSTER_LINE_RE: Final[re.Pattern[str]] = re.compile(
    r"^(\S+)\s+\(Status:\s*(\d+)\)\s*$",
)
_CMS_INTERESTING_RE: Final[re.Pattern[str]] = re.compile(
    r"(?i)\bcve-\d{4}-\d+\b|vulnerable|exploit|critical|high\s+risk",
)
_MAGESCAN_LIST_KEYS: Final[frozenset[str]] = frozenset(
    {"missingPatches", "sensitiveFiles", "unreachablePaths", "paths"}
)

_DedupKey: TypeAlias = tuple[str, str]

_DISCOVERY_CANONICAL: Final[dict[str, tuple[str, ...]]] = {
    "gobuster_dir": ("gobuster.txt",),
    "gobuster_auth": ("gobuster_auth.txt",),
    "paramspider": ("paramspider.txt",),
    "hakrawler": ("hakrawler.txt",),
    "waybackurls": ("wayback.txt",),
    "linkfinder": ("linkfinder.txt",),
    "subjs": ("subjs.txt",),
    "secretfinder": ("secretfinder.txt",),
    "kxss": ("kxss.txt",),
    "joomscan": ("joomscan.txt",),
    "cmsmap": ("cmsmap.txt",),
    "magescan": (),
}


def parse_discovery_text_lines(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Dispatch entry point for the T05 TEXT_LINES discovery cluster."""
    del stderr
    canonical = _DISCOVERY_CANONICAL.get(tool_id)
    if canonical is None:
        _logger.warning(
            "discovery_text_parser.unregistered_tool",
            extra={
                "event": "discovery_text_parser_unregistered_tool",
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

    if tool_id == "magescan":
        return _parse_magescan(text, artifacts_dir, tool_id)
    if tool_id == "secretfinder":
        return _parse_secretfinder(text, artifacts_dir, tool_id)
    if tool_id in {"joomscan", "cmsmap"}:
        return _parse_cms_text_report(text, artifacts_dir, tool_id)

    return _parse_url_discovery(text, artifacts_dir, tool_id)


def _serialise_evidence(blob: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(blob)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _parse_url_discovery(
    text: str,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        m_gob = _GOBUSTER_LINE_RE.match(line)
        if m_gob:
            path, status = m_gob.group(1), m_gob.group(2)
            token = redact_password_in_text(path) or path
            key: _DedupKey = ("gobuster_path", f"{token}:{status}")
            if key not in seen:
                seen.add(key)
                finding = make_finding_dto(
                    category=FindingCategory.INFO,
                    cwe=[200, 668],
                    cvss_v3_score=0.0,
                    confidence=ConfidenceLevel.CONFIRMED,
                    owasp_wstg=["WSTG-CONFIG-04", "WSTG-CONFIG-06"],
                )
                evidence = {
                    "tool_id": tool_id,
                    "path": token,
                    "status_code": status,
                    "fingerprint_hash": stable_hash_12(f"{token}:{status}"),
                }
                keyed.append((key, finding, _serialise_evidence(evidence)))
        else:
            for url_match in _URL_RE.findall(line):
                url = redact_password_in_text(url_match) or url_match
                key = ("url", url)
                if key in seen:
                    continue
                seen.add(key)
                finding = build_subdomain_finding()
                evidence = {
                    "tool_id": tool_id,
                    "url": url,
                    "fingerprint_hash": stable_hash_12(url),
                }
                keyed.append((key, finding, _serialise_evidence(evidence)))

            host_only = line.split()[0] if line.split() else ""
            if (
                "://" not in host_only
                and is_valid_hostname(host_only)
                and tool_id in {"kxss", "subjs", "hakrawler"}
            ):
                host = host_only.lower().rstrip(".")
                key2: _DedupKey = ("host", host)
                if key2 not in seen:
                    seen.add(key2)
                    finding = build_subdomain_finding()
                    evidence = {
                        "tool_id": tool_id,
                        "host": host,
                        "fingerprint_hash": stable_hash_12(host),
                    }
                    keyed.append((key2, finding, _serialise_evidence(evidence)))

        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "discovery_text_parser.cap_reached",
                extra={
                    "event": "discovery_text_parser_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
            break

    keyed.sort(key=lambda item: item[0])
    if keyed:
        persist_jsonl_sidecar(
            artifacts_dir,
            sidecar_name=EVIDENCE_SIDECAR,
            evidence_records=[blob for _, _, blob in keyed],
            tool_id=tool_id,
        )
    return [f for _, f, _ in keyed]


def _parse_secretfinder(
    text: str,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    seen: set[str] = set()
    keyed: list[tuple[str, FindingDTO, str]] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        redacted = redact_secret(line) or "***REDACTED***"
        fp = stable_hash_12(line)
        if fp in seen:
            continue
        seen.add(fp)
        finding = make_finding_dto(
            category=FindingCategory.SECRET_LEAK,
            cwe=[798],
            cvss_v3_score=5.0,
            confidence=ConfidenceLevel.SUSPECTED,
            owasp_wstg=["WSTG-INFO-05", "WSTG-CRYP-03"],
        )
        evidence = {
            "tool_id": tool_id,
            "preview": redacted,
            "fingerprint_hash": fp,
        }
        keyed.append((fp, finding, _serialise_evidence(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "discovery_text_parser.secretfinder_cap",
                extra={
                    "event": "discovery_text_parser_secretfinder_cap",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
            break

    keyed.sort(key=lambda item: item[0])
    if keyed:
        persist_jsonl_sidecar(
            artifacts_dir,
            sidecar_name=EVIDENCE_SIDECAR,
            evidence_records=[blob for _, _, blob in keyed],
            tool_id=tool_id,
        )
    return [f for _, f, _ in keyed]


def _parse_cms_text_report(
    text: str,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    seen: set[str] = set()
    keyed: list[tuple[str, FindingDTO, str]] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or not _CMS_INTERESTING_RE.search(line):
            continue
        safe_line = redact_password_in_text(line[:800]) or line[:800]
        fp = stable_hash_12(safe_line)
        if fp in seen:
            continue
        seen.add(fp)
        finding = make_finding_dto(
            category=FindingCategory.MISCONFIG,
            cwe=[1395, 200],
            cvss_v3_score=4.3,
            confidence=ConfidenceLevel.LIKELY,
            owasp_wstg=["WSTG-INFO-08", "WSTG-CONF-04"],
        )
        evidence = {
            "tool_id": tool_id,
            "line": safe_line,
            "fingerprint_hash": fp,
        }
        keyed.append((fp, finding, _serialise_evidence(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            break

    keyed.sort(key=lambda item: item[0])
    if keyed:
        persist_jsonl_sidecar(
            artifacts_dir,
            sidecar_name=EVIDENCE_SIDECAR,
            evidence_records=[blob for _, _, blob in keyed],
            tool_id=tool_id,
        )
    return [f for _, f, _ in keyed]


def _parse_magescan(
    text: str,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    stripped = text.strip()
    if stripped.startswith("{"):
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            payload = None
        if isinstance(payload, dict):
            return _magescan_from_dict(payload, artifacts_dir, tool_id)

    # Fallback — treat as text URLs / keywords
    return _parse_cms_text_report(text, artifacts_dir, tool_id)


def _magescan_from_dict(
    data: dict[str, Any],
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    keyed: list[tuple[str, FindingDTO, str]] = []
    seen: set[str] = set()

    base_url = str(data.get("baseUrl") or data.get("url") or "")

    for key in _MAGESCAN_LIST_KEYS:
        block = data.get(key)
        if not isinstance(block, list):
            continue
        for item in block:
            snippet = str(item)[:500]
            fp = stable_hash_12(f"{key}:{snippet}")
            if fp in seen:
                continue
            seen.add(fp)
            finding = make_finding_dto(
                category=FindingCategory.SUPPLY_CHAIN,
                cwe=[1395],
                cvss_v3_score=5.5,
                confidence=ConfidenceLevel.LIKELY,
                owasp_wstg=["WSTG-INFO-08", "WSTG-CONF-04"],
            )
            evidence = {
                "tool_id": tool_id,
                "magescan_key": key,
                "detail": redact_password_in_text(snippet) or snippet,
                "base_url": redact_password_in_text(base_url) if base_url else "",
                "fingerprint_hash": fp,
            }
            keyed.append((fp, finding, _serialise_evidence(evidence)))
            if len(keyed) >= _MAX_FINDINGS:
                break
        if len(keyed) >= _MAX_FINDINGS:
            break

    keyed.sort(key=lambda item: item[0])
    if keyed:
        persist_jsonl_sidecar(
            artifacts_dir,
            sidecar_name=EVIDENCE_SIDECAR,
            evidence_records=[blob for _, _, blob in keyed],
            tool_id=tool_id,
        )
    return [f for _, f, _ in keyed]


__all__ = ["parse_discovery_text_lines", "EVIDENCE_SIDECAR"]
