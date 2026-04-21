"""Parser for Puppeteer screenshot output (ARG-032 batch 4a).

The catalog ``puppeteer_screens`` tool persists its artifacts at
``/out/puppeteer/`` — typically:

* ``index.har`` — HTTP archive (when ``puppeteer-har`` is plumbed in);
* ``screenshot.png`` / ``viewport.png`` / ``fullpage.png`` — raster
  screenshots;
* ``dom.html`` — rendered HTML snapshot;
* ``index.json`` — manifest mapping URLs to screenshot file names.

Translation rules
-----------------

* One INFO finding per screenshot manifest entry (CWE-200) — the
  visual triage record points operators at the rendered page; the
  evidence captures the URL host + path-prefix + screenshot file
  name (raster bytes are NOT inlined).
* One INFO finding per unique HAR ``(method, status_class, hostname,
  path-prefix)`` exchange when a HAR file is present.

The parser is fail-soft: a missing manifest / HAR / artifact dir
returns ``[]``; any malformed record is skipped with a structured
warning.

CRITICAL security gate
----------------------

HAR entries are routed through :func:`iter_har_entries` so cookies /
authorization headers are masked at load time.  Manifest URLs go
through :func:`redact_password_in_text` (URL-creds masking) and the
final evidence dict is run through :func:`scrub_evidence_strings`
before sidecar persistence.
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
    safe_load_json,
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
from src.sandbox.parsers._text_base import (
    redact_password_in_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "puppeteer_screens_findings.jsonl"
_CANONICAL_DIR: Final[str] = "puppeteer"
_HAR_CANDIDATES: Final[tuple[str, ...]] = ("index.har", "puppeteer.har")
_MANIFEST_CANDIDATES: Final[tuple[str, ...]] = (
    "index.json",
    "manifest.json",
    "screens.json",
)
_MAX_SCREENSHOT_FINDINGS: Final[int] = 250
_MAX_REQUEST_FINDINGS: Final[int] = 250


_REQUEST_DEDUP_KEY: TypeAlias = tuple[str, str, str, str]


def parse_puppeteer_screens(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate Puppeteer screenshot output into FindingDTOs."""
    del stderr
    artifact_dir = browse_artifact_dir(artifacts_dir, _CANONICAL_DIR)
    manifest = _load_manifest(artifact_dir, stdout=stdout, tool_id=tool_id)
    har = _load_har(artifact_dir, tool_id=tool_id)

    findings: list[FindingDTO] = []
    evidence_blobs: list[str] = []

    findings.extend(
        _emit_screenshot_findings(
            manifest, evidence_blobs=evidence_blobs, tool_id=tool_id
        )
    )
    findings.extend(
        _emit_request_findings(har, evidence_blobs=evidence_blobs, tool_id=tool_id)
    )

    if evidence_blobs:
        persist_jsonl_sidecar(
            artifacts_dir,
            sidecar_name=EVIDENCE_SIDECAR_NAME,
            evidence_records=evidence_blobs,
            tool_id=tool_id,
        )
    return findings


def _load_manifest(artifact_dir: Path | None, *, stdout: bytes, tool_id: str) -> Any:
    candidates: list[Path] = []
    if artifact_dir is not None:
        candidates = [
            path
            for name in _MANIFEST_CANDIDATES
            if (path := safe_join_artifact(artifact_dir, name)) is not None
        ]
    raw = load_first_existing(candidates, tool_id=tool_id)
    if raw.strip():
        decoded = safe_load_json(raw, tool_id=tool_id)
        if decoded is not None:
            return decoded
    if stdout and stdout.strip():
        return safe_load_json(stdout, tool_id=tool_id)
    return None


def _load_har(artifact_dir: Path | None, *, tool_id: str) -> Any:
    if artifact_dir is None:
        return None
    candidates = [
        path
        for name in _HAR_CANDIDATES
        if (path := safe_join_artifact(artifact_dir, name)) is not None
    ]
    return load_har_payload(candidates, tool_id=tool_id)


def _path_prefix(path: str, depth: int = 2) -> str:
    raw_path = path or "/"
    segments = [seg for seg in raw_path.split("/") if seg]
    return "/" + "/".join(segments[:depth]) if segments else "/"


def _status_class(status: int) -> str:
    if status <= 0:
        return "0xx"
    return f"{(status // 100) * 100}xx"


def _safe_filename(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.replace("\\", "/").rsplit("/", 1)[-1]


def _emit_screenshot_findings(
    manifest: Any,
    *,
    evidence_blobs: list[str],
    tool_id: str,
) -> list[FindingDTO]:
    if not isinstance(manifest, (list, dict)):
        return []
    items = _normalise_manifest(manifest)
    seen: set[str] = set()
    keyed: list[tuple[str, FindingDTO, str]] = []
    for record in items:
        raw_url = str(record.get("url") or "")
        host, raw_path = safe_url_parts(raw_url)
        url = redact_password_in_text(raw_url)
        screenshot = _safe_filename(record.get("screenshot") or record.get("file"))
        if not url and not screenshot:
            continue
        path = _path_prefix(raw_path)
        key = stable_hash_12(f"{host}|{path}|{screenshot}")
        if key in seen:
            continue
        seen.add(key)
        finding = make_finding_dto(
            category=FindingCategory.INFO,
            cwe=[200],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=0.0,
            confidence=ConfidenceLevel.CONFIRMED,
            owasp_wstg=["WSTG-INFO-02", "WSTG-INFO-08"],
        )
        evidence: dict[str, object] = {
            "tool_id": tool_id,
            "host": host,
            "path_prefix": path,
            "screenshot_file": screenshot,
            "url_hash": stable_hash_12(url),
            "kind": "screenshot",
        }
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_SCREENSHOT_FINDINGS:
            _logger.warning(
                "puppeteer_screens.screenshot_cap_reached",
                extra={
                    "event": "puppeteer_screens_screenshot_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_SCREENSHOT_FINDINGS,
                },
            )
            break
    keyed.sort(key=lambda item: item[0])
    findings: list[FindingDTO] = []
    for _, finding, blob in keyed:
        findings.append(finding)
        evidence_blobs.append(blob)
    return findings


def _normalise_manifest(manifest: Any) -> list[dict[str, object]]:
    if isinstance(manifest, list):
        return [item for item in manifest if isinstance(item, dict)]
    if isinstance(manifest, dict):
        screens = manifest.get("screenshots") or manifest.get("screens")
        if isinstance(screens, list):
            return [item for item in screens if isinstance(item, dict)]
        if "url" in manifest or "screenshot" in manifest:
            return [manifest]
    return []


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
        finding = make_finding_dto(
            category=FindingCategory.INFO,
            cwe=[200, 668],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=0.0,
            confidence=ConfidenceLevel.CONFIRMED,
            owasp_wstg=["WSTG-INFO-02", "WSTG-CLNT-09"],
        )
        evidence: dict[str, object] = {
            "tool_id": tool_id,
            "method": method,
            "host": host,
            "path_prefix": path,
            "status": status,
            "url_hash": stable_hash_12(url),
            "kind": "har_request",
        }
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_REQUEST_FINDINGS:
            _logger.warning(
                "puppeteer_screens.request_cap_reached",
                extra={
                    "event": "puppeteer_screens_request_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_REQUEST_FINDINGS,
                },
            )
            break
    keyed.sort(key=lambda item: item[0])
    findings: list[FindingDTO] = []
    for _, finding, blob in keyed:
        findings.append(finding)
        evidence_blobs.append(blob)
    return findings


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_puppeteer_screens",
]
