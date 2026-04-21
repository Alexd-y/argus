"""Parser for ``apktool d`` log output (ARG-032 batch 4b).

The catalog ``apktool`` tool persists an apktool decompilation log
to ``/out/apktool.log`` plus the unpacked source tree under
``/out/apktool/``.  The log captures:

* Resource decoding warnings / errors (``W: ...`` / ``I: ...`` lines).
* Package manifest version + minSdkVersion + targetSdkVersion.
* Detected debug / cleartext network configuration flags.

Translation rules
-----------------

* One MISCONFIG finding per ``android:debuggable="true"`` /
  ``android:allowBackup="true"`` / ``cleartextTrafficPermitted=true``
  marker (CWE-489 / CWE-200 / CWE-319).
* One INFO finding per ``targetSdkVersion`` < 24 (deprecated SDK).
* One INFO finding per WARN / ERROR line (CWE-1059) capped at
  :data:`_MAX_INFO_FINDINGS` so a verbose log does not explode the
  finding count.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "apktool_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("apktool.log", "apktool.txt")
_MAX_INFO_FINDINGS: Final[int] = 200


_DEBUG_RE: Final[re.Pattern[str]] = re.compile(
    r'android:debuggable\s*=\s*"true"', re.IGNORECASE
)
_BACKUP_RE: Final[re.Pattern[str]] = re.compile(
    r'android:allowBackup\s*=\s*"true"', re.IGNORECASE
)
_CLEARTEXT_RE: Final[re.Pattern[str]] = re.compile(
    r"cleartextTraffic(?:Permitted)?\s*=\s*\"?true\"?", re.IGNORECASE
)
_TARGET_SDK_RE: Final[re.Pattern[str]] = re.compile(
    r"targetSdkVersion\s*[=:]\s*\"?(?P<sdk>\d+)\"?", re.IGNORECASE
)
_LOG_LEVEL_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<level>I|W|E):\s+(?P<message>.+)$"
)


_DedupKey: TypeAlias = tuple[str, str]


def parse_apktool(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate apktool log output into FindingDTOs."""
    del stderr
    text = load_canonical_or_stdout_text(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_names=_CANONICAL_NAMES,
        tool_id=tool_id,
    )
    if not text:
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []
    info_count = 0

    for record in _iter_records(text):
        key: _DedupKey = (record["kind"], record["fingerprint"])
        if key in seen:
            continue
        seen.add(key)
        if record["kind"] == "log_message":
            info_count += 1
            if info_count > _MAX_INFO_FINDINGS:
                _logger.warning(
                    "apktool.cap_reached",
                    extra={
                        "event": "apktool_cap_reached",
                        "tool_id": tool_id,
                        "cap": _MAX_INFO_FINDINGS,
                    },
                )
                break
        finding = _build_finding(record["kind"])
        keyed.append((key, finding, _serialise_evidence(record, tool_id=tool_id)))

    keyed.sort(key=lambda item: item[0])
    if keyed:
        persist_jsonl_sidecar(
            artifacts_dir,
            sidecar_name=EVIDENCE_SIDECAR_NAME,
            evidence_records=[blob for _, _, blob in keyed],
            tool_id=tool_id,
        )
    return [finding for _, finding, _ in keyed]


def _iter_records(text: str) -> Iterator[dict[str, str]]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if _DEBUG_RE.search(line):
            yield {
                "kind": "manifest_debuggable",
                "fingerprint": "android:debuggable=true",
                "evidence": line,
            }
            continue
        if _BACKUP_RE.search(line):
            yield {
                "kind": "manifest_backup",
                "fingerprint": "android:allowBackup=true",
                "evidence": line,
            }
            continue
        if _CLEARTEXT_RE.search(line):
            yield {
                "kind": "manifest_cleartext",
                "fingerprint": "cleartextTrafficPermitted=true",
                "evidence": line,
            }
            continue
        sdk_match = _TARGET_SDK_RE.search(line)
        if sdk_match is not None:
            try:
                sdk = int(sdk_match.group("sdk"))
            except (TypeError, ValueError):
                sdk = 0
            if 0 < sdk < 24:
                yield {
                    "kind": "deprecated_sdk",
                    "fingerprint": f"targetSdkVersion={sdk}",
                    "evidence": line,
                    "sdk": str(sdk),
                }
                continue
        log_match = _LOG_LEVEL_RE.match(line)
        if log_match is not None:
            level = log_match.group("level")
            message = log_match.group("message").strip()
            if level in {"W", "E"} and message:
                yield {
                    "kind": "log_message",
                    "fingerprint": stable_hash_12(f"{level}|{message}"),
                    "evidence": message[:200],
                    "level": level,
                }


def _build_finding(kind: str) -> FindingDTO:
    if kind == "manifest_debuggable":
        return make_finding_dto(
            category=FindingCategory.MISCONFIG,
            cwe=[489, 215],
            cvss_v3_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            cvss_v3_score=7.8,
            confidence=ConfidenceLevel.CONFIRMED,
            owasp_wstg=["WSTG-CONF-02"],
        )
    if kind == "manifest_backup":
        return make_finding_dto(
            category=FindingCategory.MISCONFIG,
            cwe=[200],
            cvss_v3_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cvss_v3_score=5.5,
            confidence=ConfidenceLevel.CONFIRMED,
            owasp_wstg=["WSTG-CONF-04"],
        )
    if kind == "manifest_cleartext":
        return make_finding_dto(
            category=FindingCategory.CRYPTO,
            cwe=[319],
            cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cvss_v3_score=7.5,
            confidence=ConfidenceLevel.CONFIRMED,
            owasp_wstg=["WSTG-CRYP-03"],
        )
    if kind == "deprecated_sdk":
        return make_finding_dto(
            category=FindingCategory.INFO,
            cwe=[1104],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=0.0,
            confidence=ConfidenceLevel.LIKELY,
            owasp_wstg=["WSTG-INFO-02"],
        )
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[1059],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.SUSPECTED,
        owasp_wstg=["WSTG-INFO-02"],
    )


def _serialise_evidence(record: dict[str, str], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "synthetic_id": stable_hash_12(
            f"{record.get('kind', '')}::{record.get('fingerprint', '')}"
        ),
        **record,
    }
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_apktool",
]
