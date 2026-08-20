"""Parser for ``ike-scan -M -A`` output (Backlog/dev1_md §4.17).

``ike-scan`` probes IKE/IPsec (UDP/500) endpoints.  A responding peer
prints a handshake line, e.g.::

    192.0.2.1  Main Mode Handshake returned HDR=(...) SA=(Enc=3DES Hash=SHA1 Group=2:modp1024 Auth=PSK LifeType=Seconds LifeDuration=28800)
    192.0.2.2  Aggressive Mode Handshake returned HDR=(...) SA=(Enc=AES KeyLength=256 Hash=SHA2-256 Group=14:modp2048 Auth=PSK ...)

Translation rules (conservative)
---------------------------------
* Every handshake response yields one :class:`FindingCategory.INFO`
  finding — an IKE/IPsec endpoint was discovered (CWE-200).  The
  negotiated SA transform is captured (scrubbed) in the evidence
  sidecar.
* An *Aggressive Mode* response additionally emits a low-severity
  :class:`FindingCategory.MISCONFIG` finding: IKEv1 aggressive mode
  leaks the PSK hash to an unauthenticated peer, enabling offline
  cracking (CWE-522 / CWE-326).

Any hash-looking material in the SA / HDR block is routed through the
shared hash-redaction scrubber before persistence, so a captured PSK
hash never lands on disk.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Final

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    SSVCDecision,
)
from src.sandbox.parsers._base import make_finding_dto
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar
from src.sandbox.parsers._text_base import (
    load_canonical_or_stdout_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)

EVIDENCE_SIDECAR_NAME: Final[str] = "ike_scan_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("ike_scan.txt",)
_MAX_FINDINGS: Final[int] = 1_000
_MAX_VALUE_LEN: Final[int] = 400

# ``192.0.2.1  Aggressive Mode Handshake returned ...``
_HANDSHAKE_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<host>\S+)\s+(?P<mode>Main Mode|Aggressive Mode)\s+Handshake returned\b(?P<rest>.*)$",
    re.IGNORECASE,
)
_SA_RE: Final[re.Pattern[str]] = re.compile(r"SA=\((?P<sa>[^)]*)\)")

DedupKey = tuple[str, str]


def parse_ike_scan(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate ike-scan handshake output into findings."""
    del stderr
    text = load_canonical_or_stdout_text(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_names=_CANONICAL_NAMES,
        tool_id=tool_id,
    )
    if not text.strip():
        return []

    seen: set[DedupKey] = set()
    keyed: list[tuple[DedupKey, FindingDTO, str]] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _HANDSHAKE_RE.match(line)
        if match is None:
            continue
        host = match.group("host").strip()
        mode = "Aggressive Mode" if "aggressive" in match.group("mode").lower() else "Main Mode"
        sa_match = _SA_RE.search(match.group("rest") or "")
        sa_transform = sa_match.group("sa").strip() if sa_match else None

        info_key: DedupKey = (host, "endpoint")
        if info_key not in seen:
            seen.add(info_key)
            keyed.append(
                (
                    info_key,
                    make_finding_dto(
                        category=FindingCategory.INFO,
                        cwe=[200],
                        cvss_v3_score=0.0,
                        confidence=ConfidenceLevel.CONFIRMED,
                        owasp_wstg=["WSTG-INFO-02", "WSTG-CRYP-01"],
                    ),
                    _serialise(
                        {
                            "tool_id": tool_id,
                            "host": host,
                            "mode": mode,
                            "sa_transform": _truncate(sa_transform) if sa_transform else None,
                        }
                    ),
                )
            )

        if mode == "Aggressive Mode":
            aggr_key: DedupKey = (host, "aggressive_mode")
            if aggr_key not in seen:
                seen.add(aggr_key)
                keyed.append(
                    (
                        aggr_key,
                        make_finding_dto(
                            category=FindingCategory.MISCONFIG,
                            cwe=[326, 522],
                            cvss_v3_score=5.9,
                            confidence=ConfidenceLevel.LIKELY,
                            ssvc_decision=SSVCDecision.ATTEND,
                            owasp_wstg=["WSTG-CRYP-01", "WSTG-INFO-02"],
                        ),
                        _serialise(
                            {
                                "tool_id": tool_id,
                                "host": host,
                                "issue": "ikev1_aggressive_mode_psk_exposure",
                                "sa_transform": _truncate(sa_transform) if sa_transform else None,
                            }
                        ),
                    )
                )

        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "ike_scan_parser.cap_reached",
                extra={
                    "event": "ike_scan_parser_cap_reached",
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


def _serialise(evidence: dict[str, Any]) -> str:
    cleaned = {key: value for key, value in evidence.items() if value not in (None, "", [], {})}
    scrubbed = scrub_evidence_strings(cleaned)
    return json.dumps(scrubbed, sort_keys=True, ensure_ascii=False)


def _truncate(value: str) -> str:
    if len(value) <= _MAX_VALUE_LEN:
        return value
    return value[:_MAX_VALUE_LEN] + "[truncated]"


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_ike_scan",
]
