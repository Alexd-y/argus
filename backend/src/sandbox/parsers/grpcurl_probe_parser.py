"""Parser for ``grpcurl ... list`` reflection output (Backlog/dev1_md §4.14).

The ARGUS catalog runs ``grpcurl -plaintext {host}:{port} list``, which
prints one fully-qualified gRPC service name per line when server
reflection is enabled::

    grpc.reflection.v1alpha.ServerReflection
    helloworld.Greeter
    routeguide.RouteGuide

Translation rules (conservative)
---------------------------------
Server reflection being enabled lets an unauthenticated client
enumerate the service surface — an information-exposure data point
(CWE-200 / CWE-16, WSTG-INFO-08).  The parser emits one
:class:`FindingCategory.INFO` finding per discovered service.  Only
tokens that match a strict gRPC fully-qualified-name shape (a dotted
identifier, each segment ``[A-Za-z_][A-Za-z0-9_]*`` and ≤63 chars) are
accepted, so error banners / diagnostics never become findings.
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
)
from src.sandbox.parsers._base import make_finding_dto
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar
from src.sandbox.parsers._text_base import load_canonical_or_stdout_text

_logger = logging.getLogger(__name__)

EVIDENCE_SIDECAR_NAME: Final[str] = "grpcurl_probe_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("grpc.txt",)
_MAX_FINDINGS: Final[int] = 2_000
_MAX_SERVICE_LEN: Final[int] = 200

# Fully-qualified gRPC/protobuf service name: a dotted identifier with at
# least one package segment.  Each segment is a protobuf identifier
# (letter/underscore start) capped at 63 chars.  Requiring ≥1 dot filters
# stray single-word diagnostics and adversarial garbage.
_SERVICE_RE: Final[re.Pattern[str]] = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]{0,62}(?:\.[A-Za-z_][A-Za-z0-9_]{0,62})+$"
)

DedupKey = str


def parse_grpcurl_probe(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate a grpcurl reflection service list into findings."""
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
        service = raw_line.strip()
        if not service or len(service) > _MAX_SERVICE_LEN:
            continue
        if not _SERVICE_RE.match(service):
            continue
        if service in seen:
            continue
        seen.add(service)

        finding = make_finding_dto(
            category=FindingCategory.INFO,
            cwe=[200, 16],
            cvss_v3_score=0.0,
            confidence=ConfidenceLevel.CONFIRMED,
            owasp_wstg=["WSTG-INFO-08"],
        )
        evidence = {
            "tool_id": tool_id,
            "service": service,
            "reflection_enabled": True,
        }
        keyed.append((service, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "grpcurl_probe_parser.cap_reached",
                extra={
                    "event": "grpcurl_probe_parser_cap_reached",
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
    return json.dumps(evidence, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_grpcurl_probe",
]
