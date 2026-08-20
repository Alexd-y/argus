"""Unit tests for :mod:`src.sandbox.parsers.grpcurl_probe_parser` (§4.14).

Pinned contracts:

* One INFO finding per fully-qualified gRPC service name.
* Diagnostic / error lines and single-word tokens are ignored.
* Empty input returns ``[]``; sidecar stamped with ``tool_id``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.grpcurl_probe_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_grpcurl_probe,
)

_SERVICE_LIST = (
    "grpc.reflection.v1alpha.ServerReflection\n" "helloworld.Greeter\n" "routeguide.RouteGuide\n"
)


def test_empty_returns_no_findings(tmp_path: Path) -> None:
    assert parse_grpcurl_probe(b"", b"", tmp_path, "grpcurl_probe") == []


def test_happy_path_one_finding_per_service(tmp_path: Path) -> None:
    findings = parse_grpcurl_probe(_SERVICE_LIST.encode("utf-8"), b"", tmp_path, "grpcurl_probe")
    assert len(findings) == 3
    assert all(f.category is FindingCategory.INFO for f in findings)
    assert all(200 in f.cwe for f in findings)
    assert all(f.confidence is ConfidenceLevel.CONFIRMED for f in findings)


def test_error_and_single_word_lines_ignored(tmp_path: Path) -> None:
    payload = (
        b"Failed to list services: server does not support the reflection API\n"
        b"Greeter\n"
        b"helloworld.Greeter\n"
    )
    findings = parse_grpcurl_probe(payload, b"", tmp_path, "grpcurl_probe")
    assert len(findings) == 1


def test_dedup_repeat_service(tmp_path: Path) -> None:
    payload = b"helloworld.Greeter\nhelloworld.Greeter\n"
    findings = parse_grpcurl_probe(payload, b"", tmp_path, "grpcurl_probe")
    assert len(findings) == 1


def test_sidecar_captures_services(tmp_path: Path) -> None:
    parse_grpcurl_probe(_SERVICE_LIST.encode("utf-8"), b"", tmp_path, "grpcurl_probe")
    lines = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    records = [json.loads(line) for line in lines if line.strip()]
    services = {rec["service"] for rec in records}
    assert "helloworld.Greeter" in services
    assert all(rec["tool_id"] == "grpcurl_probe" for rec in records)


def test_garbage_returns_no_findings(tmp_path: Path) -> None:
    assert parse_grpcurl_probe(b"=== not a service ===\n", b"", tmp_path, "grpcurl_probe") == []
