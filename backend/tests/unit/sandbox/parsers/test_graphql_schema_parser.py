"""Unit tests for :mod:`src.sandbox.parsers.graphql_schema_parser` (§4.14).

Pinned contracts (clairvoyance introspection recovery):

* A standard introspection document → one INFO finding (CWE-200).
* Both ``{"data": {"__schema": ...}}`` and bare ``{"__schema": ...}``
  envelopes are recognised.
* Empty ``{}`` / garbage / introspection-only schema → ``[]``.
* Sidecar records recovered-type / field counts and ``tool_id``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.graphql_schema_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_clairvoyance,
)


def _introspection(wrapped: bool = True) -> dict[str, Any]:
    schema = {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "subscriptionType": None,
        "types": [
            {
                "name": "Query",
                "kind": "OBJECT",
                "fields": [{"name": "user"}, {"name": "users"}],
            },
            {
                "name": "Mutation",
                "kind": "OBJECT",
                "fields": [{"name": "login"}, {"name": "deleteUser"}],
            },
            {
                "name": "User",
                "kind": "OBJECT",
                "fields": [{"name": "id"}, {"name": "email"}],
            },
            {"name": "__Type", "kind": "OBJECT", "fields": []},
        ],
    }
    if wrapped:
        return {"data": {"__schema": schema}}
    return {"__schema": schema}


def test_empty_object_returns_no_findings(tmp_path: Path) -> None:
    assert parse_clairvoyance(b"{}", b"", tmp_path, "clairvoyance") == []


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_clairvoyance(b"", b"", tmp_path, "clairvoyance") == []


def test_happy_path_single_info_finding(tmp_path: Path) -> None:
    payload = json.dumps(_introspection()).encode("utf-8")
    findings = parse_clairvoyance(payload, b"", tmp_path, "clairvoyance")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.INFO
    assert 200 in finding.cwe
    assert finding.confidence is ConfidenceLevel.CONFIRMED


def test_bare_schema_envelope_supported(tmp_path: Path) -> None:
    payload = json.dumps(_introspection(wrapped=False)).encode("utf-8")
    findings = parse_clairvoyance(payload, b"", tmp_path, "clairvoyance")
    assert len(findings) == 1


def test_sidecar_counts(tmp_path: Path) -> None:
    payload = json.dumps(_introspection()).encode("utf-8")
    parse_clairvoyance(payload, b"", tmp_path, "clairvoyance")
    record = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()[0])
    assert record["tool_id"] == "clairvoyance"
    assert record["recovered_type_count"] == 3
    assert record["query_field_count"] == 2
    assert record["mutation_field_count"] == 2
    assert record["mutations_exposed"] is True


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "clairvoyance.json"
    canonical.write_bytes(json.dumps(_introspection()).encode("utf-8"))
    findings = parse_clairvoyance(b"garbage", b"", tmp_path, "clairvoyance")
    assert len(findings) == 1


def test_introspection_only_schema_returns_no_findings(tmp_path: Path) -> None:
    schema = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "types": [{"name": "__Type", "kind": "OBJECT", "fields": []}],
            }
        }
    }
    payload = json.dumps(schema).encode("utf-8")
    assert parse_clairvoyance(payload, b"", tmp_path, "clairvoyance") == []


def test_garbage_returns_no_findings(tmp_path: Path) -> None:
    assert parse_clairvoyance(b"not json <<<>>>", b"", tmp_path, "clairvoyance") == []
