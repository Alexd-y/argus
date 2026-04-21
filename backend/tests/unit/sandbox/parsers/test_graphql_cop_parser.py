"""Unit tests for :mod:`src.sandbox.parsers.graphql_cop_parser` (Backlog §4.14 — ARG-029).

Pinned contracts:

* Top-level JSON array; canonical artefact ``graphqlcop.json`` overrides
  stdout.
* Only entries with ``result == true`` are emitted.
* Title keyword routing:

  - introspection / debug / graphiql → INFO + CWE-200
  - alias / batch / circular         → DOS + CWE-770/400
  - csrf / get-based / post-based    → CSRF + CWE-352
  - injection / sqli                 → OTHER + CWE-74
  - everything else                  → MISCONFIG + CWE-16/200

* Auth headers in ``curl_verify`` are redacted via
  :data:`_CURL_AUTH_HEADER_RE`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers import graphql_cop_parser as graphql_module
from src.sandbox.parsers.graphql_cop_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_graphql_cop_json,
)


def _entry(
    *,
    title: str = "Introspection Query Enabled",
    severity: str = "HIGH",
    impact: str = "Information Leakage",
    description: str = "Introspection enabled",
    result: bool = True,
    curl_verify: str | None = None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "title": title,
        "description": description,
        "impact": impact,
        "severity": severity,
        "result": result,
        "color": "red",
    }
    if curl_verify is not None:
        record["curl_verify"] = curl_verify
    return record


def _payload(*entries: dict[str, Any]) -> bytes:
    return json.dumps(list(entries)).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_graphql_cop_json(b"", b"", tmp_path, "graphql_cop") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = tmp_path / "graphqlcop.json"
    canonical.write_bytes(_payload(_entry(title="Canonical Check")))
    decoy = _payload(_entry(title="Decoy Check"))
    findings = parse_graphql_cop_json(decoy, b"", tmp_path, "graphql_cop")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "Canonical Check" in sidecar
    assert "Decoy Check" not in sidecar


def test_negative_results_dropped(tmp_path: Path) -> None:
    payload = _payload(
        _entry(title="Introspection Query Enabled", result=True),
        _entry(title="GET-based Mutation", result=False),
    )
    findings = parse_graphql_cop_json(payload, b"", tmp_path, "graphql_cop")
    assert len(findings) == 1


def test_introspection_routes_to_info_with_cwe_200(tmp_path: Path) -> None:
    findings = parse_graphql_cop_json(
        _payload(_entry(title="Introspection Query Enabled")),
        b"",
        tmp_path,
        "graphql_cop",
    )
    assert findings[0].category is FindingCategory.INFO
    assert 200 in findings[0].cwe


def test_alias_overload_routes_to_dos_with_cwe_770(tmp_path: Path) -> None:
    findings = parse_graphql_cop_json(
        _payload(_entry(title="Alias Overload DoS")),
        b"",
        tmp_path,
        "graphql_cop",
    )
    assert findings[0].category is FindingCategory.DOS
    assert 770 in findings[0].cwe
    assert 400 in findings[0].cwe


def test_csrf_routes_to_csrf_with_cwe_352(tmp_path: Path) -> None:
    findings = parse_graphql_cop_json(
        _payload(_entry(title="GET-based Mutation Allowed (CSRF)")),
        b"",
        tmp_path,
        "graphql_cop",
    )
    assert findings[0].category is FindingCategory.CSRF
    assert 352 in findings[0].cwe


def test_injection_routes_to_other_with_cwe_74(tmp_path: Path) -> None:
    findings = parse_graphql_cop_json(
        _payload(_entry(title="Possible NoSQL Injection")),
        b"",
        tmp_path,
        "graphql_cop",
    )
    assert findings[0].category is FindingCategory.OTHER
    assert 74 in findings[0].cwe


def test_unknown_routes_to_misconfig(tmp_path: Path) -> None:
    findings = parse_graphql_cop_json(
        _payload(_entry(title="Some Unrelated Check")),
        b"",
        tmp_path,
        "graphql_cop",
    )
    assert findings[0].category is FindingCategory.MISCONFIG
    assert set(findings[0].cwe) == {16, 200}


def test_authorization_header_in_curl_redacted(tmp_path: Path) -> None:
    curl = (
        "curl -X POST -H 'Content-Type: application/json' "
        "-H 'Authorization: Bearer abc.def.ghi' "
        '-d \'{"query":"{__schema{types{name}}}"}\' '
        "https://api.example.com/graphql"
    )
    parse_graphql_cop_json(
        _payload(_entry(curl_verify=curl)), b"", tmp_path, "graphql_cop"
    )
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "Bearer abc.def.ghi" not in sidecar
    assert "REDACTED-AUTH" in sidecar


def test_cookie_header_in_curl_redacted(tmp_path: Path) -> None:
    curl = "curl -H 'Cookie: session=abcdef.session.token' http://x"
    parse_graphql_cop_json(
        _payload(_entry(curl_verify=curl)), b"", tmp_path, "graphql_cop"
    )
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "abcdef.session.token" not in sidecar
    assert "REDACTED-AUTH" in sidecar


def test_x_api_key_header_in_curl_redacted(tmp_path: Path) -> None:
    curl = "curl -H 'X-API-Key: hunter2-rotated' http://x"
    parse_graphql_cop_json(
        _payload(_entry(curl_verify=curl)), b"", tmp_path, "graphql_cop"
    )
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8")
    assert "hunter2-rotated" not in sidecar
    assert "REDACTED-AUTH" in sidecar


def test_severity_to_cvss_mapping(tmp_path: Path) -> None:
    payload = _payload(
        _entry(title="Critical Check", severity="critical"),
        _entry(title="High Check", severity="high"),
        _entry(title="Medium Check", severity="medium"),
        _entry(title="Low Check", severity="low"),
    )
    findings = parse_graphql_cop_json(payload, b"", tmp_path, "graphql_cop")
    scores = sorted(f.cvss_v3_score for f in findings)
    assert scores == pytest.approx([3.0, 5.0, 7.5, 9.0])


def test_payload_not_array_emits_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    canonical = tmp_path / "graphqlcop.json"
    canonical.write_bytes(b'{"unexpected": true}')
    with caplog.at_level("WARNING"):
        findings = parse_graphql_cop_json(b"", b"", tmp_path, "graphql_cop")
    assert findings == []
    assert any(
        "graphql_cop_parser_payload_not_array" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_findings_have_likely_confidence(tmp_path: Path) -> None:
    findings = parse_graphql_cop_json(_payload(_entry()), b"", tmp_path, "graphql_cop")
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_dedup_collapses_same_title_severity(tmp_path: Path) -> None:
    payload = _payload(_entry(), _entry())
    findings = parse_graphql_cop_json(payload, b"", tmp_path, "graphql_cop")
    assert len(findings) == 1


def test_cap_reached_emits_warning_and_truncates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(graphql_module, "_MAX_FINDINGS", 2)
    payload = _payload(*(_entry(title=f"check-{i}") for i in range(5)))
    with caplog.at_level("WARNING"):
        findings = parse_graphql_cop_json(payload, b"", tmp_path, "graphql_cop")
    assert len(findings) == 2
    assert any(
        "graphql_cop_parser_cap_reached" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_payload_with_only_negative_results_returns_empty(tmp_path: Path) -> None:
    """Cover the early-exit path when every record has ``result == false``."""
    payload = _payload(_entry(result=False), _entry(result=False))
    assert parse_graphql_cop_json(payload, b"", tmp_path, "graphql_cop") == []


def test_non_object_entries_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Top-level array containing non-objects must be skipped (debug log)."""
    payload = json.dumps(["not-an-object", 42, _entry(title="Real Check")]).encode(
        "utf-8"
    )
    with caplog.at_level("DEBUG", logger=graphql_module._logger.name):
        findings = parse_graphql_cop_json(payload, b"", tmp_path, "graphql_cop")
    assert len(findings) == 1
    assert any(
        "graphql_cop_parser_entry_not_object" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_missing_title_skipped(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Entries without a title must be dropped with a debug log."""
    raw = _entry(title="To be removed")
    raw.pop("title")
    payload = json.dumps([raw, _entry(title="With Title")]).encode("utf-8")
    with caplog.at_level("DEBUG", logger=graphql_module._logger.name):
        findings = parse_graphql_cop_json(payload, b"", tmp_path, "graphql_cop")
    assert len(findings) == 1
    assert any(
        "graphql_cop_parser_entry_missing_title" in (record.__dict__.get("event") or "")
        for record in caplog.records
    )


def test_string_result_field_coerced(tmp_path: Path) -> None:
    """``_coerce_bool`` must accept the JSON-as-string variants."""
    raw_true = _entry(title="Stringy True")
    raw_true["result"] = "yes"
    raw_false = _entry(title="Stringy False")
    raw_false["result"] = "false"
    raw_int = _entry(title="Truthy Int")
    raw_int["result"] = 1
    payload = json.dumps([raw_true, raw_false, raw_int]).encode("utf-8")
    findings = parse_graphql_cop_json(payload, b"", tmp_path, "graphql_cop")
    titles = {
        f
        for f in (
            json.loads(line)["title"]
            for line in (
                (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
            )
        )
    }
    assert "Stringy True" in titles
    assert "Truthy Int" in titles
    assert "Stringy False" not in titles
    assert len(findings) == 2


def test_severity_aliases_normalised(tmp_path: Path) -> None:
    """Severity prefixes (``crit``, ``hi``, ``med``, ``lo``) must collapse."""
    payload = _payload(
        _entry(title="Crit Alias", severity="CRITicality"),
        _entry(title="High Alias", severity="HIGHEST"),
        _entry(title="Med Alias", severity="medium-ish"),
        _entry(title="Low Alias", severity="lower"),
        _entry(title="Bogus Alias", severity="unknown"),
    )
    findings = parse_graphql_cop_json(payload, b"", tmp_path, "graphql_cop")
    assert len(findings) == 5
    scores = sorted(f.cvss_v3_score for f in findings)
    assert scores == pytest.approx([3.0, 5.0, 5.0, 7.5, 9.0])


def test_severity_missing_defaults_to_medium(tmp_path: Path) -> None:
    """When ``severity`` is missing entirely, default to medium (5.0)."""
    raw = _entry(title="No Severity")
    raw.pop("severity")
    payload = json.dumps([raw]).encode("utf-8")
    findings = parse_graphql_cop_json(payload, b"", tmp_path, "graphql_cop")
    assert findings[0].cvss_v3_score == pytest.approx(5.0)
