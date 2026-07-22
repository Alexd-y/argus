"""Unit tests for the declarative check DSL (WB-P8a)."""

from __future__ import annotations

from uuid import uuid4

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    EvidenceTier,
    FindingCategory,
    FindingStatus,
)
from src.web_workbench.checks.severity import CheckSeverity
from src.web_workbench.extensions.check_dsl import (
    DeclarativeCheck,
    DslError,
    check_finding_to_dto,
    evaluate_check,
    evaluate_checks,
    load_check,
)
from src.web_workbench.proxy.transport import NormalizedRequest, NormalizedResponse


def _request(
    method: str = "GET",
    target: str = "/",
    headers: tuple[tuple[str, str], ...] = (),
) -> NormalizedRequest:
    return NormalizedRequest(
        method=method,
        target=target,
        http_version="HTTP/1.1",
        headers=(("Host", "app.test"), *headers),
    )


def _response(
    status: int = 200,
    headers: tuple[tuple[str, str], ...] = (),
) -> NormalizedResponse:
    return NormalizedResponse(
        http_version="HTTP/1.1",
        status_code=status,
        reason="OK",
        headers=headers,
    )


def _check(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "schema_version": 1,
        "check_id": "acme.server-header-leak",
        "name": "Server header discloses version",
        "author": "acme",
        "category": "info",
        "severity": "low",
        "cwe": [200],
        "scope": "passive",
        "match": {
            "op": "and",
            "matchers": [
                {"part": "response_header", "kind": "regex", "value": r"Server:\s*\w+/\d"},
            ],
        },
    }
    base.update(overrides)
    return base


# --------------------------------------------------------------------------- #
# Schema validation (fail-closed)                                             #
# --------------------------------------------------------------------------- #


def test_load_valid_check() -> None:
    check = load_check(_check())
    assert isinstance(check, DeclarativeCheck)
    assert check.category is FindingCategory.INFO
    assert check.severity is CheckSeverity.LOW


def test_unknown_key_rejected() -> None:
    with pytest.raises(DslError):
        load_check(_check(unexpected="boom"))


def test_non_mapping_rejected() -> None:
    with pytest.raises(DslError):
        load_check(["not", "a", "mapping"])


def test_bad_check_id_rejected() -> None:
    with pytest.raises(DslError):
        load_check(_check(check_id="Bad_ID"))


def test_invalid_regex_matcher_rejected() -> None:
    with pytest.raises(DslError):
        load_check(
            _check(match={"matchers": [{"part": "response_body", "kind": "regex", "value": "("}]})
        )


def test_status_matcher_wrong_part_rejected() -> None:
    with pytest.raises(DslError):
        load_check(
            _check(
                match={"matchers": [{"part": "response_body", "kind": "status", "value": "500"}]}
            )
        )


def test_status_matcher_bad_value_rejected() -> None:
    with pytest.raises(DslError):
        load_check(
            _check(match={"matchers": [{"part": "status_code", "kind": "status", "value": "abc"}]})
        )


def test_duplicate_cwe_rejected() -> None:
    with pytest.raises(DslError):
        load_check(_check(cwe=[200, 200]))


def test_oast_requires_active_scope() -> None:
    with pytest.raises(DslError):
        load_check(_check(requires_oast=True, scope="passive"))


def test_empty_matcher_group_rejected() -> None:
    with pytest.raises(DslError):
        load_check(_check(match={"matchers": []}))


# --------------------------------------------------------------------------- #
# Matcher evaluation                                                          #
# --------------------------------------------------------------------------- #


def test_regex_response_header_match() -> None:
    check = load_check(_check())
    finding = evaluate_check(check, _request(), _response(headers=(("Server", "nginx/1.2"),)), b"")
    assert finding is not None
    assert finding.check_id == "acme.server-header-leak"
    assert finding.category is FindingCategory.INFO


def test_no_match_returns_none() -> None:
    check = load_check(_check())
    finding = evaluate_check(check, _request(), _response(headers=(("Server", "nginx"),)), b"")
    assert finding is None


def test_contains_case_insensitive_by_default() -> None:
    check = load_check(
        _check(
            match={
                "matchers": [{"part": "response_body", "kind": "contains", "value": "STACKTRACE"}]
            }
        )
    )
    finding = evaluate_check(check, _request(), _response(500), b"...stacktrace...")
    assert finding is not None


def test_contains_case_sensitive_respected() -> None:
    check = load_check(
        _check(
            match={
                "matchers": [
                    {
                        "part": "response_body",
                        "kind": "contains",
                        "value": "STACKTRACE",
                        "case_sensitive": True,
                    }
                ]
            }
        )
    )
    assert evaluate_check(check, _request(), _response(500), b"stacktrace") is None


def test_status_matcher_exact() -> None:
    check = load_check(
        _check(match={"matchers": [{"part": "status_code", "kind": "status", "value": "500"}]})
    )
    assert evaluate_check(check, _request(), _response(500), b"") is not None
    assert evaluate_check(check, _request(), _response(200), b"") is None


def test_status_matcher_class_wildcard() -> None:
    check = load_check(
        _check(match={"matchers": [{"part": "status_code", "kind": "status", "value": "5xx"}]})
    )
    assert evaluate_check(check, _request(), _response(503), b"") is not None
    assert evaluate_check(check, _request(), _response(404), b"") is None


def test_negate_matcher() -> None:
    check = load_check(
        _check(
            match={
                "matchers": [
                    {
                        "part": "response_header",
                        "kind": "contains",
                        "value": "Strict-Transport-Security",
                        "negate": True,
                    }
                ]
            }
        )
    )
    # HSTS absent -> negate makes it match.
    assert evaluate_check(check, _request(), _response(), b"") is not None
    # HSTS present -> no match.
    resp = _response(headers=(("Strict-Transport-Security", "max-age=1"),))
    assert evaluate_check(check, _request(), resp, b"") is None


def test_and_group_requires_all() -> None:
    check = load_check(
        _check(
            match={
                "op": "and",
                "matchers": [
                    {"part": "status_code", "kind": "status", "value": "500"},
                    {"part": "response_body", "kind": "contains", "value": "mongo"},
                ],
            }
        )
    )
    assert evaluate_check(check, _request(), _response(500), b"mongo error") is not None
    assert evaluate_check(check, _request(), _response(500), b"clean") is None


def test_or_group_requires_any() -> None:
    check = load_check(
        _check(
            match={
                "op": "or",
                "matchers": [
                    {"part": "response_body", "kind": "contains", "value": "aaa"},
                    {"part": "response_body", "kind": "contains", "value": "bbb"},
                ],
            }
        )
    )
    assert evaluate_check(check, _request(), _response(), b"xxbbbxx") is not None
    assert evaluate_check(check, _request(), _response(), b"ccc") is None


def test_request_side_parts_match() -> None:
    check = load_check(
        _check(
            scope="active",
            match={"matchers": [{"part": "url", "kind": "contains", "value": "/admin"}]},
        )
    )
    assert evaluate_check(check, _request(target="/admin/panel"), _response(), b"") is not None


# --------------------------------------------------------------------------- #
# OAST gating                                                                 #
# --------------------------------------------------------------------------- #


def test_oast_check_fails_closed_without_confirmation() -> None:
    check = load_check(
        _check(
            scope="active",
            requires_oast=True,
            match={"matchers": [{"part": "status_code", "kind": "status", "value": "200"}]},
        )
    )
    assert evaluate_check(check, _request(), _response(200), b"") is None
    assert evaluate_check(check, _request(), _response(200), b"", oast_confirmed=True) is not None


# --------------------------------------------------------------------------- #
# Extractors                                                                  #
# --------------------------------------------------------------------------- #


def test_extractor_captures_group_into_evidence() -> None:
    check = load_check(
        _check(
            match={
                "matchers": [{"part": "response_header", "kind": "contains", "value": "Server"}]
            },
            extractors=[
                {
                    "name": "server",
                    "part": "response_header",
                    "regex": r"Server:\s*(\S+)",
                    "group": 1,
                }
            ],
        )
    )
    finding = evaluate_check(check, _request(), _response(headers=(("Server", "nginx/1.2"),)), b"")
    assert finding is not None
    assert "server=nginx/1.2" in finding.evidence


def test_extractor_capture_truncated() -> None:
    long_value = "A" * 500
    check = load_check(
        _check(
            match={"matchers": [{"part": "response_body", "kind": "contains", "value": "TOKEN"}]},
            extractors=[
                {"name": "tok", "part": "response_body", "regex": r"TOKEN(A+)", "group": 1}
            ],
        )
    )
    finding = evaluate_check(check, _request(), _response(), b"TOKEN" + long_value.encode())
    assert finding is not None
    captured = finding.evidence.split("tok=", 1)[1]
    assert len(captured) <= 200


# --------------------------------------------------------------------------- #
# Batch + bridge                                                              #
# --------------------------------------------------------------------------- #


def test_evaluate_checks_batch() -> None:
    hit = load_check(_check(check_id="acme.hit"))
    miss = load_check(
        _check(
            check_id="acme.miss",
            match={"matchers": [{"part": "response_body", "kind": "contains", "value": "zzz"}]},
        )
    )
    findings = evaluate_checks(
        [hit, miss], _request(), _response(headers=(("Server", "nginx/1.2"),)), b""
    )
    assert len(findings) == 1
    assert findings[0].check_id == "acme.hit"


def test_bridge_maps_to_finding_dto() -> None:
    check = load_check(_check(severity="high", cwe=[200, 16]))
    finding = evaluate_check(check, _request(), _response(headers=(("Server", "nginx/1.2"),)), b"")
    assert finding is not None
    dto = check_finding_to_dto(
        finding,
        tenant_id=uuid4(),
        scan_id=uuid4(),
        asset_id=uuid4(),
        tool_run_id=uuid4(),
    )
    assert dto.category is FindingCategory.INFO
    assert dto.cwe == [200, 16]
    assert dto.status is FindingStatus.NEW
    assert dto.evidence_tier is EvidenceTier.SUSPECTED
    assert dto.cvss_v3_score is not None and dto.cvss_v3_score > 0


def test_bridge_confirmed_confidence_maps_confirmed_tier() -> None:
    check = load_check(_check(confidence="confirmed"))
    finding = evaluate_check(check, _request(), _response(headers=(("Server", "nginx/1.2"),)), b"")
    assert finding is not None
    assert finding.confidence is ConfidenceLevel.CONFIRMED
    dto = check_finding_to_dto(
        finding,
        tenant_id=uuid4(),
        scan_id=uuid4(),
        asset_id=uuid4(),
        tool_run_id=uuid4(),
        finding_id=uuid4(),
    )
    assert dto.evidence_tier is EvidenceTier.CONFIRMED


def test_scan_is_bounded() -> None:
    # A matcher looking for a needle placed beyond the scan cap must not match.
    check = load_check(
        _check(
            match={"matchers": [{"part": "response_body", "kind": "contains", "value": "needle"}]}
        )
    )
    body = b"x" * 600_000 + b"needle"
    assert evaluate_check(check, _request(), _response(), body) is None
