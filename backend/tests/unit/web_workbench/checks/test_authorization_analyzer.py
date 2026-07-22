"""Unit tests for the workbench authorization analyzer (WB-P6a)."""

from __future__ import annotations

import pytest

from src.playbooks.oracles import OracleVerdict
from src.web_workbench.checks.authorization_analyzer import (
    AuthorizationError,
    AuthzClass,
    CapturedExchange,
    analyze_authorization,
    detect_object_id,
    evaluate_pair,
)
from src.web_workbench.proxy.transport import NormalizedRequest, NormalizedResponse


def _req(raw: bytes) -> NormalizedRequest:
    return NormalizedRequest.parse(raw)


def _resp(status: int) -> NormalizedResponse:
    raw = f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n\r\n".encode("latin-1")
    return NormalizedResponse.parse(raw)


def _capture(
    *,
    principal: str,
    target: bytes,
    status: int,
    body: bytes,
    is_anonymous: bool = False,
) -> CapturedExchange:
    return CapturedExchange(
        principal=principal,
        request=_req(target + b" HTTP/1.1\r\nHost: app\r\n\r\n"),
        response=_resp(status),
        response_body=body,
        is_anonymous=is_anonymous,
    )


_OWNER_BODY = b'{"id": 42, "ssn": "111-22-3333", "email": "victim@example.com"}'


def test_idor_when_attacker_reads_owner_object_with_numeric_id() -> None:
    owner = _capture(principal="owner", target=b"GET /api/users/42", status=200, body=_OWNER_BODY)
    attacker = _capture(
        principal="mallory", target=b"GET /api/users/42", status=200, body=_OWNER_BODY
    )
    findings = analyze_authorization(owner=owner, attackers=[attacker])
    assert len(findings) == 1
    assert findings[0].classification is AuthzClass.IDOR
    assert findings[0].verdict is OracleVerdict.FINDING
    assert findings[0].object_id == "42"
    assert findings[0].principal == "mallory"


def test_unauth_access_takes_precedence_over_id() -> None:
    owner = _capture(principal="owner", target=b"GET /api/users/42", status=200, body=_OWNER_BODY)
    anon = _capture(
        principal="anonymous",
        target=b"GET /api/users/42",
        status=200,
        body=_OWNER_BODY,
        is_anonymous=True,
    )
    findings = analyze_authorization(owner=owner, attackers=[anon])
    assert findings[0].classification is AuthzClass.UNAUTH_ACCESS


def test_bfla_when_no_object_id_in_url() -> None:
    body = b'{"role": "admin", "secret": "x"}'
    owner = _capture(principal="owner", target=b"GET /admin/dashboard", status=200, body=body)
    attacker = _capture(principal="lowpriv", target=b"GET /admin/dashboard", status=200, body=body)
    findings = analyze_authorization(owner=owner, attackers=[attacker])
    assert findings[0].classification is AuthzClass.BFLA
    assert findings[0].object_id is None


def test_no_finding_when_attacker_denied() -> None:
    owner = _capture(principal="owner", target=b"GET /api/users/42", status=200, body=_OWNER_BODY)
    attacker = _capture(
        principal="mallory", target=b"GET /api/users/42", status=403, body=b"denied"
    )
    findings = analyze_authorization(owner=owner, attackers=[attacker])
    assert findings == []


def test_no_finding_when_attacker_sees_different_data() -> None:
    owner = _capture(principal="owner", target=b"GET /api/users/42", status=200, body=_OWNER_BODY)
    attacker = _capture(
        principal="mallory",
        target=b"GET /api/users/42",
        status=200,
        body=b'{"id": 7, "ssn": "999-99-9999", "email": "mallory@example.com"}',
    )
    findings = analyze_authorization(owner=owner, attackers=[attacker])
    assert findings == []


def test_inconclusive_when_owner_baseline_not_2xx() -> None:
    owner = _capture(principal="owner", target=b"GET /api/users/42", status=500, body=b"err")
    attacker = _capture(
        principal="mallory", target=b"GET /api/users/42", status=200, body=_OWNER_BODY
    )
    result = evaluate_pair(owner, attacker)
    assert result.verdict is OracleVerdict.INCONCLUSIVE
    # And it must not surface as a finding.
    assert analyze_authorization(owner=owner, attackers=[attacker]) == []


def test_sensitive_field_match_confirms_cross_user_read() -> None:
    owner = _capture(principal="owner", target=b"GET /api/users/42", status=200, body=_OWNER_BODY)
    # Attacker body differs elsewhere but leaks the victim's ssn.
    attacker = _capture(
        principal="mallory",
        target=b"GET /api/users/42",
        status=200,
        body=b'{"id": 7, "ssn": "111-22-3333", "email": "mallory@example.com"}',
    )
    findings = analyze_authorization(owner=owner, attackers=[attacker], sensitive_fields=["ssn"])
    assert len(findings) == 1
    assert findings[0].classification is AuthzClass.IDOR


def test_multiple_attackers_are_each_evaluated() -> None:
    owner = _capture(principal="owner", target=b"GET /api/users/42", status=200, body=_OWNER_BODY)
    leaker = _capture(
        principal="mallory", target=b"GET /api/users/42", status=200, body=_OWNER_BODY
    )
    denied = _capture(principal="trudy", target=b"GET /api/users/42", status=403, body=b"no")
    anon = _capture(
        principal="anon",
        target=b"GET /api/users/42",
        status=200,
        body=_OWNER_BODY,
        is_anonymous=True,
    )
    findings = analyze_authorization(owner=owner, attackers=[leaker, denied, anon])
    classes = {f.principal: f.classification for f in findings}
    assert classes == {"mallory": AuthzClass.IDOR, "anon": AuthzClass.UNAUTH_ACCESS}


def test_empty_attackers_fails_closed() -> None:
    owner = _capture(principal="owner", target=b"GET /api/users/42", status=200, body=_OWNER_BODY)
    with pytest.raises(AuthorizationError, match="at least one attacker"):
        analyze_authorization(owner=owner, attackers=[])


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("/api/users/42", "42"),
        (
            "/api/orders/9c858901-8a57-4791-81fe-4c455b099bc9",
            "9c858901-8a57-4791-81fe-4c455b099bc9",
        ),
        ("/files?id=deadbeefcafe0001", "deadbeefcafe0001"),
        ("/api/account?user=42", "42"),
        ("/admin/dashboard", None),
        ("/profile", None),
    ],
)
def test_detect_object_id(target: str, expected: str | None) -> None:
    assert detect_object_id(target) == expected


def test_finding_carries_no_raw_body() -> None:
    owner = _capture(principal="owner", target=b"GET /api/users/42", status=200, body=_OWNER_BODY)
    attacker = _capture(
        principal="mallory", target=b"GET /api/users/42", status=200, body=_OWNER_BODY
    )
    finding = analyze_authorization(owner=owner, attackers=[attacker])[0]
    # SI-3: the victim's secret values never appear in the surfaced finding.
    serialized = f"{finding.reason}{finding.differing_fields}{finding.object_id}{finding.location}"
    assert "111-22-3333" not in serialized
    assert "victim@example.com" not in serialized
