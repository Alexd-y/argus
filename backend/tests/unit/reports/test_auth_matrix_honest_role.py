"""Authorization matrix: the role is the posture the scanner actually used,
never a bare "unknown".

Regression: for an unauthenticated external scan, findings carry no
``auth_state.role`` so every Authorization Matrix row rendered "unknown" — which
reads as "we don't know" rather than the truthful "the scanner was anonymous".
"""

from __future__ import annotations

from src.reports.valhalla_report_context import _parse_auth_testing_context


def _auth_finding(**extra):
    base = {
        "title": "Broken access control on /admin",
        "description": "access control bypass possible",
        "severity": "high",
        "target_url": "https://svalbard.ca/admin",
    }
    base.update(extra)
    return base


def test_unauthenticated_scan_role_is_anonymous_not_unknown() -> None:
    ctx = _parse_auth_testing_context([], [_auth_finding()], scan_options={})
    assert ctx.auth_matrix, "expected an authorization matrix row"
    row = ctx.auth_matrix[0]
    assert row.role == "anonymous (unauthenticated)"
    assert row.role != "unknown"
    # and a note explains why role-segregated authz was not exercised
    assert "anonymous" in ctx.notes.lower()
    assert "credentials" in ctx.notes.lower()


def test_authenticated_scan_uses_auth_method_as_default_role() -> None:
    ctx = _parse_auth_testing_context(
        [],
        [_auth_finding()],
        scan_options={"auth_credentials_provided": True, "auth_method": "form-login"},
    )
    assert ctx.auth_matrix[0].role == "form-login"
    # the anonymous note is only emitted for unauthenticated runs
    assert "anonymous" not in ctx.notes.lower()


def test_explicit_finding_role_wins() -> None:
    ctx = _parse_auth_testing_context(
        [],
        [_auth_finding(auth_state={"role": "editor"})],
        scan_options={"auth_credentials_provided": True, "auth_method": "form-login"},
    )
    assert ctx.auth_matrix[0].role == "editor"


def test_authenticated_scan_profile_maps_to_report_flags() -> None:
    # An operator configures authenticated scanning via authenticated_scan_profile;
    # the report must reflect it even without the explicit auth_* keys — and the
    # role default becomes the method, not "anonymous".
    ctx = _parse_auth_testing_context(
        [],
        [_auth_finding()],
        scan_options={
            "authenticated_scan_profile": {
                "enabled": True,
                "login_url": "https://svalbard.ca/login",
                "username": "qa@svalbard.ca",
                "password": "s3cret",
                "roles": ["admin", "member"],
            }
        },
    )
    assert ctx.auth_testing_enabled is True
    assert ctx.auth_credentials_provided is True
    assert ctx.auth_method_used == "form-login"
    assert ctx.roles_tested == ["admin", "member"]
    assert ctx.auth_matrix[0].role == "form-login"


def test_auth_profile_never_leaks_credential_values() -> None:
    ctx = _parse_auth_testing_context(
        [],
        [_auth_finding()],
        scan_options={
            "authenticated_scan_profile": {
                "enabled": True,
                "login_url": "https://svalbard.ca/login",
                "username": "qa@svalbard.ca",
                "password": "s3cret-should-never-render",
            }
        },
    )
    blob = ctx.model_dump_json()
    assert "s3cret-should-never-render" not in blob
    assert "qa@svalbard.ca" not in blob


def test_no_unknown_token_anywhere_in_matrix() -> None:
    ctx = _parse_auth_testing_context(
        [],
        [_auth_finding(severity="medium"), _auth_finding(severity="low")],
        scan_options={},
    )
    for row in ctx.auth_matrix:
        assert row.role != "unknown"
