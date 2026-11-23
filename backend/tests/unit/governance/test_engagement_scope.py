"""WP D/A (legitimate, FAIL-CLOSED) — signed-engagement scope enforcement.

Pure/offline. This is the *correct* governance gate: it DENIES by default and only
permits an action that is explicitly inside a live engagement's target/tenant/action
window. (The ARTEX spec's fail-OPEN inversion is deliberately NOT implemented.)
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from src.governance.engagement import (
    Engagement,
    ScopeViolation,
    assert_in_scope,
)

_NOW = datetime(2026, 11, 23, 12, 0, tzinfo=UTC)


def _eng(**kw) -> Engagement:
    base: dict = {
        "engagement_id": "E-1",
        "allowed_targets": ("victim.example.com",),
        "allowed_tenants": ("tenant-1",),
        "allowed_actions": ("recon", "active_scan"),
        "window_start": _NOW - timedelta(hours=1),
        "window_end": _NOW + timedelta(hours=1),
        "max_rate_per_target": 60,
    }
    base.update(kw)
    return Engagement(**base)


def test_in_scope_action_passes() -> None:
    # Returns None (no raise) when target + action + tenant + window all allow it.
    assert (
        assert_in_scope(
            "https://victim.example.com/login",
            "active_scan",
            _eng(),
            tenant_id="tenant-1",
            now=_NOW,
        )
        is None
    )


def test_missing_engagement_is_denied() -> None:
    with pytest.raises(ScopeViolation):
        assert_in_scope("https://victim.example.com", "recon", None, now=_NOW)


def test_out_of_scope_target_is_denied() -> None:
    with pytest.raises(ScopeViolation):
        assert_in_scope("https://not-in-scope.com", "recon", _eng(), now=_NOW)


def test_disallowed_action_is_denied() -> None:
    with pytest.raises(ScopeViolation):
        assert_in_scope("https://victim.example.com", "exfiltration", _eng(), now=_NOW)


def test_outside_window_is_denied() -> None:
    with pytest.raises(ScopeViolation):
        assert_in_scope(
            "https://victim.example.com",
            "recon",
            _eng(),
            now=_NOW + timedelta(hours=5),
        )


def test_revoked_engagement_is_denied() -> None:
    with pytest.raises(ScopeViolation):
        assert_in_scope("https://victim.example.com", "recon", _eng(revoked=True), now=_NOW)


def test_wrong_tenant_is_denied() -> None:
    with pytest.raises(ScopeViolation):
        assert_in_scope(
            "https://victim.example.com",
            "recon",
            _eng(),
            tenant_id="tenant-OTHER",
            now=_NOW,
        )


def test_subdomain_of_allowed_target_passes() -> None:
    assert assert_in_scope("https://api.victim.example.com/v1", "recon", _eng(), now=_NOW) is None


def test_cross_tenant_is_never_implicitly_allowed() -> None:
    """Fail-closed: an engagement with no allowed_tenants denies any tenant check."""
    eng = _eng(allowed_tenants=())
    with pytest.raises(ScopeViolation):
        assert_in_scope("https://victim.example.com", "recon", eng, tenant_id="tenant-1", now=_NOW)


@pytest.mark.parametrize(
    "sneaky",
    [
        # Backslash differential: a scanner may connect to evil.example.net while a
        # naive suffix match reads ".victim.example.com" and lets it through.
        "http://evil.example.net\\.victim.example.com/",
        # Fragment differential — everything after '#' is not the host.
        "https://evil.example.net#.victim.example.com",
        # Tab/control char hiding the real host.
        "http://evil.example.net\t.victim.example.com",
    ],
)
def test_parser_differential_targets_are_denied(sneaky: str) -> None:
    """A URL whose host a standard parser reads differently must be denied, never
    allowed by a hand-rolled suffix match (scope/allowlist bypass hardening)."""
    with pytest.raises(ScopeViolation):
        assert_in_scope(sneaky, "recon", _eng(), now=_NOW)


def test_trailing_dot_fqdn_is_normalised() -> None:
    # A trailing-dot FQDN is the same host; it must still match (not a bypass either way).
    assert assert_in_scope("https://victim.example.com./x", "recon", _eng(), now=_NOW) is None
