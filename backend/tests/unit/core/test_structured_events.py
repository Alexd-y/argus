"""Structured events + redaction (R13)."""

from __future__ import annotations

import logging

from src.core.structured_events import (
    ALL_EVENTS,
    EVENT_LAB_LEASE_PREFLIGHT_DENIED,
    EVENT_SCAN_PROFILE_RESOLVED,
    REDACTED,
    emit_event,
    redact,
)


def test_redact_masks_sensitive_keys():
    raw = {
        "scan_id": "s-1",
        "password": "hunter2",
        "authorization": "Bearer x",
        "cookie": "session=abc",
        "boundary_proof": "deadbeef",
        "signature": "sig",
        "nested": {"api_key": "k", "safe": "ok"},
        "list": [{"token": "t"}, "plain"],
    }
    out = redact(raw)
    assert out["scan_id"] == "s-1"
    assert out["password"] == REDACTED
    assert out["authorization"] == REDACTED
    assert out["cookie"] == REDACTED
    assert out["boundary_proof"] == REDACTED
    assert out["signature"] == REDACTED
    assert out["nested"]["api_key"] == REDACTED
    assert out["nested"]["safe"] == "ok"
    assert out["list"][0]["token"] == REDACTED
    assert out["list"][1] == "plain"


def test_emit_event_includes_canonical_fields():
    payload = emit_event(
        EVENT_SCAN_PROFILE_RESOLVED,
        tenant_id="t-1",
        scan_id="s-1",
        engagement_id="e-1",
        correlation_id="c-1",
        scan_profile="deep",
        phase="recon",
        reason_code="ok",
        registry_versions={"tools": "t-v1"},
        nuclei_profile="lab_unrestricted",
    )
    assert payload["event"] == EVENT_SCAN_PROFILE_RESOLVED
    assert payload["tenant_id"] == "t-1"
    assert payload["scan_id"] == "s-1"
    assert payload["engagement_id"] == "e-1"
    assert payload["correlation_id"] == "c-1"
    assert payload["scan_profile"] == "deep"
    assert payload["phase"] == "recon"
    assert payload["reason_code"] == "ok"
    assert payload["registry_versions"] == {"tools": "t-v1"}
    assert payload["nuclei_profile"] == "lab_unrestricted"


def test_emit_event_redacts_extra():
    payload = emit_event(
        EVENT_LAB_LEASE_PREFLIGHT_DENIED,
        tenant_id="t-1",
        reason_code="lab_lease_revoked",
        boundary_proof="secret-proof",
        lab_lease_id="lease-1",
    )
    assert payload["boundary_proof"] == REDACTED
    assert payload["lab_lease_id"] == "lease-1"
    assert payload["reason_code"] == "lab_lease_revoked"


def test_emit_event_logs(caplog):
    with caplog.at_level(logging.INFO, logger="argus.events"):
        emit_event(EVENT_SCAN_PROFILE_RESOLVED, scan_profile="quick")
    assert any(r.message == EVENT_SCAN_PROFILE_RESOLVED for r in caplog.records)


def test_all_events_nonempty():
    assert EVENT_SCAN_PROFILE_RESOLVED in ALL_EVENTS
    assert len(ALL_EVENTS) >= 20


def test_resolver_emits_event(caplog):
    from src.profiles import resolve_scan_profile

    with caplog.at_level(logging.INFO, logger="argus.events"):
        resolve_scan_profile("light")
    assert any(r.message == EVENT_SCAN_PROFILE_RESOLVED for r in caplog.records)


def test_lab_preflight_denied_emits_event(caplog):
    import pytest

    from src.profiles.errors import LabEngagementRequiredError
    from src.profiles.lab_preflight import evaluate_lab_lease

    with caplog.at_level(logging.WARNING, logger="argus.events"):
        with pytest.raises(LabEngagementRequiredError):
            evaluate_lab_lease(
                tenant_id="t-1",
                engagement_id=None,
                lab_lease_id=None,
                target="https://x.test",
                lease=None,
                scope=None,
            )
    assert any(r.message == EVENT_LAB_LEASE_PREFLIGHT_DENIED for r in caplog.records)
