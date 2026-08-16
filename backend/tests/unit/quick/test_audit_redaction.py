"""QUICK-009 — Quick audit events redact secrets and cover the event taxonomy."""

from __future__ import annotations

import pytest
from src.execution_mode.mode import ExecutionMode
from src.orchestration.scan_events import (
    QUICK_AUDIT_EVENT_TYPES,
    REDACTION_PLACEHOLDER,
    emit_quick_audit_event,
    get_quick_audit_events,
    redact_quick_audit_payload,
    reset_quick_audit_events,
)
from src.quick.create import (
    QUICK_MODE_DISABLED,
    QuickModeDisabledError,
    assert_execution_mode_payload,
    resolve_quick_runtime,
)

_SCAN_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
_TENANT = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"


@pytest.fixture(autouse=True)
def _reset_audit() -> None:
    reset_quick_audit_events()
    yield
    reset_quick_audit_events()


def test_taxonomy_covers_required_events() -> None:
    required = {
        "quick.create",
        "quick.policy",
        "quick.plan",
        "quick.revision",
        "quick.tool",
        "quick.cancel",
        "quick.ai_route",
        "quick.prompt_model_version",
        "quick.report",
    }
    assert required <= QUICK_AUDIT_EVENT_TYPES


def test_redact_nested_secrets_and_bearer() -> None:
    payload = {
        "profile": "balanced",
        "password": "hunter2",
        "headers": {
            "Authorization": "Bearer super-secret-token",
            "X-Api-Key": "abcd",
            "Accept": "application/json",
        },
        "cookie": "session=abc",
        "notes": ["ok", {"refresh_token": "xyz"}],
    }
    redacted = redact_quick_audit_payload(payload)
    assert redacted["profile"] == "balanced"
    assert redacted["password"] == REDACTION_PLACEHOLDER
    assert redacted["headers"]["Authorization"] == REDACTION_PLACEHOLDER
    assert redacted["headers"]["X-Api-Key"] == REDACTION_PLACEHOLDER
    assert redacted["headers"]["Accept"] == "application/json"
    assert redacted["cookie"] == REDACTION_PLACEHOLDER
    assert redacted["notes"][1]["refresh_token"] == REDACTION_PLACEHOLDER
    blob = str(redacted)
    assert "hunter2" not in blob
    assert "super-secret-token" not in blob
    assert "abcd" not in blob


def test_emit_stores_redacted_copy() -> None:
    emit_quick_audit_event(
        "quick.create",
        scan_id=_SCAN_ID,
        tenant_id=_TENANT,
        payload={
            "authenticated_context_id": "ctx-1",
            "password": "should-not-leak",
            "profile": "balanced",
        },
    )
    events = get_quick_audit_events()
    assert len(events) == 1
    assert events[0]["event_type"] == "quick.create"
    assert events[0]["data"]["profile"] == "balanced"
    assert events[0]["data"]["password"] == REDACTION_PLACEHOLDER
    assert "should-not-leak" not in str(events[0])


def test_unknown_event_type_falls_back_to_tool() -> None:
    emit_quick_audit_event("not-a-real-event", scan_id=_SCAN_ID, payload={"ok": True})
    events = get_quick_audit_events()
    assert events[0]["event_type"] == "quick.tool"


def test_create_and_policy_emit_audit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.quick.create.is_quick_mode_enabled", lambda: True)
    assert_execution_mode_payload(ExecutionMode.QUICK, has_quick_payload=True, enabled=True)
    resolve_quick_runtime(tenant_id=_TENANT, quick_payload={"profile": "balanced"})
    kinds = {item["event_type"] for item in get_quick_audit_events()}
    assert "quick.policy" in kinds
    assert "quick.create" in kinds
    joined = str(get_quick_audit_events())
    assert "password" not in joined.lower() or REDACTION_PLACEHOLDER in joined


def test_disabled_flag_emits_policy_without_secrets() -> None:
    with pytest.raises(QuickModeDisabledError):
        assert_execution_mode_payload(ExecutionMode.QUICK, has_quick_payload=True, enabled=False)
    events = get_quick_audit_events()
    assert events[-1]["event_type"] == "quick.policy"
    assert events[-1]["data"]["decision"] == QUICK_MODE_DISABLED
