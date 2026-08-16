"""QUICK-009 — authenticated context is a store ref; secrets never leak to logs/audit."""

from __future__ import annotations

from src.orchestration.scan_events import (
    REDACTION_PLACEHOLDER,
    emit_quick_audit_event,
    get_quick_audit_events,
    reset_quick_audit_events,
)
from src.quick.create import overlay_quick_options, resolve_quick_runtime
from src.quick.provenance import evidence_json_for_llm
from src.quick.resolver import QuickProfileRequest
from src.quick.schemas import QuickProfileName


def test_auth_context_secret_not_in_options_or_audit() -> None:
    reset_quick_audit_events()
    config, budget, deadline = resolve_quick_runtime(
        tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        quick_payload={
            "profile": QuickProfileName.BALANCED.value,
            "authenticated_context_id": "ctx-ref-only",
            "password": "super-secret-password",
        },
    )
    options = overlay_quick_options(
        {},
        config=config,
        budget=budget,
        deadline_at=deadline,
    )
    assert "authenticated_context_id" not in options.get("quick", {})
    assert "password" not in str(options)
    emit_quick_audit_event(
        "quick.create",
        scan_id="bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
        payload={
            "authenticated_context_id": config.authenticated_context_id,
            "password": "super-secret-password",
            "cookie": "session=abc",
        },
    )
    blob = str(get_quick_audit_events())
    assert "super-secret-password" not in blob
    assert "session=abc" not in blob or REDACTION_PLACEHOLDER in blob
    llm_json = evidence_json_for_llm(
        {
            "cookie": "session=abc",
            "authorization": "Bearer leaked",
            "title": "xss",
        }
    )
    assert "Bearer leaked" not in str(llm_json)
    assert "session=abc" not in str(llm_json)
    reset_quick_audit_events()


def test_profile_request_keeps_context_id_not_secret() -> None:
    req = QuickProfileRequest(
        profile=QuickProfileName.BALANCED.value,
        authenticated_context_id="ctx-ref-only",
    )
    assert req.authenticated_context_id == "ctx-ref-only"
