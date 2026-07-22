"""Unit tests for proxy repository ORM<->DTO mapping (WB-P2a-2)."""

from __future__ import annotations

from datetime import datetime, timezone

from src.db.models_web_workbench import (
    WbProxyListener,
    WbTrafficBodyArtifact,
    WbTrafficMessage,
)
from src.web_workbench.contracts.proxy import ProxyListenerStatus
from src.web_workbench.proxy.intercept_rules import (
    InterceptAction,
    InterceptRule,
    InterceptRuleSet,
)
from src.web_workbench.proxy.repository import (
    _body_ref,
    _listener_to_dto,
    _message_to_dto,
)

_NOW = datetime(2026, 7, 22, 12, 0, tzinfo=timezone.utc)


def _listener(**over: object) -> WbProxyListener:
    listener = WbProxyListener(
        id="l1",
        tenant_id="t1",
        project_id="p1",
        name="edge",
        host="127.0.0.1",
        port=8080,
        status=ProxyListenerStatus.ACTIVE.value,
        intercept_enabled=True,
        intercept_rules=over.get("intercept_rules"),
        ca_cert_pem=over.get("ca_cert_pem"),  # type: ignore[arg-type]
        ca_fingerprint=over.get("ca_fingerprint"),  # type: ignore[arg-type]
        version=2,
    )
    listener.created_at = _NOW
    listener.updated_at = _NOW
    return listener


def test_listener_to_dto_maps_rules() -> None:
    rules = InterceptRuleSet(
        rules=(InterceptRule(action=InterceptAction.DROP, path_prefix="/x"),),
        default_action=InterceptAction.PASS,
    )
    listener = _listener(intercept_rules=rules.model_dump(mode="json"))
    dto = _listener_to_dto(listener)
    assert dto.status is ProxyListenerStatus.ACTIVE
    assert dto.version == 2
    assert dto.intercept_rules is not None
    assert dto.intercept_rules.rules[0].action is InterceptAction.DROP
    assert dto.ca is None


def test_listener_to_dto_ca_present_only_with_both_fields() -> None:
    listener = _listener(
        ca_cert_pem="-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n",
        ca_fingerprint="f" * 64,
    )
    dto = _listener_to_dto(listener)
    assert dto.ca is not None
    assert dto.ca.fingerprint_sha256 == "f" * 64


def test_listener_to_dto_ca_absent_when_only_cert() -> None:
    listener = _listener(ca_cert_pem="cert-without-fingerprint")
    assert _listener_to_dto(listener).ca is None


def test_body_ref_none() -> None:
    assert _body_ref(None) is None


def test_body_ref_maps_fields() -> None:
    art = WbTrafficBodyArtifact(
        id="b1",
        tenant_id="t1",
        project_id="p1",
        message_id="m1",
        direction="request",
        storage_backend="inline",
        sha256="a" * 64,
        size_bytes=12,
        content_type="application/json",
        truncated=False,
    )
    ref = _body_ref(art)
    assert ref is not None
    assert ref.size_bytes == 12
    assert ref.storage_backend == "inline"


def test_message_to_dto_maps_bodies_and_tags() -> None:
    message = WbTrafficMessage(
        id="m1",
        tenant_id="t1",
        project_id="p1",
        listener_id="l1",
        source="proxy",
        method="POST",
        scheme="https",
        host="app.example.com",
        port=443,
        path="/submit",
        query="a=1",
        http_version="HTTP/1.1",
        status_code=200,
        forward_outcome="forward",
        block_reason=None,
        in_scope=True,
        tags=["flagged"],
    )
    message.created_at = _NOW
    req = WbTrafficBodyArtifact(
        id="b1",
        tenant_id="t1",
        project_id="p1",
        message_id="m1",
        direction="request",
        storage_backend="inline",
        sha256="a" * 64,
        size_bytes=3,
        truncated=False,
    )
    dto = _message_to_dto(message, req, None)
    assert dto.method == "POST"
    assert dto.in_scope is True
    assert dto.tags == ("flagged",)
    assert dto.request_body is not None
    assert dto.response_body is None
