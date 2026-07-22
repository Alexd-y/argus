"""Unit tests for repeater ORM→DTO mapping + target metadata derivation."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from types import SimpleNamespace

from src.web_workbench.repeater.repository import (
    _derive_target_metadata,
    _exchange_to_dto,
    _tab_to_dto,
)

_NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)


def _tab_row() -> SimpleNamespace:
    return SimpleNamespace(
        id="t1",
        tenant_id="tn",
        project_id="p1",
        name="login",
        raw_request=b"POST /login HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
        scheme="https",
        host="app.example.com",
        port=443,
        version=2,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _exchange_row(**overrides: object) -> SimpleNamespace:
    base = {
        "id": "e1",
        "tenant_id": "tn",
        "project_id": "p1",
        "tab_id": "t1",
        "raw_request": b"GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
        "forward_outcome": "forward",
        "block_reason": None,
        "status_code": 200,
        "raw_response": b"HTTP/1.1 200 OK\r\n\r\nok",
        "response_size": 21,
        "truncated": False,
        "duration_ms": 12,
        "created_at": _NOW,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_tab_to_dto_encodes_raw() -> None:
    dto = _tab_to_dto(_tab_row())
    assert dto.name == "login"
    assert dto.host == "app.example.com"
    assert base64.b64decode(dto.raw_request_base64).startswith(b"POST /login")


def test_exchange_to_dto_includes_raw_on_detail() -> None:
    dto = _exchange_to_dto(_exchange_row(), include_raw=True)
    assert dto.forward_outcome == "forward"
    assert dto.status_code == 200
    assert dto.raw_request_base64 is not None
    assert base64.b64decode(dto.raw_response_base64 or "").endswith(b"ok")


def test_exchange_to_dto_omits_raw_in_list() -> None:
    dto = _exchange_to_dto(_exchange_row(), include_raw=False)
    assert dto.raw_request_base64 is None
    assert dto.raw_response_base64 is None
    assert dto.response_size == 21  # metadata still present


def test_exchange_to_dto_blocked_has_no_response() -> None:
    dto = _exchange_to_dto(
        _exchange_row(
            forward_outcome="blocked",
            block_reason="out_of_scope",
            status_code=None,
            raw_response=None,
            response_size=0,
            duration_ms=None,
        ),
        include_raw=True,
    )
    assert dto.forward_outcome == "blocked"
    assert dto.block_reason == "out_of_scope"
    assert dto.status_code is None
    assert dto.raw_response_base64 is None


def test_derive_target_metadata_absolute_and_origin_form() -> None:
    scheme, host, port = _derive_target_metadata(
        b"GET https://app.example.com/x HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
    )
    assert (scheme, host, port) == ("https", "app.example.com", 443)

    scheme2, host2, port2 = _derive_target_metadata(
        b"GET /x HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
    )
    assert (scheme2, host2, port2) == ("https", "app.example.com", 443)


def test_derive_target_metadata_malformed_is_none() -> None:
    assert _derive_target_metadata(b"not a valid request") == (None, None, None)
