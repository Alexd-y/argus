"""Unit tests for organizer contracts + ORM→DTO mapping (WB-P3c)."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
from types import SimpleNamespace

from src.web_workbench.contracts.organizer import OrganizerItemCreate
from src.web_workbench.organizer.repository import _collection_to_dto, _item_to_dto

_NOW = datetime(2026, 7, 22, 12, 0, tzinfo=UTC)


def _collection_row() -> SimpleNamespace:
    return SimpleNamespace(
        id="c1",
        tenant_id="t1",
        project_id="p1",
        name="Auth flows",
        description="saved logins",
        version=3,
        created_at=_NOW,
        updated_at=_NOW,
    )


def _item_row(**overrides: object) -> SimpleNamespace:
    base = {
        "id": "i1",
        "tenant_id": "t1",
        "project_id": "p1",
        "collection_id": "c1",
        "title": "Login request",
        "method": "POST",
        "host": "app.example.com",
        "url": "https://app.example.com/login",
        "notes": None,
        "tags": ["auth", "login"],
        "raw_request": b"POST /login HTTP/1.1\r\n\r\n",
        "raw_response": None,
        "source_message_id": "m9",
        "version": 1,
        "created_at": _NOW,
        "updated_at": _NOW,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_collection_to_dto() -> None:
    dto = _collection_to_dto(_collection_row())
    assert dto.id == "c1"
    assert dto.name == "Auth flows"
    assert dto.version == 3


def test_item_to_dto_includes_raw_when_requested() -> None:
    dto = _item_to_dto(_item_row(), include_raw=True)
    assert dto.tags == ("auth", "login")
    assert dto.has_raw_request is True
    assert dto.has_raw_response is False
    assert dto.raw_request_base64 == base64.b64encode(b"POST /login HTTP/1.1\r\n\r\n").decode()
    assert dto.raw_response_base64 is None
    assert dto.source_message_id == "m9"


def test_item_to_dto_omits_raw_in_list_view() -> None:
    dto = _item_to_dto(_item_row(), include_raw=False)
    # Flags still reflect presence, but the bytes are withheld from list views.
    assert dto.has_raw_request is True
    assert dto.raw_request_base64 is None


def test_item_to_dto_handles_null_tags() -> None:
    dto = _item_to_dto(_item_row(tags=None), include_raw=False)
    assert dto.tags == ()


def test_normalized_tags_dedup_trim_and_drop_empty() -> None:
    create = OrganizerItemCreate(
        title="x",
        tags=("  auth  ", "auth", "login", "   ", "x" * 100),
    )
    tags = create.normalized_tags()
    assert tags[0] == "auth"
    assert "login" in tags
    assert tags.count("auth") == 1  # de-duplicated after trimming
    assert "" not in tags  # whitespace-only dropped
    assert all(len(t) <= 64 for t in tags)  # length-capped
