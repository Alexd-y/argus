"""JSONB serializer tolerates datetime/UUID/Decimal/Enum (phase_outputs safety)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum

from src.db.session import _json_default, _json_serializer


class _Color(Enum):
    RED = "red"


def test_datetime_serialized_iso():
    out = json.loads(_json_serializer({"t": datetime(2026, 9, 8, 4, 21, 41, tzinfo=UTC)}))
    assert out["t"].startswith("2026-09-08T04:21:41")


def test_uuid_decimal_enum_set_bytes():
    payload = {
        "id": uuid.UUID("00000000-0000-0000-0000-000000000001"),
        "amount": Decimal("1.50"),
        "color": _Color.RED,
        "tags": {"b", "a"},
        "raw": b"hi",
    }
    out = json.loads(_json_serializer(payload))
    assert out["id"] == "00000000-0000-0000-0000-000000000001"
    assert out["amount"] == 1.5
    assert out["color"] == "red"
    assert out["tags"] == ["a", "b"]
    assert out["raw"] == "hi"


def test_nested_datetime_in_exploitation_queue_like_dict():
    # Mirrors the failing phase_outputs payload: a queue dict with created_at.
    payload = {
        "exploitation_queues": {
            "web": {
                "hypotheses": [],
                "vuln_classes": [],
                "created_at": datetime(2026, 9, 8, 4, 21, 41, tzinfo=UTC),
            }
        }
    }
    # Must not raise (previously TypeError: datetime not JSON serializable).
    blob = _json_serializer(payload)
    assert "2026-09-08T04:21:41" in blob


def test_unknown_object_falls_back_to_str():
    class _Weird:
        def __str__(self):
            return "weird"

    assert _json_default(_Weird()) == "weird"
