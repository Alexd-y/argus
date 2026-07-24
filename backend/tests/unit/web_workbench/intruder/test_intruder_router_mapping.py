"""Offline unit tests for the Intruder router DTO mappers (WB-P4b).

The router mappers are pure functions (repository dataclass → API contract);
verifying them offline covers the base64 round-trip, position mapping and the
metadata-only result projection without needing a DB or the ``client`` fixture.
"""

from __future__ import annotations

import base64
from datetime import UTC, datetime

from src.api.routers.web_workbench.intruder import _attack_to_api, _request_to_api
from src.web_workbench.intruder.repository import IntruderAttackDTO, IntruderRequestDTO

_NOW = datetime(2026, 7, 24, 12, 0, 0, tzinfo=UTC)
_RAW = b"GET /?q={{x}} HTTP/1.1\r\nHost: app.example.com\r\n\r\n"


def _attack_row() -> IntruderAttackDTO:
    return IntruderAttackDTO(
        id="atk-1",
        tenant_id="t-1",
        project_id="p-1",
        name="atk",
        attack_type="sniper",
        status="queued",
        raw_request_template=_RAW,
        positions=[{"start": 8, "end": 13}],
        payload_config={"sets": [{"family_id": "xss_basic"}]},
        config={"max_requests": 100},
        checkpoint=None,
        requests_total=0,
        requests_completed=0,
        findings_total=0,
        error_reason=None,
        version=1,
        created_at=_NOW,
        updated_at=_NOW,
    )


def test_attack_mapper_base64_roundtrip_and_positions() -> None:
    dto = _attack_to_api(_attack_row())
    assert base64.b64decode(dto.raw_request_template_base64) == _RAW
    assert dto.positions is not None
    assert dto.positions[0].start == 8
    assert dto.positions[0].end == 13
    assert dto.payload_config == {"sets": [{"family_id": "xss_basic"}]}
    assert dto.version == 1


def test_attack_mapper_handles_null_positions() -> None:
    row = _attack_row()
    row = IntruderAttackDTO(**{**row.__dict__, "positions": None})
    dto = _attack_to_api(row)
    assert dto.positions is None


def test_request_mapper_is_metadata_only() -> None:
    row = IntruderRequestDTO(
        id="req-1",
        tenant_id="t-1",
        project_id="p-1",
        attack_id="atk-1",
        request_index=0,
        payload_label="xss_basic#p0",
        payload_index=0,
        forward_outcome="forward",
        block_reason=None,
        status_code=200,
        response_length=42,
        response_time_ms=5,
        response_sha256="a" * 64,
        flagged=True,
        error_reason=None,
        created_at=_NOW,
    )
    dto = _request_to_api(row)
    assert dto.payload_label == "xss_basic#p0"
    assert dto.flagged is True
    # The API contract carries no raw request/response body fields.
    assert not hasattr(dto, "raw_request_base64")
    assert not hasattr(dto, "raw_response_base64")
