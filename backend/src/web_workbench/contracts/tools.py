"""Contracts for stateless workbench tools — Decoder + Comparer (WB-P3a).

Binary payloads travel as standard base64 so arbitrary bytes survive JSON
transport unambiguously. Inputs are size-capped; decoder step lists are bounded.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from src.web_workbench.comparer.engine import DiffKind

#: Max base64-encoded input length (~2 MiB of raw bytes after decoding).
_MAX_B64_LEN = 3 * 1024 * 1024
_MAX_STEPS = 32


class DecoderStepDTO(BaseModel):
    """One decoder operation + its string-valued options (no inline secrets)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    operation: StrictStr = Field(min_length=1, max_length=32)
    options: dict[StrictStr, StrictStr] = Field(default_factory=dict, max_length=8)


class DecoderRequest(BaseModel):
    """Run a chain of transforms over base64-encoded input bytes."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    input_base64: StrictStr = Field(min_length=0, max_length=_MAX_B64_LEN)
    steps: tuple[DecoderStepDTO, ...] = Field(default=(), max_length=_MAX_STEPS)


class DecoderResponse(BaseModel):
    """Transform output — always base64; UTF-8 preview when losslessly decodable."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    output_base64: StrictStr
    output_utf8: StrictStr | None
    operations_applied: StrictInt = Field(ge=0)


class ComparerRequest(BaseModel):
    """Compare two base64-encoded payloads with the given diff mode."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    left_base64: StrictStr = Field(min_length=0, max_length=_MAX_B64_LEN)
    right_base64: StrictStr = Field(min_length=0, max_length=_MAX_B64_LEN)
    kind: DiffKind = DiffKind.LINE


class DiffSegmentDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    op: StrictStr
    a: StrictStr
    b: StrictStr


class ComparerResponse(BaseModel):
    """Structured diff result (JSON-safe; never raw payload re-parsing needed)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: StrictStr
    identical: StrictBool
    inserted: StrictInt = Field(ge=0)
    deleted: StrictInt = Field(ge=0)
    replaced: StrictInt = Field(ge=0)
    segments: tuple[DiffSegmentDTO, ...]


class MessageFormatRequest(BaseModel):
    """Render raw HTTP bytes into pretty + hex views (byte-exact source)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    raw_base64: StrictStr = Field(min_length=0, max_length=_MAX_B64_LEN)
    message_kind: Literal["request", "response"] = "request"


class HeaderDTO(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr
    value: StrictStr


class MessageFormatResponse(BaseModel):
    """Derived, read-only projections of a raw message (never mutates source)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    valid: StrictBool
    error: StrictStr | None
    start_line: StrictStr | None
    headers: tuple[HeaderDTO, ...]
    pretty: StrictStr | None
    hex_dump: StrictStr
    body_size: StrictInt = Field(ge=0)


__all__ = [
    "ComparerRequest",
    "ComparerResponse",
    "DecoderRequest",
    "DecoderResponse",
    "DecoderStepDTO",
    "DiffSegmentDTO",
    "HeaderDTO",
    "MessageFormatRequest",
    "MessageFormatResponse",
]
