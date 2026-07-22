"""Web Workbench stateless tools — Decoder + Comparer (WB-P3a).

Versioned under ``/api/v1/wb/tools`` (contract in ``docs/api-contracts.md``).
These endpoints are pure/stateless (no DB, no scope): they transform or diff
caller-supplied bytes. Auth is still required (tenant context) so the tools are
not anonymously reachable. Keyed decoder operations fail-closed with 400 because
no secret resolver is wired into the HTTP surface (secrets never cross the API).
"""

from __future__ import annotations

import base64
import binascii
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from src.core.tenant import get_current_tenant_id
from src.web_workbench.comparer.engine import ComparerError, compare, result_to_dict
from src.web_workbench.contracts.tools import (
    ComparerRequest,
    ComparerResponse,
    DecoderRequest,
    DecoderResponse,
    HeaderDTO,
    MessageFormatRequest,
    MessageFormatResponse,
)
from src.web_workbench.decoder.engine import (
    DecoderError,
    TransformStep,
    run_pipeline,
)
from src.web_workbench.message_editor.engine import (
    HttpMessageError,
    RawHttpMessage,
    parse_request,
    parse_response,
    pretty_request,
    pretty_response,
)
from src.web_workbench.message_editor.engine import hex_dump as _hex_dump

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/wb/tools", tags=["web-workbench-tools"])

_Tenant = Annotated[str, Depends(get_current_tenant_id)]


def _decode_b64(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"{field} is not valid base64") from exc


@router.post("/decoder", response_model=DecoderResponse)
async def run_decoder(body: DecoderRequest, _tenant: _Tenant) -> DecoderResponse:
    """Apply an ordered transform chain to base64-encoded input bytes."""
    data = _decode_b64(body.input_base64, "input_base64")
    steps = [TransformStep(operation=s.operation, options=dict(s.options)) for s in body.steps]
    try:
        output = run_pipeline(data, steps)
    except DecoderError as exc:
        raise HTTPException(status_code=400, detail=f"decode failed: {exc}") from exc

    try:
        preview: str | None = output.decode("utf-8")
    except UnicodeDecodeError:
        preview = None

    return DecoderResponse(
        output_base64=base64.b64encode(output).decode("ascii"),
        output_utf8=preview,
        operations_applied=len(steps),
    )


@router.post("/comparer", response_model=ComparerResponse)
async def run_comparer(body: ComparerRequest, _tenant: _Tenant) -> ComparerResponse:
    """Diff two base64-encoded payloads using the requested mode."""
    left = _decode_b64(body.left_base64, "left_base64")
    right = _decode_b64(body.right_base64, "right_base64")
    try:
        result = compare(left, right, kind=body.kind)
    except ComparerError as exc:
        raise HTTPException(status_code=400, detail=f"compare failed: {exc}") from exc
    return ComparerResponse.model_validate(result_to_dict(result))


@router.post("/message-format", response_model=MessageFormatResponse)
async def format_message(body: MessageFormatRequest, _tenant: _Tenant) -> MessageFormatResponse:
    """Render raw HTTP bytes into read-only pretty + hex views.

    The hex dump is always produced (even for a malformed head); the pretty view
    and parsed head are ``None`` when the head cannot be parsed. The raw source
    bytes are never mutated.
    """
    raw = _decode_b64(body.raw_base64, "raw_base64")
    message = RawHttpMessage.from_bytes(raw)
    hex_view = _hex_dump(raw)

    try:
        if body.message_kind == "request":
            request = parse_request(raw)
            start_line = f"{request.method} {request.target} {request.http_version}"
            header_pairs = request.headers
            pretty = pretty_request(raw)
        else:
            response = parse_response(raw)
            reason = f" {response.reason}" if response.reason else ""
            start_line = f"{response.http_version} {response.status_code}{reason}"
            header_pairs = response.headers
            pretty = pretty_response(raw)
        return MessageFormatResponse(
            valid=True,
            error=None,
            start_line=start_line,
            headers=tuple(HeaderDTO(name=n, value=v) for n, v in header_pairs),
            pretty=pretty,
            hex_dump=hex_view,
            body_size=len(message.body),
        )
    except HttpMessageError as exc:
        return MessageFormatResponse(
            valid=False,
            error=str(exc),
            start_line=None,
            headers=(),
            pretty=None,
            hex_dump=hex_view,
            body_size=len(message.body),
        )


__all__ = ["router"]
