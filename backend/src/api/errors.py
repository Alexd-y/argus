"""Unified machine-readable API error helpers.

The canonical contract error body used across scans/reports endpoints is the
flat ``{"error", "code", "details"}`` shape already produced by
``src.core.exception_handlers`` (the Frontend is the source of truth for this
shape). This module adds:

* a stable way to turn a :class:`~src.profiles.errors.ArgusProfileError` into
  that contract body (with a ``correlation_id``), and
* an exception handler so those errors are rendered consistently even when they
  bubble up uncaught.

No stack traces or secrets are ever included in the response body.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from src.core.api_contract_paths import is_frontend_contract_path
from src.profiles.errors import ArgusProfileError

logger = logging.getLogger(__name__)


def new_correlation_id() -> str:
    return str(uuid.uuid4())


def _correlation_from_request(request: Request | None) -> str:
    if request is not None:
        header = request.headers.get("x-correlation-id") or request.headers.get("x-request-id")
        if header and header.strip():
            return header.strip()[:64]
    return new_correlation_id()


def argus_error_body(exc: ArgusProfileError, *, correlation_id: str) -> dict[str, Any]:
    """Flat contract body compatible with the existing scans/reports handler."""
    details = dict(exc.details) if exc.details else {}
    details.setdefault("correlation_id", correlation_id)
    return {
        "error": exc.message,
        "code": exc.code,
        "details": details,
        "correlation_id": correlation_id,
    }


def argus_error_to_http(
    exc: ArgusProfileError, *, correlation_id: str | None = None
) -> HTTPException:
    """Convert an ArgusProfileError to an HTTPException the contract handler renders."""
    cid = correlation_id or new_correlation_id()
    return HTTPException(status_code=exc.http_status, detail=argus_error_body(exc, correlation_id=cid))


async def argus_profile_exception_handler(
    request: Request, exc: ArgusProfileError
) -> JSONResponse:
    """Render ArgusProfileError as the flat contract body + correlation_id."""
    cid = _correlation_from_request(request)
    body = argus_error_body(exc, correlation_id=cid)
    logger.info(
        "argus_profile_error",
        extra={
            "event": "argus_profile_error",
            "code": exc.code,
            "correlation_id": cid,
            "path": request.url.path,
        },
    )
    if not is_frontend_contract_path(request.url.path):
        # Non-contract paths still get a safe machine-readable body.
        return JSONResponse(status_code=exc.http_status, content=body)
    return JSONResponse(status_code=exc.http_status, content=body)


def register_profile_error_handler(app: FastAPI) -> None:
    app.add_exception_handler(ArgusProfileError, argus_profile_exception_handler)


__all__ = [
    "argus_error_body",
    "argus_error_to_http",
    "argus_profile_exception_handler",
    "new_correlation_id",
    "register_profile_error_handler",
]
