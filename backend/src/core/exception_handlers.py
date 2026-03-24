"""Global exception handlers — never expose tracebacks or internal details to users."""

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exception_handlers import (
    http_exception_handler as default_http_exception_handler,
    request_validation_exception_handler as default_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from src.core.api_contract_paths import is_frontend_contract_path
from src.core.config import settings

logger = logging.getLogger(__name__)

GENERIC_ERROR_MESSAGE = "An unexpected error occurred. Please try again later."


def _cors_headers_for_request(request: Request) -> dict[str, str]:
    """Add Access-Control-Allow-Origin to error responses so browser doesn't block on CORS."""
    allowed = settings.get_cors_origins_list()
    origin = request.headers.get("origin", "").strip()
    if origin and origin in allowed:
        return {"Access-Control-Allow-Origin": origin}
    if allowed:
        return {"Access-Control-Allow-Origin": allowed[0]}
    return {}


def _http_detail_to_error_payload(detail: Any) -> tuple[str, str | None, Any | None]:
    """Map Starlette/FastAPI HTTPException.detail to (error, code, details)."""
    if isinstance(detail, str):
        return detail, None, None
    if isinstance(detail, list):
        return "Validation error", "validation_error", detail
    if isinstance(detail, dict):
        err = detail.get("error") or detail.get("msg") or detail.get("message")
        if isinstance(err, str):
            code = detail.get("code") if isinstance(detail.get("code"), str) else None
            det = detail.get("details")
            return err, code, det if det is not None else None
        return "Request error", None, detail
    return "Request failed", None, None


def _contract_error_response(
    request: Request,
    status_code: int,
    error: str,
    code: str | None = None,
    details: Any | None = None,
) -> JSONResponse:
    body: dict[str, Any] = {"error": error}
    if code:
        body["code"] = code
    if details is not None:
        body["details"] = details
    headers = _cors_headers_for_request(request)
    return JSONResponse(status_code=status_code, content=body, headers=headers)


async def contract_http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    """JSON {error, code?, details?} for /api/v1/scans* and /api/v1/reports*."""
    if not is_frontend_contract_path(request.url.path):
        return await default_http_exception_handler(request, exc)

    error, code, details = _http_detail_to_error_payload(exc.detail)
    return _contract_error_response(request, exc.status_code, error, code, details)


async def contract_validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """422 on scans/reports with frontend ApiError shape."""
    if not is_frontend_contract_path(request.url.path):
        return await default_validation_exception_handler(request, exc)

    return _contract_error_response(
        request,
        422,
        "Validation failed",
        "validation_error",
        jsonable_encoder(exc.errors()),
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch all unhandled exceptions; return generic message, log details internally."""
    logger.exception(
        "Unhandled exception",
        extra={
            "path": request.url.path,
            "method": request.method,
        },
    )
    headers = _cors_headers_for_request(request)
    if is_frontend_contract_path(request.url.path):
        return JSONResponse(
            status_code=500,
            content={"error": GENERIC_ERROR_MESSAGE},
            headers=headers,
        )
    return JSONResponse(
        status_code=500,
        content={"detail": GENERIC_ERROR_MESSAGE},
        headers=headers,
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register security-safe exception handlers on the FastAPI app."""
    app.add_exception_handler(StarletteHTTPException, contract_http_exception_handler)
    app.add_exception_handler(RequestValidationError, contract_validation_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)
