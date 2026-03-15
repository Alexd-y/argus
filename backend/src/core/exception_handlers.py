"""Global exception handlers — never expose tracebacks or internal details to users."""

import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.core.config import settings

logger = logging.getLogger(__name__)

GENERIC_ERROR_MESSAGE = "An unexpected error occurred. Please try again later."


def _cors_headers_for_request(request: Request) -> dict[str, str]:
    """Add Access-Control-Allow-Origin to 500 responses so browser doesn't block on CORS."""
    allowed = settings.get_cors_origins_list()
    origin = request.headers.get("origin", "").strip()
    if origin and origin in allowed:
        return {"Access-Control-Allow-Origin": origin}
    if allowed:
        return {"Access-Control-Allow-Origin": allowed[0]}
    return {}


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
    return JSONResponse(
        status_code=500,
        content={"detail": GENERIC_ERROR_MESSAGE},
        headers=headers,
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Register security-safe exception handlers on the FastAPI app."""
    app.add_exception_handler(Exception, generic_exception_handler)
