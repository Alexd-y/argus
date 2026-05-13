"""OpenAPI security scanner adapter (API / web VA category §4.14)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class OpenapiScannerAdapter(ShellToolAdapter):
    """Adapter for ``openapi_scanner`` — Swagger/OpenAPI schema walker.

    ``tool_id=openapi_scanner``, category=web_va, requires_approval=False.
    Parser: :func:`src.sandbox.parsers.openapi_scanner_parser.parse_openapi_scanner_json`.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
