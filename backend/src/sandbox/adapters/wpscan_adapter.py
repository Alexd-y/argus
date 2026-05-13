"""WPScan WordPress scanner adapter (CMS category §4.7)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class WPScanAdapter(ShellToolAdapter):
    """Adapter for ``wpscan`` — WordPress security vulnerability scanner.

    ``tool_id=wpscan``, category=web_va, requires_approval=False.
    Parser: :func:`src.sandbox.parsers.wpscan_parser.parse_wpscan_json`.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
