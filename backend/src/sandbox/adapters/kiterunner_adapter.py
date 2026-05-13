"""Kiterunner API route brute adapter (API / web VA category §4.5)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class KiterunnerAdapter(ShellToolAdapter):
    """Adapter for ``kiterunner`` — API route discovery via wordlists.

    ``tool_id=kiterunner``, category=web_va, requires_approval=False.
    Parser: :func:`src.sandbox.parsers.ffuf_parser.parse_ffuf_json`.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
