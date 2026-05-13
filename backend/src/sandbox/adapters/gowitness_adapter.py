"""Gowitness screenshot tool adapter (browser category §4.4)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class GowitnessAdapter(ShellToolAdapter):
    """Adapter for ``gowitness`` — headless-Chrome screenshot capture.

    ``tool_id=gowitness``, category=recon, requires_approval=False.
    Parser: :func:`src.sandbox.parsers.gowitness_parser.parse_gowitness`.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
