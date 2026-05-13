"""Masscan fast port scanner adapter (network category §4.2)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class MasscanAdapter(ShellToolAdapter):
    """Adapter for ``masscan`` — high-speed TCP port discovery.

    ``tool_id=masscan``, category=network, requires_approval=False.
    Parser: :func:`src.sandbox.parsers.masscan_parser.parse_masscan_json`.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
