"""Naabu port scanner adapter (network category §4.2)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class NaabuAdapter(ShellToolAdapter):
    """Adapter for ``naabu`` — ProjectDiscovery TCP SYN port scan.

    ``tool_id=naabu``, category=network, requires_approval=False.
    Parser: :func:`src.sandbox.parsers.naabu_parser.parse_naabu_jsonl`.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
