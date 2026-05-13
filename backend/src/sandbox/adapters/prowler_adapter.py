"""Prowler cloud scan adapter (cloud category §4.15)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class ProwlerAdapter(ShellToolAdapter):
    """Adapter for ``prowler`` — AWS multi-compliance posture scan.

    ``tool_id=prowler``, category=cloud, requires_approval=True.
    Parser: :func:`src.sandbox.parsers.prowler_parser.parse_prowler_json`.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
