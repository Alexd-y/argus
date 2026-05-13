"""Trivy filesystem scan adapter (SCA category §4.15)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class TrivyFSAdapter(ShellToolAdapter):
    """Adapter for ``trivy_fs`` — Aqua Trivy source-tree vulnerability scan.

    ``tool_id=trivy_fs``, category=cloud, requires_approval=False.
    Parser: :func:`src.sandbox.parsers.trivy_parser.parse_trivy_json`.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
