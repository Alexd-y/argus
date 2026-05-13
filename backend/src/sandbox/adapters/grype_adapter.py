"""Grype vulnerability scan adapter (SCA category §4.15)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class GrypeAdapter(ShellToolAdapter):
    """Adapter for ``grype`` — Anchore container image SCA scanner.

    ``tool_id=grype``, category=cloud, requires_approval=False.
    Parser: :func:`src.sandbox.parsers.grype_parser.parse_grype_json`.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
