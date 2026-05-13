"""Medusa password bruteforce adapter (auth category §4.12)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class MedusaAdapter(ShellToolAdapter):
    """Adapter for ``medusa`` — parallel credential bruteforcer.

    ``tool_id=medusa``, category=auth, requires_approval=True.
    Parser: :func:`src.sandbox.parsers.medusa_parser.parse_medusa`.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
