"""Hydra password bruteforce adapter (auth category §4.12)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class HydraAdapter(ShellToolAdapter):
    """Adapter for ``hydra`` — THC-Hydra credential bruteforce.

    ``tool_id=hydra``, category=auth, requires_approval=True.
    Parser: :func:`src.sandbox.parsers.hydra_parser.parse_hydra`.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
