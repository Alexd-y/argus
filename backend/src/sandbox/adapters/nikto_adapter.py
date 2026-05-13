"""Nikto web scanner adapter (web VA category §4.8)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class NiktoAdapter(ShellToolAdapter):
    """Adapter for ``nikto`` — web server scanner with ~7000 checks.

    ``tool_id=nikto``, category=web_va, requires_approval=False.
    Parser: ``parse_nikto_json`` via nuclei parser family.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
