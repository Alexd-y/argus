"""JoomScan Joomla scanner adapter (CMS category §4.7)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class JoomscanAdapter(ShellToolAdapter):
    """Adapter for ``joomscan`` — OWASP Joomla component enumeration.

    ``tool_id=joomscan``, category=web_va, requires_approval=False.
    Parser: ``parse_discovery_text_lines`` via TEXT_LINES handler.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
