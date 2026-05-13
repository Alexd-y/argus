"""Amass subdomain enumeration adapter (recon category §4.1)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class AmassAdapter(ShellToolAdapter):
    """Adapter for ``amass_passive`` — OWASP Amass passive OSINT enumeration.

    ``tool_id=amass_passive``, category=recon, requires_approval=False.
    Parser: :func:`src.sandbox.parsers.amass_passive_parser.parse_amass_passive`.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
