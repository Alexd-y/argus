"""Nmap full TCP scan adapter (network category §4.2)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class NmapFullAdapter(ShellToolAdapter):
    """Adapter for ``nmap_tcp_full`` — full 65535-port TCP SYN scan.

    ``tool_id=nmap_tcp_full``, category=network, requires_approval=False.
    Parser: :func:`src.sandbox.parsers.nmap_parser.parse_nmap_xml`.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
