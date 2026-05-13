"""ZAP baseline scan adapter (web VA category §4.8)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class ZAPBaselineAdapter(ShellToolAdapter):
    """Adapter for ``zap_baseline`` — OWASP ZAP passive-only web scan.

    ``tool_id=zap_baseline``, category=web_va, requires_approval=False.
    Parser: :func:`src.sandbox.parsers.zap_baseline_parser.parse_zap_baseline_json`.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
