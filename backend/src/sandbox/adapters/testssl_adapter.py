"""testssl.sh TLS/SSL scanner adapter (SSL category §4.3)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class TestsslAdapter(ShellToolAdapter):
    """Adapter for ``testssl`` — comprehensive TLS/SSL audit.

    ``tool_id=testssl``, category=web_va, requires_approval=False.
    No per-tool parser yet — emits heartbeat until Cycle 3 wiring.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
