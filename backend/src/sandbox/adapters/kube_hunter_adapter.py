"""Kube-hunter K8s security scan adapter (cloud category §4.15)."""

from __future__ import annotations

from src.sandbox.adapter_base import ShellToolAdapter, ToolDescriptor


class KubeHunterAdapter(ShellToolAdapter):
    """Adapter for ``kube_hunter`` — Aqua Kubernetes attack-surface scanner.

    ``tool_id=kube_hunter``, category=cloud, requires_approval=True.
    No per-tool parser yet — emits heartbeat until Cycle 3 wiring.
    """

    def __init__(self, descriptor: ToolDescriptor) -> None:
        super().__init__(descriptor)
