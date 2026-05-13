"""Sandbox monitoring — syscall tracing, file diff, network capture."""

from __future__ import annotations

import asyncio
import logging
from typing import Any

logger = logging.getLogger(__name__)


async def trace_syscalls(
    container_id: str,
    command: str,
    *,
    timeout: int = 60,
) -> list[dict[str, str]]:
    """Trace syscalls during command execution inside sandbox container."""
    try:
        cmd = ["docker", "exec", container_id, "strace", "-f", "-e", "trace=network,file,process", "-o", "/dev/stderr", "--"] + command.split()
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        traces: list[dict[str, str]] = []
        for line in (stderr or b"").decode(errors="replace").splitlines():
            traces.append({"raw": line[:500], "source": "strace"})
        return traces
    except asyncio.TimeoutError:
        return [{"raw": "strace timed out", "source": "orchestrator"}]
    except FileNotFoundError:
        return [{"raw": "strace not available in sandbox", "source": "orchestrator"}]
    except Exception as exc:
        return [{"raw": f"strace error: {exc}", "source": "orchestrator"}]


async def capture_network_traffic(
    container_id: str,
    interface: str = "eth0",
    timeout: int = 60,
) -> list[dict[str, Any]]:
    """Capture network traffic from sandbox container.

    Uses tcpdump with allowlist-only network policy.
    Returned packets are metadata-only (no payload).
    """
    try:
        cmd = [
            "docker", "exec", container_id,
            "tcpdump", "-i", interface, "-c", "50", "-n", "-q",
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        captures: list[dict[str, Any]] = []
        for line in (stdout or b"").decode(errors="replace").splitlines():
            line = line.strip()
            if line and not line.startswith("tcpdump:"):
                captures.append({"raw": line[:300], "source": "tcpdump"})
        return captures
    except asyncio.TimeoutError:
        return [{"raw": "tcpdump timed out", "source": "orchestrator"}]
    except Exception as exc:
        return [{"raw": f"tcpdump error: {exc}", "source": "orchestrator"}]


async def get_process_telemetry(container_id: str) -> dict[str, Any]:
    """Collect process and memory telemetry from sandbox."""
    try:
        ps_proc = await asyncio.create_subprocess_exec(
            "docker", "top", container_id,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        ps_out, _ = await asyncio.wait_for(ps_proc.communicate(), timeout=10)

        stats_proc = await asyncio.create_subprocess_exec(
            "docker", "stats", container_id, "--no-stream", "--format", "json",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stats_out, _ = await asyncio.wait_for(stats_proc.communicate(), timeout=10)

        import json
        stats = {}
        if stats_out:
            try:
                stats = json.loads(stats_out.decode().strip())
            except (json.JSONDecodeError, ValueError):
                pass

        return {
            "processes": (ps_out or b"").decode(errors="replace")[:2000],
            "stats": stats,
        }
    except Exception as exc:
        return {"error": str(exc)}


class NetworkPolicyEnforcer:
    """Enforces network allowlist for validation environments."""

    @staticmethod
    def default_deny_iptables(container_id: str) -> list[str]:
        """Generate iptables commands for default-deny + allowlist DNS."""
        return [
            "iptables -P INPUT DROP",
            "iptables -P FORWARD DROP",
            "iptables -P OUTPUT DROP",
            "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT",
            "iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT",
        ]

    @staticmethod
    def allow_outbound(container_id: str, domains: list[str]) -> list[str]:
        """Generate iptables allow rules for specific domains."""
        rules = []
        for domain in domains:
            rules.append(f"iptables -A OUTPUT -d {domain} -j ACCEPT")
        return rules
