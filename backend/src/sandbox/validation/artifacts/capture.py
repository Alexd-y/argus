"""Sandbox artifact capture — logs, traces, screenshots, evidence bundles."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


async def capture_logs(container_id: str, lines: int = 200) -> list[str]:
    """Capture recent container logs."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "docker", "logs", "--tail", str(lines), container_id,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
        logs = []
        for line in (stdout or b"").decode(errors="replace").splitlines():
            logs.append(f"[stdout] {line[:500]}")
        for line in (stderr or b"").decode(errors="replace").splitlines():
            logs.append(f"[stderr] {line[:500]}")
        return logs
    except Exception as exc:
        return [f"log capture error: {exc}"]


def build_evidence_bundle(
    validation_id: str,
    finding_id: str,
    result: dict[str, Any],
    logs: list[str],
    syscalls: list[dict[str, Any]],
    network_captures: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a structured evidence bundle for a validation run."""
    bundle = {
        "validation_id": validation_id,
        "finding_id": finding_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_hash": hashlib.blake2b(
            json.dumps(result, sort_keys=True, default=str).encode(),
            digest_size=16,
        ).hexdigest(),
        "exploitability": {
            "exploitable": result.get("exploitable", False),
            "confidence": result.get("confidence", 0.0),
            "exit_code": result.get("exit_code", -1),
        },
        "outputs": {
            "stdout_preview": (result.get("stdout", "") or "")[:2000],
            "stderr_preview": (result.get("stderr", "") or "")[:1000],
        },
        "artifacts": {
            "log_line_count": len(logs),
            "syscall_event_count": len(syscalls),
            "network_packet_count": len(network_captures),
        },
        "logs": logs[:100],
        "syscalls": syscalls[:50],
        "network": network_captures[:50],
    }
    return bundle


def sign_evidence(evidence: dict[str, Any], signing_key: str = "") -> dict[str, Any]:
    """Sign evidence bundle with HMAC for chain-of-custody.

    Without a signing key, uses content hash only.
    """
    content = json.dumps(evidence, sort_keys=True, default=str)
    if signing_key:
        import hmac
        signature = hmac.new(
            signing_key.encode(), content.encode(), hashlib.sha256
        ).hexdigest()
    else:
        signature = hashlib.sha256(content.encode()).hexdigest()

    return {
        **evidence,
        "signature": signature,
        "signing_method": "hmac-sha256" if signing_key else "sha256",
    }
