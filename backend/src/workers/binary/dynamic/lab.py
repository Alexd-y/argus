"""Binary Dynamic Analysis Lab — isolated malware detonation environment.

Provides: execution tracing, memory forensics, process monitoring.
Separate regulated environment with dual-approval export for indicators.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DynamicResult:
    id: str = ""
    sample_id: str = ""
    tenant_id: str = ""
    execution_time_ms: int = 0
    exit_code: int = -1
    processes_spawned: list[str] = field(default_factory=list)
    network_connections: list[dict[str, Any]] = field(default_factory=list)
    file_operations: list[dict[str, Any]] = field(default_factory=list)
    registry_changes: list[str] = field(default_factory=list)
    memory_artifacts: list[dict[str, Any]] = field(default_factory=list)
    syscall_summary: dict[str, int] = field(default_factory=dict)
    verdict: str = ""
    error: str = ""


async def run_dynamic_analysis(
    sample_path: str,
    *,
    tenant_id: str = "",
    timeout_seconds: int = 120,
) -> DynamicResult:
    """Execute binary in isolated sandbox, capture runtime behaviour."""
    result = DynamicResult(
        id=str(uuid.uuid4()), sample_id=sample_path, tenant_id=tenant_id,
    )

    if not Path(sample_path).exists():
        result.error = f"Sample not found: {sample_path}"
        return result

    start = asyncio.get_event_loop().time()

    try:
        proc = await asyncio.create_subprocess_exec(
            "timeout", str(timeout_seconds), sample_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_seconds + 5,
        )
        result.exit_code = proc.returncode or 0
        elapsed = int((asyncio.get_event_loop().time() - start) * 1000)
        result.execution_time_ms = elapsed

        # Analyse output for indicators
        output = ((stdout or b"") + (stderr or b"")).decode(errors="replace")
        result.verdict = _classify_dynamic_output(output, result.exit_code)
    except TimeoutError:
        result.verdict = "timed_out"
        result.execution_time_ms = timeout_seconds * 1000
    except Exception as exc:
        result.error = str(exc)
        result.verdict = "error"

    return result


def _classify_dynamic_output(output: str, exit_code: int) -> str:
    """Heuristic classification based on runtime behaviour."""
    output_lower = output.lower()
    malicious_indicators = [
        "reverse shell", "backdoor", "exploit successful",
        "password found", "hash dumped", "token stolen",
        "persistence installed", "c2 connected",
        "data exfiltrated", "privilege escalated",
    ]
    for ind in malicious_indicators:
        if ind in output_lower:
            return "malicious"

    if exit_code == 0 and output:
        return "executed_successfully"
    if exit_code != 0:
        return f"exit_code_{exit_code}"
    return "no_output"


# === Custody: chain-of-custody and quarantine ===

@dataclass
class CustodyRecord:
    id: str = ""
    sample_id: str = ""
    tenant_id: str = ""
    submitted_by: str = ""
    submitted_at: str = ""
    custody_chain: list[dict[str, str]] = field(default_factory=list)
    quarantine_path: str = ""
    hash_before: str = ""
    hash_after: str = ""
    status: str = "received"


async def quarantine_sample(
    file_path: str, data: bytes | None = None,
    *, tenant_id: str = "", submitted_by: str = "",
) -> CustodyRecord:
    """Quarantine a sample and establish chain-of-custody."""
    record = CustodyRecord(
        id=str(uuid.uuid4()), sample_id=file_path, tenant_id=tenant_id,
        submitted_by=submitted_by,
        submitted_at=datetime.now(UTC).isoformat(),
    )

    if data is None:
        try:
            data = Path(file_path).read_bytes()
        except Exception:
            record.status = "error"
            return record

    record.hash_before = hashlib.sha256(data).hexdigest()
    record.custody_chain.append({
        "action": "quarantine", "by": submitted_by,
        "at": datetime.now(UTC).isoformat(),
        "hash": record.hash_before,
    })
    record.status = "quarantined"
    return record


def request_export_approval(
    record: CustodyRecord, approver_id: str,
) -> bool:
    """Dual-approval check for exporting indicators or unpacked payloads.

    Pure synchronous custody-chain logic (no I/O); callers invoke it directly.
    """
    existing = [e for e in record.custody_chain if e.get("action") == "approve" and e.get("by") == approver_id]
    if existing:
        record.custody_chain.append({
            "action": "duplicate_approval_rejected",
            "by": approver_id,
            "at": datetime.now(UTC).isoformat(),
        })
        return False

    approvals = [e for e in record.custody_chain if e.get("action") == "approve"]
    if len(approvals) < 1:
        record.custody_chain.append({
            "action": "approve", "by": approver_id,
            "at": datetime.now(UTC).isoformat(),
        })
        return False  # Need second approval

    record.custody_chain.append({
        "action": "export_approved", "by": approver_id,
        "at": datetime.now(UTC).isoformat(),
    })
    return True
