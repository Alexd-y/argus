"""Continuous re-verification — client merges fix → ARGUS re-scans → marks closed.

After a client applies a patch, this module re-scans the specific vulnerability
and marks it as verified-fixed if the issue is resolved, or re-opens it if not.

Ось E п.2 из Развитие2.md: continuous re-verification.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ReVerificationRequest:
    """Request to re-verify a previously found vulnerability."""

    finding_id: str
    scan_id: str
    original_cwe: str
    original_endpoint: str
    original_payload: str = ""
    patch_description: str = ""
    requested_by: str = ""


@dataclass
class ReVerificationResult:
    """Result of re-verifying a vulnerability after patch."""

    finding_id: str
    status: str
    still_vulnerable: bool
    verification_attempts: int = 1
    verified_fixed_at: str = ""
    details: str = ""
    re_scan_id: str = ""


class ReVerificationTracker:
    """Tracks the lifecycle of vulnerability re-verifications."""

    def __init__(self) -> None:
        self._history: dict[str, list[ReVerificationResult]] = {}

    async def re_verify(
        self,
        request: ReVerificationRequest,
        scanner_func: Any = None,
    ) -> ReVerificationResult:
        """Re-verify a finding. If scanner_func provided, actually re-scan."""
        still_vulnerable = True
        details = ""

        if scanner_func is not None:
            try:
                result = await scanner_func(request)
                still_vulnerable = result.get("vulnerable", True)
                details = result.get("details", "")
            except Exception as exc:
                logger.warning("Re-verification scan failed: %s", exc)
                details = f"Scan error: {exc}"

        status = "still_vulnerable" if still_vulnerable else "verified_fixed"
        verified_fixed_at = ""
        if not still_vulnerable:
            verified_fixed_at = datetime.now(timezone.utc).isoformat()

        rv_result = ReVerificationResult(
            finding_id=request.finding_id,
            status=status,
            still_vulnerable=still_vulnerable,
            verified_fixed_at=verified_fixed_at,
            details=details,
        )

        self._history.setdefault(request.finding_id, []).append(rv_result)
        return rv_result

    def get_history(self, finding_id: str) -> list[ReVerificationResult]:
        return self._history.get(finding_id, [])

    def get_latest(self, finding_id: str) -> ReVerificationResult | None:
        history = self._history.get(finding_id, [])
        return history[-1] if history else None


__all__ = [
    "ReVerificationRequest",
    "ReVerificationResult",
    "ReVerificationTracker",
]