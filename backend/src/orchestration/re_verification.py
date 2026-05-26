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
    still_vulnerable: bool | None
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
        """Re-verify a finding. Uses scanner_func if provided, otherwise
        attempts a lightweight HTTP re-check of the original endpoint.

        If neither scanner_func nor original_endpoint is available,
        records as 'unverified' rather than assuming still_vulnerable.
        """
        still_vulnerable: bool | None = None
        details = ""

        if scanner_func is not None:
            try:
                result = await scanner_func(request)
                still_vulnerable = result.get("vulnerable", True)
                details = result.get("details", "")
            except Exception as exc:
                logger.warning("Re-verification scan failed: %s", exc)
                details = f"Scan error: {exc}"
                still_vulnerable = True
        elif request.original_endpoint:
            try:
                import httpx
                async with httpx.AsyncClient(timeout=15.0, follow_redirects=True, verify=False) as client:
                    resp = await client.get(request.original_endpoint)
                still_vulnerable = 200 <= resp.status_code < 500
                details = f"HTTP {resp.status_code} on {request.original_endpoint}"
            except Exception as exc:
                logger.debug("re_verify_http_probe_failed: %s", exc)
                still_vulnerable = None
                details = f"HTTP probe failed: {exc}"
        else:
            logger.info(
                "re_verify_no_scanner",
                extra={"finding_id": request.finding_id},
            )
            still_vulnerable = None
            details = "No scanner function provided and no endpoint to probe — verification not performed"

        if still_vulnerable is None:
            status = "unverified"
        elif still_vulnerable:
            status = "still_vulnerable"
        else:
            status = "verified_fixed"

        verified_fixed_at = ""
        if status == "verified_fixed":
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