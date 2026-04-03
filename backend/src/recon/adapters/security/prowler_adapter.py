"""Prowler adapter — AWS security."""

import json
from typing import Any

from src.recon.adapters.security.base import SecurityToolAdapter
from src.recon.schemas.base import FindingType


def _map_prowler_severity(raw: str | None) -> str:
    if not raw:
        return "medium"
    s = str(raw).upper()
    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFORMATIONAL": "info",
    }
    return mapping.get(s, "medium")


class ProwlerAdapter(SecurityToolAdapter):
    """Adapter for Prowler — JSONL output, ``Status=FAIL`` checks only."""

    @property
    def name(self) -> str:
        return "prowler"

    @property
    def command_name(self) -> str:
        return "prowler"

    @property
    def supported_stages(self) -> list[int]:
        return [12]

    async def build_command(self, _target: str, _config: dict[str, Any]) -> list[str]:
        return ["prowler", "aws", "--output-format", "json"]

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            status = str(row.get("Status") or row.get("status") or "").upper()
            if status == "FAIL":
                results.append(row)
        return results

    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for item in raw_results:
            title = item.get("CheckTitle") or item.get("check_title") or item.get("check") or "unknown"
            sev = _map_prowler_severity(item.get("Severity") or item.get("severity"))
            resource = item.get("ResourceId") or item.get("resource_id") or ""
            region = item.get("Region") or item.get("region") or ""
            cid = item.get("CheckID") or item.get("check_id") or ""
            value = f"{region}:{resource}:{cid}" if resource else f"{region}:{cid}"
            findings.append({
                "finding_type": FindingType.MISCONFIGURATION,
                "value": value,
                "data": {
                    "title": str(title),
                    "severity": sev,
                    "resource_id": resource,
                    "region": region,
                    "check_id": cid,
                },
                "source_tool": "prowler",
                "confidence": 0.88,
            })
        return findings
