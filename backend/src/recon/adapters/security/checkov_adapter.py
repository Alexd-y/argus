"""Checkov adapter — IaC security (Terraform, etc.)."""

import json
from typing import Any

from src.recon.adapters.security.base import SecurityToolAdapter
from src.recon.schemas.base import FindingType


def _map_checkov_severity(raw: str | None) -> str:
    if not raw:
        return "medium"
    s = str(raw).upper()
    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info",
        "UNKNOWN": "medium",
    }
    return mapping.get(s, "medium")


class CheckovAdapter(SecurityToolAdapter):
    """Adapter for Checkov — IaC policy failures from JSON ``failed_checks``."""

    @property
    def name(self) -> str:
        return "checkov"

    @property
    def command_name(self) -> str:
        return "checkov"

    @property
    def supported_stages(self) -> list[int]:
        return [12]

    async def build_command(self, target: str, _config: dict[str, Any]) -> list[str]:
        return ["checkov", "-d", target or ".", "--output", "json"]

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        raw = raw_output.strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        results = data.get("results")
        if not isinstance(results, dict):
            return []
        failed = results.get("failed_checks")
        if not isinstance(failed, list):
            return []
        return [x for x in failed if isinstance(x, dict)]

    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for item in raw_results:
            cid = item.get("check_id") or item.get("checkId") or "unknown"
            name = item.get("check_name") or item.get("checkName") or cid
            title = f"{cid}: {name}" if name != cid else str(cid)
            sev = _map_checkov_severity(
                item.get("severity")
                or item.get("check_severity")
                or item.get("evaluation_status")
            )
            fpath = item.get("file_path") or item.get("filePath") or ""
            start = item.get("file_line_range") or item.get("fileLineRange") or []
            line = start[0] if isinstance(start, list) and start else 0
            value = f"{fpath}:{line}:{cid}"
            findings.append({
                "finding_type": FindingType.MISCONFIGURATION,
                "value": value,
                "data": {
                    "title": title,
                    "severity": sev,
                    "check_id": cid,
                    "file_path": fpath,
                    "line": line,
                    "cwe": "CWE-1032",
                },
                "source_tool": "checkov",
                "confidence": 0.85,
            })
        return findings
