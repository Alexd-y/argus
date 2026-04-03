"""Terrascan adapter — IaC security."""

import json
from typing import Any

from src.recon.adapters.security.base import SecurityToolAdapter
from src.recon.schemas.base import FindingType


def _map_terrascan_severity(raw: str | None) -> str:
    if not raw:
        return "medium"
    s = str(raw).upper()
    mapping = {
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "CRITICAL": "critical",
    }
    return mapping.get(s, "medium")


class TerrascanAdapter(SecurityToolAdapter):
    """Adapter for Terrascan — violations from JSON ``results.violations``."""

    @property
    def name(self) -> str:
        return "terrascan"

    @property
    def command_name(self) -> str:
        return "terrascan"

    @property
    def supported_stages(self) -> list[int]:
        return [12]

    async def build_command(self, target: str, _config: dict[str, Any]) -> list[str]:
        return ["terrascan", "scan", "-d", target or ".", "-o", "json"]

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        raw = raw_output.strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        results = data.get("results")
        violations: list[Any] = []
        if isinstance(results, dict):
            v = results.get("violations")
            if isinstance(v, list):
                violations = v
        elif isinstance(results, list):
            for block in results:
                if isinstance(block, dict):
                    v = block.get("violations")
                    if isinstance(v, list):
                        violations.extend(v)
        return [x for x in violations if isinstance(x, dict)]

    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for item in raw_results:
            rule = item.get("rule_name") or item.get("ruleName") or "unknown"
            sev = _map_terrascan_severity(item.get("severity"))
            fpath = item.get("file_name") or item.get("fileName") or ""
            line = item.get("line") or 0
            value = f"{fpath}:{line}:{rule}"
            findings.append({
                "finding_type": FindingType.MISCONFIGURATION,
                "value": value,
                "data": {
                    "title": str(rule),
                    "severity": sev,
                    "category": item.get("category") or item.get("type"),
                    "file_path": fpath,
                    "line": line,
                    "cwe": "CWE-1032",
                },
                "source_tool": "terrascan",
                "confidence": 0.85,
            })
        return findings
