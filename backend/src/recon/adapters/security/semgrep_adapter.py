"""Semgrep adapter — SAST (static application security testing)."""

import json
import logging
from typing import Any

from src.recon.adapters.security.base import SecurityToolAdapter
from src.recon.schemas.base import FindingType

logger = logging.getLogger(__name__)


class SemgrepAdapter(SecurityToolAdapter):
    """Adapter for Semgrep — SAST for code security issues."""

    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def command_name(self) -> str:
        return "semgrep"

    @property
    def supported_stages(self) -> list[int]:
        return [10]  # JS_ANALYSIS / code analysis

    async def build_command(self, target: str, config: dict[str, Any]) -> list[str]:
        path = target.strip() or "."
        cmd = ["semgrep", "scan", "--json", path]
        if config.get("config"):
            cmd.extend(["--config", config["config"]])
        if config.get("severity"):
            cmd.extend(["--severity", config["severity"]])
        return cmd

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse Semgrep JSON output."""
        results: list[dict[str, Any]] = []
        raw = raw_output.strip()
        if not raw:
            return results
        try:
            data = json.loads(raw)
            results = data.get("results", [])
        except json.JSONDecodeError:
            pass
        return results

    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Normalize to VULNERABILITY findings."""
        findings: list[dict[str, Any]] = []
        for item in raw_results:
            check_id = item.get("check_id", "unknown")
            path = item.get("path", "")
            extra = item.get("extra", {})
            message = extra.get("message", "")
            severity = extra.get("severity", "WARNING")
            start = item.get("start", {})
            line = start.get("line", 0)
            value = f"{path}:{line}:{check_id}"
            findings.append({
                "finding_type": FindingType.VULNERABILITY,
                "value": value,
                "data": {
                    "rule_id": check_id,
                    "file_path": path,
                    "line": line,
                    "message": message,
                    "severity": severity,
                    "category": extra.get("metadata", {}).get("category"),
                },
                "source_tool": "semgrep",
                "confidence": 0.9,
            })
        return findings
