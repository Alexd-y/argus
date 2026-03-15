"""Gitleaks adapter — secrets in repos."""

import asyncio
import json
import logging
import os
import shlex
import tempfile
from typing import Any

from src.core.config import settings
from src.recon.adapters.security.base import SecurityToolAdapter
from src.tools.executor import execute_command
from src.recon.schemas.base import FindingType

logger = logging.getLogger(__name__)


class GitleaksAdapter(SecurityToolAdapter):
    """Adapter for Gitleaks — detect secrets in repositories."""

    @property
    def name(self) -> str:
        return "gitleaks"

    @property
    def command_name(self) -> str:
        return "gitleaks"

    @property
    def supported_stages(self) -> list[int]:
        return [10]  # JS_ANALYSIS / code analysis

    async def build_command(self, target: str, config: dict[str, Any]) -> list[str]:
        path = target.strip() or "."
        if not os.path.isabs(path):
            path = os.path.abspath(path)
        cmd = [
            "gitleaks",
            "detect",
            "--source", path,
            "--no-git",
            "--report-format", "json",
        ]
        report_path = config.get("report_path")
        if report_path:
            cmd.extend(["--report-path", report_path])
        return cmd

    async def run(self, target: str, config: dict[str, Any]) -> list[dict[str, Any]]:
        """Override: Gitleaks writes to file, not stdout."""
        if config.get("raw_output"):
            result = await self.execute(
                target=target,
                config={"raw_output": config["raw_output"]},
                scope_validator=None,
            )
            return result.normalized_findings

        if self._should_skip(config):
            return []

        path = target.strip() or "."
        if not os.path.isabs(path):
            path = os.path.abspath(path)
        if not os.path.isdir(path):
            return []

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            report_path = f.name
        try:
            cfg = {**config, "report_path": report_path}
            cmd_parts = await self.build_command(target, cfg)
            cmd_str = " ".join(shlex.quote(p) for p in cmd_parts)
            use_sandbox = config.get("sandbox", False) and settings.sandbox_enabled

            loop = asyncio.get_event_loop()
            exec_result = await loop.run_in_executor(
                None,
                lambda: execute_command(cmd_str, use_sandbox=use_sandbox),
            )

            if os.path.exists(report_path):
                with open(report_path, encoding="utf-8") as rf:
                    raw = rf.read()
            else:
                raw = ""
        finally:
            if os.path.exists(report_path):
                try:
                    os.unlink(report_path)
                except OSError:
                    pass

        parsed = await self.parse_output(raw)
        return await self.normalize(parsed)

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse Gitleaks JSON report."""
        results: list[dict[str, Any]] = []
        raw = raw_output.strip()
        if not raw:
            return results
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                results = data
            elif isinstance(data, dict):
                results = data.get("results", data.get("findings", []))
        except json.JSONDecodeError:
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results

    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Normalize to SECRET_CANDIDATE findings."""
        findings: list[dict[str, Any]] = []
        for item in raw_results:
            rule_id = item.get("RuleID", item.get("rule_id", "unknown"))
            secret = item.get("Secret", item.get("Match", ""))
            file_path = item.get("File", item.get("file_path", ""))
            line = item.get("StartLine", item.get("line", 0))
            value_masked = secret[:8] + "***" if len(secret) > 8 else "***"
            findings.append({
                "finding_type": FindingType.SECRET_CANDIDATE,
                "value": f"{file_path}:{line}:{rule_id}",
                "data": {
                    "secret_type": rule_id,
                    "value_masked": value_masked,
                    "file_path": file_path,
                    "line": line,
                    "confidence": 0.9,
                },
                "source_tool": "gitleaks",
                "confidence": 0.9,
            })
        return findings
