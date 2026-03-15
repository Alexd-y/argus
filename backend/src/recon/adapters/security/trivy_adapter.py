"""Trivy adapter — container/image vulnerability scan."""

import json
import logging
from typing import Any

from src.recon.adapters.security.base import SecurityToolAdapter
from src.recon.schemas.base import FindingType

logger = logging.getLogger(__name__)


class TrivyAdapter(SecurityToolAdapter):
    """Adapter for Trivy — scan containers and images for vulnerabilities."""

    @property
    def name(self) -> str:
        return "trivy"

    @property
    def command_name(self) -> str:
        return "trivy"

    @property
    def supported_stages(self) -> list[int]:
        return [12]  # PORT_SCANNING / infra scan

    async def build_command(self, target: str, config: dict[str, Any]) -> list[str]:
        scan_type = config.get("scan_type", "image")
        target_str = target.strip() or "."
        cmd = ["trivy", scan_type, target_str, "--format", "json", "--scanners", "vuln"]
        if config.get("severity"):
            cmd.extend(["--severity", config["severity"]])
        if config.get("ignore_unfixed"):
            cmd.append("--ignore-unfixed")
        return cmd

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse Trivy JSON output."""
        results: list[dict[str, Any]] = []
        raw = raw_output.strip()
        if not raw:
            return results
        try:
            data = json.loads(raw)
            for result in data.get("Results", []):
                target_name = result.get("Target", "")
                for vuln in result.get("Vulnerabilities", []):
                    vuln["_target"] = target_name
                    results.append(vuln)
        except json.JSONDecodeError:
            pass
        return results

    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Normalize to VULNERABILITY findings."""
        findings: list[dict[str, Any]] = []
        for item in raw_results:
            vuln_id = item.get("VulnerabilityID", item.get("ID", "unknown"))
            pkg = item.get("PkgName", item.get("PackageName", ""))
            installed = item.get("InstalledVersion", "")
            severity = item.get("Severity", "UNKNOWN")
            target_name = item.get("_target", "")
            value = f"{target_name}:{pkg}:{vuln_id}"
            findings.append({
                "finding_type": FindingType.VULNERABILITY,
                "value": value,
                "data": {
                    "vulnerability_id": vuln_id,
                    "package": pkg,
                    "installed_version": installed,
                    "fixed_version": item.get("FixedVersion"),
                    "severity": severity,
                    "title": item.get("Title"),
                    "target": target_name,
                },
                "source_tool": "trivy",
                "confidence": 0.95,
            })
        return findings
