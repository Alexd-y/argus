"""TruffleHog adapter — secrets in repos. Run in sandbox when config allows."""

import json
from typing import Any

from src.recon.adapters.security.base import SecurityToolAdapter
from src.recon.schemas.base import FindingType


class TruffleHogAdapter(SecurityToolAdapter):
    """Adapter for TruffleHog — secret scanning (JSONL output)."""

    @property
    def name(self) -> str:
        return "trufflehog"

    @property
    def command_name(self) -> str:
        return "trufflehog"

    @property
    def supported_stages(self) -> list[int]:
        return [10]

    async def build_command(self, target: str, _config: dict[str, Any]) -> list[str]:
        return ["trufflehog", "filesystem", target, "--json"]

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for line in raw_output.splitlines():
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
        findings: list[dict[str, Any]] = []
        for item in raw_results:
            detector = item.get("DetectorName") or item.get("detector_name") or "unknown"
            verified = bool(item.get("Verified") or item.get("verified"))
            raw_val = item.get("Raw") or item.get("raw") or ""
            redacted = raw_val[:8] + "***" if len(str(raw_val)) > 8 else "***"
            severity = "high" if verified else "medium"
            meta = item.get("SourceMetadata") or item.get("source_metadata") or {}
            path_hint = ""
            if isinstance(meta, dict):
                data = meta.get("Data") or {}
                if isinstance(data, dict):
                    path_hint = str(data.get("filesystem") or data.get("path") or "")
            value = f"{path_hint}:{detector}" if path_hint else str(detector)
            findings.append({
                "finding_type": FindingType.SECRET_CANDIDATE,
                "value": value,
                "data": {
                    "title": str(detector),
                    "severity": severity,
                    "verified": verified,
                    "value_masked": redacted,
                    "cwe": "CWE-798",
                },
                "source_tool": "trufflehog",
                "confidence": 0.9 if verified else 0.65,
            })
        return findings
