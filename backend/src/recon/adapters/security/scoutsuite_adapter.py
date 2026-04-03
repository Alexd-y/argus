"""ScoutSuite adapter — multi-cloud security."""

import json
import re
from json import JSONDecoder
from typing import Any

from src.recon.adapters.security.base import SecurityToolAdapter
from src.recon.schemas.base import FindingType


class ScoutSuiteAdapter(SecurityToolAdapter):
    """Adapter for ScoutSuite — JS-prefixed JSON blob, flattened service findings."""

    @property
    def name(self) -> str:
        return "scoutsuite"

    @property
    def command_name(self) -> str:
        return "scout"

    @property
    def supported_stages(self) -> list[int]:
        return [12]

    async def build_command(self, _target: str, _config: dict[str, Any]) -> list[str]:
        return ["scout", "aws"]

    def _extract_json_object(self, raw_output: str) -> dict[str, Any] | None:
        text = raw_output.strip()
        if not text:
            return None
        m = re.search(r"scoutsuite_results\s*=\s*", text)
        if m:
            start = text.find("{", m.end())
            if start < 0:
                return None
            decoder = JSONDecoder()
            try:
                obj, _ = decoder.raw_decode(text[start:])
            except json.JSONDecodeError:
                return None
            return obj if isinstance(obj, dict) else None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        data = self._extract_json_object(raw_output)
        if not data:
            return []
        services = data.get("services")
        if not isinstance(services, dict):
            return []
        flat: list[dict[str, Any]] = []
        for svc_name, svc_body in services.items():
            if not isinstance(svc_body, dict):
                continue
            findings = svc_body.get("findings")
            if not isinstance(findings, dict):
                continue
            for fid, fdata in findings.items():
                if not isinstance(fdata, dict):
                    continue
                row = {**fdata, "_service": svc_name, "_finding_id": str(fid)}
                flat.append(row)
        return flat

    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for item in raw_results:
            flagged = item.get("flagged_items") or item.get("flaggedItems") or 0
            try:
                n = int(flagged)
            except (TypeError, ValueError):
                n = 0
            if n <= 0:
                continue
            desc = (
                item.get("description")
                or item.get("rationale")
                or item.get("name")
                or item.get("_finding_id")
                or "finding"
            )
            svc = item.get("_service") or ""
            fid = item.get("_finding_id") or ""
            value = f"{svc}:{fid}"
            findings.append({
                "finding_type": FindingType.MISCONFIGURATION,
                "value": value,
                "data": {
                    "title": str(desc),
                    "severity": "high" if n > 5 else "medium",
                    "flagged_items": n,
                    "service": svc,
                    "finding_id": fid,
                },
                "source_tool": "scoutsuite",
                "confidence": 0.8,
            })
        return findings
