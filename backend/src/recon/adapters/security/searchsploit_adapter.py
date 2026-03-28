"""Searchsploit adapter — offline Exploit-DB lookup; optional CVE linkage in normalized data."""

import asyncio
import json
import logging
import re
from typing import Any

from src.core.config import settings
from src.recon.adapters.security.base import SecurityToolAdapter
from src.recon.mcp.policy import KAL_CATEGORY_VULN_INTEL, evaluate_kal_mcp_policy
from src.recon.sandbox_tool_runner import build_sandbox_exec_argv, run_argv_simple_sync
from src.recon.schemas.base import FindingType

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
# Text table: " Title | path " or exploit path lines
_TEXT_ROW_RE = re.compile(
    r"^\s*(?P<title>.+?)\s+\|\s*(?P<path>\S+exploits/\S+)\s*$",
    re.IGNORECASE,
)


class SearchsploitAdapter(SecurityToolAdapter):
    """Adapter for ``searchsploit`` (Exploit-DB CLI). Prefer ``--json`` when available."""

    @property
    def name(self) -> str:
        return "searchsploit"

    @property
    def command_name(self) -> str:
        return "searchsploit"

    @property
    def supported_stages(self) -> list[int]:
        return [12]

    async def build_command(self, target: str, config: dict[str, Any]) -> list[str]:
        """
        ``target`` is the search string (service/version). JSON output when supported.

        Config:
            use_json: default True — append ``--json``
        """
        q = (target or "").strip()
        if not q:
            return []
        use_json = config.get("use_json", True)
        cmd = ["searchsploit", q]
        if use_json:
            cmd.append("--json")
        return cmd

    async def run(self, target: str, config: dict[str, Any]) -> list[dict[str, Any]]:
        """KAL-007: argv policy (``vuln_intel``) + shared sandbox runner; same outputs as base ``run``."""
        raw_output = config.get("raw_output")
        if not raw_output and self._should_skip(config):
            return []

        if raw_output:
            result = await self.execute(
                target=target,
                config={"raw_output": raw_output},
                scope_validator=None,
            )
            return result.normalized_findings

        cmd_parts = await self.build_command(target, config)
        if not cmd_parts:
            return []

        pol = evaluate_kal_mcp_policy(
            category=KAL_CATEGORY_VULN_INTEL,
            argv=cmd_parts,
            password_audit_opt_in=False,
            server_password_audit_enabled=False,
        )
        if not pol.allowed:
            logger.info(
                "searchsploit_kal_policy_denied",
                extra={
                    "event": "searchsploit_kal_policy_denied",
                    "reason": pol.reason,
                },
            )
            return []

        use_sandbox = bool(config.get("sandbox", False))
        run_parts = build_sandbox_exec_argv(cmd_parts, use_sandbox=use_sandbox)
        timeout_sec = float(settings.recon_tools_timeout)
        loop = asyncio.get_event_loop()
        exec_result = await loop.run_in_executor(
            None,
            lambda: run_argv_simple_sync(run_parts, timeout_sec=timeout_sec),
        )

        if not exec_result.get("success"):
            logger.warning(
                "searchsploit_execution_failed",
                extra={
                    "tool": self.name,
                    "return_code": exec_result.get("return_code"),
                },
            )
            return []

        raw = exec_result.get("stdout", "") or exec_result.get("stderr", "") or ""
        parsed = await self.parse_output(str(raw))
        normalized = await self.normalize(parsed)
        return normalized

    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        raw = (raw_output or "").strip()
        if not raw:
            return []
        # JSON array or wrapped object
        try:
            data = json.loads(raw)
            if isinstance(data, list):
                return [x for x in data if isinstance(x, dict)]
            if isinstance(data, dict):
                for key in ("RESULTS_EXPLOIT", "data", "results"):
                    inner = data.get(key)
                    if isinstance(inner, list):
                        return [x for x in inner if isinstance(x, dict)]
        except json.JSONDecodeError:
            pass
        return self._parse_text_fallback(raw)

    def _parse_text_fallback(self, raw: str) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for line in raw.splitlines():
            m = _TEXT_ROW_RE.match(line)
            if m:
                rows.append({
                    "Title": m.group("title").strip(),
                    "Path": m.group("path").strip(),
                })
        return rows

    def _extract_cves(self, item: dict[str, Any]) -> list[str]:
        codes = item.get("Codes") or item.get("codes") or ""
        blob = f"{codes} {item.get('Title', '')} {item.get('title', '')}"
        found = sorted({c.upper() for c in _CVE_RE.findall(blob)})
        return found[:16]

    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Map exploit rows to vulnerability-shaped findings (CVE in ``data`` when present)."""
        cap = 24
        findings: list[dict[str, Any]] = []
        for item in raw_results[:cap]:
            title = str(
                item.get("Title")
                or item.get("title")
                or item.get("Name")
                or "Exploit-DB entry",
            ).strip()
            edb = str(item.get("EDB-ID") or item.get("edb-id") or item.get("id") or "").strip()
            path = str(item.get("Path") or item.get("path") or "").strip()
            cves = self._extract_cves(item)
            value_parts = [title]
            if edb:
                value_parts.append(f"EDB-{edb}")
            if cves:
                value_parts.append(cves[0])
            value = ":".join(value_parts)[:512]
            findings.append({
                "finding_type": FindingType.VULNERABILITY,
                "value": value,
                "data": {
                    "type": "exploit_db",
                    "name": title[:400],
                    "severity": "info",
                    "edb_id": edb or None,
                    "exploit_path": path or None,
                    "cves": cves,
                    "platform": item.get("Platform") or item.get("platform"),
                    "verified": item.get("Verified") or item.get("verified"),
                },
                "source_tool": "searchsploit",
                "confidence": 0.55,
            })
        return findings
