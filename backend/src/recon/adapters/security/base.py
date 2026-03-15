"""Base class for security scanning adapters — is_available, run, sandbox support."""

import asyncio
import logging
import shlex
import shutil
from abc import abstractmethod
from typing import Any

from src.core.config import settings
from src.recon.adapters.base import ToolAdapter
from src.tools.executor import execute_command

logger = logging.getLogger(__name__)


class SecurityToolAdapter(ToolAdapter):
    """Base for security tools: secrets, SAST, cloud, IaC, container.

    Adds is_available() and run() for standalone execution.
    Skips when tool not installed or sandbox required but disabled.
    """

    @property
    @abstractmethod
    def command_name(self) -> str:
        """CLI command name (e.g. 'gitleaks', 'trivy')."""

    def is_available(self) -> bool:
        """Check if tool is installed and in PATH."""
        return shutil.which(self.command_name) is not None

    def _should_skip(self, config: dict[str, Any]) -> bool:
        """Skip when tool not installed or sandbox required but disabled."""
        if not self.is_available():
            return True
        use_sandbox = config.get("sandbox", False)
        if use_sandbox and not settings.sandbox_enabled:
            return True
        return False

    async def run(self, target: str, config: dict[str, Any]) -> list[dict[str, Any]]:
        """Run tool, parse output, return normalized findings.

        Skips when tool not installed or sandbox disabled (if config requires it).
        When raw_output is provided, skip check is bypassed (parsing only).
        """
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

        cmd_str = " ".join(shlex.quote(p) for p in cmd_parts)
        use_sandbox = config.get("sandbox", False) and settings.sandbox_enabled

        loop = asyncio.get_event_loop()
        exec_result = await loop.run_in_executor(
            None,
            lambda: execute_command(cmd_str, use_sandbox=use_sandbox),
        )

        if not exec_result.get("success"):
            logger.warning(
                "Tool execution failed",
                extra={
                    "tool": self.name,
                    "return_code": exec_result.get("return_code"),
                },
            )
            return []

        raw = exec_result.get("stdout", "") or exec_result.get("stderr", "")
        parsed = await self.parse_output(raw)
        normalized = await self.normalize(parsed)
        return normalized
