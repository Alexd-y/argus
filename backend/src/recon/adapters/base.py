"""Tool adapter base class and registry for recon tool integration."""

import abc
import logging
import time
from dataclasses import dataclass, field
from typing import Any

from src.recon.scope.validator import ScopeValidator

logger = logging.getLogger(__name__)


@dataclass
class ToolResult:
    """Result of a tool adapter execution."""

    success: bool = False
    raw_output: str = ""
    parsed_results: list[dict[str, Any]] = field(default_factory=list)
    normalized_findings: list[dict[str, Any]] = field(default_factory=list)
    execution_time: float = 0.0
    error: str | None = None
    tool_name: str = ""
    items_found: int = 0
    items_in_scope: int = 0


class ToolAdapter(abc.ABC):
    """Abstract base class for recon tool adapters.

    Each tool (subfinder, httpx, nmap, etc.) implements this interface.
    Adapters handle: command building, output parsing, normalization, and scope filtering.
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Tool identifier (e.g., 'subfinder')."""

    @property
    @abc.abstractmethod
    def supported_stages(self) -> list[int]:
        """Recon stages this tool supports."""

    async def validate_config(self, config: dict[str, Any]) -> bool:
        """Validate tool-specific configuration. Override for custom validation."""
        return True

    @abc.abstractmethod
    async def build_command(self, target: str, config: dict[str, Any]) -> list[str]:
        """Build command-line arguments for the tool. Returns list (no shell=True)."""

    @abc.abstractmethod
    async def parse_output(self, raw_output: str) -> list[dict[str, Any]]:
        """Parse raw tool output into structured dicts."""

    @abc.abstractmethod
    async def normalize(
        self, raw_results: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Convert parsed results into canonical finding format."""

    async def execute(
        self,
        target: str,
        config: dict[str, Any],
        scope_validator: ScopeValidator | None = None,
    ) -> ToolResult:
        """Full execution pipeline: build, run, parse, normalize, scope-filter.

        NOTE: Actual subprocess execution is intentionally NOT implemented here.
        The job runner handles execution via src/tools/executor.py.
        This method is for parsing pre-collected output.
        """
        start = time.monotonic()
        result = ToolResult(tool_name=self.name)

        try:
            raw_output = config.get("raw_output", "")
            if not raw_output:
                result.error = "No raw_output provided in config"
                return result

            result.raw_output = raw_output
            parsed = await self.parse_output(raw_output)
            result.parsed_results = parsed
            result.items_found = len(parsed)

            normalized = await self.normalize(parsed)

            if scope_validator:
                filtered = []
                for finding in normalized:
                    value = finding.get("value", "")
                    if not value:
                        filtered.append(finding)
                        continue
                    check = scope_validator.is_in_scope(value, "domain")
                    if check.is_in_scope:
                        filtered.append(finding)
                result.normalized_findings = filtered
                result.items_in_scope = len(filtered)
            else:
                result.normalized_findings = normalized
                result.items_in_scope = len(normalized)

            result.success = True

        except Exception as e:
            logger.warning(
                "Adapter execution failed",
                extra={"tool": self.name, "error": str(e)},
            )
            result.error = str(e)
        finally:
            result.execution_time = time.monotonic() - start

        return result
