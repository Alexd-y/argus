"""Base class for OSINT/Intel adapters — Stage 1 recon data sources."""

import abc
import logging
from typing import Any

logger = logging.getLogger(__name__)


def _finding(
    finding_type: str,
    value: str,
    data: dict[str, Any],
    source_tool: str,
    confidence: float = 0.9,
) -> dict[str, Any]:
    """Build a normalized finding dict for storage."""
    return {
        "finding_type": finding_type,
        "value": value,
        "data": data,
        "source_tool": source_tool,
        "confidence": confidence,
    }


class IntelAdapter(abc.ABC):
    """Abstract base for OSINT/Intel adapters.

    Each adapter: checks env key (if required), fetches when available,
    returns structured findings. Skips when no key (for key-required services).
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Adapter identifier (e.g., 'shodan')."""

    @property
    @abc.abstractmethod
    def env_key(self) -> str | None:
        """Environment variable for API key. None if no key required."""

    def is_available(self) -> bool:
        """Return True if adapter can run (key present for key-required services)."""
        if self.env_key is None:
            return True
        import os
        v = os.environ.get(self.env_key, "")
        return bool((v or "").strip())

    @abc.abstractmethod
    async def fetch(self, domain: str) -> dict[str, Any]:
        """Fetch intel for domain. Returns structured output.

        Returns:
            {
                "source": str,
                "findings": list[dict],  # normalized finding format
                "skipped": bool,
                "error": str | None,
                "raw": dict | None,  # optional raw response
            }
        """
        ...
