"""GitHub intel adapter — security advisories, requires GITHUB_TOKEN."""

from typing import Any

from src.recon.adapters.intel.base import IntelAdapter


class GitHubIntelAdapter(IntelAdapter):
    """GitHub API adapter for security advisories. Stub — skips when no key."""

    @property
    def name(self) -> str:
        return "github"

    @property
    def env_key(self) -> str | None:
        return "GITHUB_TOKEN"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {
                "source": self.name,
                "findings": [],
                "skipped": True,
                "error": None,
                "raw": None,
            }
        return {
            "source": self.name,
            "findings": [],
            "skipped": False,
            "error": "Stub — not implemented",
            "raw": None,
        }
