"""GitHub API client — activate by GITHUB_TOKEN for security advisories."""

from typing import Any

import httpx

from src.data_sources.base import DataSourceClient


class GitHubClient(DataSourceClient):
    """GitHub API client for security advisories and CVE data."""

    def __init__(self) -> None:
        super().__init__("GITHUB_TOKEN")
        self._base_url = "https://api.github.com"

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        """Query GitHub API. Returns empty dict if not configured or on error."""
        if not self.is_available():
            return {}

        token = self._get_key()
        if not token:
            return {}

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                endpoint = kwargs.get("endpoint", "advisories")
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
                resp = await client.get(
                    f"{self._base_url}/{endpoint}",
                    params=kwargs.get("params", {}),
                    headers=headers,
                )
                resp.raise_for_status()
                return resp.json()
        except Exception:
            return {}
