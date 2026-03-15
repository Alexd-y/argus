"""Base client for data source adapters."""

import os
from abc import ABC, abstractmethod
from typing import Any


class DataSourceClient(ABC):
    """Base class for optional data source clients."""

    def __init__(self, env_key: str) -> None:
        self._env_key = env_key

    def is_available(self) -> bool:
        """Return True if API key is configured."""
        v = os.environ.get(self._env_key)
        return bool((v or "").strip())

    def _get_key(self) -> str | None:
        v = os.environ.get(self._env_key)
        return (v or "").strip() or None

    @abstractmethod
    async def query(self, **kwargs: Any) -> dict[str, Any]:
        """Execute query. Returns empty dict if not configured."""
        ...
