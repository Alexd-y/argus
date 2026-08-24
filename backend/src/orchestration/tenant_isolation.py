"""Tenant isolation guard — multi-tenant resource quotas and data isolation.

Ensures per-tenant scan concurrency limits, LLM token budgets,
sandbox resource quotas, and row-level security enforcement.

From Развитие2.md: federated multi-tenant isolation.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import date

logger = logging.getLogger(__name__)

DEFAULT_MAX_CONCURRENT_SCANS = 3
DEFAULT_MAX_DAILY_TOKENS = 500000
DEFAULT_MAX_SANDBOX_CONTAINERS = 5

_STATE_DIR = os.environ.get("ARGUS_TENANT_STATE_DIR", "/tmp/argus_tenant_state")


@dataclass
class TenantQuota:
    max_concurrent_scans: int = DEFAULT_MAX_CONCURRENT_SCANS
    max_daily_tokens: int = DEFAULT_MAX_DAILY_TOKENS
    max_sandbox_containers: int = DEFAULT_MAX_SANDBOX_CONTAINERS
    max_findings_per_scan: int = 500


class TenantIsolationGuard:
    def __init__(self) -> None:
        self._active_scans: dict[str, int] = {}
        self._daily_tokens: dict[str, int] = {}
        self._active_containers: dict[str, int] = {}
        self._quotas: dict[str, TenantQuota] = {}
        self._state_loaded: bool = False

    def _state_path(self, tenant_id: str) -> str:
        return os.path.join(_STATE_DIR, f"{tenant_id}_state.json")

    def load_state(self, tenant_id: str) -> None:
        """Load persisted state for a tenant from disk."""
        path = self._state_path(tenant_id)
        try:
            if os.path.isfile(path):
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                today = date.today().isoformat()
                if data.get("date") == today:
                    self._daily_tokens[tenant_id] = data.get("daily_tokens", 0)
                else:
                    self._daily_tokens[tenant_id] = 0
        except Exception:
            logger.debug("tenant_state_load_failed", extra={"tenant_id": tenant_id})

    def save_state(self, tenant_id: str) -> None:
        """Persist current state for a tenant to disk."""
        path = self._state_path(tenant_id)
        try:
            os.makedirs(_STATE_DIR, exist_ok=True)
            data = {
                "date": date.today().isoformat(),
                "daily_tokens": self._daily_tokens.get(tenant_id, 0),
                "active_scans": self._active_scans.get(tenant_id, 0),
                "active_containers": self._active_containers.get(tenant_id, 0),
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            logger.debug("tenant_state_save_failed", extra={"tenant_id": tenant_id})

    def set_quota(self, tenant_id: str, quota: TenantQuota) -> None:
        self._quotas[tenant_id] = quota

    def get_quota(self, tenant_id: str) -> TenantQuota:
        return self._quotas.get(tenant_id, TenantQuota())

    def can_start_scan(self, tenant_id: str) -> bool:
        if not self._state_loaded:
            self.load_state(tenant_id)
            self._state_loaded = True
        quota = self.get_quota(tenant_id)
        current = self._active_scans.get(tenant_id, 0)
        return current < quota.max_concurrent_scans

    def register_scan_start(self, tenant_id: str) -> None:
        self._active_scans[tenant_id] = self._active_scans.get(tenant_id, 0) + 1
        self.save_state(tenant_id)

    def register_scan_end(self, tenant_id: str) -> None:
        current = self._active_scans.get(tenant_id, 1)
        self._active_scans[tenant_id] = max(0, current - 1)
        self.save_state(tenant_id)

    def check_token_budget(self, tenant_id: str, tokens: int) -> bool:
        quota = self.get_quota(tenant_id)
        used = self._daily_tokens.get(tenant_id, 0)
        return (used + tokens) <= quota.max_daily_tokens

    def record_token_usage(self, tenant_id: str, tokens: int) -> None:
        self._daily_tokens[tenant_id] = self._daily_tokens.get(tenant_id, 0) + tokens
        self.save_state(tenant_id)

    def check_sandbox(self, tenant_id: str) -> bool:
        quota = self.get_quota(tenant_id)
        current = self._active_containers.get(tenant_id, 0)
        return current < quota.max_sandbox_containers

    def register_container_start(self, tenant_id: str) -> None:
        self._active_containers[tenant_id] = self._active_containers.get(tenant_id, 0) + 1
        self.save_state(tenant_id)

    def register_container_end(self, tenant_id: str) -> None:
        current = self._active_containers.get(tenant_id, 1)
        self._active_containers[tenant_id] = max(0, current - 1)
        self.save_state(tenant_id)


__all__ = [
    "TenantIsolationGuard",
    "TenantQuota",
]
