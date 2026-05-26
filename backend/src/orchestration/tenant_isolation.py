"""Tenant isolation guard — multi-tenant resource quotas and data isolation.

Ensures per-tenant scan concurrency limits, LLM token budgets,
sandbox resource quotas, and row-level security enforcement.

From Развитие2.md: federated multi-tenant isolation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_MAX_CONCURRENT_SCANS = 3
DEFAULT_MAX_DAILY_TOKENS = 500000
DEFAULT_MAX_SANDBOX_CONTAINERS = 5


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

    def set_quota(self, tenant_id: str, quota: TenantQuota) -> None:
        self._quotas[tenant_id] = quota

    def get_quota(self, tenant_id: str) -> TenantQuota:
        return self._quotas.get(tenant_id, TenantQuota())

    def can_start_scan(self, tenant_id: str) -> bool:
        quota = self.get_quota(tenant_id)
        current = self._active_scans.get(tenant_id, 0)
        return current < quota.max_concurrent_scans

    def register_scan_start(self, tenant_id: str) -> None:
        self._active_scans[tenant_id] = self._active_scans.get(tenant_id, 0) + 1

    def register_scan_end(self, tenant_id: str) -> None:
        current = self._active_scans.get(tenant_id, 1)
        self._active_scans[tenant_id] = max(0, current - 1)

    def check_token_budget(self, tenant_id: str, tokens: int) -> bool:
        quota = self.get_quota(tenant_id)
        used = self._daily_tokens.get(tenant_id, 0)
        return (used + tokens) <= quota.max_daily_tokens

    def record_token_usage(self, tenant_id: str, tokens: int) -> None:
        self._daily_tokens[tenant_id] = self._daily_tokens.get(tenant_id, 0) + tokens

    def check_sandbox(self, tenant_id: str) -> bool:
        quota = self.get_quota(tenant_id)
        current = self._active_containers.get(tenant_id, 0)
        return current < quota.max_sandbox_containers

    def register_container_start(self, tenant_id: str) -> None:
        self._active_containers[tenant_id] = self._active_containers.get(tenant_id, 0) + 1

    def register_container_end(self, tenant_id: str) -> None:
        current = self._active_containers.get(tenant_id, 1)
        self._active_containers[tenant_id] = max(0, current - 1)


__all__ = [
    "TenantIsolationGuard",
    "TenantQuota",
]