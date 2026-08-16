"""Unified LLM routing policy (master prompt §6).

LAB mode never refuses or downgrades offensive tasks at the router layer.
Failover returns an ordered provider chain for real sequential attempts.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from src.llm.registry import ModelRecord, UnifiedRegistry, get_unified_registry
from src.llm.schemas import ContentClass, ExecutionMode, LlmRequest

logger = logging.getLogger(__name__)

NON_RETRYABLE_ERROR_CODES: frozenset[str] = frozenset(
    {
        "auth_error",
        "authentication_error",
        "invalid_request",
        "401",
        "403",
    }
)

OFFENSIVE_TASK_TYPES: frozenset[str] = frozenset(
    {
        "exploit_generation",
        "exploitation",
        "post_exploitation",
        "privilege_escalation",
        "lateral_movement",
        "credential_dumping",
        "reverse_shell",
        "malware_analysis",
        "reverse_engineering",
        "offensive_plan",
        "payload_generation",
        "shell_generation",
        "tunneling",
    }
)

CONFIDENTIAL_CONTENT_CLASSES: frozenset[ContentClass] = frozenset(
    {
        ContentClass.TENANT_CONFIDENTIAL,
        ContentClass.SECRET_REF_ONLY,
        ContentClass.LAB_ARTIFACT,
    }
)


@dataclass(frozen=True)
class ResolvedRoute:
    provider_id: str
    provider: str
    model: str
    alias: str
    cloud: bool = False
    reason_codes: tuple[str, ...] = field(default_factory=tuple)


class RoutingPolicy:
    """Select ordered provider chain for a unified LLM request."""

    def __init__(self, registry: UnifiedRegistry | None = None) -> None:
        self._registry = registry or get_unified_registry()

    def build_chain(self, request: LlmRequest) -> list[ResolvedRoute]:
        alias_entry = self._registry.aliases.resolve(request.preferred_alias)
        if alias_entry is None:
            logger.warning(
                "unified_router_unknown_alias",
                extra={
                    "event": "unified_router_unknown_alias",
                    "alias": request.preferred_alias,
                },
            )
            candidates: list[ModelRecord] = []
        else:
            candidates = self._registry.aliases.resolve_models(request.preferred_alias)
        reason_codes: list[str] = ["alias_resolved"]
        routes: list[ResolvedRoute] = []

        for record in candidates:
            route_reasons = list(reason_codes)
            if not self._passes_capability_gate(record, request, route_reasons):
                continue
            if not self._passes_content_class_gate(record, request, route_reasons):
                continue
            if not self._passes_execution_mode_gate(record, request, route_reasons):
                continue
            if not self._passes_health_gate(record, route_reasons):
                continue
            if not self._passes_budget_gate(record, request, route_reasons):
                continue
            if not record.is_configured:
                route_reasons.append("skipped_not_configured")
                continue

            routes.append(
                ResolvedRoute(
                    provider_id=record.provider_id,
                    provider=record.provider_id,
                    model=record.model,
                    alias=request.preferred_alias,
                    cloud=record.cloud,
                    reason_codes=tuple(route_reasons),
                )
            )

        if request.execution_mode == ExecutionMode.LAB_UNRESTRICTED:
            routes = self._ensure_lab_offensive_chain(request, routes)

        return routes

    def _passes_capability_gate(
        self,
        record: ModelRecord,
        request: LlmRequest,
        reasons: list[str],
    ) -> bool:
        for cap in request.required_capabilities:
            if not record.capabilities.supports(cap):
                reasons.append(f"capability_missing:{cap}")
                return False
        if request.context_budget_tokens > record.capabilities.max_context:
            reasons.append("context_budget_exceeded")
            return False
        reasons.append("capabilities_ok")
        return True

    def _passes_content_class_gate(
        self,
        record: ModelRecord,
        request: LlmRequest,
        reasons: list[str],
    ) -> bool:
        if request.execution_mode == ExecutionMode.LAB_UNRESTRICTED:
            reasons.append("lab_content_class_allowed")
            return True

        if not record.capabilities.allows_content_class(request.content_class):
            reasons.append("content_class_blocked")
            return False

        if record.cloud and request.content_class in CONFIDENTIAL_CONTENT_CLASSES:
            reasons.append("cloud_blocked_for_confidential")
            return False

        reasons.append("content_class_ok")
        return True

    def _passes_execution_mode_gate(
        self,
        record: ModelRecord,
        request: LlmRequest,
        reasons: list[str],
    ) -> bool:
        if request.execution_mode == ExecutionMode.LAB_UNRESTRICTED:
            if record.cloud and not request.lab_cloud_allowed:
                reasons.append("lab_cloud_not_allowed")
                return False
            if request.task_type in OFFENSIVE_TASK_TYPES:
                reasons.append("lab_offensive_task_allowed")
            return True

        if request.task_type in OFFENSIVE_TASK_TYPES and record.cloud:
            reasons.append("production_offensive_local_preferred")
            # Still allow cloud in production chain as fallback — not a refusal.

        reasons.append("execution_mode_ok")
        return True

    def _passes_health_gate(self, record: ModelRecord, reasons: list[str]) -> bool:
        health = self._registry.health.get(record.provider_id)
        if not health.is_available():
            reasons.append("circuit_open")
            return False
        reasons.append("health_ok")
        return True

    def _passes_budget_gate(
        self,
        record: ModelRecord,
        request: LlmRequest,
        reasons: list[str],
    ) -> bool:
        if request.execution_mode == ExecutionMode.LAB_UNRESTRICTED:
            reasons.append("lab_budget_unlimited")
            return True

        if (
            request.cost_budget_usd <= 0.0
            and record.cloud
            and (
                record.price_input_per_million_usd > 0
                or record.price_output_per_million_usd > 0
            )
        ):
            reasons.append("zero_cost_budget_cloud_skipped")
            return False

        health = self._registry.health.get(record.provider_id)
        if request.latency_budget_ms and health.p95_ms > request.latency_budget_ms:
            reasons.append("latency_budget_exceeded")
            return False

        reasons.append("budget_ok")
        return True

    def _ensure_lab_offensive_chain(
        self,
        request: LlmRequest,
        routes: list[ResolvedRoute],
    ) -> list[ResolvedRoute]:
        """LAB: never return empty chain for offensive tasks due to policy filtering."""
        if routes:
            return routes

        if request.task_type not in OFFENSIVE_TASK_TYPES:
            return routes

        fallback_ids = ("local_qwythos", "local_wrb", "local_qwen_fast")
        rebuilt: list[ResolvedRoute] = []
        for provider_id in fallback_ids:
            record = self._registry.providers.get(provider_id)
            if record is None:
                continue
            rebuilt.append(
                ResolvedRoute(
                    provider_id=record.provider_id,
                    provider=record.provider_id,
                    model=record.model,
                    alias=request.preferred_alias,
                    cloud=record.cloud,
                    reason_codes=(
                        "lab_offensive_forced_local",
                        "lab_no_refusal",
                    ),
                )
            )
        return rebuilt

    def is_non_retryable(self, error_code: str) -> bool:
        normalized = (error_code or "").strip().lower()
        return normalized in NON_RETRYABLE_ERROR_CODES
