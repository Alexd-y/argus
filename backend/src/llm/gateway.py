"""Unified LLM gateway — typed generate() path (master prompt §5, §6)."""

from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any

import httpx
import jsonschema

from src.core.config import settings
from src.core.unified_ai_metrics import (
    record_llm_fallback,
    record_llm_request,
    record_llm_schema_failure,
)
from src.llm.adapters import OpenAICompatibleAdapter, _get_key
from src.llm.citation_postprocessor import postprocess_response_text
from src.llm.prompts.prompts_pack import (
    PROMPTS_BY_ID,
    SYSTEM_BASE_V3,
    SYSTEM_LAB_UNRESTRICTED_V1,
)
from src.llm.registry import ModelRecord, UnifiedRegistry, get_unified_registry
from src.llm.schemas import (
    ExecutionMode,
    FallbackAttempt,
    LlmRequest,
    LlmResponseEnvelope,
    LlmResponseStatus,
    UsageMetrics,
)
from src.llm.unified_router import ResolvedRoute, RoutingPolicy
from src.llm.unknown_ids import (
    LAB_GENERATED_ARTIFACT_SCHEMA,
    LAB_GENERATED_ARTIFACT_SCHEMA_ID,
    classify_unknown_ids,
)
from src.llm.whiterabbitneo_adapter import get_whiterabbitneo_adapter

logger = logging.getLogger(__name__)

RESPONSE_SCHEMAS: dict[str, dict[str, Any]] = {
    "ScanPlanV2": {
        "type": "object",
        "required": ["steps"],
        "properties": {
            "steps": {"type": "array"},
        },
        "additionalProperties": True,
    },
    "TestSchemaV1": {
        "type": "object",
        "required": ["answer"],
        "properties": {
            "answer": {"type": "string"},
        },
        "additionalProperties": False,
    },
    "quick_scan_plan_v1": {
        "type": "object",
        "required": ["tasks"],
        "properties": {
            "tasks": {"type": "array"},
        },
        "additionalProperties": True,
    },
    "asset_fingerprint_v1": {
        "type": "object",
        "required": ["asset_id"],
        "properties": {
            "asset_id": {"type": "string"},
        },
        "additionalProperties": True,
    },
    "finding_triage_v1": {
        "type": "object",
        "required": ["finding_id", "verdict", "severity", "confidence", "fact_summary"],
        "properties": {
            "finding_id": {"type": "string"},
            "verdict": {"type": "string"},
            "severity": {"type": "string"},
            "confidence": {"type": "number"},
            "fact_summary": {"type": "string"},
            "citations": {"type": "array"},
        },
        "additionalProperties": True,
    },
    "security_critique_v1": {
        "type": "object",
        "required": ["triage_id", "evidence_to_weakness_valid"],
        "properties": {
            "triage_id": {"type": "string"},
            "evidence_to_weakness_valid": {"type": "boolean"},
            "citations": {"type": "array"},
        },
        "additionalProperties": True,
    },
    "quick_report_v1": {
        "type": "object",
        "required": ["scan_id", "profile", "executive_summary"],
        "properties": {
            "scan_id": {"type": "string"},
            "profile": {"type": "string"},
            "executive_summary": {"type": "array"},
        },
        "additionalProperties": True,
    },
    LAB_GENERATED_ARTIFACT_SCHEMA_ID: LAB_GENERATED_ARTIFACT_SCHEMA,
}

_JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*([\{\[].*?[\}\]])\s*```", re.DOTALL)


def _unified_gateway_enabled() -> bool:
    return settings.argus_unified_llm_gateway


@dataclass
class ProviderCallResult:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0


class ProviderCallError(Exception):
    def __init__(self, message: str, error_code: str) -> None:
        super().__init__(message)
        self.error_code = error_code


class UnifiedLlmGateway:
    """Single typed entry point for unified LLM requests."""

    def __init__(
        self,
        registry: UnifiedRegistry | None = None,
        routing_policy: RoutingPolicy | None = None,
    ) -> None:
        self._registry = registry or get_unified_registry()
        self._routing = routing_policy or RoutingPolicy(self._registry)

    async def generate(self, request: LlmRequest) -> LlmResponseEnvelope:
        if not _unified_gateway_enabled():
            raise RuntimeError(
                "ARGUS unified LLM gateway is disabled (ARGUS_UNIFIED_LLM_GATEWAY=false). "
                "Use legacy facade or enable the unified gateway."
            )

        trace_id = f"llm_{uuid.uuid4().hex[:16]}"
        unknown = classify_unknown_ids(
            request,
            known_schema_ids=set(RESPONSE_SCHEMAS),
        )
        if unknown.reject:
            self._record_gateway_outcome(
                request,
                alias=request.preferred_alias,
                provider="_none",
                model="_none",
                status=LlmResponseStatus.UNKNOWN_ID,
                latency_ms=0,
            )
            return LlmResponseEnvelope(
                request_id=request.request_id,
                status=LlmResponseStatus.UNKNOWN_ID,
                alias=request.preferred_alias,
                routing_reason_codes=["unknown_id", *unknown.unknown_ids],
                prompt_id=request.prompt_id,
                prompt_version=request.prompt_version,
                schema_id=request.response_schema_id,
                result={
                    "error_code": "unknown_id",
                    "unknown_ids": list(unknown.unknown_ids),
                },
                trace_id=trace_id,
            )

        resolved_schema_id = unknown.resolved_schema_id
        chain = self._routing.build_chain(request)
        routing_reason_codes: list[str] = []
        if unknown.lab_generated_schema:
            routing_reason_codes.append("lab_generated_schema")
        if unknown.unknown_ids:
            routing_reason_codes.extend(unknown.unknown_ids)
        if chain:
            routing_reason_codes.extend(chain[0].reason_codes)

        if not chain:
            self._record_gateway_outcome(
                request,
                alias=request.preferred_alias,
                provider="_none",
                model="_none",
                status=LlmResponseStatus.PROVIDER_ERROR,
                latency_ms=0,
            )
            return LlmResponseEnvelope(
                request_id=request.request_id,
                status=LlmResponseStatus.PROVIDER_ERROR,
                alias=request.preferred_alias,
                routing_reason_codes=["no_provider_chain"],
                prompt_id=request.prompt_id,
                prompt_version=request.prompt_version,
                schema_id=request.response_schema_id,
                trace_id=trace_id,
            )

        system_prompt = self._build_system_prompt(request)
        fallback_attempts: list[FallbackAttempt] = []
        last_error_code = "provider_error"
        last_route: ResolvedRoute | None = None

        for idx, route in enumerate(chain):
            started = time.monotonic()
            next_route = chain[idx + 1] if idx + 1 < len(chain) else None
            try:
                call_result = await self._invoke_provider(
                    route,
                    request,
                    system_prompt=system_prompt,
                )
                latency_ms = int((time.monotonic() - started) * 1000)
                self._registry.health.record_success(route.provider_id, latency_ms)

                cost_usd = self._estimate_cost(
                    self._registry.providers.get(route.provider_id),
                    call_result.input_tokens,
                    call_result.output_tokens,
                )
                usage = UsageMetrics(
                    input_tokens=call_result.input_tokens,
                    output_tokens=call_result.output_tokens,
                    latency_ms=latency_ms,
                    cost_usd=cost_usd,
                )

                parsed, status = self._parse_and_validate(
                    call_result.text,
                    resolved_schema_id,
                )
                if status == LlmResponseStatus.SCHEMA_ERROR:
                    record_llm_schema_failure(
                        alias=route.alias,
                        provider=route.provider,
                        model=route.model,
                        task=request.task_type,
                        mode=request.execution_mode.value,
                    )
                    self._record_gateway_outcome(
                        request,
                        alias=route.alias,
                        provider=route.provider,
                        model=route.model,
                        status=status,
                        latency_ms=latency_ms,
                    )
                    return LlmResponseEnvelope(
                        request_id=request.request_id,
                        status=LlmResponseStatus.SCHEMA_ERROR,
                        provider=route.provider,
                        model=route.model,
                        alias=route.alias,
                        routing_reason_codes=list(routing_reason_codes),
                        fallback_attempts=fallback_attempts,
                        prompt_id=request.prompt_id,
                        prompt_version=request.prompt_version,
                        schema_id=resolved_schema_id,
                        result=parsed,
                        usage=usage,
                        trace_id=trace_id,
                    )

                gated_text, inferred_claims, citations, cve_rows = (
                    postprocess_response_text(
                        call_result.text,
                        evidence_refs=request.evidence_refs,
                    )
                )
                if "text" in parsed:
                    parsed = {**parsed, "text": gated_text}
                if cve_rows:
                    parsed = {**parsed, "cve_applicability": cve_rows}

                self._record_gateway_outcome(
                    request,
                    alias=route.alias,
                    provider=route.provider,
                    model=route.model,
                    status=LlmResponseStatus.OK,
                    latency_ms=latency_ms,
                )
                return LlmResponseEnvelope(
                    request_id=request.request_id,
                    status=LlmResponseStatus.OK,
                    provider=route.provider,
                    model=route.model,
                    alias=route.alias,
                    routing_reason_codes=list(routing_reason_codes),
                    fallback_attempts=fallback_attempts,
                    prompt_id=request.prompt_id,
                    prompt_version=request.prompt_version,
                    schema_id=resolved_schema_id,
                    result=parsed,
                    citations=citations,
                    inferred_claims=inferred_claims,
                    usage=usage,
                    trace_id=trace_id,
                )
            except ProviderCallError as exc:
                latency_ms = int((time.monotonic() - started) * 1000)
                self._registry.health.record_failure(route.provider_id, exc.error_code)
                fallback_attempts.append(
                    FallbackAttempt(provider=route.provider, error_code=exc.error_code)
                )
                record_llm_fallback(
                    from_provider=route.provider,
                    to_provider=next_route.provider if next_route else "_exhausted",
                    mode=request.execution_mode.value,
                )
                last_route = route
                last_error_code = exc.error_code
                logger.warning(
                    "unified_llm_provider_failed",
                    extra={
                        "event": "unified_llm_provider_failed",
                        "provider": route.provider,
                        "model": route.model,
                        "error_code": exc.error_code,
                        "latency_ms": latency_ms,
                    },
                )
                continue
            except (httpx.HTTPError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
                error_code = self._classify_error(exc)
                latency_ms = int((time.monotonic() - started) * 1000)
                self._registry.health.record_failure(route.provider_id, error_code)
                fallback_attempts.append(
                    FallbackAttempt(provider=route.provider, error_code=error_code)
                )
                record_llm_fallback(
                    from_provider=route.provider,
                    to_provider=next_route.provider if next_route else "_exhausted",
                    mode=request.execution_mode.value,
                )
                last_route = route
                last_error_code = error_code
                logger.warning(
                    "unified_llm_provider_failed",
                    extra={
                        "event": "unified_llm_provider_failed",
                        "provider": route.provider,
                        "model": route.model,
                        "error_code": error_code,
                        "latency_ms": latency_ms,
                    },
                )
                continue

        self._record_gateway_outcome(
            request,
            alias=last_route.alias if last_route is not None else request.preferred_alias,
            provider=last_route.provider if last_route is not None else "_exhausted",
            model=last_route.model if last_route is not None else "_none",
            status=LlmResponseStatus.PROVIDER_ERROR,
            latency_ms=0,
        )
        return LlmResponseEnvelope(
            request_id=request.request_id,
            status=LlmResponseStatus.PROVIDER_ERROR,
            alias=request.preferred_alias,
            routing_reason_codes=list(routing_reason_codes),
            fallback_attempts=fallback_attempts,
            prompt_id=request.prompt_id,
            prompt_version=request.prompt_version,
            schema_id=resolved_schema_id,
            result={"error_code": last_error_code},
            trace_id=trace_id,
        )

    def _record_gateway_outcome(
        self,
        request: LlmRequest,
        *,
        alias: str,
        provider: str,
        model: str,
        status: LlmResponseStatus,
        latency_ms: int,
    ) -> None:
        try:
            record_llm_request(
                alias=alias,
                provider=provider,
                model=model,
                task=request.task_type,
                status=status.value,
                mode=request.execution_mode.value,
                latency_ms=float(latency_ms),
            )
        except Exception:  # pragma: no cover — metrics must not break gateway
            logger.warning(
                "unified_llm_metrics_emit_failed",
                extra={"event": "unified_llm_metrics_emit_failed"},
            )

    def _build_system_prompt(self, request: LlmRequest) -> str:
        parts: list[str] = [SYSTEM_BASE_V3]
        if request.execution_mode == ExecutionMode.LAB_UNRESTRICTED:
            parts.append(SYSTEM_LAB_UNRESTRICTED_V1)
        if request.prompt_id and request.prompt_id in PROMPTS_BY_ID:
            parts.append(PROMPTS_BY_ID[request.prompt_id])
        if request.system_prompt:
            parts.append(request.system_prompt)
        return "\n\n".join(parts)

    async def _invoke_provider(
        self,
        route: ResolvedRoute,
        request: LlmRequest,
        *,
        system_prompt: str,
    ) -> ProviderCallResult:
        record = self._registry.providers.get(route.provider_id)
        if record is None:
            raise ProviderCallError("provider_not_found", "invalid_request")

        if record.adapter_kind == "whiterabbitneo":
            return await self._call_wrb(record, request, system_prompt=system_prompt)
        if record.adapter_kind == "cloud_adapter":
            return await self._call_cloud_adapter(record, request, system_prompt=system_prompt)
        return await self._call_openai_compatible(record, request, system_prompt=system_prompt)

    async def _call_wrb(
        self,
        record: ModelRecord,
        request: LlmRequest,
        *,
        system_prompt: str,
    ) -> ProviderCallResult:
        adapter = get_whiterabbitneo_adapter()
        if not adapter.is_configured and record.base_url:
            from src.llm.whiterabbitneo_adapter import WhiteRabbitNeoAdapter

            adapter = WhiteRabbitNeoAdapter(
                base_url=record.base_url,
                api_key=os.environ.get(record.env_key, ""),
            )
        if not adapter.is_configured:
            raise ProviderCallError("wrb_not_configured", "provider_unavailable")

        text, usage = await adapter.call_with_usage(
            request.user_prompt,
            system_prompt=system_prompt,
            model=record.model,
        )
        return ProviderCallResult(
            text=text,
            input_tokens=int(usage.get("prompt_tokens", 0)),
            output_tokens=int(usage.get("completion_tokens", 0)),
        )

    async def _call_cloud_adapter(
        self,
        record: ModelRecord,
        request: LlmRequest,
        *,
        system_prompt: str,
    ) -> ProviderCallResult:
        if not _get_key(record.env_key):
            raise ProviderCallError("cloud_key_missing", "auth_error")

        adapter = OpenAICompatibleAdapter(
            record.env_key,
            record.base_url,
            record.model,
        )
        text = await adapter.call(
            request.user_prompt,
            system_prompt=system_prompt,
            model=record.model,
        )
        input_est = max(1, len(system_prompt) // 4 + len(request.user_prompt) // 4)
        output_est = max(1, len(text) // 4)
        return ProviderCallResult(
            text=text,
            input_tokens=input_est,
            output_tokens=output_est,
        )

    async def _call_openai_compatible(
        self,
        record: ModelRecord,
        request: LlmRequest,
        *,
        system_prompt: str,
    ) -> ProviderCallResult:
        if not record.base_url:
            raise ProviderCallError("base_url_missing", "provider_unavailable")

        messages: list[dict[str, str]] = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": request.user_prompt})

        payload: dict[str, Any] = {
            "model": record.model,
            "messages": messages,
            "temperature": 0.3,
        }
        url = f"{record.base_url.rstrip('/')}/chat/completions"
        headers = {"Content-Type": "application/json"}
        api_key = _get_key(record.env_key) if record.env_key else None
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        timeout = httpx.Timeout(connect=30.0, read=120.0, write=120.0, pool=30.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json=payload, headers=headers)
            if resp.status_code in (401, 403):
                raise ProviderCallError(f"http_{resp.status_code}", "auth_error")
            if resp.status_code == 429:
                raise ProviderCallError("rate_limited", "429")
            if resp.status_code >= 400:
                raise ProviderCallError(f"http_{resp.status_code}", "invalid_request")
            resp.raise_for_status()
            data = resp.json()

        choices = data.get("choices", [])
        if not choices:
            raise ProviderCallError("empty_response", "provider_error")

        content = (choices[0].get("message", {}).get("content", "") or "").strip()
        usage_raw = data.get("usage", {})
        return ProviderCallResult(
            text=content,
            input_tokens=int(usage_raw.get("prompt_tokens", 0)),
            output_tokens=int(usage_raw.get("completion_tokens", 0)),
        )

    def _parse_and_validate(
        self,
        text: str,
        schema_id: str | None,
    ) -> tuple[dict[str, Any], LlmResponseStatus]:
        if not schema_id:
            return {"text": text}, LlmResponseStatus.OK

        raw_json = self._extract_json(text)
        if raw_json is None:
            return {"raw_text": text}, LlmResponseStatus.SCHEMA_ERROR

        try:
            parsed = json.loads(raw_json)
        except json.JSONDecodeError:
            return {"raw_text": text}, LlmResponseStatus.SCHEMA_ERROR

        if not isinstance(parsed, dict):
            return {"raw_text": text}, LlmResponseStatus.SCHEMA_ERROR

        schema = RESPONSE_SCHEMAS.get(schema_id)
        if schema is not None:
            try:
                jsonschema.validate(instance=parsed, schema=schema)
            except jsonschema.ValidationError:
                return {"raw_text": text, "parsed": parsed}, LlmResponseStatus.SCHEMA_ERROR

        return parsed, LlmResponseStatus.OK

    def _extract_json(self, text: str) -> str | None:
        stripped = text.strip()
        if stripped.startswith(("{", "[")):
            return stripped
        match = _JSON_BLOCK_RE.search(text)
        if match:
            return match.group(1).strip()
        return None

    def _estimate_cost(
        self,
        record: ModelRecord | None,
        input_tokens: int,
        output_tokens: int,
    ) -> float:
        if record is None:
            return 0.0
        input_cost = (input_tokens / 1_000_000) * record.price_input_per_million_usd
        output_cost = (output_tokens / 1_000_000) * record.price_output_per_million_usd
        return round(input_cost + output_cost, 6)

    def _classify_error(self, exc: Exception) -> str:
        if isinstance(exc, httpx.HTTPStatusError):
            if exc.response.status_code in (401, 403):
                return "auth_error"
            if exc.response.status_code == 429:
                return "429"
            if exc.response.status_code == 400:
                return "invalid_request"
            return f"http_{exc.response.status_code}"
        if isinstance(exc, httpx.TimeoutException):
            return "timeout"
        return "provider_error"


_gateway: UnifiedLlmGateway | None = None


def get_unified_llm_gateway() -> UnifiedLlmGateway:
    global _gateway
    if _gateway is None:
        _gateway = UnifiedLlmGateway()
    return _gateway


def reset_unified_llm_gateway() -> None:
    global _gateway
    _gateway = None
