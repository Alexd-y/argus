"""LLM Gateway Router — OpenAI-compatible /v1/chat/completions endpoint.

Enforces policy, routes through WhiteRabbitNeo → cloud fallback chain,
records usage, redacts sensitive content.
"""

import uuid
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/v1", tags=["llm"])


class ChatMessage(BaseModel):
    role: str = "user"
    content: str = ""


class GatewayRequest(BaseModel):
    model: str = "argus-pentest-primary"
    messages: list[ChatMessage]
    temperature: float = 0.2
    max_tokens: int = 2000
    metadata: dict[str, Any] = Field(default_factory=dict)
    policy: dict[str, Any] = Field(default_factory=dict)


class UsageInfo(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0


class Choice(BaseModel):
    index: int = 0
    message: ChatMessage
    finish_reason: str = "stop"


class PolicyDecision(BaseModel):
    allowed: bool = True
    reason: str | None = None


class GatewayResponse(BaseModel):
    id: str = ""
    model: str = ""
    resolved_provider: str = ""
    resolved_model: str = ""
    choices: list[Choice] = Field(default_factory=list)
    usage: UsageInfo = Field(default_factory=UsageInfo)
    policy_decision: PolicyDecision = Field(default_factory=PolicyDecision)


class GatewayError(BaseModel):
    error: dict[str, Any]


@router.post("/chat/completions", response_model=GatewayResponse)
async def chat_completions(request: GatewayRequest) -> GatewayResponse:
    from src.llm_gateway.policy_enforcer import PolicyEnforcer
    from src.llm_gateway.provider_clients import ProviderRouter

    req_id = f"llmreq_{uuid.uuid4().hex[:12]}"
    policy = request.policy
    metadata = request.metadata

    # 1. Policy enforcement
    enforcer = PolicyEnforcer()
    try:
        enforcer.evaluate(policy, request)
    except PolicyDeniedError as exc:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "llm_policy_denied",
                "message": str(exc),
                "details": exc.details,
            },
        )

    # 2. Route through WRB → cloud fallback
    router = ProviderRouter()
    try:
        provider = await router.select_provider(request.model, policy)
        raw = await router.call_provider(
            provider,
            [m.model_dump() for m in request.messages],
            temperature=request.temperature,
            max_tokens=request.max_tokens,
        )
    except AllProvidersFailedError as exc:
        raise HTTPException(
            status_code=502,
            detail={
                "code": "llm_all_providers_failed",
                "message": str(exc),
            },
        )

    # 3. Record usage
    from src.llm_gateway.usage_ledger import record_usage
    record_usage(
        tenant_id=metadata.get("tenant_id", ""),
        scan_id=metadata.get("scan_id", ""),
        phase=metadata.get("phase", ""),
        task=metadata.get("task", ""),
        alias=request.model,
        provider=provider["key"],
        model=provider["model"],
        prompt_tokens=raw["usage"]["prompt_tokens"],
        completion_tokens=raw["usage"]["completion_tokens"],
        estimated_cost=provider.get("price", {}).get("input_per_million_usd", 0) * raw["usage"]["prompt_tokens"] / 1_000_000 +
                       provider.get("price", {}).get("output_per_million_usd", 0) * raw["usage"]["completion_tokens"] / 1_000_000,
    )

    # 4. Redact response
    from src.llm_gateway.redaction import redact_response
    content = redact_response(raw["content"])

    return GatewayResponse(
        id=req_id,
        model=request.model,
        resolved_provider=provider["key"],
        resolved_model=provider["model"],
        choices=[Choice(message=ChatMessage(role="assistant", content=content))],
        usage=UsageInfo(
            prompt_tokens=raw["usage"]["prompt_tokens"],
            completion_tokens=raw["usage"]["completion_tokens"],
            total_tokens=raw["usage"]["total_tokens"],
            estimated_cost_usd=0.0,
        ),
        policy_decision=PolicyDecision(allowed=True),
    )


@router.get("/models")
async def list_models() -> list[dict[str, str]]:
    return [
        {"id": "argus-pentest-primary", "object": "model", "owned_by": "whiterabbitneo"},
        {"id": "argus-planner-fast", "object": "model", "owned_by": "deepseek"},
        {"id": "argus-planner-deep", "object": "model", "owned_by": "deepseek"},
        {"id": "argus-code-cloud", "object": "model", "owned_by": "qwen"},
        {"id": "argus-report", "object": "model", "owned_by": "deepseek"},
        {"id": "argus-osint", "object": "model", "owned_by": "perplexity"},
    ]


class PolicyDeniedError(Exception):
    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.details = details or {}


class AllProvidersFailedError(Exception):
    pass
