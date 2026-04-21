"""LLM provider abstraction for the ARGUS AI orchestrator (Backlog/dev1_md §6).

Three concerns live in this module:

* :class:`LLMRequest` / :class:`LLMResponse` — frozen Pydantic envelopes that
  the orchestrator passes to every provider. Every request carries a
  :class:`~uuid.UUID` ``correlation_id`` so the request, the response, the
  cost record, and the audit event share a single trace key.
* :class:`LLMProvider` — runtime-checkable :class:`typing.Protocol` that every
  concrete provider must satisfy. Keeps the orchestrator decoupled from the
  HTTP / SDK details of any specific vendor (OpenAI, Anthropic, …).
* :class:`EchoLLMProvider` / :class:`OpenAILLMProvider` — concrete providers.
  ``EchoLLMProvider`` is the default for unit tests and dev mode (no
  network, deterministic, canned responses keyed on ``prompt_id``).
  ``OpenAILLMProvider`` is the placeholder for real-vendor integration: it
  raises :class:`LLMProviderUnavailableError` when no API key is configured
  and a clear :class:`NotImplementedError` when one is present (real HTTP
  integration is out-of-scope for this cycle).

Security notes
--------------
* Provider implementations MUST never log the request / response content.
  The structured logger emits only ``correlation_id``, ``model_id``,
  ``prompt_id``, ``prompt_tokens``, ``completion_tokens``, ``usd_cost``,
  ``latency_ms``, and ``finish_reason``.
* :class:`LLMResponse.parsed_json` is intentionally a ``dict[str, Any] |
  None`` — the orchestrator's downstream layers are responsible for
  schema-validating the parsed structure (see
  :func:`src.orchestrator.schemas.loader.validate_validation_plan`).
"""

from __future__ import annotations

import json
import logging
from enum import StrEnum
from typing import Any, Final, Protocol, Self, runtime_checkable
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

_logger = logging.getLogger(__name__)


_MAX_PROMPT_TOKENS: Final[int] = 8192
_MAX_RESPONSE_LEN: Final[int] = 65_536


class LLMProviderError(Exception):
    """Base class for every error raised by this module's providers."""


class LLMProviderUnavailableError(LLMProviderError):
    """Raised when a provider cannot service requests (missing creds, etc.).

    Carries the provider name in :attr:`provider` so the retry loop can route
    on it without parsing the error message.
    """

    def __init__(self, provider: str, *, reason: str = "unavailable") -> None:
        self.provider = provider
        self.reason = reason
        super().__init__(f"LLM provider {provider!r} is unavailable: {reason}")


class ResponseFormat(StrEnum):
    """Response-format hint passed to providers.

    Mirrors the OpenAI / Anthropic ``response_format`` option:
    * ``json_object`` — strict JSON object output.
    * ``json_schema`` — JSON conforming to ``expected_schema``.
    * ``text`` — free-form text (used by reporter narrative blocks).
    """

    JSON_OBJECT = "json_object"
    JSON_SCHEMA = "json_schema"
    TEXT = "text"


class LLMRequest(BaseModel):
    """Frozen request envelope handed to :meth:`LLMProvider.call`."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    correlation_id: UUID
    model_id: StrictStr = Field(min_length=1, max_length=128)
    prompt_id: StrictStr = Field(min_length=1, max_length=128)
    system_prompt: StrictStr = Field(min_length=1, max_length=16_000)
    user_prompt: StrictStr = Field(min_length=1, max_length=32_000)
    max_tokens: StrictInt = Field(ge=1, le=_MAX_PROMPT_TOKENS)
    temperature: StrictFloat = Field(ge=0.0, le=1.0)
    response_format: ResponseFormat = ResponseFormat.JSON_OBJECT
    expected_schema: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _check_schema_present_when_required(self) -> Self:
        if (
            self.response_format is ResponseFormat.JSON_SCHEMA
            and self.expected_schema is None
        ):
            raise ValueError(
                "expected_schema must be provided when response_format=json_schema"
            )
        return self


class LLMResponse(BaseModel):
    """Frozen response envelope returned by :meth:`LLMProvider.call`.

    ``parsed_json`` is populated for JSON response formats (the provider
    parses once and shares the dict). Plain-text responses keep
    ``parsed_json=None`` and the consumer reads :attr:`content`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    correlation_id: UUID
    content: StrictStr = Field(min_length=0, max_length=_MAX_RESPONSE_LEN)
    parsed_json: dict[str, Any] | None = None
    model_id: StrictStr = Field(min_length=1, max_length=128)
    prompt_tokens: StrictInt = Field(ge=0)
    completion_tokens: StrictInt = Field(ge=0)
    usd_cost: StrictFloat = Field(ge=0.0)
    latency_ms: StrictInt = Field(ge=0)
    finish_reason: StrictStr = Field(min_length=1, max_length=32)

    @field_validator("finish_reason")
    @classmethod
    def _check_finish_reason(cls, value: str) -> str:
        if value not in {"stop", "length", "tool_calls", "content_filter", "echo"}:
            raise ValueError(
                f"finish_reason {value!r} is not in the closed taxonomy "
                "(stop|length|tool_calls|content_filter|echo)"
            )
        return value


@runtime_checkable
class LLMProvider(Protocol):
    """Async protocol every concrete LLM provider must satisfy."""

    name: str

    async def call(self, request: LLMRequest) -> LLMResponse:
        """Issue ``request`` and return the response envelope.

        Implementations MUST:
        * Honour :attr:`LLMRequest.response_format`.
        * Populate :attr:`LLMResponse.parsed_json` for JSON formats.
        * Account for cost in :attr:`LLMResponse.usd_cost` (USD).
        * Raise :class:`LLMProviderUnavailableError` when the provider
          cannot service the request (missing creds, quota exhausted).
        """


# ---------------------------------------------------------------------------
# Echo provider
# ---------------------------------------------------------------------------


_ECHO_USD_PER_1K_INPUT: Final[float] = 0.0001
_ECHO_USD_PER_1K_OUTPUT: Final[float] = 0.0002


class EchoLLMProvider:
    """In-memory deterministic provider intended for unit tests and dev mode.

    Maintains a ``prompt_id -> canned response`` map; each call returns the
    canned response with synthetic but deterministic token counts derived
    from prompt / response lengths. No I/O, no concurrency hazards (the
    map is mutated only via :meth:`register_canned`).
    """

    name = "echo"

    def __init__(self) -> None:
        self._canned: dict[str, str] = {}

    def register_canned(self, prompt_id: str, response: dict[str, Any] | str) -> None:
        """Register the canned response for ``prompt_id``.

        Dict values are serialised to JSON so the provider can return the
        same bytes regardless of how the test author constructed the
        payload. Re-registration overwrites the prior entry (handy for
        test setup / teardown).
        """
        if not isinstance(prompt_id, str) or not prompt_id:
            raise ValueError("prompt_id must be a non-empty string")
        if isinstance(response, str):
            self._canned[prompt_id] = response
        elif isinstance(response, dict):
            self._canned[prompt_id] = json.dumps(
                response, sort_keys=True, ensure_ascii=False
            )
        else:
            raise TypeError(
                f"response must be a str or dict, got {type(response).__name__}"
            )

    def has(self, prompt_id: str) -> bool:
        """Return ``True`` if a canned response is registered for ``prompt_id``."""
        return prompt_id in self._canned

    async def call(self, request: LLMRequest) -> LLMResponse:
        """Return the canned response for ``request.prompt_id``.

        Raises :class:`LLMProviderUnavailableError` (with reason
        ``no_canned_response``) when the prompt was never registered —
        defensive: an unregistered prompt in a deterministic test
        almost always indicates the test author forgot to wire it.
        """
        canned = self._canned.get(request.prompt_id)
        if canned is None:
            raise LLMProviderUnavailableError(
                self.name,
                reason=f"no canned response for prompt_id={request.prompt_id!r}",
            )

        prompt_tokens = _approx_token_count(request.system_prompt + request.user_prompt)
        completion_tokens = _approx_token_count(canned)
        usd_cost = _estimate_usd(prompt_tokens, completion_tokens)

        parsed: dict[str, Any] | None = None
        if request.response_format in {
            ResponseFormat.JSON_OBJECT,
            ResponseFormat.JSON_SCHEMA,
        }:
            parsed = _safe_parse_json(canned)

        return LLMResponse(
            correlation_id=request.correlation_id,
            content=canned,
            parsed_json=parsed,
            model_id=request.model_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            usd_cost=usd_cost,
            latency_ms=0,
            finish_reason="echo",
        )


def _approx_token_count(text: str) -> int:
    """Return a deterministic synthetic token count for tests.

    Uses the well-known "~4 chars per token" GPT heuristic so test
    assertions can hard-code expected numbers. Real providers report
    exact counts from the tokenizer.
    """
    if not text:
        return 0
    return max(1, len(text) // 4)


def _estimate_usd(prompt_tokens: int, completion_tokens: int) -> float:
    """Return the synthetic USD cost for ``EchoLLMProvider`` responses."""
    return round(
        (prompt_tokens / 1000.0) * _ECHO_USD_PER_1K_INPUT
        + (completion_tokens / 1000.0) * _ECHO_USD_PER_1K_OUTPUT,
        6,
    )


def _safe_parse_json(content: str) -> dict[str, Any] | None:
    """Return the JSON object encoded in ``content`` or ``None`` on failure.

    The retry loop checks :attr:`LLMResponse.parsed_json` for ``None`` to
    decide whether to invoke the Fixer agent. Returning ``None`` (not
    raising) keeps the contract simple: ``content`` is always available;
    ``parsed_json`` is best-effort.
    """
    try:
        decoded = json.loads(content)
    except (ValueError, TypeError):
        return None
    if not isinstance(decoded, dict):
        return None
    return decoded


# ---------------------------------------------------------------------------
# OpenAI provider stub
# ---------------------------------------------------------------------------


class OpenAILLMProvider:
    """OpenAI-compatible provider stub (real HTTP integration out-of-scope).

    Two-state behaviour:
    * ``api_key is None`` → :meth:`call` raises
      :class:`LLMProviderUnavailableError` immediately. The orchestrator
      treats this as a routing miss (degrades gracefully to the next
      configured provider).
    * ``api_key is not None`` → :meth:`call` raises
      :class:`NotImplementedError` to make it explicit that the real
      HTTP integration has not been implemented in this cycle. Wiring
      a real OpenAI / OpenRouter / DeepSeek call requires the cost table
      from §6 and budget caps from §14 — landing it here would entangle
      this task with provider-specific concerns. Production deployments
      should swap in their own ``LLMProvider`` implementation.
    """

    name = "openai"

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
    ) -> None:
        self._api_key = api_key
        self._base_url = base_url

    @property
    def api_key_present(self) -> bool:
        return self._api_key is not None

    @property
    def base_url(self) -> str | None:
        return self._base_url

    async def call(self, request: LLMRequest) -> LLMResponse:
        if self._api_key is None:
            raise LLMProviderUnavailableError(
                self.name, reason="OPENAI_API_KEY not configured"
            )
        _logger.warning(
            "openai_provider.real_http_call_blocked",
            extra={
                "correlation_id": str(request.correlation_id),
                "model_id": request.model_id,
                "prompt_id": request.prompt_id,
            },
        )
        raise NotImplementedError(
            "OpenAILLMProvider real HTTP integration is intentionally out of "
            "scope for this cycle. Provide a custom LLMProvider implementation "
            "(see EchoLLMProvider for the reference shape) or wire the OpenAI "
            "Responses API in a follow-up cycle."
        )


__all__ = [
    "EchoLLMProvider",
    "LLMProvider",
    "LLMProviderError",
    "LLMProviderUnavailableError",
    "LLMRequest",
    "LLMResponse",
    "OpenAILLMProvider",
    "ResponseFormat",
]
