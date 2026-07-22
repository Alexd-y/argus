"""Declarative action interpreter for playbook steps (P2-PLAYBOOKS-002).

Actions are **pure structural operations** over declarative params. There are
no shell strings anywhere (SI-4): an ``http_request`` produces an
:class:`HttpRequestSpec` value object and hands it to an injected
:class:`HttpClient`; the network itself lives behind that abstraction so unit
tests substitute a deterministic stub.

Implemented here (real, tested): ``http_request``, ``extract``, ``compare``,
``wait``. ``browser_action`` is a defined interface whose interpreter lands in
P3/P4 — invoking it raises :class:`BrowserActionNotSupported` rather than
silently passing. ``register_cleanup`` is a control directive resolved by the
executor (P4); at the action layer it is a validated no-op that records the
cleanup id in the variable store.
"""

from __future__ import annotations

import json
import re
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Final, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr

from src.playbooks.schema import (
    ActionType,
    CompareMode,
    CompareParams,
    ExtractParams,
    ExtractSource,
    HttpMethod,
    HttpRequestParams,
    PlaybookStep,
    RegisterCleanupParams,
    WaitParams,
)

_TEMPLATE_RE: Final[re.Pattern[str]] = re.compile(r"\{([a-z][a-z0-9_.]*)\}")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ActionError(RuntimeError):
    """Raised when a step cannot be executed (bad reference, missing var)."""


class BrowserActionNotSupported(ActionError):
    """Raised when a ``browser_action`` step is executed before P3/P4 lands."""

    def __init__(self) -> None:
        super().__init__(
            "browser_action interpreter is not available yet (planned for P3/P4); "
            "the declarative schema is defined but no execution backend is wired"
        )


# ---------------------------------------------------------------------------
# Value objects
# ---------------------------------------------------------------------------


class HttpRequestSpec(BaseModel):
    """Fully-resolved, structural HTTP request handed to the client."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: HttpMethod
    url: StrictStr = Field(min_length=1, max_length=2048)
    headers: dict[StrictStr, StrictStr] = Field(default_factory=dict)
    query: dict[StrictStr, StrictStr] = Field(default_factory=dict)
    body: StrictStr | None = Field(default=None, max_length=65536)


class HttpResponse(BaseModel):
    """Structural HTTP response returned by the client abstraction."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: StrictInt = Field(ge=100, le=599)
    headers: dict[StrictStr, StrictStr] = Field(default_factory=dict)
    body: StrictStr = Field(default="", max_length=1_048_576)
    elapsed_ms: StrictInt = Field(default=0, ge=0, le=3_600_000)

    def header(self, name: str) -> str | None:
        """Case-insensitive header lookup."""
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return None


class HttpExchange(BaseModel):
    """A request paired with its response (unit of evidence)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    request: HttpRequestSpec
    response: HttpResponse


@runtime_checkable
class HttpClient(Protocol):
    """Abstraction over the network. Implementations live outside this layer.

    Keeping the client behind a Protocol means the action interpreter never
    imports an HTTP library, and tests inject a deterministic stub.
    """

    def send(self, spec: HttpRequestSpec, *, principal: str | None = None) -> HttpResponse:
        """Send ``spec`` (optionally as ``principal``) and return the response."""
        ...


@dataclass
class ActionContext:
    """Mutable per-scenario execution context.

    ``variables`` is the scenario variable store populated by ``save_as`` /
    ``extract``. ``sleep`` is injectable so ``wait`` never blocks tests.
    """

    http: HttpClient
    variables: dict[str, object] = field(default_factory=dict)
    exchanges: list[HttpExchange] = field(default_factory=list)
    sleep: Callable[[float], None] = time.sleep

    def get_var(self, name: str) -> object:
        try:
            return self.variables[name]
        except KeyError as exc:
            raise ActionError(f"unknown scenario variable {name!r}") from exc


@dataclass(frozen=True)
class ActionResult:
    """Outcome of a single step execution."""

    action: ActionType
    step_id: str
    ok: bool
    value: object = None
    exchange: HttpExchange | None = None
    detail: str = ""


# ---------------------------------------------------------------------------
# Templating (declarative variable substitution, never eval)
# ---------------------------------------------------------------------------


def substitute(template: str, variables: Mapping[str, object]) -> str:
    """Replace ``{var}`` / ``{var.subkey}`` tokens from ``variables``.

    Substitution is a plain string replacement — no expression evaluation.
    A missing variable raises :class:`ActionError` (fail-closed).
    """

    def _replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in variables:
            raise ActionError(f"template references unknown variable {name!r}")
        return str(variables[name])

    return _TEMPLATE_RE.sub(_replace, template)


def _substitute_map(mapping: Mapping[str, str], variables: Mapping[str, object]) -> dict[str, str]:
    return {key: substitute(value, variables) for key, value in mapping.items()}


# ---------------------------------------------------------------------------
# Action interface + implementations
# ---------------------------------------------------------------------------


class Action(ABC):
    """Interface for a single declarative step interpreter."""

    action_type: ActionType

    @abstractmethod
    def execute(self, step: PlaybookStep, ctx: ActionContext) -> ActionResult:
        """Execute ``step`` against ``ctx`` and return an :class:`ActionResult`."""
        raise NotImplementedError


class HttpRequestAction(Action):
    """Build a structural request from declarative params and send it."""

    action_type = ActionType.HTTP_REQUEST

    def execute(self, step: PlaybookStep, ctx: ActionContext) -> ActionResult:
        params = HttpRequestParams.model_validate(step.params)
        spec = HttpRequestSpec(
            method=params.method,
            url=substitute(params.url, ctx.variables),
            headers=_substitute_map(params.headers, ctx.variables),
            query=_substitute_map(params.query, ctx.variables),
            body=(substitute(params.body, ctx.variables) if params.body is not None else None),
        )
        response = ctx.http.send(spec, principal=step.principal)
        exchange = HttpExchange(request=spec, response=response)
        ctx.exchanges.append(exchange)
        if step.save_as is not None:
            ctx.variables[step.save_as] = exchange
        return ActionResult(
            action=self.action_type,
            step_id=step.id,
            ok=True,
            value=exchange,
            exchange=exchange,
        )


class ExtractAction(Action):
    """Read a value out of a prior exchange into the variable store."""

    action_type = ActionType.EXTRACT

    def execute(self, step: PlaybookStep, ctx: ActionContext) -> ActionResult:
        params = ExtractParams.model_validate(step.params)
        source_var = ctx.get_var(params.from_step)
        if not isinstance(source_var, HttpExchange):
            raise ActionError(f"extract source {params.from_step!r} is not an HttpExchange")
        value = self._read(source_var.response, params)
        if params.regex is not None and value is not None:
            match = re.search(params.regex, str(value))
            value = match.group(match.lastindex or 0) if match else None
        if step.save_as is not None:
            ctx.variables[step.save_as] = value
        return ActionResult(
            action=self.action_type,
            step_id=step.id,
            ok=value is not None,
            value=value,
        )

    @staticmethod
    def _read(response: HttpResponse, params: ExtractParams) -> object:
        if params.source is ExtractSource.STATUS_CODE:
            return response.status
        if params.source is ExtractSource.RESPONSE_HEADER:
            assert params.selector is not None  # enforced by schema validator
            return response.header(params.selector)
        # RESPONSE_BODY
        if params.selector:
            return _read_json_path(response.body, params.selector)
        return response.body


class CompareAction(Action):
    """Compare two resolved values with a fixed operator (pure)."""

    action_type = ActionType.COMPARE

    def execute(self, step: PlaybookStep, ctx: ActionContext) -> ActionResult:
        params = CompareParams.model_validate(step.params)
        left = substitute(params.left, ctx.variables)
        right = substitute(params.right, ctx.variables)
        ok = self._apply(params.mode, left, right)
        if step.save_as is not None:
            ctx.variables[step.save_as] = ok
        return ActionResult(
            action=self.action_type,
            step_id=step.id,
            ok=ok,
            value=ok,
            detail=f"{params.mode.value}({left!r}, {right!r})={ok}",
        )

    @staticmethod
    def _apply(mode: CompareMode, left: str, right: str) -> bool:
        if mode is CompareMode.EQUAL:
            return left == right
        if mode is CompareMode.NOT_EQUAL:
            return left != right
        if mode is CompareMode.CONTAINS:
            return right in left
        if mode is CompareMode.NOT_CONTAINS:
            return right not in left
        if mode is CompareMode.STATUS_CHANGED:
            return left != right
        # Exhaustive over CompareMode; unreachable unless the enum grows.
        raise ActionError(f"unhandled compare mode {mode!r}")


class WaitAction(Action):
    """Bounded declarative wait; delegates sleeping to the injected sleeper."""

    action_type = ActionType.WAIT

    def execute(self, step: PlaybookStep, ctx: ActionContext) -> ActionResult:
        params = WaitParams.model_validate(step.params)
        ctx.sleep(params.seconds)
        return ActionResult(
            action=self.action_type,
            step_id=step.id,
            ok=True,
            value=params.seconds,
        )


class RegisterCleanupAction(Action):
    """Record a cleanup step id in the context (executor consumes it in P4)."""

    action_type = ActionType.REGISTER_CLEANUP
    _VAR_KEY: Final[str] = "__registered_cleanups__"

    def execute(self, step: PlaybookStep, ctx: ActionContext) -> ActionResult:
        params = RegisterCleanupParams.model_validate(step.params)
        registered = ctx.variables.setdefault(self._VAR_KEY, [])
        if not isinstance(registered, list):
            raise ActionError("registered-cleanup store is corrupt")
        registered.append(params.cleanup_step_id)
        return ActionResult(
            action=self.action_type,
            step_id=step.id,
            ok=True,
            value=params.cleanup_step_id,
        )


class BrowserAction(Action):
    """Declarative browser step. Execution backend arrives in P3/P4."""

    action_type = ActionType.BROWSER_ACTION

    def execute(self, step: PlaybookStep, ctx: ActionContext) -> ActionResult:
        raise BrowserActionNotSupported


# ---------------------------------------------------------------------------
# JSON path reader (dotted, declarative)
# ---------------------------------------------------------------------------


def _read_json_path(body: str, path: str) -> object:
    """Read a dotted ``a.b.0.c`` path out of a JSON body.

    Returns ``None`` if the body is not JSON or the path is absent. Pure and
    side-effect free; never evaluates the path as code.
    """
    try:
        current: object = json.loads(body)
    except (ValueError, TypeError):
        return None
    for segment in path.split("."):
        if isinstance(current, Mapping):
            if segment not in current:
                return None
            current = current[segment]
        elif isinstance(current, list):
            if not segment.isdigit():
                return None
            index = int(segment)
            if index >= len(current):
                return None
            current = current[index]
        else:
            return None
    return current


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


_ACTIONS: Final[dict[ActionType, Action]] = {
    action.action_type: action
    for action in (
        HttpRequestAction(),
        ExtractAction(),
        CompareAction(),
        WaitAction(),
        RegisterCleanupAction(),
        BrowserAction(),
    )
}


def get_action(action_type: ActionType) -> Action:
    """Return the interpreter registered for ``action_type``."""
    return _ACTIONS[action_type]


def execute_step(step: PlaybookStep, ctx: ActionContext) -> ActionResult:
    """Dispatch ``step`` to its registered :class:`Action` interpreter."""
    return get_action(step.action).execute(step, ctx)


__all__ = [
    "Action",
    "ActionContext",
    "ActionError",
    "ActionResult",
    "BrowserAction",
    "BrowserActionNotSupported",
    "CompareAction",
    "ExtractAction",
    "HttpClient",
    "HttpExchange",
    "HttpRequestAction",
    "HttpRequestSpec",
    "HttpResponse",
    "RegisterCleanupAction",
    "WaitAction",
    "execute_step",
    "get_action",
    "substitute",
]
