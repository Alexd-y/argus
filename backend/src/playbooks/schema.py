"""Declarative, non-executable playbook schema for ARGUS (P2-PLAYBOOKS-002).

A *playbook* is a signed, declarative description of a security scenario
(IDOR, auth-bypass, rate-limit abuse, ...). It is intentionally **data, not
code**: a playbook can never carry Python, shell strings, or import paths.

Security invariants baked into these models:

* ``model_config = ConfigDict(extra="forbid", frozen=True)`` everywhere — any
  unexpected YAML key is a hard validation error (fail-closed), and loaded
  playbooks are immutable at runtime.
* ``PlaybookStep.action`` is a closed :class:`ActionType` enum; ``params`` are
  re-validated against a per-action typed model (SI-4: no free-form execution
  fields, no shell strings, no ``eval``/``exec``/import).
* Payload families are referenced by ``family_id`` **strings only** — a
  playbook never inlines or generates payloads (SI-5). Materialisation stays
  the sole responsibility of :class:`~src.payloads.builder.PayloadBuilder`.
* ``title`` / ``description`` are human documentation, never LLM instructions
  (SI-6). No consumer in this module feeds them into a prompt.

The runtime interpreter (actions / oracles / evidence) lives in sibling
modules; this file defines only the on-disk contract.
"""

from __future__ import annotations

import re
from datetime import date
from enum import StrEnum
from typing import Annotated, Final, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)

# ``idor.cross-user-read`` style: a dotted, lowercase, hyphen-friendly slug.
_PLAYBOOK_ID_PATTERN: Final[str] = r"^[a-z][a-z0-9]*(\.[a-z0-9-]+)+$"
_PLAYBOOK_ID_RE: Final[re.Pattern[str]] = re.compile(_PLAYBOOK_ID_PATTERN)
_STEP_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_SAVE_AS_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_WSTG_RE: Final[re.Pattern[str]] = re.compile(r"^WSTG-[A-Z]{4}-\d{2}$")
_OWASP_API_RE: Final[re.Pattern[str]] = re.compile(r"^API\d{1,2}:20\d{2}$")


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class PlaybookCategory(StrEnum):
    """Top-level scenario category a playbook belongs to."""

    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    ACCOUNT_LIFECYCLE = "account_lifecycle"
    SESSION_MANAGEMENT = "session_management"
    BUSINESS_LOGIC = "business_logic"
    RATE_LIMIT = "rate_limit"
    RACE_CONDITIONS = "race_conditions"
    FILE_UPLOAD = "file_upload"
    TECHNOLOGY_EXPOSURE = "technology_exposure"


class PlaybookRiskLevel(StrEnum):
    """Risk classification for a playbook (drives the approval gate)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DESTRUCTIVE = "destructive"


class ActionType(StrEnum):
    """Closed set of declarative step actions.

    Adding a new action requires adding a matching params model and wiring an
    interpreter in :mod:`src.playbooks.actions`. There is deliberately no
    "run_shell" / "eval" member (SI-4).
    """

    HTTP_REQUEST = "http_request"
    BROWSER_ACTION = "browser_action"
    EXTRACT = "extract"
    COMPARE = "compare"
    WAIT = "wait"
    REGISTER_CLEANUP = "register_cleanup"


class HttpMethod(StrEnum):
    """HTTP verbs a declarative request may use."""

    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"


class BrowserActionKind(StrEnum):
    """Declarative browser interaction kinds (interpreter lands in P3/P4)."""

    NAVIGATE = "navigate"
    CLICK = "click"
    TYPE = "type"
    WAIT_FOR = "wait_for"
    SCREENSHOT = "screenshot"


class ExtractSource(StrEnum):
    """Where an ``extract`` step reads a value from."""

    RESPONSE_BODY = "response_body"
    RESPONSE_HEADER = "response_header"
    STATUS_CODE = "status_code"


class CompareMode(StrEnum):
    """Comparison operator for a ``compare`` step."""

    EQUAL = "equal"
    NOT_EQUAL = "not_equal"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STATUS_CHANGED = "status_changed"


class InputKind(StrEnum):
    """Kinds of injectable inputs a playbook may target."""

    PATH_PARAM = "path_param"
    QUERY_PARAM = "query_param"
    BODY_JSON = "body_json"
    BODY_FORM = "body_form"
    HEADER = "header"
    COOKIE = "cookie"
    MULTIPART_FILE = "multipart_file"


class OracleType(StrEnum):
    """Closed set of oracle kinds a playbook may assert against."""

    AUTHZ = "authz"
    AUTHN = "authn"
    RATE_LIMIT = "rate_limit"
    RACE = "race"
    FILE_UPLOAD = "file_upload"
    BUSINESS_LOGIC = "business_logic"


class PreconditionKind(StrEnum):
    """Declarative precondition kinds evaluated before a scenario runs."""

    PRINCIPAL_AVAILABLE = "principal_available"
    CAPABILITY_AVAILABLE = "capability_available"
    ENDPOINT_REACHABLE = "endpoint_reachable"
    OPENAPI_AVAILABLE = "openapi_available"


# ---------------------------------------------------------------------------
# Provenance / applicability
# ---------------------------------------------------------------------------


class Provenance(BaseModel):
    """Where a playbook was adapted from (audit / attribution trail)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_url: StrictStr | None = Field(default=None, max_length=512)
    commit: StrictStr | None = Field(default=None, max_length=64)
    adapted_at: date | None = None
    note: StrictStr = Field(default="", max_length=1024)


class AppliesWhen(BaseModel):
    """Declarative applicability predicate for an endpoint / asset.

    All conditions are *conjunctive*: a playbook applies only when every
    populated condition matches. Empty conditions are treated as
    "no constraint" (see :meth:`matches` in the planner).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    methods: list[HttpMethod] = Field(default_factory=list, max_length=len(HttpMethod))
    path_globs: list[StrictStr] = Field(default_factory=list, max_length=64)
    requires_openapi: StrictBool = False
    input_kinds: list[InputKind] = Field(default_factory=list, max_length=len(InputKind))

    @field_validator("path_globs")
    @classmethod
    def _check_globs(cls, value: list[str]) -> list[str]:
        for glob in value:
            if not glob or len(glob) > 512:
                raise ValueError("path_globs entries must be 1..512 chars")
            if "\n" in glob or "\r" in glob:
                raise ValueError("path_globs entries must be single-line")
        return value


# ---------------------------------------------------------------------------
# Per-action typed params (validated dispatch below)
# ---------------------------------------------------------------------------


class HttpRequestParams(BaseModel):
    """Declarative HTTP request. No network call, no shell strings (SI-4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    method: HttpMethod
    url: StrictStr = Field(min_length=1, max_length=2048)
    headers: dict[StrictStr, StrictStr] = Field(default_factory=dict, max_length=64)
    query: dict[StrictStr, StrictStr] = Field(default_factory=dict, max_length=64)
    body: StrictStr | None = Field(default=None, max_length=65536)
    payload_family: StrictStr | None = Field(default=None, max_length=64)

    @field_validator("url")
    @classmethod
    def _check_url(cls, value: str) -> str:
        if "\n" in value or "\r" in value:
            raise ValueError("url must be single-line")
        return value


class BrowserActionParams(BaseModel):
    """Declarative browser interaction (interpreter arrives in P3/P4)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: BrowserActionKind
    selector: StrictStr | None = Field(default=None, max_length=1024)
    value: StrictStr | None = Field(default=None, max_length=8192)
    url: StrictStr | None = Field(default=None, max_length=2048)


class ExtractParams(BaseModel):
    """Read a value from a prior response into the scenario variable store."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    from_step: StrictStr = Field(min_length=1, max_length=64)
    source: ExtractSource
    # For RESPONSE_HEADER: the header name. For RESPONSE_BODY: a dotted JSON
    # path (declarative, evaluated by the interpreter, never eval'd).
    selector: StrictStr | None = Field(default=None, max_length=512)
    regex: StrictStr | None = Field(default=None, max_length=512)

    @field_validator("regex")
    @classmethod
    def _check_regex(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            re.compile(value)
        except re.error as exc:
            raise ValueError(f"invalid extract regex: {exc}") from exc
        return value

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.source is ExtractSource.RESPONSE_HEADER and not self.selector:
            raise ValueError("extract from response_header requires a selector")
        return self


class CompareParams(BaseModel):
    """Compare two scenario variables / literals with a fixed operator."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    left: StrictStr = Field(min_length=1, max_length=1024)
    right: StrictStr = Field(min_length=1, max_length=1024)
    mode: CompareMode


class WaitParams(BaseModel):
    """Bounded declarative wait (seconds)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    seconds: float = Field(gt=0.0, le=60.0)


class RegisterCleanupParams(BaseModel):
    """Register a cleanup step (by id) to run during teardown."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    cleanup_step_id: StrictStr = Field(min_length=1, max_length=64)


# Map each action to the params model that validates it. Central so the
# registry, planner, and interpreter share one source of truth.
_ACTION_PARAM_MODELS: Final[dict[ActionType, type[BaseModel]]] = {
    ActionType.HTTP_REQUEST: HttpRequestParams,
    ActionType.BROWSER_ACTION: BrowserActionParams,
    ActionType.EXTRACT: ExtractParams,
    ActionType.COMPARE: CompareParams,
    ActionType.WAIT: WaitParams,
    ActionType.REGISTER_CLEANUP: RegisterCleanupParams,
}


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------


class PlaybookStep(BaseModel):
    """One declarative step. ``params`` are validated against ``action``.

    The raw ``params`` mapping is re-parsed through the matching typed model
    in :data:`_ACTION_PARAM_MODELS`; unknown keys or wrong shapes fail
    validation. Use :meth:`typed_params` to obtain the parsed model.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(min_length=1, max_length=64)
    action: ActionType
    params: dict[StrictStr, object] = Field(default_factory=dict)
    principal: StrictStr | None = Field(default=None, max_length=64)
    save_as: StrictStr | None = Field(default=None, max_length=64)

    @field_validator("id")
    @classmethod
    def _check_id(cls, value: str) -> str:
        if not _STEP_ID_RE.fullmatch(value):
            raise ValueError("step id must match ^[a-z][a-z0-9_]{0,63}$ " f"(got {value!r})")
        return value

    @field_validator("save_as")
    @classmethod
    def _check_save_as(cls, value: str | None) -> str | None:
        if value is not None and not _SAVE_AS_RE.fullmatch(value):
            raise ValueError("save_as must match ^[a-z][a-z0-9_]{0,63}$ " f"(got {value!r})")
        return value

    @model_validator(mode="after")
    def _validate_params(self) -> Self:
        model_cls = _ACTION_PARAM_MODELS[self.action]
        try:
            model_cls.model_validate(self.params)
        except ValidationError as exc:
            raise ValueError(
                f"params for action {self.action.value!r} are invalid: "
                f"{exc.error_count()} error(s)"
            ) from exc
        return self

    def typed_params(self) -> BaseModel:
        """Return the validated, strongly-typed params model for this step."""
        return _ACTION_PARAM_MODELS[self.action].model_validate(self.params)


# ---------------------------------------------------------------------------
# Oracles / preconditions
# ---------------------------------------------------------------------------


class OracleSpec(BaseModel):
    """Assertion the scenario evaluates to decide CONFIRMED vs REJECTED."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: OracleType
    params: dict[StrictStr, object] = Field(default_factory=dict)


class Precondition(BaseModel):
    """Declarative gate evaluated before a scenario is allowed to run."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: PreconditionKind
    value: StrictStr = Field(min_length=1, max_length=256)


# ---------------------------------------------------------------------------
# Top-level playbook
# ---------------------------------------------------------------------------


class Playbook(BaseModel):
    """Top-level signed, declarative playbook descriptor."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: StrictInt = Field(ge=1, le=1_000)
    playbook_id: Annotated[
        StrictStr, Field(min_length=3, max_length=128, pattern=_PLAYBOOK_ID_PATTERN)
    ]
    version: StrictInt = Field(ge=1, le=1_000_000)
    title: StrictStr = Field(min_length=1, max_length=200)
    description: StrictStr = Field(min_length=1, max_length=4000)
    category: PlaybookCategory
    provenance: Provenance = Field(default_factory=Provenance)
    cwe: list[StrictInt] = Field(default_factory=list, max_length=16)
    wstg: list[StrictStr] = Field(default_factory=list, max_length=32)
    owasp_api: list[StrictStr] = Field(default_factory=list, max_length=16)
    tags: list[StrictStr] = Field(default_factory=list, max_length=32)
    applies_when: AppliesWhen = Field(default_factory=AppliesWhen)
    required_capabilities: list[StrictStr] = Field(default_factory=list, max_length=32)
    required_principals: list[StrictStr] = Field(default_factory=list, max_length=16)
    risk_level: PlaybookRiskLevel
    requires_approval: StrictBool = False
    preconditions: list[Precondition] = Field(default_factory=list, max_length=32)
    steps: list[PlaybookStep] = Field(min_length=1, max_length=128)
    assertions: list[OracleSpec] = Field(min_length=1, max_length=32)
    required_evidence: list[StrictStr] = Field(default_factory=list, max_length=32)
    cleanup: list[PlaybookStep] = Field(default_factory=list, max_length=64)
    timeout_seconds: StrictInt = Field(default=300, ge=1, le=86_400)
    max_concurrency: StrictInt = Field(default=1, ge=1, le=64)

    # -- field validators ----------------------------------------------------

    @field_validator("cwe")
    @classmethod
    def _check_cwe(cls, value: list[int]) -> list[int]:
        for cwe in value:
            if cwe <= 0:
                raise ValueError(f"CWE id must be positive, got {cwe}")
        if len(set(value)) != len(value):
            raise ValueError("cwe entries must be unique")
        return value

    @field_validator("wstg")
    @classmethod
    def _check_wstg(cls, value: list[str]) -> list[str]:
        for entry in value:
            if not _WSTG_RE.fullmatch(entry):
                raise ValueError(f"wstg entries must look like WSTG-XXXX-NN, got {entry!r}")
        return value

    @field_validator("owasp_api")
    @classmethod
    def _check_owasp_api(cls, value: list[str]) -> list[str]:
        for entry in value:
            if not _OWASP_API_RE.fullmatch(entry):
                raise ValueError(f"owasp_api entries must look like API3:2023, got {entry!r}")
        return value

    @field_validator("required_principals")
    @classmethod
    def _check_principals(cls, value: list[str]) -> list[str]:
        for principal in value:
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", principal):
                raise ValueError(
                    "required_principals entries must match [a-z][a-z0-9_]{0,31}, "
                    f"got {principal!r}"
                )
        if len(set(value)) != len(value):
            raise ValueError("required_principals must be unique")
        return value

    # -- cross-field validation ----------------------------------------------

    @model_validator(mode="after")
    def _validate(self) -> Self:
        self._check_unique_step_ids()
        self._check_principal_references()
        self._check_cleanup_references()
        self._check_approval_gate()
        return self

    def _all_steps(self) -> list[PlaybookStep]:
        return [*self.steps, *self.cleanup]

    def _check_unique_step_ids(self) -> None:
        ids = [step.id for step in self._all_steps()]
        if len(set(ids)) != len(ids):
            raise ValueError("step ids must be unique across steps + cleanup")

    def _check_principal_references(self) -> None:
        if not self.required_principals:
            return
        declared = set(self.required_principals)
        for step in self._all_steps():
            if step.principal is not None and step.principal not in declared:
                raise ValueError(
                    f"step {step.id!r} references principal "
                    f"{step.principal!r} not in required_principals"
                )

    def _check_cleanup_references(self) -> None:
        cleanup_ids = {step.id for step in self.cleanup}
        for step in self.steps:
            if step.action is not ActionType.REGISTER_CLEANUP:
                continue
            params = RegisterCleanupParams.model_validate(step.params)
            if params.cleanup_step_id not in cleanup_ids:
                raise ValueError(
                    f"register_cleanup step {step.id!r} references unknown "
                    f"cleanup step {params.cleanup_step_id!r}"
                )

    def _check_approval_gate(self) -> None:
        if self.risk_level in {PlaybookRiskLevel.HIGH, PlaybookRiskLevel.DESTRUCTIVE}:
            if not self.requires_approval:
                raise ValueError(
                    f"playbook_id={self.playbook_id!r}: risk_level="
                    f"{self.risk_level.value} requires requires_approval=True"
                )


def is_valid_playbook_id(value: str) -> bool:
    """Return ``True`` if ``value`` is a well-formed ``playbook_id``."""
    return bool(_PLAYBOOK_ID_RE.fullmatch(value))


# StrEnum aliases used by callers that want a Literal-free import surface.
ActionLiteral = Literal[
    "http_request",
    "browser_action",
    "extract",
    "compare",
    "wait",
    "register_cleanup",
]


__all__ = [
    "ActionLiteral",
    "ActionType",
    "AppliesWhen",
    "BrowserActionKind",
    "BrowserActionParams",
    "CompareMode",
    "CompareParams",
    "ExtractParams",
    "ExtractSource",
    "HttpMethod",
    "HttpRequestParams",
    "InputKind",
    "OracleSpec",
    "OracleType",
    "Playbook",
    "PlaybookCategory",
    "PlaybookRiskLevel",
    "PlaybookStep",
    "Precondition",
    "PreconditionKind",
    "Provenance",
    "RegisterCleanupParams",
    "WaitParams",
    "is_valid_playbook_id",
]
