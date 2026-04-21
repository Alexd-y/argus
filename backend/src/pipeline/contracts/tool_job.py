"""ToolJob and supporting value objects.

A :class:`ToolJob` is the typed dispatchable unit for a single tool invocation.
It travels from the Planner / Dispatcher (control-plane) to the SandboxAdapter
(execution-plane) over a typed queue. Sensitive substitution values such as
secrets MUST NOT be placed in :attr:`ToolJob.parameters`; only allow-listed
placeholders defined by :mod:`src.pipeline.contracts._placeholders` are valid
(see Backlog/dev1_md §18). The same allow-list is consumed by
:mod:`src.sandbox.templating` to render the final argv.

The job DOES NOT carry a command string. The command is materialised inside the
sandbox by the ToolAdapter using a signed registry entry; see Backlog/dev1_md §3.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from src.pipeline.contracts._placeholders import ALLOWED_PLACEHOLDERS as _ALLOWED_PARAM_KEYS
from src.pipeline.contracts.phase_io import ScanPhase

# ``_ALLOWED_PARAM_KEYS`` is intentionally a thin re-export of the canonical
# allow-list defined in :mod:`src.pipeline.contracts._placeholders`. The same
# frozenset is also re-exported by :mod:`src.sandbox.templating` so that the
# YAML template renderer and the ``ToolJob`` contract can never drift apart
# (Backlog/dev1_md §18). Adding a new placeholder requires editing the
# canonical module + a security review.

_PARAM_KEY_RE = re.compile(r"^[a-z_][a-z0-9_]{0,30}$")
_TOOL_ID_RE = re.compile(r"^[a-z][a-z0-9_]{1,63}$")
_CORRELATION_ID_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")


class RiskLevel(StrEnum):
    """Risk classification of a tool / action (Backlog/dev1_md §3)."""

    PASSIVE = "passive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    DESTRUCTIVE = "destructive"


class TargetKind(StrEnum):
    """Discriminator for :class:`TargetSpec`.

    Each ToolJob targets exactly one of these representations; the sandbox adapter
    chooses the appropriate placeholder when rendering the command template.
    """

    URL = "url"
    HOST = "host"
    IP = "ip"
    CIDR = "cidr"
    DOMAIN = "domain"


class TargetSpec(BaseModel):
    """Mutually-exclusive specification of the scan target for a single ToolJob.

    Exactly one of ``url`` / ``host`` / ``ip`` / ``cidr`` / ``domain`` MUST be set.
    The validator enforces this; downstream code can rely on
    ``spec.kind`` to know which field is populated.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: TargetKind
    url: StrictStr | None = Field(default=None, max_length=2048)
    host: StrictStr | None = Field(default=None, max_length=255)
    ip: StrictStr | None = Field(default=None, max_length=45)
    cidr: StrictStr | None = Field(default=None, max_length=49)
    domain: StrictStr | None = Field(default=None, max_length=253)

    @model_validator(mode="after")
    def _validate_exclusive(self) -> Self:
        fields = {
            TargetKind.URL: self.url,
            TargetKind.HOST: self.host,
            TargetKind.IP: self.ip,
            TargetKind.CIDR: self.cidr,
            TargetKind.DOMAIN: self.domain,
        }
        populated = [k for k, v in fields.items() if v is not None]
        if len(populated) != 1:
            raise ValueError(
                "TargetSpec requires exactly one of url/host/ip/cidr/domain to be set, "
                f"got {len(populated)} ({[k.value for k in populated]})"
            )
        if populated[0] is not self.kind:
            raise ValueError(
                f"TargetSpec.kind={self.kind.value} but populated field is "
                f"{populated[0].value}"
            )
        return self

    @property
    def value(self) -> str:
        """Return the populated target string (always present after validation)."""
        # mypy/strict: kind is always one of the enum values and exactly one field is set.
        if self.kind is TargetKind.URL:
            assert self.url is not None
            return self.url
        if self.kind is TargetKind.HOST:
            assert self.host is not None
            return self.host
        if self.kind is TargetKind.IP:
            assert self.ip is not None
            return self.ip
        if self.kind is TargetKind.CIDR:
            assert self.cidr is not None
            return self.cidr
        assert self.domain is not None
        return self.domain


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


class ToolJob(BaseModel):
    """Typed dispatchable unit for a single tool invocation.

    See Backlog/dev1_md §3 (ToolAdapter) and §16.1 (contracts step).

    Notes
    -----
    * ``parameters`` substitute into the registered ``command_template``; only the
      placeholders enumerated in ``_ALLOWED_PARAM_KEYS`` are accepted at the contract
      level. Secrets MUST come from CSI-mounted Kubernetes Secrets, never from here.
    * ``approval_id`` MUST be set whenever ``requires_approval`` is True; the
      Dispatcher refuses to enqueue jobs that violate this invariant.
    * ``correlation_id`` is a free-form OTel trace id — keep it short and printable.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: UUID
    tenant_id: UUID
    scan_id: UUID
    tool_id: StrictStr = Field(min_length=2, max_length=64)
    phase: ScanPhase
    risk_level: RiskLevel
    target: TargetSpec
    parameters: dict[str, str] = Field(default_factory=dict)
    inputs_dir: StrictStr | None = Field(default=None, max_length=512)
    outputs_dir: StrictStr = Field(min_length=1, max_length=512)
    timeout_s: StrictInt = Field(ge=1, le=86_400)
    requires_approval: StrictBool = False
    approval_id: UUID | None = None
    policy_decision_id: UUID | None = None
    correlation_id: StrictStr = Field(min_length=1, max_length=128)
    created_at: datetime = Field(default_factory=_utcnow)

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if not _TOOL_ID_RE.fullmatch(self.tool_id):
            raise ValueError(
                "tool_id must match ^[a-z][a-z0-9_]{1,63}$ (lowercase, snake_case)"
            )
        if not _CORRELATION_ID_RE.fullmatch(self.correlation_id):
            raise ValueError("correlation_id contains illegal characters")
        # ``parameters`` is typed ``dict[str, str]`` and validated by Pydantic
        # before this hook runs, so we only need key-shape and allow-list checks.
        for key in self.parameters:
            if not _PARAM_KEY_RE.fullmatch(key):
                raise ValueError(
                    f"parameter key {key!r} is not snake_case / too long"
                )
            if key not in _ALLOWED_PARAM_KEYS:
                raise ValueError(
                    f"parameter key {key!r} is not in the sandbox allow-list "
                    f"(see src.sandbox.templating)"
                )
        if self.requires_approval and self.approval_id is None:
            raise ValueError("approval_id is required when requires_approval is True")
        if not self.requires_approval and self.approval_id is not None:
            raise ValueError(
                "approval_id must be empty when requires_approval is False"
            )
        if self.risk_level in {RiskLevel.HIGH, RiskLevel.DESTRUCTIVE} and not self.requires_approval:
            raise ValueError(
                f"risk_level={self.risk_level.value} requires requires_approval=True"
            )
        if self.inputs_dir is not None and self.inputs_dir == self.outputs_dir:
            raise ValueError("inputs_dir and outputs_dir must differ")
        return self
