"""Cairn API contracts (Pydantic) + shared constants.

Ported from ``_external/Cairn/cairn/src/cairn/server/models.py`` (AGPL-3.0),
preserving the external contract shape so existing Cairn clients keep working.

Contract note (documented in ``docs/cairn_port_deviations.md``): path parameters
accept ARGUS UUIDs, but graph-node ``id`` fields in response bodies carry the
human-readable ``ref`` (``origin`` / ``goal`` / ``f001`` / ``i001``) so ``from`` /
``to`` edges line up exactly as in upstream. ARGUS-specific fields are optional
additions and never change the base shape.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Final, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

# --- shared constants --------------------------------------------------------

#: Special fact refs created together with the project.
ORIGIN_REF: Final[str] = "origin"
GOAL_REF: Final[str] = "goal"

#: Creator string used for the dispatcher-created bootstrap intent (upstream D-04).
BOOTSTRAP_CREATOR: Final[str] = "dispatcher.bootstrap"
BOOTSTRAP_DESCRIPTION: Final[str] = "bootstrap"


def _non_empty(value: str) -> str:
    text = value.strip()
    if not text:
        raise ValueError("must not be empty")
    return text


def _clean_refs(value: list[str]) -> list[str]:
    cleaned = [item.strip() for item in value]
    if any(not item for item in cleaned):
        raise ValueError("fact ids must not be empty")
    return cleaned


#: Trimmed, non-empty string (mirrors the upstream field validators).
NonEmptyStr = Annotated[str, AfterValidator(_non_empty)]
#: List of trimmed, non-empty fact refs.
FactRefList = Annotated[list[str], AfterValidator(_clean_refs)]


# --- response models ---------------------------------------------------------


class Fact(BaseModel):
    id: str  # ref
    description: str
    # ARGUS additions (optional — do not change the base shape)
    uuid: str | None = None
    evidence_refs: list[Any] | None = None
    evidence_tier: int | None = None
    finding_id: str | None = None


class Intent(BaseModel):
    id: str  # ref
    from_: list[str] = Field(alias="from")  # source refs
    to: str | None = None  # to-fact ref (``goal`` for completion) or None
    description: str
    creator: str
    worker: str | None = None
    last_heartbeat_at: datetime | None = None
    created_at: datetime
    concluded_at: datetime | None = None
    uuid: str | None = None

    model_config = ConfigDict(populate_by_name=True)


class Hint(BaseModel):
    id: str  # ref
    content: str
    creator: str
    created_at: datetime
    uuid: str | None = None


class ProjectReason(BaseModel):
    worker: str
    trigger: str | None = None
    started_at: datetime | None = None
    last_heartbeat_at: datetime | None = None


class ProjectMeta(BaseModel):
    id: str  # ARGUS project UUID (path id)
    ref: str
    title: str
    status: Literal["active", "stopped", "completed"]
    bootstrap_enabled: bool
    created_at: datetime
    reason: ProjectReason | None = None
    scan_id: str | None = None
    execution_mode: str | None = None


class ProjectSummary(ProjectMeta):
    fact_count: int
    intent_count: int
    working_intent_count: int
    unclaimed_intent_count: int
    hint_count: int


class ProjectDetail(BaseModel):
    project: ProjectMeta
    facts: list[Fact]
    intents: list[Intent]
    hints: list[Hint]


class ConcludeResponse(BaseModel):
    fact: Fact
    intent: Intent


class ReopenResponse(BaseModel):
    project: ProjectMeta
    fact: Fact
    intent: Intent


class Settings(BaseModel):
    intent_timeout: int = Field(ge=5)
    reason_timeout: int = Field(ge=5)
    max_intents: int = Field(ge=1, default=3)
    max_workers: int = Field(ge=1, default=8)
    max_running_projects: int = Field(ge=1, default=3)
    max_project_workers: int = Field(ge=1, default=4)
    tick_interval_sec: int = Field(ge=1, default=10)


# --- request models ----------------------------------------------------------


class CreateHintInline(BaseModel):
    content: NonEmptyStr
    creator: NonEmptyStr


class CreateProjectRequest(BaseModel):
    title: NonEmptyStr
    origin: NonEmptyStr
    goal: NonEmptyStr
    bootstrap_enabled: bool = True
    hints: list[CreateHintInline] | None = None
    # ARGUS additions
    scan_id: str | None = None
    execution_mode: str = "production"
    options: dict[str, Any] | None = None


class CreateHintRequest(BaseModel):
    content: NonEmptyStr
    creator: NonEmptyStr
    author_user_id: str | None = None


class CreateIntentRequest(BaseModel):
    from_: FactRefList = Field(alias="from", min_length=1)
    description: NonEmptyStr
    creator: NonEmptyStr
    worker: NonEmptyStr | None = None

    model_config = ConfigDict(populate_by_name=True)


class HeartbeatRequest(BaseModel):
    worker: NonEmptyStr


class ReasonClaimRequest(BaseModel):
    worker: NonEmptyStr
    trigger: NonEmptyStr


class ConcludeRequest(BaseModel):
    worker: NonEmptyStr
    description: NonEmptyStr
    evidence_refs: list[Any] | None = None
    evidence_tier: int | None = None


class CompleteRequest(BaseModel):
    from_: FactRefList = Field(alias="from", min_length=1)
    description: NonEmptyStr
    worker: NonEmptyStr

    model_config = ConfigDict(populate_by_name=True)


class UpdateProjectStatusRequest(BaseModel):
    status: Literal["active", "stopped"]


class UpdateProjectTitleRequest(BaseModel):
    title: NonEmptyStr


class ReopenRequest(BaseModel):
    description: NonEmptyStr
    creator: NonEmptyStr


class CreateFactRequest(BaseModel):
    """ARGUS addition — human adds an external-feedback fact directly (§5.2)."""

    description: NonEmptyStr
    evidence_refs: list[Any] | None = None
