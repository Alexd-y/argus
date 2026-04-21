"""Signed prompt registry for the ARGUS AI orchestrator (Backlog/dev1_md §6, §19).

Mirrors :mod:`src.payloads.registry` for prompt definitions: every YAML
under ``backend/config/prompts/<prompt_id>.yaml`` carries one
:class:`PromptDefinition` and is verified against
``backend/config/prompts/SIGNATURES`` using the same Ed25519 infrastructure
exposed by :mod:`src.sandbox.signing`.

Why signed prompts?
-------------------
Prompts are part of the trust boundary: a malicious or accidentally edited
``planner_v1.yaml`` can shift the planner's behaviour, downgrade safety
constraints, or open the door to prompt-injection chains. Signing keeps
the supply-chain story consistent (tools, payloads, prompts all under the
same Ed25519 key rotation policy).

The registry is **fail-closed**:

* unknown / missing signatures → :class:`PromptSignatureError`
* missing or malformed YAML / unknown prompt_id → :class:`PromptRegistryError`
* duplicate prompt_id → :class:`PromptRegistryError`

Lookup is O(1) by ``prompt_id``; :meth:`PromptRegistry.list_by_role`
returns the precomputed per-role bucket (also O(1) on the role index).
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
)

from src.sandbox.signing import (
    IntegrityError,
    KeyManager,
    KeyNotFoundError,
    SignatureError,
    SignaturesFile,
)

_logger = logging.getLogger(__name__)


_SIGNATURES_FILENAME: Final[str] = "SIGNATURES"
_KEYS_DIRNAME: Final[str] = "_keys"
_PROMPT_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_VERSION_RE: Final[re.Pattern[str]] = re.compile(r"^\d+\.\d+\.\d+$")
_SCHEMA_REF_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9_]{2,63}$")
_MODEL_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9._\-]{1,127}$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PromptRegistryError(Exception):
    """Raised by :meth:`PromptRegistry.load` for any fail-closed condition."""


class PromptSignatureError(PromptRegistryError):
    """Raised when a prompt YAML fails Ed25519 signature verification."""


class PromptNotFoundError(KeyError):
    """Raised by :meth:`PromptRegistry.get` for an unknown ``prompt_id``."""

    def __init__(self, prompt_id: str) -> None:
        super().__init__(prompt_id)
        self.prompt_id = prompt_id


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class AgentRole(StrEnum):
    """Closed taxonomy of orchestrator agent roles (Backlog/dev1_md §17)."""

    PLANNER = "planner"
    CRITIC = "critic"
    VERIFIER = "verifier"
    REPORTER = "reporter"
    FIXER = "fixer"


class PromptDefinition(BaseModel):
    """One signed prompt entry parsed from a YAML descriptor.

    Notes
    -----
    * ``user_prompt_template`` is rendered with ``str.format(**kwargs)``
      by :class:`~src.orchestrator.agents.BaseAgent`. Keep placeholders
      simple (``{key}``); braces in literal text must be escaped (``{{`` / ``}}``).
    * ``expected_schema_ref`` is a *string id* (e.g. ``validation_plan_v1``)
      resolved to a JSON Schema by the agent layer at runtime; the registry
      does not own that mapping (keeps the dependency direction one-way).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    prompt_id: StrictStr = Field(min_length=3, max_length=64)
    version: StrictStr = Field(min_length=5, max_length=16)
    agent_role: AgentRole
    description: StrictStr = Field(min_length=1, max_length=500)
    system_prompt: StrictStr = Field(min_length=1, max_length=8_000)
    user_prompt_template: StrictStr = Field(min_length=1, max_length=16_000)
    expected_schema_ref: StrictStr | None = Field(default=None, max_length=64)
    default_model_id: StrictStr = Field(min_length=1, max_length=128)
    default_max_tokens: StrictInt = Field(ge=1, le=8192)
    default_temperature: StrictFloat = Field(ge=0.0, le=1.0)

    @field_validator("prompt_id")
    @classmethod
    def _check_prompt_id(cls, value: str) -> str:
        if not _PROMPT_ID_RE.fullmatch(value):
            raise ValueError(f"prompt_id {value!r} must match ^[a-z][a-z0-9_]{{2,63}}$")
        return value

    @field_validator("version")
    @classmethod
    def _check_version(cls, value: str) -> str:
        if not _VERSION_RE.fullmatch(value):
            raise ValueError(
                f"version {value!r} must be semver-compatible (\\d+\\.\\d+\\.\\d+)"
            )
        return value

    @field_validator("expected_schema_ref")
    @classmethod
    def _check_schema_ref(cls, value: str | None) -> str | None:
        if value is not None and not _SCHEMA_REF_RE.fullmatch(value):
            raise ValueError(
                f"expected_schema_ref {value!r} must match ^[a-z][a-z0-9_]{{2,63}}$"
            )
        return value

    @field_validator("default_model_id")
    @classmethod
    def _check_model_id(cls, value: str) -> str:
        if not _MODEL_ID_RE.fullmatch(value):
            raise ValueError(
                f"default_model_id {value!r} must match ^[a-z][a-z0-9._\\-]{{1,127}}$"
            )
        return value


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PromptRegistrySummary:
    """Summary of a successful registry load (consumed by readiness probes)."""

    total: int
    prompt_ids: tuple[str, ...]
    by_role: dict[str, int]


@dataclass(frozen=True)
class _RegisteredPrompt:
    """Internal record bundling a prompt definition with its source path."""

    prompt: PromptDefinition
    yaml_path: Path


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class PromptRegistry:
    """In-memory index of signed prompt definitions.

    Constructed once per process; :meth:`load` is idempotent (call again
    on rotation). The registry never spawns subprocesses or performs
    network I/O — pure parse + verify + index.
    """

    def __init__(
        self,
        prompts_dir: Path,
        *,
        signatures_path: Path | None = None,
        public_keys_dir: Path | None = None,
    ) -> None:
        self._prompts_dir = prompts_dir
        self._signatures_path = signatures_path or prompts_dir / _SIGNATURES_FILENAME
        self._keys_dir = public_keys_dir or prompts_dir / _KEYS_DIRNAME
        self._registered: dict[str, _RegisteredPrompt] = {}
        self._by_role: dict[AgentRole, list[PromptDefinition]] = defaultdict(list)
        self._key_manager = KeyManager(self._keys_dir)

    # -- public API ----------------------------------------------------------

    @property
    def prompts_dir(self) -> Path:
        return self._prompts_dir

    @property
    def signatures_path(self) -> Path:
        return self._signatures_path

    @property
    def keys_dir(self) -> Path:
        return self._keys_dir

    def load(self) -> PromptRegistrySummary:
        """Discover, verify, and index every YAML under :attr:`prompts_dir`.

        Fail-closed: aborts with :class:`PromptRegistryError` /
        :class:`PromptSignatureError` on any problem. Returns a
        :class:`PromptRegistrySummary` on success.
        """
        if not self._prompts_dir.exists():
            raise PromptRegistryError(
                f"prompts directory {self._prompts_dir!s} does not exist"
            )
        if not self._prompts_dir.is_dir():
            raise PromptRegistryError(
                f"prompts path {self._prompts_dir!s} is not a directory"
            )

        try:
            self._key_manager.load()
        except SignatureError as exc:
            raise PromptRegistryError(f"failed to load signing keys: {exc}") from exc

        signatures = self._load_signatures()
        yaml_paths = sorted(p for p in self._prompts_dir.glob("*.yaml") if p.is_file())
        if not yaml_paths:
            raise PromptRegistryError(
                f"no prompt YAMLs found under {self._prompts_dir!s}"
            )

        registered: dict[str, _RegisteredPrompt] = {}
        for yaml_path in yaml_paths:
            prompt = self._load_and_verify(yaml_path, signatures)
            if prompt.prompt_id in registered:
                raise PromptRegistryError(
                    f"duplicate prompt_id {prompt.prompt_id!r} "
                    f"(already loaded from another YAML)"
                )
            if prompt.prompt_id != yaml_path.stem:
                raise PromptRegistryError(
                    f"prompt_id {prompt.prompt_id!r} does not match filename "
                    f"stem {yaml_path.stem!r}"
                )
            registered[prompt.prompt_id] = _RegisteredPrompt(
                prompt=prompt, yaml_path=yaml_path
            )

        self._registered = registered
        self._rebuild_role_index()
        summary = self._build_summary()
        _logger.info(
            "prompt_registry.loaded",
            extra={
                "total": summary.total,
                "by_role": summary.by_role,
            },
        )
        return summary

    def get(self, prompt_id: str) -> PromptDefinition:
        """Return the definition for ``prompt_id`` or raise :class:`PromptNotFoundError`."""
        record = self._registered.get(prompt_id)
        if record is None:
            raise PromptNotFoundError(prompt_id)
        return record.prompt

    def list_by_role(self, role: AgentRole) -> list[PromptDefinition]:
        """Return every prompt for ``role`` (sorted by ``prompt_id``).

        Returns a fresh list per call so callers cannot mutate the
        registry's internal index by reference.
        """
        return list(self._by_role.get(role, ()))

    def list_all(self) -> list[PromptDefinition]:
        """Return every loaded prompt, sorted by ``prompt_id``."""
        return [self._registered[pid].prompt for pid in sorted(self._registered)]

    def __len__(self) -> int:
        return len(self._registered)

    def __contains__(self, prompt_id: object) -> bool:
        return isinstance(prompt_id, str) and prompt_id in self._registered

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._registered))

    # -- private helpers -----------------------------------------------------

    def _load_signatures(self) -> SignaturesFile:
        if not self._signatures_path.exists():
            raise PromptRegistryError(
                f"SIGNATURES file {self._signatures_path!s} does not exist"
            )
        try:
            return SignaturesFile.from_file(self._signatures_path)
        except SignatureError as exc:
            raise PromptRegistryError(f"failed to parse SIGNATURES: {exc}") from exc

    def _load_and_verify(
        self, yaml_path: Path, signatures: SignaturesFile
    ) -> PromptDefinition:
        try:
            yaml_bytes = yaml_path.read_bytes()
        except OSError as exc:
            raise PromptRegistryError(
                f"failed to read prompt descriptor {yaml_path!s}: {exc}"
            ) from exc

        relative_path = yaml_path.relative_to(self._prompts_dir).as_posix()
        try:
            signatures.verify_one(
                relative_path=relative_path,
                yaml_bytes=yaml_bytes,
                public_key_resolver=self._key_manager.get,
            )
        except (IntegrityError, KeyNotFoundError) as exc:
            raise PromptSignatureError(
                f"signature verification failed for {relative_path!r}: {exc}"
            ) from exc

        try:
            payload = yaml.safe_load(yaml_bytes)
        except yaml.YAMLError as exc:
            raise PromptRegistryError(
                f"YAML parse error in {relative_path!r}: {exc}"
            ) from exc

        if not isinstance(payload, dict):
            raise PromptRegistryError(
                f"{relative_path!r} must be a YAML mapping at the top level"
            )

        try:
            prompt = PromptDefinition(**payload)
        except ValidationError as exc:
            raise PromptRegistryError(
                f"schema validation failed for {relative_path!r}: "
                f"{exc.error_count()} errors"
            ) from exc

        return prompt

    def _rebuild_role_index(self) -> None:
        self._by_role = defaultdict(list)
        for prompt_id in sorted(self._registered):
            prompt = self._registered[prompt_id].prompt
            self._by_role[prompt.agent_role].append(prompt)

    def _build_summary(self) -> PromptRegistrySummary:
        by_role: dict[str, int] = {}
        for role, prompts in self._by_role.items():
            by_role[role.value] = len(prompts)
        return PromptRegistrySummary(
            total=len(self._registered),
            prompt_ids=tuple(sorted(self._registered)),
            by_role=by_role,
        )


__all__ = [
    "AgentRole",
    "PromptDefinition",
    "PromptNotFoundError",
    "PromptRegistry",
    "PromptRegistryError",
    "PromptRegistrySummary",
    "PromptSignatureError",
]
