"""Signed registry for ARGUS payload-family descriptors (Backlog/dev1_md §7).

Mirrors :mod:`src.sandbox.tool_registry` for payload families: each family
lives as one signed YAML under ``backend/config/payloads/<family_id>.yaml``
and is fetched once at startup, schema-validated, and signature-verified
against ``backend/config/payloads/SIGNATURES`` using the same Ed25519
infrastructure (:mod:`src.sandbox.signing`).

The registry is **fail-closed**:

* unknown / missing signatures → :class:`PayloadSignatureError`
* missing or malformed YAML / unknown family_id → :class:`RegistryLoadError`
* duplicate family_id → :class:`RegistryLoadError`
* unknown encoder / mutation referenced by a family → :class:`RegistryLoadError`

The ``PayloadFamily`` model intentionally captures only metadata + a
**small canonical seed set**. The mutator + encoder layers turn those seeds
into the broader payload space at request time inside
:class:`~src.payloads.builder.PayloadBuilder`.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Self

import yaml
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

from src.payloads.encoders import ENCODER_NAMES
from src.payloads.mutations import MUTATION_NAMES
from src.pipeline.contracts.finding_dto import ConfidenceLevel
from src.pipeline.contracts.tool_job import RiskLevel
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
_FAMILY_ID_PATTERN: Final[str] = r"^[a-z_][a-z0-9_]{2,32}$"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RegistryLoadError(Exception):
    """Raised by :meth:`PayloadRegistry.load` for any fail-closed condition."""


class PayloadSignatureError(RegistryLoadError):
    """Raised when a payload YAML fails Ed25519 signature verification."""


class PayloadFamilyNotFoundError(KeyError):
    """Raised by :meth:`PayloadRegistry.get_family` for unknown ``family_id``."""

    def __init__(self, family_id: str) -> None:
        super().__init__(family_id)
        self.family_id = family_id


# ---------------------------------------------------------------------------
# Pydantic models (parsed from signed YAML)
# ---------------------------------------------------------------------------


class MutationRule(BaseModel):
    """One mutation rule applied to a payload before encoding.

    ``name`` MUST be a registered key in :data:`src.payloads.mutations.MUTATION_NAMES`.
    ``max_per_payload`` caps how many times this mutation may run on a single
    payload — the builder uses it to bound transformation depth.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=64)
    max_per_payload: StrictInt = Field(default=1, ge=1, le=8)
    description: StrictStr = Field(default="", max_length=256)

    @field_validator("name")
    @classmethod
    def _check_name(cls, value: str) -> str:
        if value not in MUTATION_NAMES:
            raise ValueError(
                f"unknown mutation rule {value!r}; "
                f"must be one of {sorted(MUTATION_NAMES)}"
            )
        return value


class EncodingPipeline(BaseModel):
    """Named ordered pipeline of encoders applied at the end of materialisation.

    ``name`` is a human-readable identifier ("url_only", "url_then_b64");
    ``stages`` is the ordered list of encoder names (validated against
    :data:`src.payloads.encoders.ENCODER_NAMES`).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=64)
    stages: list[StrictStr] = Field(min_length=0, max_length=8)
    description: StrictStr = Field(default="", max_length=256)

    @field_validator("stages")
    @classmethod
    def _check_stages(cls, value: list[str]) -> list[str]:
        for stage in value:
            if stage not in ENCODER_NAMES:
                raise ValueError(
                    f"unknown encoder stage {stage!r}; "
                    f"must be one of {sorted(ENCODER_NAMES)}"
                )
        return value


class PayloadEntry(BaseModel):
    """One canonical seed payload inside a :class:`PayloadFamily`.

    The registry stores a *small* set per family (3..10). The builder
    expands them via mutations + encoders at request time. ``id`` is
    stable across runs; the validator persists it on every emitted
    finding for traceability.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_\-]+$")
    template: StrictStr = Field(min_length=1, max_length=2048)
    confidence: ConfidenceLevel = ConfidenceLevel.SUSPECTED
    notes: StrictStr = Field(default="", max_length=512)


class PayloadFamily(BaseModel):
    """Top-level signed YAML descriptor for a payload family.

    Mirrors the cycle plan §7: family_id, risk metadata, declarative
    mutation/encoder declarations, OAST requirement, and the small
    canonical seed set under :attr:`payloads`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    family_id: StrictStr = Field(
        min_length=3, max_length=32, pattern=_FAMILY_ID_PATTERN
    )
    description: StrictStr = Field(min_length=1, max_length=500)
    cwe_ids: list[StrictInt] = Field(min_length=1, max_length=16)
    owasp_top10: list[StrictStr] = Field(min_length=1, max_length=10)
    risk_level: RiskLevel
    requires_approval: StrictBool = False
    oast_required: StrictBool = False
    payloads: list[PayloadEntry] = Field(min_length=1, max_length=32)
    mutations: list[MutationRule] = Field(default_factory=list, max_length=16)
    encodings: list[EncodingPipeline] = Field(default_factory=list, max_length=16)

    @field_validator("cwe_ids")
    @classmethod
    def _check_cwe_ids(cls, value: list[int]) -> list[int]:
        for cwe in value:
            if cwe <= 0:
                raise ValueError(f"CWE id must be positive, got {cwe}")
        if len(set(value)) != len(value):
            raise ValueError("cwe_ids must be unique")
        return value

    @field_validator("owasp_top10")
    @classmethod
    def _check_owasp(cls, value: list[str]) -> list[str]:
        for owasp in value:
            if not owasp.startswith("A"):
                raise ValueError(
                    f"owasp_top10 entries must start with 'A' (e.g. A03:2021), got {owasp!r}"
                )
        if len(set(value)) != len(value):
            raise ValueError("owasp_top10 must be unique")
        return value

    @model_validator(mode="after")
    def _validate(self) -> Self:
        ids = [p.id for p in self.payloads]
        if len(set(ids)) != len(ids):
            raise ValueError("payload entry ids must be unique within a family")

        mutation_names = [m.name for m in self.mutations]
        if len(set(mutation_names)) != len(mutation_names):
            raise ValueError("mutation rule names must be unique within a family")

        pipeline_names = [p.name for p in self.encodings]
        if len(set(pipeline_names)) != len(pipeline_names):
            raise ValueError("encoding pipeline names must be unique within a family")

        if self.risk_level in {RiskLevel.HIGH, RiskLevel.DESTRUCTIVE}:
            if not self.requires_approval:
                raise ValueError(
                    f"family_id={self.family_id!r}: "
                    f"risk_level={self.risk_level.value} requires requires_approval=True"
                )
        return self


# ---------------------------------------------------------------------------
# Public summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PayloadRegistrySummary:
    """Summary of a successful registry load (consumed by readiness probes)."""

    total: int
    family_ids: tuple[str, ...]
    by_risk: dict[str, int] = field(default_factory=dict)
    requires_approval_count: int = 0
    oast_required_count: int = 0


@dataclass(frozen=True)
class _RegisteredFamily:
    """Internal record bundling a family with its source path."""

    family: PayloadFamily
    yaml_path: Path


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class PayloadRegistry:
    """In-memory index of signed payload-family descriptors.

    Constructed once per process; :meth:`load` is idempotent (call again
    on rotation). Lookups are O(1). The registry never spawns subprocesses
    or performs network I/O — pure parse + verify + index.
    """

    def __init__(
        self,
        payloads_dir: Path,
        *,
        keys_dir: Path | None = None,
        signatures_path: Path | None = None,
    ) -> None:
        self._payloads_dir = payloads_dir
        self._keys_dir = keys_dir or payloads_dir / _KEYS_DIRNAME
        self._signatures_path = signatures_path or payloads_dir / _SIGNATURES_FILENAME
        self._registered: dict[str, _RegisteredFamily] = {}
        self._key_manager = KeyManager(self._keys_dir)

    # -- public API ----------------------------------------------------------

    @property
    def payloads_dir(self) -> Path:
        return self._payloads_dir

    @property
    def keys_dir(self) -> Path:
        return self._keys_dir

    @property
    def signatures_path(self) -> Path:
        return self._signatures_path

    def load(self) -> PayloadRegistrySummary:
        """Discover, verify, and index every YAML descriptor under :attr:`payloads_dir`.

        Fail-closed: aborts with :class:`RegistryLoadError` /
        :class:`PayloadSignatureError` on any problem.

        Returns a :class:`PayloadRegistrySummary` on success.
        """
        if not self._payloads_dir.exists():
            raise RegistryLoadError(
                f"payloads directory {self._payloads_dir!s} does not exist"
            )
        if not self._payloads_dir.is_dir():
            raise RegistryLoadError(
                f"payloads path {self._payloads_dir!s} is not a directory"
            )

        try:
            self._key_manager.load()
        except SignatureError as exc:
            raise RegistryLoadError(f"failed to load signing keys: {exc}") from exc

        signatures = self._load_signatures()
        yaml_paths = sorted(p for p in self._payloads_dir.glob("*.yaml") if p.is_file())
        if not yaml_paths:
            raise RegistryLoadError(
                f"no payload YAMLs found under {self._payloads_dir!s}"
            )

        registered: dict[str, _RegisteredFamily] = {}
        for yaml_path in yaml_paths:
            family = self._load_and_verify(yaml_path, signatures)
            if family.family_id in registered:
                raise RegistryLoadError(
                    f"duplicate family_id {family.family_id!r} "
                    f"(already loaded from another YAML)"
                )
            if family.family_id != yaml_path.stem:
                raise RegistryLoadError(
                    f"family_id {family.family_id!r} does not match filename "
                    f"stem {yaml_path.stem!r}"
                )
            registered[family.family_id] = _RegisteredFamily(
                family=family, yaml_path=yaml_path
            )

        self._registered = registered
        summary = self._build_summary()
        _logger.info(
            "payload_registry.loaded",
            extra={
                "total": summary.total,
                "by_risk": summary.by_risk,
                "requires_approval": summary.requires_approval_count,
                "oast_required": summary.oast_required_count,
            },
        )
        return summary

    def get_family(self, family_id: str) -> PayloadFamily:
        """Return the family for ``family_id`` or raise :class:`PayloadFamilyNotFoundError`."""
        record = self._registered.get(family_id)
        if record is None:
            raise PayloadFamilyNotFoundError(family_id)
        return record.family

    def list_families(self) -> tuple[PayloadFamily, ...]:
        """Return every loaded family, sorted by ``family_id``.

        The result is an immutable tuple to keep the registry's internal
        catalog effectively read-only — callers must build a new
        collection if they need to mutate it.
        """
        return tuple(self._registered[fid].family for fid in sorted(self._registered))

    def families_requiring_approval(self) -> list[PayloadFamily]:
        """Return only families with ``requires_approval=True``."""
        return [f for f in self.list_families() if f.requires_approval]

    def __len__(self) -> int:
        return len(self._registered)

    def __contains__(self, family_id: object) -> bool:
        return isinstance(family_id, str) and family_id in self._registered

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._registered))

    # -- private helpers -----------------------------------------------------

    def _load_signatures(self) -> SignaturesFile:
        if not self._signatures_path.exists():
            raise RegistryLoadError(
                f"SIGNATURES file {self._signatures_path!s} does not exist"
            )
        try:
            return SignaturesFile.from_file(self._signatures_path)
        except SignatureError as exc:
            raise RegistryLoadError(f"failed to parse SIGNATURES: {exc}") from exc

    def _load_and_verify(
        self, yaml_path: Path, signatures: SignaturesFile
    ) -> PayloadFamily:
        try:
            yaml_bytes = yaml_path.read_bytes()
        except OSError as exc:
            raise RegistryLoadError(
                f"failed to read payload descriptor {yaml_path!s}: {exc}"
            ) from exc

        relative_path = yaml_path.relative_to(self._payloads_dir).as_posix()
        try:
            signatures.verify_one(
                relative_path=relative_path,
                yaml_bytes=yaml_bytes,
                public_key_resolver=self._key_manager.get,
            )
        except (IntegrityError, KeyNotFoundError) as exc:
            raise PayloadSignatureError(
                f"signature verification failed for {relative_path!r}: {exc}"
            ) from exc

        try:
            payload = yaml.safe_load(yaml_bytes)
        except yaml.YAMLError as exc:
            raise RegistryLoadError(
                f"YAML parse error in {relative_path!r}: {exc}"
            ) from exc

        if not isinstance(payload, dict):
            raise RegistryLoadError(
                f"{relative_path!r} must be a YAML mapping at the top level"
            )

        try:
            family = PayloadFamily(**payload)
        except ValidationError as exc:
            raise RegistryLoadError(
                f"schema validation failed for {relative_path!r}: "
                f"{exc.error_count()} errors"
            ) from exc

        return family

    def _build_summary(self) -> PayloadRegistrySummary:
        risks: Counter[str] = Counter()
        approvals = 0
        oast = 0
        for record in self._registered.values():
            risks[record.family.risk_level.value] += 1
            if record.family.requires_approval:
                approvals += 1
            if record.family.oast_required:
                oast += 1
        return PayloadRegistrySummary(
            total=len(self._registered),
            family_ids=tuple(sorted(self._registered)),
            by_risk=dict(risks),
            requires_approval_count=approvals,
            oast_required_count=oast,
        )
