"""Signed, fail-closed registry for declarative playbooks (P2-PLAYBOOKS-002).

Mirrors :class:`src.payloads.registry.PayloadRegistry`. Playbooks live as
signed YAML under ``backend/config/playbooks/<category>/<playbook_id>.yaml``
and are loaded once at startup: schema-validated, Ed25519 signature-verified
against ``backend/config/playbooks/SIGNATURES``, and indexed by ``playbook_id``.

The registry is **fail-closed** — any of the following aborts the load with an
exception (never a silent skip):

* missing / malformed / unknown-key YAML → :class:`RegistryLoadError`
* signature missing / mismatched / unknown key → :class:`PlaybookSignatureError`
* duplicate ``playbook_id`` → :class:`RegistryLoadError`
* ``playbook_id`` not matching the file stem → :class:`RegistryLoadError`
* an assertion whose oracle params fail validation → :class:`RegistryLoadError`

Unlike the payload catalog (flat), playbooks are organised into per-category
subdirectories, so discovery is recursive (``rglob``) and the signed relative
path includes the category segment.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import yaml
from pydantic import ValidationError

from src.playbooks.oracles import validate_params as validate_oracle_params
from src.playbooks.schema import Playbook, PlaybookCategory, PlaybookRiskLevel
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


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RegistryLoadError(Exception):
    """Raised by :meth:`PlaybookRegistry.load` for any fail-closed condition."""


class PlaybookSignatureError(RegistryLoadError):
    """Raised when a playbook YAML fails Ed25519 signature verification."""


class PlaybookNotFoundError(KeyError):
    """Raised by :meth:`PlaybookRegistry.get` for an unknown ``playbook_id``."""

    def __init__(self, playbook_id: str) -> None:
        super().__init__(playbook_id)
        self.playbook_id = playbook_id


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PlaybookRegistrySummary:
    """Summary of a successful registry load (consumed by readiness probes)."""

    total: int
    playbook_ids: tuple[str, ...]
    by_category: dict[str, int] = field(default_factory=dict)
    by_risk: dict[str, int] = field(default_factory=dict)
    requires_approval_count: int = 0


@dataclass(frozen=True)
class _RegisteredPlaybook:
    """Internal record bundling a playbook with its source path."""

    playbook: Playbook
    yaml_path: Path


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class PlaybookRegistry:
    """In-memory index of signed playbook descriptors (fail-closed).

    Pure parse + verify + index: no network I/O, no subprocesses. Construct
    once per process; :meth:`load` is idempotent (safe to re-run on rotation).
    """

    def __init__(
        self,
        playbooks_dir: Path,
        *,
        keys_dir: Path | None = None,
        signatures_path: Path | None = None,
    ) -> None:
        self._playbooks_dir = playbooks_dir
        self._keys_dir = keys_dir or playbooks_dir / _KEYS_DIRNAME
        self._signatures_path = signatures_path or playbooks_dir / _SIGNATURES_FILENAME
        self._registered: dict[str, _RegisteredPlaybook] = {}
        self._key_manager = KeyManager(self._keys_dir)

    # -- properties ----------------------------------------------------------

    @property
    def playbooks_dir(self) -> Path:
        return self._playbooks_dir

    @property
    def keys_dir(self) -> Path:
        return self._keys_dir

    @property
    def signatures_path(self) -> Path:
        return self._signatures_path

    # -- public API ----------------------------------------------------------

    def load(self) -> PlaybookRegistrySummary:
        """Discover, verify, and index every playbook under :attr:`playbooks_dir`."""
        if not self._playbooks_dir.exists():
            raise RegistryLoadError(f"playbooks directory {self._playbooks_dir!s} does not exist")
        if not self._playbooks_dir.is_dir():
            raise RegistryLoadError(f"playbooks path {self._playbooks_dir!s} is not a directory")

        try:
            self._key_manager.load()
        except SignatureError as exc:
            raise RegistryLoadError(f"failed to load signing keys: {exc}") from exc

        signatures = self._load_signatures()
        yaml_paths = self._discover_yaml()
        if not yaml_paths:
            raise RegistryLoadError(f"no playbook YAMLs found under {self._playbooks_dir!s}")

        registered: dict[str, _RegisteredPlaybook] = {}
        for yaml_path in yaml_paths:
            playbook = self._load_and_verify(yaml_path, signatures)
            if playbook.playbook_id in registered:
                raise RegistryLoadError(
                    f"duplicate playbook_id {playbook.playbook_id!r} "
                    f"(already loaded from {registered[playbook.playbook_id].yaml_path})"
                )
            if playbook.playbook_id != yaml_path.stem:
                raise RegistryLoadError(
                    f"playbook_id {playbook.playbook_id!r} does not match filename "
                    f"stem {yaml_path.stem!r} ({yaml_path})"
                )
            registered[playbook.playbook_id] = _RegisteredPlaybook(
                playbook=playbook, yaml_path=yaml_path
            )

        self._registered = registered
        summary = self._build_summary()
        _logger.info(
            "playbook_registry.loaded",
            extra={
                "total": summary.total,
                "by_category": summary.by_category,
                "by_risk": summary.by_risk,
                "requires_approval": summary.requires_approval_count,
            },
        )
        return summary

    def get(self, playbook_id: str) -> Playbook:
        """Return the playbook for ``playbook_id`` or raise :class:`PlaybookNotFoundError`."""
        record = self._registered.get(playbook_id)
        if record is None:
            raise PlaybookNotFoundError(playbook_id)
        return record.playbook

    def all(self) -> tuple[Playbook, ...]:
        """Return every loaded playbook, sorted by ``playbook_id`` (immutable)."""
        return tuple(self._registered[pid].playbook for pid in sorted(self._registered))

    def filter(
        self,
        *,
        category: PlaybookCategory | None = None,
        capability: str | None = None,
        risk: PlaybookRiskLevel | None = None,
        requires_approval: bool | None = None,
    ) -> list[Playbook]:
        """Return playbooks matching every supplied (conjunctive) criterion."""
        result: list[Playbook] = []
        for playbook in self.all():
            if category is not None and playbook.category is not category:
                continue
            if capability is not None and capability not in playbook.required_capabilities:
                continue
            if risk is not None and playbook.risk_level is not risk:
                continue
            if (
                requires_approval is not None
                and playbook.requires_approval is not requires_approval
            ):
                continue
            result.append(playbook)
        return result

    def __len__(self) -> int:
        return len(self._registered)

    def __contains__(self, playbook_id: object) -> bool:
        return isinstance(playbook_id, str) and playbook_id in self._registered

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._registered))

    # -- private helpers -----------------------------------------------------

    def _discover_yaml(self) -> list[Path]:
        return sorted(
            p
            for p in self._playbooks_dir.rglob("*.yaml")
            if p.is_file() and _KEYS_DIRNAME not in p.relative_to(self._playbooks_dir).parts
        )

    def _load_signatures(self) -> SignaturesFile:
        if not self._signatures_path.exists():
            raise RegistryLoadError(f"SIGNATURES file {self._signatures_path!s} does not exist")
        try:
            return SignaturesFile.from_file(self._signatures_path)
        except SignatureError as exc:
            raise RegistryLoadError(f"failed to parse SIGNATURES: {exc}") from exc

    def _load_and_verify(self, yaml_path: Path, signatures: SignaturesFile) -> Playbook:
        try:
            yaml_bytes = yaml_path.read_bytes()
        except OSError as exc:
            raise RegistryLoadError(
                f"failed to read playbook descriptor {yaml_path!s}: {exc}"
            ) from exc

        relative_path = yaml_path.relative_to(self._playbooks_dir).as_posix()
        try:
            signatures.verify_one(
                relative_path=relative_path,
                yaml_bytes=yaml_bytes,
                public_key_resolver=self._key_manager.get,
            )
        except (IntegrityError, KeyNotFoundError) as exc:
            raise PlaybookSignatureError(
                f"signature verification failed for {relative_path!r}: {exc}"
            ) from exc

        try:
            payload = yaml.safe_load(yaml_bytes)
        except yaml.YAMLError as exc:
            raise RegistryLoadError(f"YAML parse error in {relative_path!r}: {exc}") from exc

        if not isinstance(payload, dict):
            raise RegistryLoadError(f"{relative_path!r} must be a YAML mapping at the top level")

        try:
            playbook = Playbook(**payload)
        except ValidationError as exc:
            raise RegistryLoadError(
                f"schema validation failed for {relative_path!r}: " f"{exc.error_count()} error(s)"
            ) from exc

        self._validate_assertions(playbook, relative_path)
        self._validate_category_dir(playbook, yaml_path, relative_path)
        return playbook

    @staticmethod
    def _validate_assertions(playbook: Playbook, relative_path: str) -> None:
        """Fail-closed validation of every assertion's oracle params."""
        for index, spec in enumerate(playbook.assertions):
            try:
                validate_oracle_params(spec.type, spec.params)
            except (ValidationError, ValueError) as exc:
                raise RegistryLoadError(
                    f"assertion #{index} ({spec.type.value}) in {relative_path!r} "
                    f"has invalid params: {exc}"
                ) from exc

    def _validate_category_dir(
        self, playbook: Playbook, yaml_path: Path, relative_path: str
    ) -> None:
        """Ensure the file sits under a directory matching its category.

        Playbooks are organised as ``<category>/<playbook_id>.yaml``; a file
        placed in the wrong category dir is a fail-closed error so the on-disk
        layout stays a reliable index.
        """
        parent = yaml_path.parent
        if parent == self._playbooks_dir:
            raise RegistryLoadError(
                f"playbook {relative_path!r} must live under a category "
                f"subdirectory, not the catalog root"
            )
        if parent.name != playbook.category.value:
            raise RegistryLoadError(
                f"playbook {relative_path!r} category {playbook.category.value!r} "
                f"does not match its directory {parent.name!r}"
            )

    def _build_summary(self) -> PlaybookRegistrySummary:
        categories: Counter[str] = Counter()
        risks: Counter[str] = Counter()
        approvals = 0
        for record in self._registered.values():
            categories[record.playbook.category.value] += 1
            risks[record.playbook.risk_level.value] += 1
            if record.playbook.requires_approval:
                approvals += 1
        return PlaybookRegistrySummary(
            total=len(self._registered),
            playbook_ids=tuple(sorted(self._registered)),
            by_category=dict(categories),
            by_risk=dict(risks),
            requires_approval_count=approvals,
        )


__all__ = [
    "PlaybookNotFoundError",
    "PlaybookRegistry",
    "PlaybookRegistrySummary",
    "PlaybookSignatureError",
    "RegistryLoadError",
]
