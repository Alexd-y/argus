"""Discovery, signature verification, and indexing of the ARGUS tool catalog.

At application startup :class:`ToolRegistry.load` walks
``backend/config/tools/*.yaml``, parses each descriptor through
:class:`~src.sandbox.adapter_base.ToolDescriptor`, verifies its signature
against ``backend/config/tools/SIGNATURES`` (Ed25519, see
:mod:`src.sandbox.signing`), validates the command template against the
sandbox allow-list (see :mod:`src.sandbox.templating`), and registers a
:class:`~src.sandbox.adapter_base.ShellToolAdapter` per ``tool_id``.

The contract is **fail-closed**: any signature mismatch, schema mismatch,
duplicate ``tool_id``, or template typo aborts startup with
:class:`RegistryLoadError`. The application MUST NOT continue with a
partially-validated catalog.

A successful load returns a :class:`RegistrySummary` for the
``/health/ready`` endpoint and operator dashboards.
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

import yaml
from pydantic import ValidationError

from src.pipeline.contracts.phase_io import ScanPhase
from src.sandbox.adapter_base import (
    AdapterRegistrationError,
    ShellToolAdapter,
    ToolAdapter,
    ToolCategory,
    ToolDescriptor,
)
from src.sandbox.signing import (
    IntegrityError,
    KeyManager,
    KeyNotFoundError,
    SignatureError,
    SignaturesFile,
)
from src.sandbox.templating import TemplateRenderError, validate_template


_logger = logging.getLogger(__name__)


_SIGNATURES_FILENAME: Final[str] = "SIGNATURES"
_KEYS_DIRNAME: Final[str] = "_keys"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RegistryLoadError(Exception):
    """Raised by :meth:`ToolRegistry.load` for any fail-closed condition."""


# ---------------------------------------------------------------------------
# Public summary
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegistrySummary:
    """Summary of a successful registry load (consumed by readiness probes)."""

    total: int
    tool_ids: tuple[str, ...]
    by_phase: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class _RegisteredTool:
    """Internal record bundling a descriptor with its adapter instance."""

    descriptor: ToolDescriptor
    adapter: ToolAdapter


# ---------------------------------------------------------------------------
# Adapter factory
# ---------------------------------------------------------------------------

AdapterFactory = Callable[[ToolDescriptor], ToolAdapter]


def _default_adapter_factory(descriptor: ToolDescriptor) -> ToolAdapter:
    """Default factory: every descriptor is bound to a :class:`ShellToolAdapter`.

    ARG-003 will introduce per-tool subclasses with structured ``parse_output``
    implementations; the registry can be re-instantiated with a custom
    ``adapter_factory`` to dispatch on ``tool_id`` once those exist.
    """
    return ShellToolAdapter(descriptor)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class ToolRegistry:
    """In-memory index of signed tool descriptors.

    Construct once per process; :meth:`load` is idempotent (re-loads on
    rotation). Lookups are O(1). The registry never spawns subprocesses or
    touches the network — it is pure parse + verify + index.
    """

    def __init__(
        self,
        tools_dir: Path,
        *,
        keys_dir: Path | None = None,
        signatures_path: Path | None = None,
        adapter_factory: AdapterFactory = _default_adapter_factory,
    ) -> None:
        self._tools_dir = tools_dir
        self._keys_dir = keys_dir or tools_dir / _KEYS_DIRNAME
        self._signatures_path = signatures_path or tools_dir / _SIGNATURES_FILENAME
        self._adapter_factory = adapter_factory
        self._registered: dict[str, _RegisteredTool] = {}
        self._key_manager = KeyManager(self._keys_dir)

    # -- public API ----------------------------------------------------------

    @property
    def tools_dir(self) -> Path:
        return self._tools_dir

    @property
    def keys_dir(self) -> Path:
        return self._keys_dir

    @property
    def signatures_path(self) -> Path:
        return self._signatures_path

    def load(self) -> RegistrySummary:
        """Discover, verify, and index every YAML descriptor under :attr:`tools_dir`.

        Fail-closed: aborts with :class:`RegistryLoadError` if any descriptor
        fails its schema, its signature, its template-allow-list check, or
        introduces a duplicate ``tool_id``.

        Returns a :class:`RegistrySummary` (count by phase / category, list of
        ``tool_id``s) on success.
        """
        if not self._tools_dir.exists():
            raise RegistryLoadError(
                f"tools directory {self._tools_dir!s} does not exist"
            )
        if not self._tools_dir.is_dir():
            raise RegistryLoadError(
                f"tools path {self._tools_dir!s} is not a directory"
            )

        try:
            self._key_manager.load()
        except SignatureError as exc:
            raise RegistryLoadError(f"failed to load signing keys: {exc}") from exc

        signatures = self._load_signatures()
        yaml_paths = sorted(p for p in self._tools_dir.glob("*.yaml") if p.is_file())

        registered: dict[str, _RegisteredTool] = {}
        for yaml_path in yaml_paths:
            descriptor = self._load_and_verify(yaml_path, signatures)
            if descriptor.tool_id in registered:
                raise RegistryLoadError(
                    f"duplicate tool_id {descriptor.tool_id!r} "
                    f"(already loaded from another YAML)"
                )
            try:
                adapter = self._adapter_factory(descriptor)
            except (AdapterRegistrationError, TemplateRenderError, ValueError) as exc:
                raise RegistryLoadError(
                    f"failed to build adapter for tool_id={descriptor.tool_id!r}: {exc}"
                ) from exc
            self._validate_adapter_conformance(adapter, descriptor)
            registered[descriptor.tool_id] = _RegisteredTool(
                descriptor=descriptor, adapter=adapter
            )

        self._registered = registered
        summary = self._build_summary()
        _logger.info(
            "tool_registry.loaded",
            extra={
                "total": summary.total,
                "by_phase": summary.by_phase,
                "by_category": summary.by_category,
            },
        )
        return summary

    def get(self, tool_id: str) -> ToolDescriptor | None:
        """Return the descriptor for ``tool_id`` or ``None`` if absent."""
        record = self._registered.get(tool_id)
        return record.descriptor if record is not None else None

    def get_adapter(self, tool_id: str) -> ToolAdapter | None:
        """Return the adapter instance for ``tool_id`` or ``None`` if absent."""
        record = self._registered.get(tool_id)
        return record.adapter if record is not None else None

    def list_by_phase(self, phase: ScanPhase) -> list[ToolDescriptor]:
        """Return descriptors for all tools registered in ``phase``."""
        return [
            r.descriptor
            for r in self._registered.values()
            if r.descriptor.phase is phase
        ]

    def list_by_category(self, category: ToolCategory) -> list[ToolDescriptor]:
        """Return descriptors for all tools in ``category``."""
        return [
            r.descriptor
            for r in self._registered.values()
            if r.descriptor.category is category
        ]

    def all_descriptors(self) -> list[ToolDescriptor]:
        """Return every loaded descriptor (sorted by ``tool_id``)."""
        return [self._registered[tid].descriptor for tid in sorted(self._registered)]

    def __len__(self) -> int:
        return len(self._registered)

    def __contains__(self, tool_id: object) -> bool:
        return isinstance(tool_id, str) and tool_id in self._registered

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._registered))

    @staticmethod
    def validate_template_placeholders(descriptor: ToolDescriptor) -> None:
        """Static helper that re-runs the template allow-list check.

        Used in tests and by the catalog-coverage integrity script (ARG-010).
        Raises :class:`TemplateRenderError` (transparent) on any forbidden
        placeholder.
        """
        validate_template(descriptor.command_template)

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
    ) -> ToolDescriptor:
        try:
            yaml_bytes = yaml_path.read_bytes()
        except OSError as exc:
            raise RegistryLoadError(
                f"failed to read tool descriptor {yaml_path!s}: {exc}"
            ) from exc

        relative_path = yaml_path.relative_to(self._tools_dir).as_posix()
        try:
            signatures.verify_one(
                relative_path=relative_path,
                yaml_bytes=yaml_bytes,
                public_key_resolver=self._key_manager.get,
            )
        except (IntegrityError, KeyNotFoundError) as exc:
            raise RegistryLoadError(
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
            descriptor = ToolDescriptor(**payload)
        except ValidationError as exc:
            raise RegistryLoadError(
                f"schema validation failed for {relative_path!r}: {exc.error_count()} errors"
            ) from exc

        try:
            validate_template(descriptor.command_template)
        except TemplateRenderError as exc:
            raise RegistryLoadError(
                f"forbidden placeholder in command_template for "
                f"{relative_path!r}: {exc.reason} (placeholder={exc.placeholder!r})"
            ) from exc

        return descriptor

    @staticmethod
    def _validate_adapter_conformance(
        adapter: ToolAdapter, descriptor: ToolDescriptor
    ) -> None:
        """Defence-in-depth: ensure the adapter mirrors the descriptor.

        Catches custom factories that return an adapter for the wrong
        ``tool_id`` (a registration mistake that would otherwise surface
        only at dispatch time).
        """
        if adapter.tool_id != descriptor.tool_id:
            raise RegistryLoadError(
                f"adapter.tool_id={adapter.tool_id!r} does not match "
                f"descriptor.tool_id={descriptor.tool_id!r}"
            )

    def _build_summary(self) -> RegistrySummary:
        phases: Counter[str] = Counter()
        categories: Counter[str] = Counter()
        for record in self._registered.values():
            phases[record.descriptor.phase.value] += 1
            categories[record.descriptor.category.value] += 1
        return RegistrySummary(
            total=len(self._registered),
            tool_ids=tuple(sorted(self._registered)),
            by_phase=dict(phases),
            by_category=dict(categories),
        )
