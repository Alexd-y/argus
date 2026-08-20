"""Signed tool-selection profiles (vulnerability type → sandbox tools).

This is the config-driven replacement for the hardcoded ``_VULN_TOOL_MAP`` table
in :mod:`src.orchestration.exploitation_executor`. The mapping lives in a signed
YAML catalog (``backend/config/tool_profiles/tool_profiles.yaml``) verified with
the same Ed25519 fail-closed infrastructure as the tool / payload / prompt
catalogs (:mod:`src.sandbox.signing`).

Design:

* The catalog is **signed** — an operator edits the YAML and re-signs it with
  ``backend/scripts/tools_sign.py`` (see the header comment in the YAML). A
  tampered or unsigned catalog is rejected by :meth:`ToolProfileRegistry.load`.
* Loading is **fail-open at the call site, fail-closed at the crypto layer**:
  :func:`load_tool_profile_catalog` never raises — it returns ``None`` on any
  load/verify error so the executor degrades to its in-code default table (a
  logged fallback), while :meth:`ToolProfileRegistry.load` itself raises so
  tests and tooling can assert tamper-evidence.
* Tool selection mirrors the legacy keyword-in-blob semantics exactly:
  :meth:`ToolProfileCatalog.tools_for` scans ``vuln_type + title`` for each
  profile key, de-duplicates, and caps the result — so swapping the in-code
  table for this catalog is behaviour-preserving.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Final, Self

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr, model_validator

from src.sandbox.signing import (
    IntegrityError,
    KeyManager,
    KeyNotFoundError,
    SignatureError,
    SignaturesFile,
)

logger = logging.getLogger(__name__)

_CATALOG_FILENAME: Final[str] = "tool_profiles.yaml"
_KEYS_DIRNAME: Final[str] = "_keys"
_SIGNATURES_FILENAME: Final[str] = "SIGNATURES"
_DEFAULT_MAX_TOOLS: Final[int] = 3


class ToolProfileError(Exception):
    """Raised by :meth:`ToolProfileRegistry.load` on any fail-closed condition."""


class ToolProfile(BaseModel):
    """The sandbox tools that probe / exploit one vulnerability type."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tools: list[StrictStr] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def _no_duplicate_tools(self) -> Self:
        if len(set(self.tools)) != len(self.tools):
            raise ValueError(f"duplicate tool ids in profile: {self.tools}")
        return self


class ToolProfileCatalog(BaseModel):
    """Top-level signed catalog: default tools + per-vuln-type profiles."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    version: StrictInt = Field(ge=1)
    defaults: ToolProfile
    profiles: dict[StrictStr, ToolProfile] = Field(min_length=1)

    def tools_for(self, blob: str, *, max_tools: int = _DEFAULT_MAX_TOOLS) -> list[str]:
        """Select sandbox tools for a finding ``blob`` (``vuln_type + title``).

        Replicates the legacy ``_select_tools_for_finding`` semantics: every
        profile key found as a substring of ``blob`` contributes its tools, the
        union is de-duplicated preserving first-seen order, and the result is
        capped at ``max_tools``. When nothing matches, the catalog defaults are
        returned (also capped).
        """
        matched: list[str] = []
        for vuln_type, profile in self.profiles.items():
            if vuln_type in blob:
                matched.extend(profile.tools)
        if not matched:
            matched = list(self.defaults.tools)
        return list(dict.fromkeys(matched))[:max_tools]

    def as_vuln_tool_map(self) -> dict[str, list[str]]:
        """Return the ``{vuln_type: [tools]}`` view (parity with ``_VULN_TOOL_MAP``)."""
        return {vuln_type: list(profile.tools) for vuln_type, profile in self.profiles.items()}


class ToolProfileRegistry:
    """Loader + signature verifier for the signed tool-profile catalog.

    Mirrors :class:`~src.payloads.registry.PayloadRegistry` / the tool registry:
    a single signed YAML is verified fail-closed against a ``SIGNATURES``
    manifest using Ed25519 public keys under ``_keys/``.
    """

    def __init__(
        self,
        catalog_dir: Path,
        *,
        filename: str = _CATALOG_FILENAME,
        keys_dir: Path | None = None,
        signatures_path: Path | None = None,
    ) -> None:
        self._catalog_dir = catalog_dir
        self._filename = filename
        self._keys_dir = keys_dir or catalog_dir / _KEYS_DIRNAME
        self._signatures_path = signatures_path or catalog_dir / _SIGNATURES_FILENAME
        self._key_manager = KeyManager(self._keys_dir)

    def load(self) -> ToolProfileCatalog:
        """Verify the catalog signature (fail-closed) and return the parsed model.

        Raises :class:`ToolProfileError` on a missing file, a missing / malformed
        ``SIGNATURES`` manifest, an unknown signing key, a hash / signature
        mismatch, or a schema-invalid catalog.
        """
        yaml_path = self._catalog_dir / self._filename
        if not yaml_path.is_file():
            raise ToolProfileError(f"tool profile catalog {yaml_path!s} does not exist")

        try:
            self._key_manager.load()
        except SignatureError as exc:
            raise ToolProfileError(f"failed to load signing keys: {exc}") from exc

        try:
            signatures = SignaturesFile.from_file(self._signatures_path)
        except SignatureError as exc:
            raise ToolProfileError(f"failed to parse SIGNATURES: {exc}") from exc

        yaml_bytes = yaml_path.read_bytes()
        relative_path = yaml_path.relative_to(self._catalog_dir).as_posix()
        try:
            signatures.verify_one(
                relative_path=relative_path,
                yaml_bytes=yaml_bytes,
                public_key_resolver=self._key_manager.get,
            )
        except (IntegrityError, KeyNotFoundError) as exc:
            raise ToolProfileError(
                f"signature verification failed for {relative_path!r}: {exc}"
            ) from exc

        try:
            payload = yaml.safe_load(yaml_bytes)
        except yaml.YAMLError as exc:
            raise ToolProfileError(f"YAML parse error in {relative_path!r}: {exc}") from exc

        if not isinstance(payload, dict):
            raise ToolProfileError(f"{relative_path!r} must be a YAML mapping at the top level")

        try:
            return ToolProfileCatalog(**payload)
        except ValueError as exc:
            raise ToolProfileError(
                f"schema validation failed for {relative_path!r}: {exc}"
            ) from exc


def _default_catalog_dir() -> Path:
    """Return ``backend/config/tool_profiles`` relative to this module."""
    return Path(__file__).resolve().parents[2] / "config" / "tool_profiles"


_CATALOG: ToolProfileCatalog | None = None
_LOAD_ATTEMPTED: bool = False


def load_tool_profile_catalog() -> ToolProfileCatalog | None:
    """Return the signed catalog, or ``None`` if it cannot be loaded/verified.

    Result is cached process-wide (including the ``None`` fallback) so the
    per-finding tool-selection hot path never re-reads / re-verifies the file.
    Never raises: verification failures are logged and surfaced as ``None`` so
    the caller can fall back to its in-code default table.
    """
    global _CATALOG, _LOAD_ATTEMPTED
    if _LOAD_ATTEMPTED:
        return _CATALOG
    _LOAD_ATTEMPTED = True
    try:
        _CATALOG = ToolProfileRegistry(_default_catalog_dir()).load()
    except ToolProfileError as exc:
        logger.warning(
            "tool_profiles_load_failed_fallback",
            extra={"event": "tool_profiles_load_failed_fallback", "error": str(exc)},
        )
        _CATALOG = None
    return _CATALOG


__all__ = [
    "ToolProfile",
    "ToolProfileCatalog",
    "ToolProfileError",
    "ToolProfileRegistry",
    "load_tool_profile_catalog",
]
