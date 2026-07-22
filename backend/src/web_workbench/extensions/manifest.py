"""Extension manifest schema + signed loader (WB-P8b offline core, pure).

An :class:`ExtensionManifest` is the signed, data-only descriptor of a Web
Workbench extension bundle: metadata, declared **permissions**, embedded
:class:`~src.web_workbench.extensions.check_dsl.DeclarativeCheck` definitions, an
SBOM, and provenance. Like the tool / prompt / payload catalogs it is bytes-on-
disk signed with Ed25519 (see :mod:`src.sandbox.signing`), and it is *data, not
code* — ``extra="forbid"`` + frozen everywhere (fail-closed).

Two security invariants are enforced at load time (offline, unit-tested):

* **Least privilege** — an extension may only ship checks whose scope / OAST
  needs are covered by an explicitly-declared permission. A passive check needs
  ``register_passive_check``; an active check needs ``register_active_check``;
  any OAST-dependent check needs ``use_oast``. Missing → hard reject.
* **Egress attribution** — declaring ``network_egress`` requires a provenance
  ``source_url`` so the capability is auditable.

:func:`verify_and_load` binds the two halves: it verifies the manifest bytes
against a :class:`~src.sandbox.signing.SignaturesFile` **before** parsing, so an
unsigned / tampered / unknown-key manifest never reaches the schema layer.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from enum import StrEnum
from typing import Final, Self

import yaml
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from src.sandbox.signing import (
    KeyNotFoundError,
    SignatureError,
    SignaturesFile,
)
from src.web_workbench.extensions.check_dsl import (
    CheckScope,
    DeclarativeCheck,
    DslError,
)

#: ``author.my-extension`` dotted slug (same shape as check_id).
_EXTENSION_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z][a-z0-9]*(\.[a-z0-9-]+)+$")


class ManifestError(ValueError):
    """Raised when an extension manifest cannot be loaded / verified (fail-closed)."""


class ExtensionPermission(StrEnum):
    """Closed set of capabilities an extension may request (least privilege)."""

    READ_HTTP_HISTORY = "read_http_history"
    EMIT_FINDINGS = "emit_findings"
    REGISTER_PASSIVE_CHECK = "register_passive_check"
    REGISTER_ACTIVE_CHECK = "register_active_check"
    USE_OAST = "use_oast"
    NETWORK_EGRESS = "network_egress"
    READ_SECRETS = "read_secrets"


class SbomComponent(BaseModel):
    """One third-party component the extension bundles (supply-chain audit)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: StrictStr = Field(min_length=1, max_length=200)
    version: StrictStr = Field(min_length=1, max_length=64)
    license: StrictStr = Field(default="", max_length=128)
    purl: StrictStr | None = Field(default=None, max_length=512)


class ExtensionProvenance(BaseModel):
    """Where the extension came from (attribution / audit trail)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    source_url: StrictStr | None = Field(default=None, max_length=512)
    commit: StrictStr | None = Field(default=None, max_length=64)
    license: StrictStr = Field(default="", max_length=128)
    notice: StrictStr = Field(default="", max_length=2000)


class ExtensionManifest(BaseModel):
    """Top-level signed, declarative extension descriptor (data, not code)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: StrictInt = Field(ge=1, le=1_000)
    extension_id: StrictStr = Field(min_length=3, max_length=128, pattern=_EXTENSION_ID_RE.pattern)
    name: StrictStr = Field(min_length=1, max_length=200)
    author: StrictStr = Field(default="", max_length=200)
    version: StrictInt = Field(ge=1, le=1_000_000)
    description: StrictStr = Field(default="", max_length=4000)
    permissions: list[ExtensionPermission] = Field(
        default_factory=list, max_length=len(ExtensionPermission)
    )
    checks: list[DeclarativeCheck] = Field(default_factory=list, max_length=128)
    sbom: list[SbomComponent] = Field(default_factory=list, max_length=256)
    provenance: ExtensionProvenance = Field(default_factory=ExtensionProvenance)
    min_platform_version: StrictStr | None = Field(default=None, max_length=32)

    @field_validator("permissions")
    @classmethod
    def _unique_permissions(cls, value: list[ExtensionPermission]) -> list[ExtensionPermission]:
        if len(set(value)) != len(value):
            raise ValueError("permissions must be unique")
        return value

    @model_validator(mode="after")
    def _validate(self) -> Self:
        self._check_unique_check_ids()
        self._check_least_privilege()
        self._check_egress_attribution()
        return self

    def _check_unique_check_ids(self) -> None:
        ids = [check.check_id for check in self.checks]
        if len(set(ids)) != len(ids):
            raise ValueError("embedded check_id values must be unique")

    def _check_least_privilege(self) -> None:
        granted = set(self.permissions)
        for check in self.checks:
            if check.scope is CheckScope.ACTIVE:
                if ExtensionPermission.REGISTER_ACTIVE_CHECK not in granted:
                    raise ValueError(
                        f"check {check.check_id!r} is active but manifest lacks "
                        "register_active_check permission"
                    )
            elif ExtensionPermission.REGISTER_PASSIVE_CHECK not in granted:
                raise ValueError(
                    f"check {check.check_id!r} is passive but manifest lacks "
                    "register_passive_check permission"
                )
            if check.requires_oast and ExtensionPermission.USE_OAST not in granted:
                raise ValueError(
                    f"check {check.check_id!r} requires OAST but manifest lacks "
                    "use_oast permission"
                )

    def _check_egress_attribution(self) -> None:
        if (
            ExtensionPermission.NETWORK_EGRESS in self.permissions
            and not self.provenance.source_url
        ):
            raise ValueError("network_egress permission requires provenance.source_url for audit")


def load_manifest(data: object) -> ExtensionManifest:
    """Validate an untrusted mapping into an :class:`ExtensionManifest`.

    Fail-closed: any unexpected key, wrong type, bad check, or invalid
    permission combo raises :class:`ManifestError` (never a raw pydantic /
    stack trace, per the error-handling policy).
    """
    if not isinstance(data, dict):
        raise ManifestError("manifest must be a mapping")
    try:
        return ExtensionManifest.model_validate(data)
    except (ValueError, DslError) as exc:
        raise ManifestError(f"invalid extension manifest: {exc.__class__.__name__}") from exc


def parse_manifest_bytes(raw: bytes) -> ExtensionManifest:
    """Parse raw YAML manifest bytes into a validated :class:`ExtensionManifest`."""
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise ManifestError(f"manifest is not valid YAML: {exc.__class__.__name__}") from exc
    return load_manifest(data)


def verify_and_load(
    raw: bytes,
    *,
    relative_path: str,
    signatures: SignaturesFile,
    public_key_resolver: Callable[[str], Ed25519PublicKey],
) -> ExtensionManifest:
    """Verify a manifest's Ed25519 signature, then parse it (fail-closed).

    Signature verification happens **before** any YAML/schema parsing, so an
    unsigned, tampered, or unknown-key manifest is rejected with
    :class:`ManifestError` before it can influence the loader.
    """
    try:
        signatures.verify_one(
            relative_path=relative_path,
            yaml_bytes=raw,
            public_key_resolver=public_key_resolver,
        )
    except (SignatureError, KeyNotFoundError) as exc:
        raise ManifestError(
            f"manifest signature verification failed: {exc.__class__.__name__}"
        ) from exc
    return parse_manifest_bytes(raw)


__all__ = [
    "ExtensionManifest",
    "ExtensionPermission",
    "ExtensionProvenance",
    "ManifestError",
    "SbomComponent",
    "load_manifest",
    "parse_manifest_bytes",
    "verify_and_load",
]
