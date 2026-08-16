"""NucleiTemplateRegistry — in-memory template catalog with provenance (§9.3)."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from typing import Any

from src.core.unified_ai_metrics import record_nuclei_templates_loaded
from src.execution_mode.mode import ExecutionMode, parse_execution_mode
from src.nuclei.schemas import (
    LabTemplateArtifact,
    NucleiTemplateManifest,
    TemplateSource,
)


def _provenance_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _lower_set(values: Sequence[str] | None) -> frozenset[str]:
    if not values:
        return frozenset()
    return frozenset(str(item).strip().lower() for item in values if str(item).strip())


def _manifest_matches(
    manifest: NucleiTemplateManifest,
    *,
    tags: Sequence[str] | None,
    product: str | None,
    product_version: str | None,
    severity: str | Sequence[str] | None,
    oast: bool | None,
    headless: bool | None,
    enabled_modes: Sequence[str] | None,
    protocols: Sequence[str] | None,
    verified: bool | None,
) -> bool:
    if tags:
        have = _lower_set(manifest.tags)
        wanted = _lower_set(tags)
        if not have.intersection(wanted):
            return False
    if product:
        actual = (manifest.product or "").strip().lower()
        if actual != product.strip().lower():
            return False
    if product_version:
        actual_version = (manifest.product_version or "").strip().lower()
        if actual_version != product_version.strip().lower():
            return False
    if severity is not None:
        if isinstance(severity, str):
            allowed = {severity.strip().lower()}
        else:
            allowed = _lower_set(severity)
        if manifest.severity.strip().lower() not in allowed:
            return False
    if oast is not None and bool(manifest.requires_oast) is not oast:
        return False
    if headless is not None and bool(manifest.requires_headless) is not headless:
        return False
    if enabled_modes:
        modes = _lower_set(tuple(str(item) for item in manifest.execution_modes))
        wanted_modes = _lower_set(enabled_modes)
        if not wanted_modes.issubset(modes):
            return False
    if protocols:
        have_protocols = _lower_set(manifest.protocols)
        wanted_protocols = _lower_set(protocols)
        if not have_protocols.intersection(wanted_protocols):
            return False
    if verified is None:
        return True
    return bool(manifest.verified) is verified


class TemplateRegistryError(ValueError):
    """Template rejected by production signature/verification gate."""


class NucleiTemplateRegistry:
    """In-memory registry — LAB skips signature gate; provenance always recorded."""

    def __init__(self) -> None:
        self._templates: dict[str, NucleiTemplateManifest] = {}
        self._provenance_hashes: dict[str, str] = {}
        self._artifacts: dict[str, LabTemplateArtifact] = {}

    def get(self, template_id: str) -> NucleiTemplateManifest | None:
        return self._templates.get(template_id)

    def provenance_hash(self, template_id: str) -> str | None:
        return self._provenance_hashes.get(template_id)

    def list_template_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._templates.keys()))

    def query(
        self,
        *,
        tags: Sequence[str] | None = None,
        product: str | None = None,
        product_version: str | None = None,
        severity: str | Sequence[str] | None = None,
        oast: bool | None = None,
        headless: bool | None = None,
        enabled_modes: Sequence[str] | None = None,
        protocols: Sequence[str] | None = None,
        verified: bool | None = None,
    ) -> tuple[NucleiTemplateManifest, ...]:
        """Deterministic catalog query. Results are sorted by template_id."""
        matched: list[NucleiTemplateManifest] = []
        for template_id in sorted(self._templates):
            manifest = self._templates[template_id]
            if _manifest_matches(
                manifest,
                tags=tags,
                product=product,
                product_version=product_version,
                severity=severity,
                oast=oast,
                headless=headless,
                enabled_modes=enabled_modes,
                protocols=protocols,
                verified=verified,
            ):
                matched.append(manifest)
        return tuple(matched)

    def register(
        self,
        manifest: NucleiTemplateManifest,
        *,
        mode: ExecutionMode | str = ExecutionMode.PRODUCTION,
        skip_signature_gate: bool = False,
    ) -> str:
        resolved_mode = parse_execution_mode(mode)
        provenance = dict(manifest.provenance)
        provenance.update(
            {
                "template_id": manifest.template_id,
                "version": manifest.version,
                "source": str(manifest.source),
                "sha256": manifest.sha256,
            }
        )
        prov_hash = _provenance_hash(provenance)

        apply_signature_gate: bool
        match resolved_mode:
            case ExecutionMode.LAB_UNRESTRICTED:
                apply_signature_gate = False
            case ExecutionMode.PRODUCTION | ExecutionMode.QUICK:
                apply_signature_gate = not skip_signature_gate
            case _:
                raise ValueError(f"unsupported_execution_mode:{resolved_mode}")

        if apply_signature_gate:
            if (
                manifest.source not in (TemplateSource.INTERNAL, TemplateSource.PROJECTDISCOVERY)
                and not manifest.verified
            ):
                raise TemplateRegistryError(
                    f"template_not_verified:{manifest.template_id}"
                )
            if manifest.signature is None and manifest.source != TemplateSource.INTERNAL:
                raise TemplateRegistryError(
                    f"template_missing_signature:{manifest.template_id}"
                )

        self._templates[manifest.template_id] = manifest
        self._provenance_hashes[manifest.template_id] = prov_hash
        protocols = manifest.protocols or ("unknown",)
        for protocol in protocols:
            record_nuclei_templates_loaded(
                verified=bool(manifest.verified),
                protocol=str(protocol),
                mode=resolved_mode.value,
            )
        return prov_hash

    def ingest_lab_artifact(
        self,
        artifact: LabTemplateArtifact,
        *,
        mode: ExecutionMode | str = ExecutionMode.LAB_UNRESTRICTED,
    ) -> str:
        """LAB ingest — signature gate skipped; provenance hash always recorded."""
        resolved_mode = parse_execution_mode(mode)
        if resolved_mode is not ExecutionMode.LAB_UNRESTRICTED:
            raise TemplateRegistryError("lab_artifact_requires_lab_mode")

        provenance = dict(artifact.provenance)
        provenance.update(
            {
                "artifact_id": artifact.artifact_id,
                "template_id": artifact.template_id,
                "content_sha256": artifact.content_sha256,
            }
        )
        prov_hash = _provenance_hash(provenance)

        manifest = NucleiTemplateManifest(
            template_id=artifact.template_id,
            version="lab",
            source=TemplateSource.GENERATED,
            sha256=artifact.content_sha256,
            signature=None,
            verified=False,
            protocols=("*",),
            capabilities=("*",),
            risk_level="code_execution",
            requires_oast=False,
            execution_modes=("lab_unrestricted",),
            provenance=provenance,
        )
        self._templates[artifact.template_id] = manifest
        self._provenance_hashes[artifact.template_id] = prov_hash
        stored = artifact.model_copy(
            update={"provenance_hash": prov_hash, "provenance": provenance}
        )
        self._artifacts[artifact.artifact_id] = stored
        return prov_hash

    def get_artifact(self, artifact_id: str) -> LabTemplateArtifact | None:
        return self._artifacts.get(artifact_id)
