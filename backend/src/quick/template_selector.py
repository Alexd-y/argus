"""Deterministic Nuclei template selection for Quick (master §7.2)."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Final

from src.nuclei.profile_compiler import load_scan_profile
from src.nuclei.schemas import (
    NucleiTemplateManifest,
    NucleiTemplateSelectionManifest,
    TemplateSource,
    digest_nuclei_template_ids,
)
from src.nuclei.template_registry import NucleiTemplateRegistry
from src.quick.applicability import fingerprint_tokens
from src.quick.schemas import AssetFingerprint, QuickScanConfig, SeverityFloor

_CVE_ID_RE: Final[re.Pattern[str]] = re.compile(r"cve-\d{4}-\d+", re.IGNORECASE)
_CODE_PROTOCOLS: Final[frozenset[str]] = frozenset({"code", "javascript"})
_MISCONFIG_TAGS: Final[frozenset[str]] = frozenset(
    {
        "misconfig",
        "misconfiguration",
        "exposure",
        "config",
        "default-login",
        "panel",
        "debug",
        "admin",
        "takeover",
        "unauth",
        "disclosure",
    }
)
_CVE_TAGS: Final[frozenset[str]] = frozenset({"cve", "rce"})
_SEVERITY_RANK: Final[dict[str, int]] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}
_DEFAULT_MAX_TEMPLATES: Final[int] = 50
_PROFILE_MAX_TEMPLATES: Final[dict[str, int]] = {
    "compact": 25,
    "balanced": 50,
    "extended": 80,
}


def _tags(manifest: NucleiTemplateManifest) -> frozenset[str]:
    return frozenset(str(tag).strip().lower() for tag in manifest.tags if str(tag).strip())


def _severity_rank(value: str) -> int:
    return _SEVERITY_RANK.get(str(value).strip().lower(), 0)


def _meets_severity_floor(manifest: NucleiTemplateManifest, floor: SeverityFloor) -> bool:
    return _severity_rank(manifest.severity) >= _severity_rank(floor.value)


def _is_unsigned_disallowed(manifest: NucleiTemplateManifest) -> bool:
    source = (
        manifest.source
        if isinstance(manifest.source, TemplateSource)
        else str(manifest.source)
    )
    if source in (TemplateSource.INTERNAL, TemplateSource.INTERNAL.value):
        return False
    return manifest.signature is None


def _is_code_template(manifest: NucleiTemplateManifest) -> bool:
    protocols = {str(item).strip().lower() for item in manifest.protocols}
    return bool(protocols & _CODE_PROTOCOLS)


def _is_cve_template(manifest: NucleiTemplateManifest) -> bool:
    tags = _tags(manifest)
    if tags & _CVE_TAGS:
        return True
    if _CVE_ID_RE.search(manifest.template_id):
        return True
    return any(_CVE_ID_RE.search(tag) for tag in tags)


def _is_misconfig_template(manifest: NucleiTemplateManifest) -> bool:
    return bool(_tags(manifest) & _MISCONFIG_TAGS)


def _product_of(fingerprint: AssetFingerprint) -> str:
    for fact in (fingerprint.product, fingerprint.cms, fingerprint.framework, fingerprint.web_server):
        if fact is not None and fact.value and fact.value.strip():
            return fact.value.strip().lower()
    return ""


def _version_of(fingerprint: AssetFingerprint) -> str:
    if fingerprint.version is None or not fingerprint.version.value:
        return ""
    return fingerprint.version.value.strip().lower()


def _exact_product_version(manifest: NucleiTemplateManifest, fingerprint: AssetFingerprint) -> bool:
    product = (manifest.product or "").strip().lower()
    if not product:
        return False
    fp_product = _product_of(fingerprint)
    if not fp_product or product != fp_product:
        return False
    template_version = (manifest.product_version or "").strip().lower()
    fp_version = _version_of(fingerprint)
    return bool(template_version) and bool(fp_version) and template_version == fp_version


def _technology_tag_match(manifest: NucleiTemplateManifest, fingerprint: AssetFingerprint) -> bool:
    tokens = fingerprint_tokens(fingerprint)
    if not tokens:
        return False
    product = (manifest.product or "").strip().lower()
    if product and product in tokens:
        return True
    return bool(_tags(manifest) & tokens)


def _generic_protocol_match(manifest: NucleiTemplateManifest, fingerprint: AssetFingerprint) -> bool:
    protocols = {str(item).strip().lower() for item in manifest.protocols}
    if not protocols:
        return False
    fp_protocol = ""
    if fingerprint.protocol is not None and fingerprint.protocol.value:
        fp_protocol = fingerprint.protocol.value.strip().lower()
    if fp_protocol == "https":
        return bool(protocols & {"http", "https", "ssl", "tls"})
    if fp_protocol == "http":
        return "http" in protocols
    return fp_protocol in protocols


def _max_templates(config: QuickScanConfig) -> int:
    fallback = _PROFILE_MAX_TEMPLATES.get(config.profile.value, _DEFAULT_MAX_TEMPLATES)
    try:
        profile = load_scan_profile(config.template_policy_id)
    except (FileNotFoundError, OSError, ValueError):
        return fallback
    extra = profile.model_extra or {}
    selection = extra.get("selection") if isinstance(extra, dict) else None
    if isinstance(selection, dict):
        raw = selection.get("max_templates_per_asset")
        if isinstance(raw, int) and raw > 0:
            return raw
    return fallback


class QuickTemplateSelector:
    """Select a frozen Nuclei template id list. Repeat select → same digest."""

    def __init__(
        self,
        registry: NucleiTemplateRegistry | None = None,
        *,
        max_templates_per_asset: int | None = None,
    ) -> None:
        self._registry = registry or NucleiTemplateRegistry()
        self._max_templates_override = max_templates_per_asset

    @property
    def registry(self) -> NucleiTemplateRegistry:
        return self._registry

    def select(
        self,
        fingerprint: AssetFingerprint,
        config: QuickScanConfig,
        *,
        oast_available: bool = False,
        headless_signal: bool = False,
        budget_allows_oast: bool = True,
        budget_allows_headless: bool = True,
    ) -> NucleiTemplateSelectionManifest:
        """Apply master §7.2 order; never emit CLI flags."""
        pool = self._eligible_pool(config)
        tiers = self._bucket(pool, fingerprint)
        limit = self._max_templates_override or _max_templates(config)
        selected: list[str] = []
        seen: set[str] = set()
        oast_ok = bool(config.enable_oast and oast_available and budget_allows_oast)
        headless_ok = bool(
            config.enable_headless_on_signal and headless_signal and budget_allows_headless
        )
        for index, tier in enumerate(tiers):
            if index == 5 and not (oast_ok or headless_ok):
                continue
            for manifest in tier:
                if index == 5:
                    if manifest.requires_oast and not oast_ok:
                        continue
                    if manifest.requires_headless and not headless_ok:
                        continue
                    if not manifest.requires_oast and not manifest.requires_headless:
                        continue
                if manifest.template_id in seen:
                    continue
                selected.append(manifest.template_id)
                seen.add(manifest.template_id)
                if len(selected) >= limit:
                    ids = tuple(selected)
                    return NucleiTemplateSelectionManifest(
                        template_ids=ids,
                        digest_sha256=digest_nuclei_template_ids(ids),
                        profile_id=config.template_policy_id,
                    )
        ids = tuple(selected)
        return NucleiTemplateSelectionManifest(
            template_ids=ids,
            digest_sha256=digest_nuclei_template_ids(ids),
            profile_id=config.template_policy_id,
        )

    def _eligible_pool(self, config: QuickScanConfig) -> tuple[NucleiTemplateManifest, ...]:
        candidates = self._registry.query(enabled_modes=("quick",), verified=True)
        allowed: list[NucleiTemplateManifest] = []
        for manifest in candidates:
            if not _meets_severity_floor(manifest, config.severity_floor):
                continue
            if _is_unsigned_disallowed(manifest):
                continue
            if _is_code_template(manifest):
                continue
            allowed.append(manifest)
        return tuple(allowed)

    def _bucket(
        self,
        pool: Sequence[NucleiTemplateManifest],
        fingerprint: AssetFingerprint,
    ) -> tuple[tuple[NucleiTemplateManifest, ...], ...]:
        exact: list[NucleiTemplateManifest] = []
        technology: list[NucleiTemplateManifest] = []
        misconfig: list[NucleiTemplateManifest] = []
        cve: list[NucleiTemplateManifest] = []
        generic: list[NucleiTemplateManifest] = []
        delayed: list[NucleiTemplateManifest] = []
        for manifest in pool:
            if manifest.requires_oast or manifest.requires_headless:
                delayed.append(manifest)
                continue
            if _exact_product_version(manifest, fingerprint):
                exact.append(manifest)
                continue
            if _technology_tag_match(manifest, fingerprint):
                technology.append(manifest)
                continue
            if _is_misconfig_template(manifest):
                misconfig.append(manifest)
                continue
            if _is_cve_template(manifest) and _severity_rank(manifest.severity) >= _severity_rank(
                "high"
            ):
                cve.append(manifest)
                continue
            if _generic_protocol_match(manifest, fingerprint):
                generic.append(manifest)
        return (
            _sorted_manifests(exact),
            _sorted_manifests(technology),
            _sorted_manifests(misconfig),
            _sorted_manifests(cve),
            _sorted_manifests(generic),
            _sorted_manifests(delayed),
        )


def _sorted_manifests(
    items: Sequence[NucleiTemplateManifest],
) -> tuple[NucleiTemplateManifest, ...]:
    return tuple(sorted(items, key=lambda item: item.template_id))
