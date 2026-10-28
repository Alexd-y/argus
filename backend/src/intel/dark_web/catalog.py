"""Signed Dark Web Monitoring catalog loader (fail-closed).

Loads ``backend/config/darkweb/*.yaml`` and verifies each file's Ed25519
signature against ``config/darkweb/SIGNATURES`` + ``config/darkweb/_keys``
BEFORE parsing — the same contract as the payloads/tools catalogs. Any tamper,
missing signature, or unknown key raises; the caller must treat the catalog as
unavailable (fail-closed), never silently fall back to unsigned content.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from src.sandbox.signing import KeyManager, SignatureError, SignaturesFile

logger = logging.getLogger(__name__)

_CATALOG_DIR = Path(__file__).resolve().parents[3] / "config" / "darkweb"
_SIGNATURES = _CATALOG_DIR / "SIGNATURES"
_KEYS_DIR = _CATALOG_DIR / "_keys"

_FILES = (
    "sources.yaml",
    "classifier_rules.yaml",
    "selector_rules.yaml",
    "onion_seeds.yaml",
    "telegram_channels.yaml",
)


class DarkWebCatalogError(RuntimeError):
    """Raised when the signed catalog is missing or fails verification."""


@dataclass(frozen=True)
class DarkWebCatalog:
    sources: dict[str, Any] = field(default_factory=dict)
    classifier_rules: dict[str, Any] = field(default_factory=dict)
    selector_rules: dict[str, Any] = field(default_factory=dict)
    onion_seeds: dict[str, Any] = field(default_factory=dict)
    telegram_channels: dict[str, Any] = field(default_factory=dict)


def _verify_all() -> None:
    if not _SIGNATURES.is_file():
        raise DarkWebCatalogError(f"SIGNATURES missing: {_SIGNATURES}")
    if not _KEYS_DIR.is_dir():
        raise DarkWebCatalogError(f"keys dir missing: {_KEYS_DIR}")
    try:
        signatures = SignaturesFile.from_file(_SIGNATURES)
        keys = KeyManager(_KEYS_DIR)
        keys.load()
    except SignatureError as exc:  # pragma: no cover - defensive
        raise DarkWebCatalogError(f"catalog manifest/keys invalid: {exc}") from exc

    for name in _FILES:
        path = _CATALOG_DIR / name
        if not path.is_file():
            raise DarkWebCatalogError(f"catalog file missing: {name}")
        try:
            signatures.verify_one(
                relative_path=name,
                yaml_bytes=path.read_bytes(),
                public_key_resolver=keys.get,
            )
        except SignatureError as exc:
            raise DarkWebCatalogError(f"signature verification failed for {name}: {exc}") from exc


def _parse(name: str) -> dict[str, Any]:
    data = yaml.safe_load((_CATALOG_DIR / name).read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


@lru_cache(maxsize=1)
def load_catalog(verify: bool = True) -> DarkWebCatalog:
    """Load + (optionally) verify the signed DWM catalog. Fail-closed on tamper."""

    if verify:
        _verify_all()
    return DarkWebCatalog(
        sources=_parse("sources.yaml"),
        classifier_rules=_parse("classifier_rules.yaml"),
        selector_rules=_parse("selector_rules.yaml"),
        onion_seeds=_parse("onion_seeds.yaml"),
        telegram_channels=_parse("telegram_channels.yaml"),
    )


__all__ = ["DarkWebCatalog", "DarkWebCatalogError", "load_catalog"]
