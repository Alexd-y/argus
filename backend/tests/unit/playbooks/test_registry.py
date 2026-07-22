"""Fail-closed loading tests for :class:`src.playbooks.registry.PlaybookRegistry`."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any, Final

import pytest

from src.playbooks.registry import (
    PlaybookNotFoundError,
    PlaybookRegistry,
    PlaybookSignatureError,
    RegistryLoadError,
)
from src.playbooks.schema import PlaybookCategory, PlaybookRiskLevel

_REAL_CATALOG: Final[Path] = Path(__file__).resolve().parents[3] / "config" / "playbooks"

CatalogEntry = tuple[str, dict[str, Any], bool]
Factory = Callable[..., dict[str, Any]]
Builder = Callable[[Sequence[CatalogEntry]], Path]


def test_loads_real_signed_catalog() -> None:
    registry = PlaybookRegistry(_REAL_CATALOG)
    summary = registry.load()
    assert summary.total >= 1
    assert "idor.cross-user-read" in registry
    playbook = registry.get("idor.cross-user-read")
    assert playbook.category is PlaybookCategory.AUTHORIZATION


def test_load_single_signed_entry(build_signed_catalog: Builder, playbook_dict: Factory) -> None:
    catalog = build_signed_catalog(
        [("authorization/idor.cross-user-read.yaml", playbook_dict(), True)]
    )
    registry = PlaybookRegistry(catalog)
    summary = registry.load()
    assert summary.total == 1
    assert registry.get("idor.cross-user-read").playbook_id == "idor.cross-user-read"


def test_duplicate_playbook_id_is_fatal(
    build_signed_catalog: Builder, playbook_dict: Factory
) -> None:
    dup = playbook_dict(playbook_id="dup.case", category="authorization")
    dup_other = playbook_dict(playbook_id="dup.case", category="authentication")
    catalog = build_signed_catalog(
        [
            ("authorization/dup.case.yaml", dup, True),
            ("authentication/dup.case.yaml", dup_other, True),
        ]
    )
    registry = PlaybookRegistry(catalog)
    with pytest.raises(RegistryLoadError, match="duplicate playbook_id"):
        registry.load()


def test_unsigned_entry_is_fatal(build_signed_catalog: Builder, playbook_dict: Factory) -> None:
    catalog = build_signed_catalog(
        [
            ("authorization/idor.cross-user-read.yaml", playbook_dict(), True),
            (
                "authentication/auth.bypass.yaml",
                playbook_dict(playbook_id="auth.bypass", category="authentication"),
                False,  # written but NOT signed
            ),
        ]
    )
    registry = PlaybookRegistry(catalog)
    with pytest.raises(PlaybookSignatureError):
        registry.load()


def test_tampered_entry_is_fatal(build_signed_catalog: Builder, playbook_dict: Factory) -> None:
    catalog = build_signed_catalog(
        [("authorization/idor.cross-user-read.yaml", playbook_dict(), True)]
    )
    target = catalog / "authorization" / "idor.cross-user-read.yaml"
    target.write_text(target.read_text(encoding="utf-8") + "\n# tampered\n")
    registry = PlaybookRegistry(catalog)
    with pytest.raises(PlaybookSignatureError):
        registry.load()


def test_playbook_id_must_match_filename(
    build_signed_catalog: Builder, playbook_dict: Factory
) -> None:
    catalog = build_signed_catalog([("authorization/wrong.name.yaml", playbook_dict(), True)])
    registry = PlaybookRegistry(catalog)
    with pytest.raises(RegistryLoadError, match="does not match filename"):
        registry.load()


def test_category_dir_must_match(build_signed_catalog: Builder, playbook_dict: Factory) -> None:
    payload = playbook_dict(playbook_id="idor.cross-user-read", category="authorization")
    catalog = build_signed_catalog([("authentication/idor.cross-user-read.yaml", payload, True)])
    registry = PlaybookRegistry(catalog)
    with pytest.raises(RegistryLoadError, match="does not match its directory"):
        registry.load()


def test_missing_directory_is_fatal(tmp_path: Path) -> None:
    registry = PlaybookRegistry(tmp_path / "does-not-exist")
    with pytest.raises(RegistryLoadError, match="does not exist"):
        registry.load()


def test_get_unknown_raises(build_signed_catalog: Builder, playbook_dict: Factory) -> None:
    catalog = build_signed_catalog(
        [("authorization/idor.cross-user-read.yaml", playbook_dict(), True)]
    )
    registry = PlaybookRegistry(catalog)
    registry.load()
    with pytest.raises(PlaybookNotFoundError):
        registry.get("nope.missing")


def test_filter(build_signed_catalog: Builder, playbook_dict: Factory) -> None:
    catalog = build_signed_catalog(
        [
            ("authorization/idor.cross-user-read.yaml", playbook_dict(), True),
            (
                "rate_limit/rl.no-throttle.yaml",
                playbook_dict(playbook_id="rl.no-throttle", category="rate_limit"),
                True,
            ),
        ]
    )
    registry = PlaybookRegistry(catalog)
    registry.load()
    assert len(registry.filter(category=PlaybookCategory.AUTHORIZATION)) == 1
    assert len(registry.filter(capability="http_client")) == 2
    assert len(registry.filter(risk=PlaybookRiskLevel.LOW)) == 2
    assert registry.filter(requires_approval=True) == []
