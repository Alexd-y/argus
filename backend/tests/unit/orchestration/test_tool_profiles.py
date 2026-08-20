"""Unit tests for the signed tool-profile catalog (vuln type → sandbox tools).

Locks in the config-driven replacement for the in-code ``_VULN_TOOL_MAP``:

* the committed catalog loads and verifies against its Ed25519 SIGNATURES;
* ``tools_for`` reproduces the legacy keyword-in-blob selection semantics;
* the catalog stays in parity with ``_VULN_TOOL_MAP`` (migration safety net);
* a tampered or unsigned catalog is rejected fail-closed.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from src.orchestration.exploitation_executor import _VULN_TOOL_MAP
from src.orchestration.tool_profiles import (
    ToolProfileCatalog,
    ToolProfileError,
    ToolProfileRegistry,
    load_tool_profile_catalog,
)

_CATALOG_DIR: Path = Path(__file__).resolve().parents[3] / "config" / "tool_profiles"


@pytest.fixture(scope="module")
def catalog() -> ToolProfileCatalog:
    return ToolProfileRegistry(_CATALOG_DIR).load()


# ---------------------------------------------------------------------------
# Load + signature verification
# ---------------------------------------------------------------------------


def test_signed_catalog_loads(catalog: ToolProfileCatalog) -> None:
    assert catalog.version >= 1
    assert "xss" in catalog.profiles
    assert catalog.defaults.tools == ["nuclei", "ffuf"]


def test_module_accessor_returns_catalog() -> None:
    assert load_tool_profile_catalog() is not None


def test_parity_with_vuln_tool_map(catalog: ToolProfileCatalog) -> None:
    # The signed catalog must mirror the in-code fallback table exactly so the
    # migration is behaviour-preserving (and so ``_select_tools_for_finding``
    # yields identical results whether it reads the catalog or the fallback).
    assert catalog.as_vuln_tool_map() == _VULN_TOOL_MAP


# ---------------------------------------------------------------------------
# tools_for — keyword-in-blob selection (parity with _select_tools_for_finding)
# ---------------------------------------------------------------------------


class TestToolsFor:
    def test_xss(self, catalog: ToolProfileCatalog) -> None:
        assert catalog.tools_for("xss ") == ["dalfox", "xsstrike"]

    def test_sqli(self, catalog: ToolProfileCatalog) -> None:
        assert catalog.tools_for("sqli ") == ["sqlmap"]

    def test_unknown_defaults(self, catalog: ToolProfileCatalog) -> None:
        assert catalog.tools_for("something_weird ") == ["nuclei", "ffuf"]

    def test_empty_defaults(self, catalog: ToolProfileCatalog) -> None:
        assert catalog.tools_for(" ") == ["nuclei", "ffuf"]

    def test_capped_at_three(self, catalog: ToolProfileCatalog) -> None:
        assert len(catalog.tools_for("xss sqli ssrf lfi")) <= 3

    def test_deduplicated(self, catalog: ToolProfileCatalog) -> None:
        assert catalog.tools_for("xss and xss again") == ["dalfox", "xsstrike"]

    def test_title_overlap_collects_multiple(self, catalog: ToolProfileCatalog) -> None:
        tools = catalog.tools_for("xss stored xss and sqli injection")
        assert "dalfox" in tools
        assert "xsstrike" in tools
        assert "sqlmap" in tools


# ---------------------------------------------------------------------------
# Fail-closed: tamper / missing signature
# ---------------------------------------------------------------------------


def test_tampered_catalog_rejected(tmp_path: Path) -> None:
    dst = tmp_path / "tool_profiles"
    shutil.copytree(_CATALOG_DIR, dst)
    yaml_path = dst / "tool_profiles.yaml"
    yaml_path.write_text(
        yaml_path.read_text(encoding="utf-8") + "\n# tampered after signing\n",
        encoding="utf-8",
    )
    with pytest.raises(ToolProfileError):
        ToolProfileRegistry(dst).load()


def test_missing_signatures_rejected(tmp_path: Path) -> None:
    dst = tmp_path / "tp"
    dst.mkdir()
    (dst / "tool_profiles.yaml").write_text(
        "version: 1\ndefaults:\n  tools: [nuclei]\nprofiles:\n  xss:\n    tools: [dalfox]\n",
        encoding="utf-8",
    )
    with pytest.raises(ToolProfileError):
        ToolProfileRegistry(dst).load()


def test_missing_catalog_file_rejected(tmp_path: Path) -> None:
    with pytest.raises(ToolProfileError):
        ToolProfileRegistry(tmp_path).load()
