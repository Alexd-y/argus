"""Unit tests for the single canonical tool-name namespace (Backlog T7).

Two layers are exercised:

* **Pure resolution** — :func:`resolve_tool_alias` / :func:`canonical_tool_id`
  need no catalog and cover generic→variant aliases, MCP/Celery operation
  prefixes, and separator folds.
* **Reconciliation / drift guard** — every alias target, every
  ``_VULN_TOOL_MAP`` tool, and every LLM/phase allowlist entry must resolve
  to a real catalog ``tool_id`` (or be an explicitly-declared virtual tool).
  Catalog ids are enumerated from raw YAML so the guard runs even when the
  signed catalog has Ed25519 drift (ARG-058).
* **Registry wiring** — :meth:`ToolRegistry.resolve` accepts aliases and
  returns the canonical descriptor, verified against a self-signed catalog.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from src.orchestration.exploitation_executor import _VULN_TOOL_MAP
from src.orchestration.mcp_allowlist import (
    PHASE_TOOL_ALLOWLIST,
    VULN_DOMAIN_TOOL_ALLOWLIST,
)
from src.sandbox.signing import SignatureRecord, SignaturesFile, sign_blob
from src.sandbox.tool_aliases import (
    TOOL_ALIASES,
    VIRTUAL_TOOLS,
    all_aliases,
    canonical_tool_id,
    normalize_tool_name,
    resolve_tool_alias,
)
from src.sandbox.tool_registry import ToolRegistry

_TOOLS_DIR = Path(__file__).resolve().parents[3] / "config" / "tools"


def _catalog_tool_ids() -> set[str]:
    """Enumerate canonical ``tool_id``s from raw YAML (signature-agnostic)."""
    ids: set[str] = set()
    for yaml_path in _TOOLS_DIR.glob("*.yaml"):
        try:
            parsed = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if isinstance(parsed, dict):
            tool_id = parsed.get("tool_id")
            if isinstance(tool_id, str) and tool_id:
                ids.add(tool_id)
    return ids


@pytest.fixture(scope="module")
def catalog_ids() -> set[str]:
    ids = _catalog_tool_ids()
    assert len(ids) >= 150, f"expected the full catalog, found {len(ids)}"
    return ids


# ---------------------------------------------------------------------------
# Pure resolution (no catalog)
# ---------------------------------------------------------------------------


def test_normalize_tool_name_lowercases_and_strips() -> None:
    assert normalize_tool_name("  SQLMap  ") == "sqlmap"
    assert normalize_tool_name("NUCLEI") == "nuclei"


@pytest.mark.parametrize(
    ("alias", "expected"),
    [
        ("sqlmap", "sqlmap_safe"),
        ("sqlmap_detect", "sqlmap_safe"),
        ("nmap", "nmap_tcp_top"),
        ("ffuf", "ffuf_dir"),
        ("gobuster", "gobuster_dir"),
        ("amass", "amass_passive"),
        ("trivy", "trivy_fs"),
        ("shodan", "shodan_cli"),
        ("wappalyzer", "wappalyzer_cli"),
        ("scout", "scoutsuite"),
        ("impacket", "impacket_examples"),
        ("nosqli", "nosqlmap"),
        ("enum4linux", "enum4linux_ng"),
        ("crtsh", "crt_sh"),
        ("testssl.sh", "testssl"),
    ],
)
def test_resolve_generic_alias(alias: str, expected: str) -> None:
    assert resolve_tool_alias(alias) == expected


def test_resolve_is_case_insensitive() -> None:
    assert resolve_tool_alias("SQLMap") == "sqlmap_safe"


@pytest.mark.parametrize(
    ("operation", "expected"),
    [
        ("run_sqlmap", "sqlmap_safe"),
        ("argus.va.run_sqlmap", "sqlmap_safe"),
        ("run_dalfox", "dalfox"),
        ("run_nuclei", "nuclei"),
        ("run_nosqli", "nosqlmap"),
    ],
)
def test_resolve_operation_prefixes(operation: str, expected: str) -> None:
    assert resolve_tool_alias(operation) == expected


def test_resolve_returns_none_for_canonical_name() -> None:
    # A real ``tool_id`` is not an alias — canonical_tool_id decides identity.
    assert resolve_tool_alias("nuclei") is None
    assert resolve_tool_alias("sqlmap_safe") is None


def test_resolve_returns_none_for_empty() -> None:
    assert resolve_tool_alias("") is None
    assert resolve_tool_alias("   ") is None


def test_canonical_identity(catalog_ids: set[str]) -> None:
    assert canonical_tool_id("nuclei", catalog_ids) == "nuclei"
    assert canonical_tool_id("sqlmap_safe", catalog_ids) == "sqlmap_safe"


def test_canonical_via_alias(catalog_ids: set[str]) -> None:
    assert canonical_tool_id("sqlmap", catalog_ids) == "sqlmap_safe"
    assert canonical_tool_id("run_ffuf", catalog_ids) == "ffuf_dir"


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("enum4linux-ng", "enum4linux_ng"),
        ("kube-bench", "kube_bench"),
        ("kube-hunter", "kube_hunter"),
        ("graphql-cop", "graphql_cop"),
        ("openapi-scanner", "openapi_scanner"),
        ("impacket-secretsdump", "impacket_secretsdump"),
        ("crt.sh", "crt_sh"),
    ],
)
def test_canonical_separator_fold(name: str, expected: str, catalog_ids: set[str]) -> None:
    assert canonical_tool_id(name, catalog_ids) == expected


def test_canonical_unknown_returns_none(catalog_ids: set[str]) -> None:
    assert canonical_tool_id("definitely_not_a_tool", catalog_ids) is None
    assert canonical_tool_id("", catalog_ids) is None


# ---------------------------------------------------------------------------
# Reconciliation / drift guard
# ---------------------------------------------------------------------------


def test_every_alias_target_is_a_real_tool_id(catalog_ids: set[str]) -> None:
    for alias, target in all_aliases().items():
        assert target in catalog_ids, f"alias {alias!r} → {target!r} not in catalog"


def test_no_alias_shadows_a_real_tool_id(catalog_ids: set[str]) -> None:
    # An alias key must never collide with a canonical id, otherwise the
    # short name would ambiguously mean both itself and its target.
    for alias in TOOL_ALIASES:
        assert alias not in catalog_ids, f"alias {alias!r} shadows a real tool_id"


def test_virtual_tools_are_not_catalog_ids(catalog_ids: set[str]) -> None:
    overlap = VIRTUAL_TOOLS & catalog_ids
    assert not overlap, f"virtual tools shadow real tool_ids: {sorted(overlap)}"


def test_vuln_tool_map_reconciles_to_catalog(catalog_ids: set[str]) -> None:
    for vuln_type, tools in _VULN_TOOL_MAP.items():
        for tool in tools:
            resolved = canonical_tool_id(tool, catalog_ids)
            assert resolved is not None, (
                f"_VULN_TOOL_MAP[{vuln_type!r}] tool {tool!r} does not resolve "
                f"to any catalog tool_id"
            )


def test_phase_allowlists_reconcile_to_catalog(catalog_ids: set[str]) -> None:
    entries: set[str] = set()
    for tools in PHASE_TOOL_ALLOWLIST.values():
        entries |= tools
    for tools in VULN_DOMAIN_TOOL_ALLOWLIST.values():
        entries |= tools
    unresolved = {
        name
        for name in entries
        if name not in VIRTUAL_TOOLS and canonical_tool_id(name, catalog_ids) is None
    }
    assert not unresolved, f"allowlist entries with no catalog mapping: {sorted(unresolved)}"


# ---------------------------------------------------------------------------
# Registry wiring (self-signed mini catalog)
# ---------------------------------------------------------------------------


@pytest.fixture()
def resolve_registry(
    tmp_path: Path,
    ed25519_keypair: tuple[Ed25519PrivateKey, Ed25519PublicKey, str],
    sample_descriptor_payload: Callable[..., dict[str, object]],
) -> ToolRegistry:
    """A loaded registry containing catalog-variant ids used by the alias table."""
    private_key, public_key, kid = ed25519_keypair
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    keys = tmp_path / "_keys"
    keys.mkdir()
    (keys / f"{kid}.ed25519.pub").write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )

    signatures = SignaturesFile()
    for tool_id in ("sqlmap_safe", "nuclei", "enum4linux_ng", "ffuf_dir"):
        payload = sample_descriptor_payload(tool_id)
        relative = f"{tool_id}.yaml"
        yaml_bytes = yaml.safe_dump(payload, sort_keys=True).encode("utf-8")
        (tools_dir / relative).write_bytes(yaml_bytes)
        signatures.upsert(
            SignatureRecord(
                sha256_hex=hashlib.sha256(yaml_bytes).hexdigest(),
                relative_path=relative,
                signature_b64=sign_blob(private_key, yaml_bytes),
                public_key_id=kid,
            )
        )
    signatures_path = tools_dir / "SIGNATURES"
    signatures.write(signatures_path)

    registry = ToolRegistry(tools_dir=tools_dir, keys_dir=keys, signatures_path=signatures_path)
    registry.load()
    return registry


def test_registry_resolve_identity(resolve_registry: ToolRegistry) -> None:
    descriptor = resolve_registry.resolve("nuclei")
    assert descriptor is not None
    assert descriptor.tool_id == "nuclei"


@pytest.mark.parametrize(
    ("name", "expected_id"),
    [
        ("sqlmap", "sqlmap_safe"),
        ("run_sqlmap", "sqlmap_safe"),
        ("argus.va.run_sqlmap", "sqlmap_safe"),
        ("ffuf", "ffuf_dir"),
        ("enum4linux-ng", "enum4linux_ng"),
        ("enum4linux", "enum4linux_ng"),
    ],
)
def test_registry_resolve_alias(
    resolve_registry: ToolRegistry, name: str, expected_id: str
) -> None:
    descriptor = resolve_registry.resolve(name)
    assert descriptor is not None, f"{name!r} did not resolve"
    assert descriptor.tool_id == expected_id


def test_registry_resolve_unknown_returns_none(resolve_registry: ToolRegistry) -> None:
    assert resolve_registry.resolve("ghost_tool") is None
    # Present in the alias table but not in this mini catalog → None.
    assert resolve_registry.resolve("prowler") is None
