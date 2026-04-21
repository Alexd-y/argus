"""End-to-end integration test: ARG-014 §4.7 ``wpscan`` vertical slice.

Wires up the three subsystems ARG-014 ships in lockstep — YAML descriptor,
templating-rendered argv, parser dispatch — against the real
:mod:`src.sandbox.tool_registry` and the real :mod:`src.sandbox.parsers`
registry. No mocks for the registry layers; only the *raw* WPScan output
is synthesised.

Concretely the test verifies:

1.  Loading the production catalog through :class:`ToolRegistry` yields a
    descriptor for ``wpscan`` whose ``parse_strategy`` is JSON_OBJECT,
    image is ``argus-kali-web:latest`` and network policy is
    ``recon-active-tcp``.
2.  Rendering ``descriptor.command_template`` with ``url=...`` /
    ``out_dir=/out`` produces a clean argv whose tokens are free of any
    shell metacharacters or unrendered placeholders.
3.  Feeding a synthetic WPScan JSON stdout (one interesting finding,
    one CVE-bearing core vulnerability, one plugin vulnerability, two
    enumerated users) into :func:`dispatch_parse` with the descriptor's
    strategy yields exactly the expected number of FindingDTOs with the
    correct categories, CWEs, OWASP-WSTG hints and confidence levels.
4.  The shared evidence sidecar (``wpscan_findings.jsonl``) is written
    to the artefacts directory with one record per finding, each stamped
    with ``tool_id=wpscan`` and the source CVEs (when present).

Sister vertical slices for the seven other §4.7 tools are pinned in the
companion :mod:`test_wpscan_dispatch` integration suite.

Hard isolation: the ``loaded_registry`` fixture builds an *isolated* tool
catalog under ``tmp_path`` containing only the eight §4.7 YAML files
(plus a fresh dev signing key) so the test cannot be flaked by parallel
batches that may land broken descriptors in the production
``backend/config/tools/`` tree (the registry is fail-closed: ANY broken
peer aborts the whole load).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Final

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import dispatch_parse
from src.sandbox.parsers._base import SENTINEL_CVSS_SCORE
from src.sandbox.parsers.wpscan_parser import EVIDENCE_SIDECAR_NAME
from src.sandbox.signing import (
    KeyManager,
    SignatureRecord,
    SignaturesFile,
    compute_yaml_hash,
    load_private_key_bytes,
    sign_blob,
)
from src.sandbox.templating import render_argv
from src.sandbox.tool_registry import ToolRegistry


_SHELL_METACHARS: Final[tuple[str, ...]] = (
    ";",
    "|",
    "&&",
    "||",
    "&",
    "`",
    "$(",
    ">",
    "<",
    "\n",
    "\r",
)


# Eight §4.7 CMS / platform-specific scanners that ARG-014 ships in
# lockstep. The isolated catalog mirrors only this set so the e2e test is
# robust against parallel batches landing broken peers.
_CMS_TOOL_IDS: Final[tuple[str, ...]] = (
    "wpscan",
    "joomscan",
    "droopescan",
    "cmsmap",
    "magescan",
    "nextjs_check",
    "spring_boot_actuator",
    "jenkins_enum",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def production_catalog_dir() -> Path:
    """Resolve ``backend/config/tools/`` from this test file's location.

    Used only as the *source* of YAML descriptors that we copy into the
    isolated tmp catalog; never loaded directly through ``ToolRegistry``.
    """
    here = Path(__file__).resolve()
    backend_dir = here.parents[3]
    catalog = backend_dir / "config" / "tools"
    assert catalog.is_dir(), f"expected catalog dir at {catalog}"
    return catalog


@pytest.fixture(scope="module")
def isolated_catalog(
    tmp_path_factory: pytest.TempPathFactory,
    production_catalog_dir: Path,
) -> Path:
    """Build an isolated, freshly-signed mirror of the eight ARG-014 YAMLs.

    Defence-in-depth: copy ``wpscan.yaml`` and the seven other §4.7
    descriptors into ``tmp_path / tools``, generate a one-shot dev keypair,
    sign the eight YAMLs, and write a clean ``SIGNATURES`` manifest.
    The result is a self-contained registry directory that the test can
    load with :class:`ToolRegistry` regardless of the state of the
    production catalog (which may carry in-flight ARG-015+ work).
    """
    catalog_root = tmp_path_factory.mktemp("arg014_catalog")
    tools_dir = catalog_root / "tools"
    keys_dir = tools_dir / "_keys"
    tools_dir.mkdir(parents=True)
    keys_dir.mkdir(parents=True)

    for tool_id in _CMS_TOOL_IDS:
        src = production_catalog_dir / f"{tool_id}.yaml"
        assert src.is_file(), f"source YAML missing: {src}"
        shutil.copy2(src, tools_dir / f"{tool_id}.yaml")

    priv_path, _, key_id = KeyManager.generate_dev_keypair(
        keys_dir, name="arg014_e2e_signing"
    )
    private_key = load_private_key_bytes(priv_path.read_bytes())
    priv_path.unlink()  # private material lives only in this test process

    signatures = SignaturesFile()
    for tool_id in _CMS_TOOL_IDS:
        rel = f"{tool_id}.yaml"
        yaml_path = tools_dir / rel
        signatures.upsert(
            SignatureRecord(
                sha256_hex=compute_yaml_hash(yaml_path),
                relative_path=rel,
                signature_b64=sign_blob(private_key, yaml_path.read_bytes()),
                public_key_id=key_id,
            )
        )
    signatures.write(tools_dir / "SIGNATURES")
    return tools_dir


@pytest.fixture(scope="module")
def loaded_registry(isolated_catalog: Path) -> ToolRegistry:
    """Load the isolated ARG-014 catalog and return the registry instance."""
    registry = ToolRegistry(tools_dir=isolated_catalog)
    registry.load()
    return registry


@pytest.fixture(scope="module")
def registry_summary(isolated_catalog: Path):  # type: ignore[no-untyped-def]
    """Return the :class:`RegistrySummary` captured from a fresh ``load()``.

    Kept distinct from :func:`loaded_registry` because :class:`ToolRegistry`
    exposes the summary only as the return value of ``load()`` — there is no
    ``.summary`` property to call from the cached registry instance.
    """
    return ToolRegistry(tools_dir=isolated_catalog).load()


def _wpscan_synthetic_payload() -> dict[str, Any]:
    """Build a minimal but representative WPScan ``--format json`` payload."""
    return {
        "interesting_findings": [
            {
                "type": "headers",
                "to_s": "Server: Apache/2.4.41",
                "url": "https://target.example/",
            },
        ],
        "version": {
            "number": "5.8.1",
            "vulnerabilities": [
                {
                    "title": "WP Core 5.8.0 < 5.8.2 — auth bypass",
                    "fixed_in": "5.8.2",
                    "references": {"cve": ["2024-12345"]},
                },
            ],
        },
        "plugins": {
            "akismet": {
                "version": {"number": "4.0.0"},
                "vulnerabilities": [
                    {
                        "title": "Akismet < 4.0.3 — XSS",
                        "fixed_in": "4.0.3",
                        "references": {"cve": ["2023-9999"]},
                    },
                ],
            },
        },
        "users": {
            "admin": {"id": 1},
            "editor": {"id": 2},
        },
    }


def _wpscan_stdout(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True).encode("utf-8")


# ---------------------------------------------------------------------------
# YAML → render
# ---------------------------------------------------------------------------


def test_wpscan_descriptor_loads_with_json_object_strategy(
    loaded_registry: ToolRegistry,
) -> None:
    """The catalog must expose ``wpscan`` with JSON_OBJECT dispatch strategy."""
    descriptor = loaded_registry.get("wpscan")
    assert descriptor is not None, "wpscan missing from loaded catalog"
    assert descriptor.parse_strategy is ParseStrategy.JSON_OBJECT
    assert descriptor.image == "argus-kali-web:latest"
    assert descriptor.network_policy.name == "recon-active-tcp"


def test_wpscan_argv_renders_clean_with_url_out_placeholders(
    loaded_registry: ToolRegistry,
) -> None:
    """Render with sandbox-internal /out + url placeholders and audit the argv.

    ``render_argv`` validates every placeholder value and refuses any that
    contains shell-meaningful characters. We then re-audit the output as
    defence-in-depth: rendered tokens must contain no metacharacter and no
    leftover ``{...}`` sequence (a bug class where a placeholder name is
    misspelled and silently survives substitution would otherwise hide).
    """
    descriptor = loaded_registry.get("wpscan")
    assert descriptor is not None

    argv = render_argv(
        list(descriptor.command_template),
        {"url": "https://target.example", "out_dir": "/out"},
    )

    assert argv, "rendered argv must be non-empty"
    assert argv[0] == "wpscan", f"first token must be the binary, got {argv[0]!r}"

    offenders: list[tuple[str, str]] = []
    for token in argv:
        if "{" in token or "}" in token:
            offenders.append((token, "unrendered placeholder"))
        for meta in _SHELL_METACHARS:
            if meta in token:
                offenders.append((token, meta))
    assert not offenders, (
        f"rendered wpscan argv contains shell metachars / placeholders: {offenders}"
    )


# ---------------------------------------------------------------------------
# Render → dispatch → findings
# ---------------------------------------------------------------------------


def test_dispatch_parse_yields_expected_finding_breakdown(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """Synthetic WPScan output → 1 INFO + 1 INFO (interesting)
    + 2 INFO (users) + 2 MISCONFIG (vulns) = 5 findings total.

    Splits captured below by category to make a future regression in the
    classification logic light up the diff in CI immediately.
    """
    descriptor = loaded_registry.get("wpscan")
    assert descriptor is not None

    raw_stdout = _wpscan_stdout(_wpscan_synthetic_payload())
    findings = dispatch_parse(
        descriptor.parse_strategy,
        raw_stdout,
        b"",
        tmp_path,
        tool_id="wpscan",
    )

    assert len(findings) == 5, (
        f"expected 5 findings (1 interesting + 2 users + 2 vulns), got {len(findings)}"
    )

    info_count = sum(1 for f in findings if f.category is FindingCategory.INFO)
    misconfig_count = sum(
        1 for f in findings if f.category is FindingCategory.MISCONFIG
    )
    assert info_count == 3, f"expected 3 INFO findings, got {info_count}"
    assert misconfig_count == 2, f"expected 2 MISCONFIG findings, got {misconfig_count}"

    for misconfig in (f for f in findings if f.category is FindingCategory.MISCONFIG):
        assert 1395 in misconfig.cwe
        assert misconfig.confidence is ConfidenceLevel.LIKELY  # CVE attached
        assert misconfig.cvss_v3_score == SENTINEL_CVSS_SCORE


def test_dispatch_parse_writes_evidence_sidecar(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """The wpscan parser must persist a JSONL sidecar in ``artifacts_dir``."""
    descriptor = loaded_registry.get("wpscan")
    assert descriptor is not None

    raw_stdout = _wpscan_stdout(_wpscan_synthetic_payload())
    findings = dispatch_parse(
        descriptor.parse_strategy,
        raw_stdout,
        b"",
        tmp_path,
        tool_id="wpscan",
    )
    assert findings

    sidecar = tmp_path / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file(), "wpscan parser must write an evidence sidecar"

    parsed = [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(parsed) == len(findings), (
        f"sidecar must hold one record per finding, got {len(parsed)}"
    )
    assert all(rec["tool_id"] == "wpscan" for rec in parsed), (
        "every sidecar record must tag tool_id=wpscan"
    )

    plugin_records = [r for r in parsed if r["component"] == "plugin"]
    assert plugin_records, "expected at least one plugin record"
    assert plugin_records[0]["slug"] == "akismet"
    assert plugin_records[0]["cve"] == ["CVE-2023-9999"]


def test_dispatch_parse_canonical_artifact_round_trip(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """Writing the canonical ``wpscan.json`` artefact short-circuits stdout
    and produces the same finding set — proves the dispatch flow respects
    the ``--output /out/wpscan.json`` contract documented in the YAML.
    """
    descriptor = loaded_registry.get("wpscan")
    assert descriptor is not None

    payload = _wpscan_synthetic_payload()
    canonical_path = tmp_path / "wpscan.json"
    canonical_path.write_bytes(_wpscan_stdout(payload))

    # Pass garbage stdout — the canonical artefact must take precedence.
    findings = dispatch_parse(
        descriptor.parse_strategy,
        b'{"<<<garbage>>>": true}',
        b"",
        tmp_path,
        tool_id="wpscan",
    )
    assert len(findings) == 5

    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "akismet" in sidecar
    assert "garbage" not in sidecar


def test_isolated_catalog_loads_exactly_eight_cms_tools(registry_summary) -> None:  # type: ignore[no-untyped-def]
    """The isolated ARG-014 catalog must hold exactly the eight §4.7 tools.

    The whole-catalog ``>= 70 tools`` invariant lives in the production
    inventory tests (:mod:`tests.unit.sandbox.test_yaml_schema_per_tool` and
    :mod:`tests.integration.sandbox.test_tool_catalog_load`); this e2e suite
    runs against an isolated tmp catalog so it can never be flaked by
    parallel batches landing broken peers.
    """
    assert registry_summary.total == len(_CMS_TOOL_IDS), (
        f"isolated catalog expected exactly {len(_CMS_TOOL_IDS)} §4.7 tools, "
        f"got {registry_summary.total}; per-phase breakdown: "
        f"{registry_summary.by_phase}"
    )


def test_isolated_catalog_includes_all_eight_cms_tools(
    loaded_registry: ToolRegistry,
) -> None:
    """Every §4.7 tool must be discoverable by ``tool_id`` after the load."""
    missing = [tid for tid in _CMS_TOOL_IDS if loaded_registry.get(tid) is None]
    assert not missing, f"missing §4.7 tool descriptors after load: {missing}"
