"""Per-§4.5 invariant tests for the content-discovery YAMLs (ARG-012).

Sister suite to ``test_yaml_http_fingerprint_semantics.py`` — that file pins
the ARG-011 §4.4 contract (fingerprinting, all passive recon); this file
pins the ARG-012 §4.5 contract (content / path / parameter / vhost
discovery, mostly active TCP).

The §4.5 batch is heterogeneous on purpose:

* ``ffuf_vhost``                        — recon (vhost enumeration is
                                          recon proper, not vuln analysis).
* ``paramspider``                       — recon, *passive* (Wayback only).
* All eight remaining tools             — vuln_analysis, low-risk active
                                          probing of in-scope targets.

…so we cannot blanket-assert ``phase=recon`` like §4.4 does. Each invariant
below documents its own per-tool exceptions where needed.

Invariants pinned (any drift fails CI):

* The catalog contains exactly the ten §4.5 tool ids — no more, no less.
* Every tool ships ``risk_level`` ∈ {low, passive}, ``requires_approval=False``,
  and lives behind ``argus-kali-web:latest`` whose Dockerfile stub exists.
* Per-phase split: ``ffuf_vhost`` + ``paramspider`` are RECON, the other
  eight are VULN_ANALYSIS. No drift.
* ``network_policy.name`` resolves in the seeded registry. ``paramspider``
  uses ``recon-passive``; the other nine use ``recon-active-tcp``.
* ``evidence_artifacts`` is non-empty and lives under ``/out``.
* ``cwe_hints`` includes 200 (Information Exposure — universal) and the
  field is explicitly present in the raw YAML (not a Pydantic default).
* ``owasp_wstg`` is non-empty and matches the per-tool taxonomy from the
  ARG-012 cycle plan (CONFIG-04/06 for path discovery, INPV-04 for
  parameter discovery, INFO-04 for vhost discovery).
* Parser-strategy split: ffuf-family + JSON-emitting tools declare
  ``json_object``; ``gobuster_dir`` + ``paramspider`` declare ``text_lines``.
* ``default_timeout_s ≥ 60`` (these are slow brute-force scanners — a
  30-second timeout would mass-fail every legitimate run).
* ``cpu_limit`` / ``memory_limit`` / ``seccomp_profile`` are populated.
* ``command_template`` argv carries no shell metacharacters.

These tests parse the raw YAML directly (no signature verification) so they
stay collection-cheap and re-runnable without keys.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest
import yaml

from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel
from src.sandbox.adapter_base import ParseStrategy, ToolDescriptor
from src.sandbox.network_policies import NETWORK_POLICY_NAMES


# §4.5 batch — hard-coded so a silent drop / addition breaks CI.
CONTENT_DISCOVERY_TOOL_IDS: Final[tuple[str, ...]] = (
    "ffuf_dir",
    "ffuf_vhost",
    "ffuf_param",
    "feroxbuster",
    "gobuster_dir",
    "dirsearch",
    "kiterunner",
    "arjun",
    "paramspider",
    "wfuzz",
)


# ---------------------------------------------------------------------------
# Per-tool taxonomy maps. Pinned here so a future YAML edit can't silently
# flip a tool from one bucket to another.
# ---------------------------------------------------------------------------


PHASE_BY_TOOL: Final[dict[str, ScanPhase]] = {
    "ffuf_dir": ScanPhase.VULN_ANALYSIS,
    "ffuf_vhost": ScanPhase.RECON,
    "ffuf_param": ScanPhase.VULN_ANALYSIS,
    "feroxbuster": ScanPhase.VULN_ANALYSIS,
    "gobuster_dir": ScanPhase.VULN_ANALYSIS,
    "dirsearch": ScanPhase.VULN_ANALYSIS,
    "kiterunner": ScanPhase.VULN_ANALYSIS,
    "arjun": ScanPhase.VULN_ANALYSIS,
    "paramspider": ScanPhase.RECON,
    "wfuzz": ScanPhase.VULN_ANALYSIS,
}


RISK_BY_TOOL: Final[dict[str, RiskLevel]] = {
    "ffuf_dir": RiskLevel.LOW,
    "ffuf_vhost": RiskLevel.LOW,
    "ffuf_param": RiskLevel.LOW,
    "feroxbuster": RiskLevel.LOW,
    "gobuster_dir": RiskLevel.LOW,
    "dirsearch": RiskLevel.LOW,
    "kiterunner": RiskLevel.LOW,
    "arjun": RiskLevel.LOW,
    "paramspider": RiskLevel.PASSIVE,
    "wfuzz": RiskLevel.LOW,
}


NETWORK_POLICY_BY_TOOL: Final[dict[str, str]] = {
    "ffuf_dir": "recon-active-tcp",
    "ffuf_vhost": "recon-active-tcp",
    "ffuf_param": "recon-active-tcp",
    "feroxbuster": "recon-active-tcp",
    "gobuster_dir": "recon-active-tcp",
    "dirsearch": "recon-active-tcp",
    "kiterunner": "recon-active-tcp",
    "arjun": "recon-active-tcp",
    "paramspider": "recon-passive",
    "wfuzz": "recon-active-tcp",
}


PARSE_STRATEGY_BY_TOOL: Final[dict[str, ParseStrategy]] = {
    "ffuf_dir": ParseStrategy.JSON_OBJECT,
    "ffuf_vhost": ParseStrategy.JSON_OBJECT,
    "ffuf_param": ParseStrategy.JSON_OBJECT,
    "feroxbuster": ParseStrategy.JSON_OBJECT,
    "gobuster_dir": ParseStrategy.TEXT_LINES,
    "dirsearch": ParseStrategy.JSON_OBJECT,
    "kiterunner": ParseStrategy.JSON_OBJECT,
    "arjun": ParseStrategy.JSON_OBJECT,
    "paramspider": ParseStrategy.TEXT_LINES,
    "wfuzz": ParseStrategy.JSON_OBJECT,
}


OWASP_WSTG_BY_TOOL: Final[dict[str, frozenset[str]]] = {
    "ffuf_dir": frozenset({"WSTG-CONFIG-04", "WSTG-CONFIG-06"}),
    "ffuf_vhost": frozenset({"WSTG-INFO-04"}),
    "ffuf_param": frozenset({"WSTG-INPV-04"}),
    "feroxbuster": frozenset({"WSTG-CONFIG-04", "WSTG-CONFIG-06"}),
    "gobuster_dir": frozenset({"WSTG-CONFIG-04", "WSTG-CONFIG-06"}),
    "dirsearch": frozenset({"WSTG-CONFIG-04", "WSTG-CONFIG-06"}),
    "kiterunner": frozenset({"WSTG-CONFIG-04", "WSTG-CONFIG-06"}),
    "arjun": frozenset({"WSTG-INPV-04"}),
    "paramspider": frozenset({"WSTG-INPV-04"}),
    "wfuzz": frozenset({"WSTG-INPV-04"}),
}


# Shell metacharacters that must NOT appear in a YAML argv. Mirrors the
# §4.4 audit — see test_yaml_http_fingerprint_semantics.py for rationale.
SHELL_METACHARS: Final[tuple[str, ...]] = (
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _catalog_dir() -> Path:
    """Locate ``backend/config/tools/`` from this test file's path.

    ``parents`` indices for ``backend/tests/unit/sandbox/<file>.py``:
    ``[0]=sandbox, [1]=unit, [2]=tests, [3]=backend``.
    """
    here = Path(__file__).resolve()
    backend_dir = here.parents[3]
    return backend_dir / "config" / "tools"


def _images_dir() -> Path:
    """Locate ``sandbox/images/`` from this test file's path."""
    here = Path(__file__).resolve()
    repo_root = here.parents[4]
    return repo_root / "sandbox" / "images"


@pytest.fixture(scope="module")
def catalog_dir() -> Path:
    catalog = _catalog_dir()
    assert catalog.is_dir(), f"expected catalog dir at {catalog}"
    return catalog


@pytest.fixture(scope="module")
def images_dir() -> Path:
    images = _images_dir()
    assert images.is_dir(), f"expected sandbox images dir at {images}"
    return images


def _load_descriptor(catalog_dir: Path, tool_id: str) -> ToolDescriptor:
    payload = yaml.safe_load((catalog_dir / f"{tool_id}.yaml").read_bytes())
    assert isinstance(payload, dict), (
        f"{tool_id}.yaml must be a YAML mapping at the top level"
    )
    return ToolDescriptor(**payload)


# ---------------------------------------------------------------------------
# Inventory completeness
# ---------------------------------------------------------------------------


def test_inventory_contains_exactly_ten_tools() -> None:
    """The §4.5 batch is exactly ten tools — drift breaks alignment with
    Backlog/dev1_md §4.5 and the CONTENT_DISCOVERY_TOOLS frozenset in
    ``test_tool_catalog_load.py``.
    """
    assert len(CONTENT_DISCOVERY_TOOL_IDS) == 10
    assert len(set(CONTENT_DISCOVERY_TOOL_IDS)) == 10


def test_per_tool_taxonomy_maps_cover_every_tool() -> None:
    """Each per-tool map covers exactly the §4.5 batch — no extras, no gaps."""
    expected = set(CONTENT_DISCOVERY_TOOL_IDS)
    assert set(PHASE_BY_TOOL.keys()) == expected
    assert set(RISK_BY_TOOL.keys()) == expected
    assert set(NETWORK_POLICY_BY_TOOL.keys()) == expected
    assert set(PARSE_STRATEGY_BY_TOOL.keys()) == expected
    assert set(OWASP_WSTG_BY_TOOL.keys()) == expected


# ---------------------------------------------------------------------------
# Phase / risk / approval invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CONTENT_DISCOVERY_TOOL_IDS)
def test_phase_matches_expected_split(catalog_dir: Path, tool_id: str) -> None:
    """ffuf_vhost + paramspider are RECON; the other eight are VULN_ANALYSIS."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = PHASE_BY_TOOL[tool_id]
    assert descriptor.phase is expected, (
        f"{tool_id}: phase must be {expected.value}, got {descriptor.phase.value}"
    )


@pytest.mark.parametrize("tool_id", CONTENT_DISCOVERY_TOOL_IDS)
def test_risk_level_is_low_except_paramspider_passive(
    catalog_dir: Path, tool_id: str
) -> None:
    """Active probing tools are LOW; paramspider (Wayback only) is PASSIVE."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = RISK_BY_TOOL[tool_id]
    assert descriptor.risk_level is expected, (
        f"{tool_id}: risk_level must be {expected.value}, "
        f"got {descriptor.risk_level.value}"
    )


@pytest.mark.parametrize("tool_id", CONTENT_DISCOVERY_TOOL_IDS)
def test_no_tool_requires_approval(catalog_dir: Path, tool_id: str) -> None:
    """All §4.5 tools are pre-approved (low risk or passive)."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.requires_approval is False, (
        f"{tool_id}: requires_approval must be False for §4.5 tools"
    )


# ---------------------------------------------------------------------------
# Image namespace + Dockerfile existence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CONTENT_DISCOVERY_TOOL_IDS)
def test_image_is_argus_kali_web_latest(catalog_dir: Path, tool_id: str) -> None:
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.image == "argus-kali-web:latest", (
        f"{tool_id}: image must be argus-kali-web:latest, got {descriptor.image!r}"
    )


def test_argus_kali_web_dockerfile_stub_exists(images_dir: Path) -> None:
    """The image referenced by every §4.5 YAML must have a buildable stub.

    The actual tool installation graph is provided by the cycle 3
    Dockerfile; for now we only require the file to exist so the CI
    build pipeline can ``docker build`` the placeholder image without a
    "no such file" failure.
    """
    dockerfile = images_dir / "argus-kali-web" / "Dockerfile"
    assert dockerfile.is_file(), (
        f"missing Dockerfile stub at {dockerfile} — every YAML referencing "
        "argus-kali-web:latest needs a corresponding image directory"
    )


# ---------------------------------------------------------------------------
# Network policy — name must resolve + match the per-tool split
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CONTENT_DISCOVERY_TOOL_IDS)
def test_network_policy_name_is_a_known_template(
    catalog_dir: Path, tool_id: str
) -> None:
    """A YAML cannot reference a NetworkPolicy template that doesn't exist."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.network_policy.name in NETWORK_POLICY_NAMES, (
        f"{tool_id}: references unknown network policy "
        f"{descriptor.network_policy.name!r}; "
        f"known: {sorted(NETWORK_POLICY_NAMES)}"
    )


@pytest.mark.parametrize("tool_id", CONTENT_DISCOVERY_TOOL_IDS)
def test_network_policy_matches_active_passive_split(
    catalog_dir: Path, tool_id: str
) -> None:
    """paramspider sits behind ``recon-passive`` (Wayback only); every other
    §4.5 tool probes the in-scope target via ``recon-active-tcp``.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = NETWORK_POLICY_BY_TOOL[tool_id]
    assert descriptor.network_policy.name == expected, (
        f"{tool_id}: expected network_policy {expected!r}, "
        f"got {descriptor.network_policy.name!r}"
    )


# ---------------------------------------------------------------------------
# Evidence + CWE/OWASP fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CONTENT_DISCOVERY_TOOL_IDS)
def test_evidence_artifacts_non_empty(catalog_dir: Path, tool_id: str) -> None:
    """The evidence pipeline needs at least one artefact path per tool."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.evidence_artifacts, f"{tool_id}: must declare evidence_artifacts"
    for path in descriptor.evidence_artifacts:
        assert path.startswith("/out"), (
            f"{tool_id}: evidence path {path!r} must live under /out"
        )


@pytest.mark.parametrize("tool_id", CONTENT_DISCOVERY_TOOL_IDS)
def test_cwe_hints_field_present_with_information_exposure(
    catalog_dir: Path, tool_id: str
) -> None:
    """CWE-200 (Information Exposure) is the universal CWE for §4.5 tools.

    Re-reads the raw YAML to assert the key is *explicitly* present
    (Pydantic would default to ``[]`` for a missing key, hiding the gap).
    """
    payload = yaml.safe_load((catalog_dir / f"{tool_id}.yaml").read_bytes())
    assert "cwe_hints" in payload, f"{tool_id}.yaml missing the cwe_hints key"
    assert isinstance(payload["cwe_hints"], list), (
        f"{tool_id}.yaml: cwe_hints must be a list"
    )
    assert 200 in payload["cwe_hints"], (
        f"{tool_id}.yaml: cwe_hints must include CWE-200 "
        "(Information Exposure) for §4.5 tools"
    )


@pytest.mark.parametrize("tool_id", CONTENT_DISCOVERY_TOOL_IDS)
def test_owasp_wstg_matches_per_tool_taxonomy(catalog_dir: Path, tool_id: str) -> None:
    """OWASP-WSTG hint set matches the per-tool taxonomy from the cycle plan."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.owasp_wstg, (
        f"{tool_id}: owasp_wstg must be non-empty for §4.5 tools"
    )
    expected = OWASP_WSTG_BY_TOOL[tool_id]
    assert frozenset(descriptor.owasp_wstg) == expected, (
        f"{tool_id}: owasp_wstg drift; got {sorted(descriptor.owasp_wstg)}, "
        f"expected {sorted(expected)}"
    )


# ---------------------------------------------------------------------------
# Parser dispatch strategy split
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CONTENT_DISCOVERY_TOOL_IDS)
def test_parse_strategy_matches_per_tool_split(catalog_dir: Path, tool_id: str) -> None:
    """Eight JSON tools => json_object; gobuster_dir + paramspider => text_lines."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = PARSE_STRATEGY_BY_TOOL[tool_id]
    assert descriptor.parse_strategy is expected, (
        f"{tool_id}: parse_strategy must be {expected.value}, "
        f"got {descriptor.parse_strategy.value!r}"
    )


# ---------------------------------------------------------------------------
# Resource limits + timeout floor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CONTENT_DISCOVERY_TOOL_IDS)
def test_default_timeout_at_least_60s(catalog_dir: Path, tool_id: str) -> None:
    """Below 60s the brute-force scanners can't even cold-start a wordlist."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.default_timeout_s >= 60, (
        f"{tool_id}: default_timeout_s={descriptor.default_timeout_s}s too low"
    )


@pytest.mark.parametrize("tool_id", CONTENT_DISCOVERY_TOOL_IDS)
def test_cpu_and_memory_limits_set(catalog_dir: Path, tool_id: str) -> None:
    """``cpu_limit`` / ``memory_limit`` / ``seccomp_profile`` are populated."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.cpu_limit, f"{tool_id}: empty cpu_limit"
    assert descriptor.memory_limit, f"{tool_id}: empty memory_limit"
    assert descriptor.seccomp_profile == "runtime/default", (
        f"{tool_id}: must use seccomp_profile=runtime/default, "
        f"got {descriptor.seccomp_profile!r}"
    )


# ---------------------------------------------------------------------------
# Argv shell-metachar audit (defence-in-depth on top of templating)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CONTENT_DISCOVERY_TOOL_IDS)
def test_command_template_has_no_shell_metacharacters(
    catalog_dir: Path, tool_id: str
) -> None:
    """No argv token may contain shell metacharacters.

    Defence-in-depth on top of the templating allow-list: an author who
    inlined a ``"sh -c ..."`` form would slip past the placeholder check
    (no ``{...}`` in the string) but produce a shell-injectable argv
    element here. Pinning the raw token charset closes that loophole at
    YAML-author time.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    offenders: list[tuple[str, str]] = []
    for token in descriptor.command_template:
        for meta in SHELL_METACHARS:
            if meta in token:
                offenders.append((token, meta))
    assert not offenders, (
        f"{tool_id}: command_template contains shell metacharacters: {offenders}"
    )


@pytest.mark.parametrize("tool_id", CONTENT_DISCOVERY_TOOL_IDS)
def test_command_template_first_token_is_real_binary_name(
    catalog_dir: Path, tool_id: str
) -> None:
    """First argv token is the binary name — no leading ``sh``, ``bash``,
    ``cmd``, or path-traversal prefix.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    first = descriptor.command_template[0]
    forbidden_first = {"sh", "bash", "cmd", "powershell", "/bin/sh", "/bin/bash"}
    assert first not in forbidden_first, (
        f"{tool_id}: first argv token {first!r} would launch a shell"
    )
    assert ".." not in first, (
        f"{tool_id}: first argv token {first!r} contains path traversal"
    )
