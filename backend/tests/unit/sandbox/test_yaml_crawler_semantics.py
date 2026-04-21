"""Per-§4.6 invariant tests for the crawler / JS / endpoint extraction YAMLs (ARG-013).

Sister suite to ``test_yaml_content_discovery_semantics.py`` — that file
pins the ARG-012 §4.5 contract; this file pins the ARG-013 §4.6 contract:

* Three **active crawlers** (``katana``, ``gospider``, ``hakrawler``) walk
  the application graph from a starting URL and emit endpoints. Risk
  profile: ``recon-active-tcp``, ``risk_level=low``.
* Four **passive endpoint miners** (``waybackurls``, ``gau``,
  ``linkfinder``, ``subjs``) reach for archive APIs / static JS bundles
  and never hit the in-scope target. Risk profile: ``recon-passive``,
  ``risk_level=passive``, phase ``recon``.
* One **secret-discovery** tool (``secretfinder``) scans JS bundles for
  hard-coded credentials. Risk profile: ``recon-passive``,
  ``risk_level=passive``, phase ``vuln_analysis`` (it produces a
  vulnerability finding, not a recon artefact).

Invariants pinned (any drift fails CI):

* The catalog contains exactly the eight §4.6 tool ids — no more, no less.
* Every tool ships ``risk_level`` ∈ {low, passive}, ``requires_approval=False``,
  and lives behind ``argus-kali-web:latest``.
* Per-phase split: 7 RECON + 1 VULN_ANALYSIS (secretfinder).
* ``network_policy.name`` resolves in the seeded registry. The three active
  crawlers use ``recon-active-tcp``; the five passive tools use
  ``recon-passive``.
* ``evidence_artifacts`` is non-empty and lives under ``/out``.
* ``cwe_hints`` includes 200 (Information Exposure — universal for §4.6
  endpoint discovery + secret leak hints) and the field is explicitly
  present in the raw YAML (not a Pydantic default).
* ``owasp_wstg`` is non-empty and matches the per-tool taxonomy.
* Parser-strategy split: 3 ``json_lines`` (katana / gospider / gau);
  5 ``text_lines`` (the rest).
* ``default_timeout_s`` ≥ 60 (active crawlers cap higher).
* ``cpu_limit`` / ``memory_limit`` / ``seccomp_profile`` are populated.
* ``command_template`` argv carries no shell metacharacters.
* ``description`` field includes the upstream author / source URL so the
  catalog stays self-documenting.

These tests parse the raw YAML directly (no signature verification) so
they stay collection-cheap and re-runnable without keys.
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


# §4.6 batch — hard-coded so a silent drop / addition breaks CI.
CRAWLER_TOOL_IDS: Final[tuple[str, ...]] = (
    "katana",
    "gospider",
    "hakrawler",
    "waybackurls",
    "gau",
    "linkfinder",
    "subjs",
    "secretfinder",
)


# ---------------------------------------------------------------------------
# Per-tool taxonomy maps. Pinned here so a future YAML edit can't silently
# flip a tool from one bucket to another.
# ---------------------------------------------------------------------------


PHASE_BY_TOOL: Final[dict[str, ScanPhase]] = {
    "katana": ScanPhase.RECON,
    "gospider": ScanPhase.RECON,
    "hakrawler": ScanPhase.RECON,
    "waybackurls": ScanPhase.RECON,
    "gau": ScanPhase.RECON,
    "linkfinder": ScanPhase.RECON,
    "subjs": ScanPhase.RECON,
    "secretfinder": ScanPhase.VULN_ANALYSIS,
}


RISK_BY_TOOL: Final[dict[str, RiskLevel]] = {
    "katana": RiskLevel.LOW,
    "gospider": RiskLevel.LOW,
    "hakrawler": RiskLevel.LOW,
    "waybackurls": RiskLevel.PASSIVE,
    "gau": RiskLevel.PASSIVE,
    "linkfinder": RiskLevel.PASSIVE,
    "subjs": RiskLevel.PASSIVE,
    "secretfinder": RiskLevel.PASSIVE,
}


NETWORK_POLICY_BY_TOOL: Final[dict[str, str]] = {
    "katana": "recon-active-tcp",
    "gospider": "recon-active-tcp",
    "hakrawler": "recon-active-tcp",
    "waybackurls": "recon-passive",
    "gau": "recon-passive",
    "linkfinder": "recon-passive",
    "subjs": "recon-passive",
    "secretfinder": "recon-passive",
}


PARSE_STRATEGY_BY_TOOL: Final[dict[str, ParseStrategy]] = {
    "katana": ParseStrategy.JSON_LINES,
    "gospider": ParseStrategy.JSON_LINES,
    "gau": ParseStrategy.JSON_LINES,
    "hakrawler": ParseStrategy.TEXT_LINES,
    "waybackurls": ParseStrategy.TEXT_LINES,
    "linkfinder": ParseStrategy.TEXT_LINES,
    "subjs": ParseStrategy.TEXT_LINES,
    "secretfinder": ParseStrategy.TEXT_LINES,
}


OWASP_WSTG_BY_TOOL: Final[dict[str, frozenset[str]]] = {
    # Endpoint discovery / map execution paths.
    "katana": frozenset({"WSTG-INFO-06", "WSTG-INFO-07"}),
    "gospider": frozenset({"WSTG-INFO-06", "WSTG-INFO-07"}),
    "hakrawler": frozenset({"WSTG-INFO-06", "WSTG-INFO-07"}),
    "waybackurls": frozenset({"WSTG-INFO-06", "WSTG-INFO-07"}),
    "gau": frozenset({"WSTG-INFO-06", "WSTG-INFO-07"}),
    # JS analysis (entry points + page content review).
    "linkfinder": frozenset({"WSTG-INFO-05", "WSTG-INFO-06"}),
    "subjs": frozenset({"WSTG-INFO-05", "WSTG-INFO-06"}),
    # Secret discovery (page content review + sensitive data exposure).
    "secretfinder": frozenset({"WSTG-INFO-05", "WSTG-CRYP-03"}),
}


# Per-tool minimum timeout. Active crawlers (katana / gospider /
# hakrawler) need at least 600 s on a real-world site; the passive tools
# only need 300 s because they only call out to archive APIs.
DEFAULT_TIMEOUT_S_BY_TOOL: Final[dict[str, int]] = {
    "katana": 600,
    "gospider": 600,
    "hakrawler": 600,
    "waybackurls": 300,
    "gau": 300,
    "linkfinder": 300,
    "subjs": 300,
    "secretfinder": 300,
}


# Shell metacharacters that must NOT appear in a YAML argv.
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


def test_inventory_contains_exactly_eight_tools() -> None:
    """The §4.6 batch is exactly eight tools — drift breaks alignment with
    Backlog/dev1_md §4.6 and the CRAWLER_TOOLS frozenset in
    ``test_tool_catalog_load.py``.
    """
    assert len(CRAWLER_TOOL_IDS) == 8
    assert len(set(CRAWLER_TOOL_IDS)) == 8


def test_per_tool_taxonomy_maps_cover_every_tool() -> None:
    """Each per-tool map covers exactly the §4.6 batch — no extras, no gaps."""
    expected = set(CRAWLER_TOOL_IDS)
    assert set(PHASE_BY_TOOL.keys()) == expected
    assert set(RISK_BY_TOOL.keys()) == expected
    assert set(NETWORK_POLICY_BY_TOOL.keys()) == expected
    assert set(PARSE_STRATEGY_BY_TOOL.keys()) == expected
    assert set(OWASP_WSTG_BY_TOOL.keys()) == expected
    assert set(DEFAULT_TIMEOUT_S_BY_TOOL.keys()) == expected


# ---------------------------------------------------------------------------
# Phase / risk / approval invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CRAWLER_TOOL_IDS)
def test_phase_matches_expected_split(catalog_dir: Path, tool_id: str) -> None:
    """7 RECON + secretfinder VULN_ANALYSIS — pinned per the cycle plan."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = PHASE_BY_TOOL[tool_id]
    assert descriptor.phase is expected, (
        f"{tool_id}: phase must be {expected.value}, got {descriptor.phase.value}"
    )


@pytest.mark.parametrize("tool_id", CRAWLER_TOOL_IDS)
def test_risk_level_matches_active_passive_split(
    catalog_dir: Path, tool_id: str
) -> None:
    """Active crawlers (katana/gospider/hakrawler) → LOW; the rest → PASSIVE."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = RISK_BY_TOOL[tool_id]
    assert descriptor.risk_level is expected, (
        f"{tool_id}: risk_level must be {expected.value}, "
        f"got {descriptor.risk_level.value}"
    )


@pytest.mark.parametrize("tool_id", CRAWLER_TOOL_IDS)
def test_no_tool_requires_approval(catalog_dir: Path, tool_id: str) -> None:
    """All §4.6 tools are pre-approved (low risk or passive)."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.requires_approval is False, (
        f"{tool_id}: requires_approval must be False for §4.6 tools"
    )


# ---------------------------------------------------------------------------
# Image namespace + Dockerfile existence
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CRAWLER_TOOL_IDS)
def test_image_is_argus_kali_web_latest(catalog_dir: Path, tool_id: str) -> None:
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.image == "argus-kali-web:latest", (
        f"{tool_id}: image must be argus-kali-web:latest, got {descriptor.image!r}"
    )


def test_argus_kali_web_dockerfile_stub_exists(images_dir: Path) -> None:
    """The image referenced by every §4.6 YAML must have a buildable stub."""
    dockerfile = images_dir / "argus-kali-web" / "Dockerfile"
    assert dockerfile.is_file(), (
        f"missing Dockerfile stub at {dockerfile} — every YAML referencing "
        "argus-kali-web:latest needs a corresponding image directory"
    )


# ---------------------------------------------------------------------------
# Network policy — name must resolve + match the per-tool split
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CRAWLER_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", CRAWLER_TOOL_IDS)
def test_network_policy_matches_active_passive_split(
    catalog_dir: Path, tool_id: str
) -> None:
    """Active crawlers → ``recon-active-tcp``; passive tools → ``recon-passive``."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = NETWORK_POLICY_BY_TOOL[tool_id]
    assert descriptor.network_policy.name == expected, (
        f"{tool_id}: expected network_policy {expected!r}, "
        f"got {descriptor.network_policy.name!r}"
    )


# ---------------------------------------------------------------------------
# Evidence + CWE/OWASP fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CRAWLER_TOOL_IDS)
def test_evidence_artifacts_non_empty(catalog_dir: Path, tool_id: str) -> None:
    """The evidence pipeline needs at least one artefact path per tool."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.evidence_artifacts, f"{tool_id}: must declare evidence_artifacts"
    for path in descriptor.evidence_artifacts:
        assert path.startswith("/out"), (
            f"{tool_id}: evidence path {path!r} must live under /out"
        )


@pytest.mark.parametrize("tool_id", CRAWLER_TOOL_IDS)
def test_cwe_hints_field_present_with_information_exposure(
    catalog_dir: Path, tool_id: str
) -> None:
    """CWE-200 (Information Exposure) is the universal CWE for §4.6 tools.

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
        "(Information Exposure) for §4.6 tools"
    )


@pytest.mark.parametrize("tool_id", CRAWLER_TOOL_IDS)
def test_owasp_wstg_matches_per_tool_taxonomy(catalog_dir: Path, tool_id: str) -> None:
    """OWASP-WSTG hint set matches the per-tool taxonomy from the cycle plan."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.owasp_wstg, (
        f"{tool_id}: owasp_wstg must be non-empty for §4.6 tools"
    )
    expected = OWASP_WSTG_BY_TOOL[tool_id]
    assert frozenset(descriptor.owasp_wstg) == expected, (
        f"{tool_id}: owasp_wstg drift; got {sorted(descriptor.owasp_wstg)}, "
        f"expected {sorted(expected)}"
    )


# ---------------------------------------------------------------------------
# Parser dispatch strategy split
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CRAWLER_TOOL_IDS)
def test_parse_strategy_matches_per_tool_split(catalog_dir: Path, tool_id: str) -> None:
    """3 JSON tools (katana / gospider / gau) → ``json_lines``;
    the other 5 → ``text_lines`` (parser ships in Cycle 3).
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = PARSE_STRATEGY_BY_TOOL[tool_id]
    assert descriptor.parse_strategy is expected, (
        f"{tool_id}: parse_strategy must be {expected.value}, "
        f"got {descriptor.parse_strategy.value!r}"
    )


# ---------------------------------------------------------------------------
# Resource limits + per-tool timeout floor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CRAWLER_TOOL_IDS)
def test_default_timeout_matches_per_tool_floor(
    catalog_dir: Path, tool_id: str
) -> None:
    """Active crawlers floor at 600 s; passive tools at 300 s."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = DEFAULT_TIMEOUT_S_BY_TOOL[tool_id]
    assert descriptor.default_timeout_s >= expected, (
        f"{tool_id}: default_timeout_s={descriptor.default_timeout_s}s "
        f"below floor of {expected}s"
    )


@pytest.mark.parametrize("tool_id", CRAWLER_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", CRAWLER_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", CRAWLER_TOOL_IDS)
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


# ---------------------------------------------------------------------------
# Description must include author / source URL
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CRAWLER_TOOL_IDS)
def test_description_carries_author_and_source(catalog_dir: Path, tool_id: str) -> None:
    """Every §4.6 YAML's ``description`` references the upstream project URL.

    The signed catalog stays self-documenting: anyone diffing the YAML
    can follow the author / source URL to verify provenance, version,
    and licence without leaving the repo.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.description, f"{tool_id}: empty description"
    assert "github.com" in descriptor.description, (
        f"{tool_id}: description must include the upstream github.com URL; "
        f"got: {descriptor.description!r}"
    )
    assert "§4.6" in descriptor.description, (
        f"{tool_id}: description must reference Backlog/dev1_md §4.6; "
        f"got: {descriptor.description!r}"
    )
