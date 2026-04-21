"""Per-§4.7 invariant tests for the CMS / platform scanner YAMLs (ARG-014).

Sister suite to ``test_yaml_crawler_semantics.py`` (ARG-013) — that file
pins the ARG-013 §4.6 contract; this file pins the ARG-014 §4.7 contract:

* Two **flagship CMS scanners** with parseable JSON output:
  ``wpscan`` (WordPress) and ``droopescan`` (Drupal/Joomla/SilverStripe).
* Three **text-only CMS scanners**: ``joomscan`` (OWASP Joomla),
  ``cmsmap`` (multi-CMS), ``magescan`` (Magento). Their full JSON parsing
  is deferred to Cycle 3.
* Three **nuclei template wrappers**: ``nextjs_check``,
  ``spring_boot_actuator``, ``jenkins_enum`` — they wrap nuclei tag sets
  for platform-specific exposure checks; parsers ship in ARG-015.

Invariants pinned (any drift fails CI):

* The catalog contains exactly the eight §4.7 tool ids — no more, no less.
* Every tool ships ``risk_level=low``, ``requires_approval=False``,
  ``category=web_va``, ``phase=vuln_analysis``, and lives behind
  ``argus-kali-web:latest``.
* ``network_policy.name`` resolves in the seeded registry; every §4.7
  tool uses ``recon-active-tcp`` (CMS scanning is by definition active).
* ``evidence_artifacts`` are ``/out``-relative when present; magescan is
  the only exception (text on stdout).
* ``cwe_hints`` includes both 200 (Information Exposure) and 1395
  (Dependency on Vulnerable Third-Party Component) for the CMS scanners
  — the §4.7 universal CWE pair.
* ``owasp_wstg`` is non-empty.
* Parser-strategy split: 2 ``json_object`` (wpscan / droopescan), 3
  ``text_lines`` (joomscan / cmsmap / magescan), 3 ``nuclei_jsonl`` (the
  three nuclei wrappers).
* ``default_timeout_s`` ≥ 600 s — CMS scanners legitimately enumerate
  thousands of plugins / themes against real targets.
* ``cpu_limit`` / ``memory_limit`` / ``seccomp_profile`` are populated.
* ``command_template`` argv carries no shell metacharacters; first token
  is the real binary (never a shell).
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
from src.sandbox.adapter_base import ParseStrategy, ToolCategory, ToolDescriptor
from src.sandbox.network_policies import NETWORK_POLICY_NAMES


# §4.7 batch — hard-coded so a silent drop / addition breaks CI.
CMS_TOOL_IDS: Final[tuple[str, ...]] = (
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
# Per-tool taxonomy maps. Pinned so a future YAML edit cannot silently
# flip a tool from one bucket to another.
# ---------------------------------------------------------------------------


PARSE_STRATEGY_BY_TOOL: Final[dict[str, ParseStrategy]] = {
    "wpscan": ParseStrategy.JSON_OBJECT,
    "droopescan": ParseStrategy.JSON_OBJECT,
    "joomscan": ParseStrategy.TEXT_LINES,
    "cmsmap": ParseStrategy.TEXT_LINES,
    "magescan": ParseStrategy.TEXT_LINES,
    "nextjs_check": ParseStrategy.NUCLEI_JSONL,
    "spring_boot_actuator": ParseStrategy.NUCLEI_JSONL,
    "jenkins_enum": ParseStrategy.NUCLEI_JSONL,
}


# Tools that emit a real artefact file (the rest stream JSON / text on
# stdout). magescan deliberately has no artefact — its JSON output lands
# on stdout and is parsed text-only in Cycle 2.
TOOLS_WITH_EVIDENCE_ARTIFACTS: Final[frozenset[str]] = frozenset(
    {
        "wpscan",
        "joomscan",
        "droopescan",
        "cmsmap",
        "nextjs_check",
        "spring_boot_actuator",
        "jenkins_enum",
    }
)


# Per-tool minimum timeout. CMS scanners legitimately walk thousands of
# plugin / theme paths; nuclei wrappers cap lower.
DEFAULT_TIMEOUT_S_BY_TOOL: Final[dict[str, int]] = {
    "wpscan": 1800,
    "joomscan": 1200,
    "droopescan": 1200,
    "cmsmap": 1200,
    "magescan": 900,
    "nextjs_check": 600,
    "spring_boot_actuator": 600,
    "jenkins_enum": 600,
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


@pytest.fixture(scope="module")
def catalog_dir() -> Path:
    catalog = _catalog_dir()
    assert catalog.is_dir(), f"expected catalog dir at {catalog}"
    return catalog


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
    """The §4.7 batch is exactly eight tools — drift breaks alignment with
    Backlog/dev1_md §4.7 and the CMS_TOOLS frozenset in
    ``test_tool_catalog_load.py``.
    """
    assert len(CMS_TOOL_IDS) == 8
    assert len(set(CMS_TOOL_IDS)) == 8


def test_per_tool_taxonomy_maps_cover_every_tool() -> None:
    """Each per-tool map covers exactly the §4.7 batch — no extras, no gaps."""
    expected = set(CMS_TOOL_IDS)
    assert set(PARSE_STRATEGY_BY_TOOL.keys()) == expected
    assert set(DEFAULT_TIMEOUT_S_BY_TOOL.keys()) == expected
    assert TOOLS_WITH_EVIDENCE_ARTIFACTS.issubset(expected)


# ---------------------------------------------------------------------------
# Phase / risk / approval invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
def test_category_is_web_va(catalog_dir: Path, tool_id: str) -> None:
    """All §4.7 tools belong to the web_va category."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.category is ToolCategory.WEB_VA


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
def test_phase_is_vuln_analysis(catalog_dir: Path, tool_id: str) -> None:
    """All §4.7 tools run in the vuln_analysis phase."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.phase is ScanPhase.VULN_ANALYSIS


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
def test_risk_level_is_low(catalog_dir: Path, tool_id: str) -> None:
    """All §4.7 tools are non-destructive enumeration / detection (LOW risk)."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.risk_level is RiskLevel.LOW


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
def test_no_tool_requires_approval(catalog_dir: Path, tool_id: str) -> None:
    """All §4.7 tools are pre-approved (low risk)."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.requires_approval is False


# ---------------------------------------------------------------------------
# Image namespace
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
def test_image_is_argus_kali_web_latest(catalog_dir: Path, tool_id: str) -> None:
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.image == "argus-kali-web:latest", (
        f"{tool_id}: image must be argus-kali-web:latest, got {descriptor.image!r}"
    )


# ---------------------------------------------------------------------------
# Network policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
def test_network_policy_is_recon_active_tcp(catalog_dir: Path, tool_id: str) -> None:
    """All §4.7 tools probe live HTTP(S); they all use ``recon-active-tcp``."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.network_policy.name == "recon-active-tcp"


# ---------------------------------------------------------------------------
# Evidence + CWE/OWASP fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
def test_evidence_artifacts_under_out_when_present(
    catalog_dir: Path, tool_id: str
) -> None:
    """Whatever evidence path is declared lives under ``/out``."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    if tool_id in TOOLS_WITH_EVIDENCE_ARTIFACTS:
        assert descriptor.evidence_artifacts, (
            f"{tool_id}: must declare at least one evidence artefact"
        )
    for path in descriptor.evidence_artifacts:
        assert path.startswith("/out"), (
            f"{tool_id}: evidence path {path!r} must live under /out"
        )


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
def test_cwe_hints_include_information_exposure(
    catalog_dir: Path, tool_id: str
) -> None:
    """CWE-200 (Information Exposure) is the universal CWE for §4.7 tools.

    Re-reads the raw YAML to assert the key is *explicitly* present
    (Pydantic would default to ``[]`` for a missing key, hiding the gap).
    """
    payload = yaml.safe_load((catalog_dir / f"{tool_id}.yaml").read_bytes())
    assert "cwe_hints" in payload, f"{tool_id}.yaml missing the cwe_hints key"
    assert isinstance(payload["cwe_hints"], list), (
        f"{tool_id}.yaml: cwe_hints must be a list"
    )
    assert 200 in payload["cwe_hints"], (
        f"{tool_id}.yaml: cwe_hints must include CWE-200 (Information Exposure)"
    )


@pytest.mark.parametrize(
    "tool_id",
    [t for t in CMS_TOOL_IDS if t not in {"spring_boot_actuator"}],
)
def test_cms_cwe_includes_vulnerable_component(catalog_dir: Path, tool_id: str) -> None:
    """Every CMS / Jenkins scanner ships CWE-1395 hint (vulnerable third-party).

    Spring Boot Actuator is exempted because its primary failure mode is
    misconfiguration (CWE-16), not a vulnerable upstream package. Next.js
    exposure check (nextjs_check.yaml) keeps CWE-1395 — CVE-2025-29927 is a
    framework vuln.
    """
    payload = yaml.safe_load((catalog_dir / f"{tool_id}.yaml").read_bytes())
    assert 1395 in payload["cwe_hints"], (
        f"{tool_id}.yaml: cwe_hints must include CWE-1395 "
        "(Dependency on Vulnerable Third-Party Component) for §4.7 CMS scanners"
    )


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
def test_owasp_wstg_non_empty(catalog_dir: Path, tool_id: str) -> None:
    """Every §4.7 tool ships an OWASP-WSTG taxonomy hint."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.owasp_wstg, (
        f"{tool_id}: owasp_wstg must be non-empty for §4.7 tools"
    )


# ---------------------------------------------------------------------------
# Parser dispatch strategy split
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
def test_parse_strategy_matches_per_tool_split(catalog_dir: Path, tool_id: str) -> None:
    """2 ``json_object`` + 3 ``text_lines`` + 3 ``nuclei_jsonl`` — pinned."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = PARSE_STRATEGY_BY_TOOL[tool_id]
    assert descriptor.parse_strategy is expected, (
        f"{tool_id}: parse_strategy must be {expected.value}, "
        f"got {descriptor.parse_strategy.value!r}"
    )


# ---------------------------------------------------------------------------
# Resource limits + per-tool timeout floor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
def test_default_timeout_matches_per_tool_floor(
    catalog_dir: Path, tool_id: str
) -> None:
    """Every §4.7 tool floors at the per-tool minimum from the cycle plan."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = DEFAULT_TIMEOUT_S_BY_TOOL[tool_id]
    assert descriptor.default_timeout_s >= expected, (
        f"{tool_id}: default_timeout_s={descriptor.default_timeout_s}s "
        f"below floor of {expected}s"
    )


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
def test_command_template_first_token_matches_expected_binary(
    catalog_dir: Path, tool_id: str
) -> None:
    """Pin the binary the YAML invokes per tool — drift breaks the image contract."""
    expected_first: Final[dict[str, str]] = {
        "wpscan": "wpscan",
        "joomscan": "joomscan",
        "droopescan": "droopescan",
        "cmsmap": "cmsmap",
        "magescan": "magescan",
        "nextjs_check": "nuclei",
        "spring_boot_actuator": "nuclei",
        "jenkins_enum": "nuclei",
    }
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.command_template[0] == expected_first[tool_id], (
        f"{tool_id}: expected binary {expected_first[tool_id]!r}, "
        f"got {descriptor.command_template[0]!r}"
    )


# ---------------------------------------------------------------------------
# Description must reference §4.7 + author / source URL
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", CMS_TOOL_IDS)
def test_description_references_section_47(catalog_dir: Path, tool_id: str) -> None:
    """Every §4.7 description tags the backlog section so docs stay traceable."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert "§4.7" in descriptor.description, (
        f"{tool_id}: description must reference Backlog/dev1_md §4.7; "
        f"got: {descriptor.description!r}"
    )


@pytest.mark.parametrize(
    "tool_id",
    # nuclei wrappers don't bundle their own author URL — they reference
    # the underlying nuclei templates handled by ARG-015.
    ["wpscan", "joomscan", "droopescan", "cmsmap", "magescan"],
)
def test_description_references_upstream_author(
    catalog_dir: Path, tool_id: str
) -> None:
    """Each non-nuclei §4.7 description carries the upstream author / source URL."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert "https://" in descriptor.description, (
        f"{tool_id}: description must include upstream author / source URL; "
        f"got: {descriptor.description!r}"
    )
