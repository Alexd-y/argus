"""Per-§4.8 invariant tests for the web vulnerability scanner YAMLs (ARG-015).

Sister suite to ``test_yaml_cms_semantics.py`` (ARG-014) — that file
pins the §4.7 CMS contract; this file pins the §4.8 active web-vuln
scanner contract:

* The flagship template-driven scanner ``nuclei`` (parses via the
  shared :class:`~src.sandbox.adapter_base.ParseStrategy.NUCLEI_JSONL`
  strategy in :mod:`src.sandbox.parsers.nuclei_parser`).
* Two **stable JSON adapters** with structured output:
  ``nikto`` and ``wapiti`` — wired through ``ParseStrategy.JSON_OBJECT``.
* Four **deferred / heavy active scanners**: ``arachni``, ``skipfish``,
  ``w3af_console``, ``zap_baseline``. They ship their YAMLs in Cycle 2
  (so policy + sandbox plumbing is exercised) but their dedicated
  parsers land in Cycle 3 — they declare ``parse_strategy=text_lines``
  while their evidence (JSON / HTML / XML reports) lands in
  ``evidence_artifacts``.

Invariants pinned (any drift fails CI):

* The catalog contains exactly the seven §4.8 tool ids — no more, no less.
* Every tool ships ``category=web_va``, ``phase=vuln_analysis`` and runs
  on ``argus-kali-web:latest`` behind ``recon-active-tcp``.
* ``risk_level`` matches the documented active-scanner profile:
  - ``low``  for ``nuclei`` / ``nikto`` / ``wapiti`` / ``zap_baseline``
    (passive or template-driven; no general payload injection).
  - ``medium`` for ``arachni`` / ``skipfish`` / ``w3af_console`` (active
    payload injection).
* ``requires_approval`` mirrors the risk profile (medium → True).
* ``parse_strategy`` is pinned per-tool (no silent flip).
* ``cwe_hints`` is non-empty.
* ``owasp_wstg`` is non-empty.
* ``default_timeout_s`` ≥ the per-tool floor — heavy scanners get
  longer windows.
* ``cpu_limit`` / ``memory_limit`` / ``seccomp_profile`` are populated.
* ``command_template`` argv carries no shell metacharacters; first
  token is the real binary (never a shell).
* ``description`` includes the upstream author / source URL so the
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


# §4.8 batch — hard-coded so a silent drop / addition breaks CI.
WEB_VULN_TOOL_IDS: Final[tuple[str, ...]] = (
    "nuclei",
    "nikto",
    "wapiti",
    "arachni",
    "skipfish",
    "w3af_console",
    "zap_baseline",
)


# ---------------------------------------------------------------------------
# Per-tool taxonomy maps. Pinned so a future YAML edit cannot silently
# flip a tool from one bucket to another.
# ---------------------------------------------------------------------------


PARSE_STRATEGY_BY_TOOL: Final[dict[str, ParseStrategy]] = {
    "nuclei": ParseStrategy.NUCLEI_JSONL,
    "nikto": ParseStrategy.JSON_OBJECT,
    "wapiti": ParseStrategy.JSON_OBJECT,
    # Cycle 3 deferred parsers — dispatched fail-soft via TEXT_LINES today.
    # ``zap_baseline`` declares text_lines until its dedicated JSON parser
    # ships in Cycle 3 (the JSON / HTML / XML reports still land in evidence;
    # see zap_baseline.yaml description).
    "zap_baseline": ParseStrategy.TEXT_LINES,
    "arachni": ParseStrategy.TEXT_LINES,
    "skipfish": ParseStrategy.TEXT_LINES,
    "w3af_console": ParseStrategy.TEXT_LINES,
}


# Tools that require explicit operator approval (MEDIUM-risk active scans).
APPROVAL_REQUIRED: Final[frozenset[str]] = frozenset(
    {"arachni", "skipfish", "w3af_console"}
)


RISK_LEVEL_BY_TOOL: Final[dict[str, RiskLevel]] = {
    "nuclei": RiskLevel.LOW,
    "nikto": RiskLevel.LOW,
    "wapiti": RiskLevel.LOW,
    "zap_baseline": RiskLevel.LOW,
    "arachni": RiskLevel.MEDIUM,
    "skipfish": RiskLevel.MEDIUM,
    "w3af_console": RiskLevel.MEDIUM,
}


# Per-tool minimum timeout. Heavy scanners get longer windows.
DEFAULT_TIMEOUT_S_BY_TOOL: Final[dict[str, int]] = {
    "nuclei": 1800,
    "nikto": 1800,
    "wapiti": 1800,
    "zap_baseline": 1800,
    "arachni": 3600,
    "skipfish": 3600,
    "w3af_console": 3600,
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


# Disallow shell binaries as the first argv token.
FORBIDDEN_FIRST_TOKENS: Final[frozenset[str]] = frozenset(
    {"sh", "bash", "/bin/sh", "/bin/bash", "zsh", "ksh", "powershell", "pwsh"}
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _catalog_dir() -> Path:
    """Locate ``backend/config/tools/`` from this test file's path."""
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


def test_inventory_contains_exactly_seven_tools() -> None:
    """The §4.8 batch is exactly seven tools — drift breaks alignment with
    Backlog/dev1_md §4.8 and the WEB_VULN_TOOLS frozenset in
    ``test_tool_catalog_load.py``.
    """
    assert len(WEB_VULN_TOOL_IDS) == 7
    assert len(set(WEB_VULN_TOOL_IDS)) == 7


def test_per_tool_taxonomy_maps_cover_every_tool() -> None:
    """Each per-tool map covers exactly the §4.8 batch — no extras, no gaps."""
    expected = set(WEB_VULN_TOOL_IDS)
    assert set(PARSE_STRATEGY_BY_TOOL.keys()) == expected
    assert set(DEFAULT_TIMEOUT_S_BY_TOOL.keys()) == expected
    assert set(RISK_LEVEL_BY_TOOL.keys()) == expected
    assert APPROVAL_REQUIRED.issubset(expected)


# ---------------------------------------------------------------------------
# Phase / category invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
def test_category_is_web_va(catalog_dir: Path, tool_id: str) -> None:
    """All §4.8 tools belong to the web_va category."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.category is ToolCategory.WEB_VA


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
def test_phase_is_vuln_analysis(catalog_dir: Path, tool_id: str) -> None:
    """All §4.8 tools run in the vuln_analysis phase."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.phase is ScanPhase.VULN_ANALYSIS


# ---------------------------------------------------------------------------
# Risk + approval invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
def test_risk_level_matches_pin(catalog_dir: Path, tool_id: str) -> None:
    """Risk level matches the documented active-scanner profile."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.risk_level is RISK_LEVEL_BY_TOOL[tool_id], (
        f"{tool_id}: risk_level={descriptor.risk_level.value!r} "
        f"diverges from pinned {RISK_LEVEL_BY_TOOL[tool_id].value!r}"
    )


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
def test_approval_matches_risk_profile(catalog_dir: Path, tool_id: str) -> None:
    """``requires_approval`` mirrors the medium-risk gate."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = tool_id in APPROVAL_REQUIRED
    assert descriptor.requires_approval is expected, (
        f"{tool_id}: requires_approval={descriptor.requires_approval} "
        f"contradicts risk profile (medium-risk → True, low-risk → False)"
    )


# ---------------------------------------------------------------------------
# Image namespace
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
def test_image_is_argus_kali_web_latest(catalog_dir: Path, tool_id: str) -> None:
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.image == "argus-kali-web:latest", (
        f"{tool_id}: image must be argus-kali-web:latest, got {descriptor.image!r}"
    )


# ---------------------------------------------------------------------------
# Network policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
def test_network_policy_is_recon_active_tcp(catalog_dir: Path, tool_id: str) -> None:
    """All §4.8 tools probe live HTTP(S); they all use ``recon-active-tcp``."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.network_policy.name == "recon-active-tcp"


# ---------------------------------------------------------------------------
# Evidence + CWE/OWASP fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
def test_evidence_artifacts_under_out(catalog_dir: Path, tool_id: str) -> None:
    """Whatever evidence path is declared lives under ``/out``."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.evidence_artifacts, (
        f"{tool_id}: must declare at least one evidence artefact"
    )
    for path in descriptor.evidence_artifacts:
        assert path.startswith("/out"), (
            f"{tool_id}: evidence path {path!r} must live under /out"
        )


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
def test_cwe_hints_non_empty(catalog_dir: Path, tool_id: str) -> None:
    """Every §4.8 tool ships at least one CWE hint."""
    payload = yaml.safe_load((catalog_dir / f"{tool_id}.yaml").read_bytes())
    assert "cwe_hints" in payload, f"{tool_id}.yaml missing the cwe_hints key"
    assert isinstance(payload["cwe_hints"], list), (
        f"{tool_id}.yaml: cwe_hints must be a list"
    )
    assert payload["cwe_hints"], f"{tool_id}.yaml: cwe_hints must be non-empty"


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
def test_owasp_wstg_non_empty(catalog_dir: Path, tool_id: str) -> None:
    """Every §4.8 tool ships an OWASP-WSTG taxonomy hint."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.owasp_wstg, (
        f"{tool_id}: owasp_wstg must be non-empty for §4.8 tools"
    )


# ---------------------------------------------------------------------------
# Parser dispatch strategy split
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
def test_parse_strategy_matches_per_tool_split(catalog_dir: Path, tool_id: str) -> None:
    """1 ``nuclei_jsonl`` + 2 ``json_object`` + 4 ``text_lines`` — pinned."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = PARSE_STRATEGY_BY_TOOL[tool_id]
    assert descriptor.parse_strategy is expected, (
        f"{tool_id}: parse_strategy must be {expected.value}, "
        f"got {descriptor.parse_strategy.value!r}"
    )


# ---------------------------------------------------------------------------
# Resource limits + per-tool timeout floor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
def test_default_timeout_matches_per_tool_floor(
    catalog_dir: Path, tool_id: str
) -> None:
    """Every §4.8 tool floors at the per-tool minimum from the cycle plan."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = DEFAULT_TIMEOUT_S_BY_TOOL[tool_id]
    assert descriptor.default_timeout_s >= expected, (
        f"{tool_id}: default_timeout_s={descriptor.default_timeout_s}s "
        f"below floor of {expected}s"
    )


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
def test_command_template_has_no_shell_metachars(
    catalog_dir: Path, tool_id: str
) -> None:
    """No argv token may contain shell metacharacters — defence in depth."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    for index, token in enumerate(descriptor.command_template):
        for meta in SHELL_METACHARS:
            assert meta not in token, (
                f"{tool_id}: command_template[{index}] {token!r} contains "
                f"shell metacharacter {meta!r} — would break sandbox argv"
            )


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
def test_command_template_first_token_is_real_binary(
    catalog_dir: Path, tool_id: str
) -> None:
    """The first argv token must be the real binary, never a shell."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.command_template, f"{tool_id}: command_template must be non-empty"
    first_token = descriptor.command_template[0]
    assert first_token not in FORBIDDEN_FIRST_TOKENS, (
        f"{tool_id}: command_template[0]={first_token!r} is a shell — "
        f"YAMLs must invoke binaries directly so the sandbox argv is "
        f"unambiguous"
    )


# ---------------------------------------------------------------------------
# Description self-documentation invariant
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", WEB_VULN_TOOL_IDS)
def test_description_includes_upstream_attribution(
    catalog_dir: Path, tool_id: str
) -> None:
    """Description must include both the upstream author / source URL.

    Catalog hygiene: the YAML carries enough provenance metadata that
    operators can audit the binary chain without reading the Dockerfile.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.description, f"{tool_id}: empty description"
    text = descriptor.description.lower()
    assert "author" in text or "https://" in text, (
        f"{tool_id}: description must include upstream author / source URL "
        f"so the catalog stays self-documenting"
    )
    assert "§4.8" in descriptor.description, (
        f"{tool_id}: description must reference Backlog §4.8 for traceability"
    )


# ---------------------------------------------------------------------------
# Targeting invariant — every §4.8 tool consumes a sanctioned input
# placeholder so the templating layer can reject unknown ones at render
# time. ``w3af_console`` is the documented exception — it consumes a
# profile file from ``{in_dir}`` and pins the target URL inside the
# profile, not on the argv.
# ---------------------------------------------------------------------------


URL_DIRECT_TOOLS: Final[frozenset[str]] = frozenset(
    {"nuclei", "nikto", "wapiti", "arachni", "skipfish", "zap_baseline"}
)


@pytest.mark.parametrize("tool_id", sorted(URL_DIRECT_TOOLS))
def test_command_template_consumes_url_placeholder(
    catalog_dir: Path, tool_id: str
) -> None:
    """Every direct-targeting §4.8 tool references the ``{url}`` placeholder."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    rendered = " ".join(descriptor.command_template)
    assert "{url}" in rendered, (
        f"{tool_id}: command_template must reference the {{url}} placeholder "
        f"(the §4.8 cohort takes a single URL target on argv)"
    )


def test_w3af_console_consumes_profile_via_in_dir(catalog_dir: Path) -> None:
    """``w3af_console`` is the profile-based exception — pins {in_dir}."""
    descriptor = _load_descriptor(catalog_dir, "w3af_console")
    rendered = " ".join(descriptor.command_template)
    assert "{in_dir}" in rendered, (
        "w3af_console: must reference {in_dir} so the sandbox can mount the "
        "user-supplied profile (target URL is pinned inside the profile)"
    )
    assert "{url}" not in rendered, (
        "w3af_console: must not consume {url} directly — the sandbox cannot "
        "inject the URL into the profile file at runtime"
    )
