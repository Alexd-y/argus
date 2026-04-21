"""Per-§4.9 invariant tests for the SQL-injection scanner YAMLs (ARG-016).

Sister suite to ``test_yaml_web_vuln_semantics.py`` (ARG-015) — that file
pins the §4.8 contract; this file pins the §4.9 SQL-injection contract:

* ``sqlmap_safe`` — conservative passive sweep
  (``--technique=BT --level 2 --risk 1 --safe-url``).
  Approval-free, parsed by
  :func:`src.sandbox.parsers.sqlmap_parser.parse_sqlmap_output`.
* ``sqlmap_confirm`` — error-based exploitation + DBMS schema
  enumeration (``--technique=E --dbs --count``).  Requires approval,
  runs in the **exploitation** phase, parsed by the same sqlmap parser.
* ``ghauri`` — automated SQLi exploitation.  Approval-gated.  Parser
  deferred to Cycle 3 (dispatch falls through to ``unmapped_tool``).
* ``jsql`` — JSON-emitting SQLi pipeline.  Approval-gated.  Parser
  deferred to Cycle 3.
* ``tplmap`` — server-side template-injection (SSTI) RCE attempts.
  Backlog §4.9 groups it with the SQLi cohort because of the
  active-injection risk profile, but its CWEs are SSTI-specific
  (CWE-1336 / CWE-94 / CWE-78).  Approval-gated.
* ``nosqlmap`` — NoSQL injection brute force.  Approval-gated.

Invariants pinned (any drift fails CI):

* The catalog contains exactly the six §4.9 tool ids — no more, no less.
* Every tool ships ``category=web_va`` and runs on
  ``argus-kali-web:latest`` behind ``recon-active-tcp``.
* Phase split: ``sqlmap_confirm`` graduates to ``exploitation``;
  the other five live in ``vuln_analysis``.
* ``risk_level`` matches the documented cost / severity profile:
  - ``low``    — ``sqlmap_safe`` (boolean+time-based blind only).
  - ``medium`` — ``ghauri`` / ``jsql`` / ``nosqlmap``.
  - ``high``   — ``sqlmap_confirm`` (data exfil) and ``tplmap`` (SSTI RCE).
* ``requires_approval`` mirrors the active-injection gate: every §4.9
  entry now requires approval, including ``sqlmap_safe`` (reviewer M1
  cycle 2 closed the historical gap that left it dispatchable
  unattended — the BT-only profile still generates WAF noise + DB log
  churn that violates the ARGUS default-deny posture).
* ``parse_strategy`` is pinned per-tool.
* ``cwe_hints`` matches the per-tool CWE set
  (CWE-89 for the SQLi five, CWE-943 for ``nosqlmap``,
  CWE-1336/94/78 for ``tplmap``).
* ``owasp_wstg`` carries at least one WSTG-INPV-* hint.
* ``default_timeout_s`` ≥ the per-tool floor.
* ``cpu_limit`` / ``memory_limit`` / ``seccomp_profile`` populated.
* ``command_template`` argv carries no shell metacharacters; first
  token is the real binary (never a shell).
* ``description`` includes the upstream author / source URL and
  references ``§4.9``.

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


# §4.9 batch — hard-coded so a silent drop / addition breaks CI.
SQLI_TOOL_IDS: Final[tuple[str, ...]] = (
    "sqlmap_safe",
    "sqlmap_confirm",
    "ghauri",
    "jsql",
    "tplmap",
    "nosqlmap",
)


# ---------------------------------------------------------------------------
# Per-tool taxonomy maps. Pinned so a future YAML edit cannot silently
# flip a tool from one bucket to another.
# ---------------------------------------------------------------------------


PHASE_BY_TOOL: Final[dict[str, ScanPhase]] = {
    "sqlmap_safe": ScanPhase.VULN_ANALYSIS,
    "sqlmap_confirm": ScanPhase.EXPLOITATION,
    "ghauri": ScanPhase.VULN_ANALYSIS,
    "jsql": ScanPhase.VULN_ANALYSIS,
    "tplmap": ScanPhase.VULN_ANALYSIS,
    "nosqlmap": ScanPhase.VULN_ANALYSIS,
}


PARSE_STRATEGY_BY_TOOL: Final[dict[str, ParseStrategy]] = {
    "sqlmap_safe": ParseStrategy.TEXT_LINES,
    "sqlmap_confirm": ParseStrategy.TEXT_LINES,
    "ghauri": ParseStrategy.TEXT_LINES,
    "jsql": ParseStrategy.JSON_OBJECT,
    "tplmap": ParseStrategy.TEXT_LINES,
    "nosqlmap": ParseStrategy.TEXT_LINES,
}


# Tools that require explicit operator approval.  Every §4.9 SQLi scanner
# now requires approval — even the ``sqlmap_safe`` profile (BT-only,
# level 2, risk 1) generates WAF noise and DB log churn that violates
# the ARGUS security-policy default-deny posture.  Reviewer M1 (cycle 2)
# closes the historical gap that left ``sqlmap_safe`` dispatchable
# without operator green-light.
APPROVAL_REQUIRED: Final[frozenset[str]] = frozenset(SQLI_TOOL_IDS)


RISK_LEVEL_BY_TOOL: Final[dict[str, RiskLevel]] = {
    # ``sqlmap_safe`` was bumped from LOW to MEDIUM in ARG-020 to satisfy
    # the new "requires_approval=True implies risk_level >= MEDIUM" invariant.
    # The technical exploitation surface is unchanged (BT-only, level 2,
    # risk 1) — the bump reflects the operational impact (WAF noise + DB
    # log churn) that already justified the approval gate.
    "sqlmap_safe": RiskLevel.MEDIUM,
    "sqlmap_confirm": RiskLevel.HIGH,
    "ghauri": RiskLevel.MEDIUM,
    "jsql": RiskLevel.MEDIUM,
    "tplmap": RiskLevel.HIGH,
    "nosqlmap": RiskLevel.MEDIUM,
}


# Per-tool CWE floor — the set of CWE ids each YAML must carry.  Pinned
# per-tool because the cohort spans three CWE families:
# - SQLi (CWE-89)             — sqlmap_*, ghauri, jsql.
# - NoSQLi (CWE-943)          — nosqlmap.
# - SSTI / RCE (CWE-1336/94/78) — tplmap.
REQUIRED_CWE_BY_TOOL: Final[dict[str, frozenset[int]]] = {
    "sqlmap_safe": frozenset({89}),
    "sqlmap_confirm": frozenset({89}),
    "ghauri": frozenset({89}),
    "jsql": frozenset({89}),
    "tplmap": frozenset({1336, 94, 78}),
    "nosqlmap": frozenset({943}),
}


# Per-tool minimum timeout.  Heavy / multi-stage scanners get longer
# windows.  The sqlmap variants run multi-pass technique sweeps (BT for
# safe, error-based + schema dump for confirm) so they get 30 minutes;
# the four lighter-weight specialists get 15 minutes.
DEFAULT_TIMEOUT_S_BY_TOOL: Final[dict[str, int]] = {
    "sqlmap_safe": 1800,
    "sqlmap_confirm": 1800,
    "ghauri": 900,
    "jsql": 900,
    "tplmap": 900,
    "nosqlmap": 900,
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


def test_inventory_contains_exactly_six_tools() -> None:
    """The §4.9 batch is exactly six tools — drift breaks alignment with
    Backlog/dev1_md §4.9 and the SQLI_TOOLS frozenset in
    ``test_tool_catalog_load.py``.
    """
    assert len(SQLI_TOOL_IDS) == 6
    assert len(set(SQLI_TOOL_IDS)) == 6


def test_per_tool_taxonomy_maps_cover_every_tool() -> None:
    """Each per-tool map covers exactly the §4.9 batch — no extras, no gaps."""
    expected = set(SQLI_TOOL_IDS)
    assert set(PHASE_BY_TOOL.keys()) == expected
    assert set(PARSE_STRATEGY_BY_TOOL.keys()) == expected
    assert set(DEFAULT_TIMEOUT_S_BY_TOOL.keys()) == expected
    assert set(RISK_LEVEL_BY_TOOL.keys()) == expected
    assert set(REQUIRED_CWE_BY_TOOL.keys()) == expected
    assert APPROVAL_REQUIRED.issubset(expected)


# ---------------------------------------------------------------------------
# Phase / category invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
def test_category_is_web_va(catalog_dir: Path, tool_id: str) -> None:
    """All §4.9 tools belong to the web_va category."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.category is ToolCategory.WEB_VA


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
def test_phase_matches_per_tool_pin(catalog_dir: Path, tool_id: str) -> None:
    """``sqlmap_confirm`` graduates to exploitation; the rest stay vuln_analysis."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.phase is PHASE_BY_TOOL[tool_id], (
        f"{tool_id}: phase={descriptor.phase.value!r} "
        f"diverges from pinned {PHASE_BY_TOOL[tool_id].value!r}"
    )


# ---------------------------------------------------------------------------
# Risk + approval invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
def test_risk_level_matches_pin(catalog_dir: Path, tool_id: str) -> None:
    """Risk level matches the documented active-injection profile."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.risk_level is RISK_LEVEL_BY_TOOL[tool_id], (
        f"{tool_id}: risk_level={descriptor.risk_level.value!r} "
        f"diverges from pinned {RISK_LEVEL_BY_TOOL[tool_id].value!r}"
    )


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
def test_approval_matches_active_injection_gate(
    catalog_dir: Path, tool_id: str
) -> None:
    """``requires_approval`` mirrors the active-injection gate.

    Every §4.9 tool fires SQL / NoSQL / template-injection payloads
    against the in-scope target.  Reviewer M1 (cycle 2) elevated
    ``sqlmap_safe`` into this set as well — the BT-only profile still
    generates WAF noise + DB log churn that violates the ARGUS
    default-deny security posture.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = tool_id in APPROVAL_REQUIRED
    assert descriptor.requires_approval is expected, (
        f"{tool_id}: requires_approval={descriptor.requires_approval} "
        f"contradicts approval gate (every §4.9 SQLi entry must be True)"
    )


# ---------------------------------------------------------------------------
# Image namespace
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
def test_image_is_argus_kali_web_latest(catalog_dir: Path, tool_id: str) -> None:
    """All §4.9 tools live in ``argus-kali-web:latest`` (Kali web tooling image)."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.image == "argus-kali-web:latest", (
        f"{tool_id}: image must be argus-kali-web:latest, got {descriptor.image!r}"
    )


# ---------------------------------------------------------------------------
# Network policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
def test_network_policy_is_recon_active_tcp(catalog_dir: Path, tool_id: str) -> None:
    """All §4.9 tools probe live HTTP(S); they all use ``recon-active-tcp``."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.network_policy.name == "recon-active-tcp"


# ---------------------------------------------------------------------------
# Evidence + CWE/OWASP fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
def test_cwe_hints_match_per_tool_floor(catalog_dir: Path, tool_id: str) -> None:
    """Every §4.9 tool ships its per-tool CWE floor (SQLi / NoSQLi / SSTI)."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    cwes = set(descriptor.cwe_hints)
    required = REQUIRED_CWE_BY_TOOL[tool_id]
    missing = required - cwes
    assert not missing, (
        f"{tool_id}: missing CWE hints {sorted(missing)}; "
        f"per-tool floor = {sorted(required)}, declared = {sorted(cwes)}"
    )


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
def test_owasp_wstg_includes_inpv_family(catalog_dir: Path, tool_id: str) -> None:
    """Every §4.9 tool ships at least one OWASP WSTG-INPV-* hint.

    The WSTG INPV (input validation) family covers SQLi (INPV-05),
    NoSQLi (INPV-13), template injection (INPV-18) and the broader
    "test for injection" suite — all relevant to §4.9.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.owasp_wstg, (
        f"{tool_id}: owasp_wstg must be non-empty for §4.9 tools"
    )
    assert any(tag.startswith("WSTG-INPV") for tag in descriptor.owasp_wstg), (
        f"{tool_id}: owasp_wstg must include at least one WSTG-INPV-* hint; "
        f"got {descriptor.owasp_wstg}"
    )


# ---------------------------------------------------------------------------
# Parser dispatch strategy split
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
def test_parse_strategy_matches_per_tool_split(catalog_dir: Path, tool_id: str) -> None:
    """5 ``text_lines`` + 1 ``json_object`` (jsql) — pinned."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = PARSE_STRATEGY_BY_TOOL[tool_id]
    assert descriptor.parse_strategy is expected, (
        f"{tool_id}: parse_strategy must be {expected.value}, "
        f"got {descriptor.parse_strategy.value!r}"
    )


# ---------------------------------------------------------------------------
# Resource limits + per-tool timeout floor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
def test_default_timeout_matches_per_tool_floor(
    catalog_dir: Path, tool_id: str
) -> None:
    """Every §4.9 tool floors at the per-tool minimum from the cycle plan."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = DEFAULT_TIMEOUT_S_BY_TOOL[tool_id]
    assert descriptor.default_timeout_s >= expected, (
        f"{tool_id}: default_timeout_s={descriptor.default_timeout_s}s "
        f"below floor of {expected}s"
    )


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
def test_description_includes_upstream_attribution(
    catalog_dir: Path, tool_id: str
) -> None:
    """Description must include both the upstream author / source URL and
    the §4.9 backlog reference.

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
    assert "§4.9" in descriptor.description, (
        f"{tool_id}: description must reference Backlog §4.9 for traceability"
    )


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
def test_description_within_500_char_limit(catalog_dir: Path, tool_id: str) -> None:
    """``ToolDescriptor`` caps ``description`` at 500 characters.

    Catalog hygiene: long descriptions should land in the doc generator
    output, not the YAML itself.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert len(descriptor.description) <= 500, (
        f"{tool_id}: description length {len(descriptor.description)} > 500 "
        f"(would fail Pydantic validation on load)"
    )


# ---------------------------------------------------------------------------
# Targeting invariant — every §4.9 tool consumes the ``{url}`` placeholder
# so the templating layer can reject unknown ones at render time.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", SQLI_TOOL_IDS)
def test_command_template_consumes_url_placeholder(
    catalog_dir: Path, tool_id: str
) -> None:
    """Every §4.9 tool references the ``{url}`` placeholder."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    rendered = " ".join(descriptor.command_template)
    assert "{url}" in rendered, (
        f"{tool_id}: command_template must reference the {{url}} placeholder "
        f"(the §4.9 cohort takes a single URL target on argv)"
    )


# ---------------------------------------------------------------------------
# sqlmap-specific contract: both variants share the same parser, so they
# must declare the same `text_lines` strategy and route their evidence
# under a sqlmap-specific subdirectory of /out.
# ---------------------------------------------------------------------------


def test_sqlmap_safe_and_confirm_share_parser(catalog_dir: Path) -> None:
    """Both sqlmap variants use the shared text_lines parser."""
    safe = _load_descriptor(catalog_dir, "sqlmap_safe")
    confirm = _load_descriptor(catalog_dir, "sqlmap_confirm")
    assert safe.parse_strategy is ParseStrategy.TEXT_LINES
    assert confirm.parse_strategy is ParseStrategy.TEXT_LINES


def test_sqlmap_safe_uses_passive_techniques_only(catalog_dir: Path) -> None:
    """``sqlmap_safe`` MUST pin ``--technique=BT`` (boolean + time-based blind only).

    The whole point of the safe profile is to skip error-based / union /
    stacked techniques that are loud / disruptive.  If a future YAML edit
    drops the technique flag the tool would silently switch to the
    sqlmap default ``BEUSTQ`` and start firing union queries — a
    regression we want CI to catch.
    """
    descriptor = _load_descriptor(catalog_dir, "sqlmap_safe")
    rendered = " ".join(descriptor.command_template)
    assert "--technique=BT" in rendered, (
        "sqlmap_safe: must pin --technique=BT to keep the passive profile honest "
        f"(got argv: {descriptor.command_template!r})"
    )


def test_sqlmap_confirm_uses_error_based_technique(catalog_dir: Path) -> None:
    """``sqlmap_confirm`` MUST pin ``--technique=E`` and request DBMS dumping.

    The confirmation pass is what justifies the approval gate: it
    actively exfiltrates schema metadata.  Drift here would degrade the
    tool to a passive sweep and silently weaken the approval contract.
    """
    descriptor = _load_descriptor(catalog_dir, "sqlmap_confirm")
    rendered = " ".join(descriptor.command_template)
    assert "--technique=E" in rendered, (
        "sqlmap_confirm: must pin --technique=E (error-based exploitation) "
        f"(got argv: {descriptor.command_template!r})"
    )
    assert "--dbs" in rendered, (
        "sqlmap_confirm: must request --dbs to enumerate schema "
        f"(got argv: {descriptor.command_template!r})"
    )
