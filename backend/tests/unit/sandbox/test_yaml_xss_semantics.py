"""Per-§4.10 invariant tests for the XSS scanner YAMLs (ARG-016).

Sister suite to ``test_yaml_sqli_semantics.py`` (ARG-016) — that file
pins the §4.9 SQLi contract; this file pins the §4.10 XSS contract:

* ``dalfox`` — flagship parameter-aware XSS scanner with DOM mining.
  Approval-free, parsed by
  :func:`src.sandbox.parsers.dalfox_parser.parse_dalfox_json`.
* ``xsstrike`` — XSS context-aware fuzzer.  Approval-free.  Parser
  deferred to Cycle 3 (dispatch falls through to ``unmapped_tool``).
* ``kxss`` — pure stdin grep wrapper for reflection grep.  Approval-free.
  Parser deferred to Cycle 3.
* ``xsser`` — multi-vector XSS framework.  Approval-free (reflection-
  only payloads).  Parser deferred to Cycle 3.
* ``playwright_xss_verify`` — headless Chromium verifier that lands an
  XSS canary and captures DOM execution + screenshot.  Lives in
  ``argus-kali-browser:latest`` (Chromium runtime), runs in
  ``exploitation`` phase (Backlog §4.10 lists it as "validation"
  which doesn't exist in :class:`ScanPhase`; ARG-016 maps that to
  ``exploitation`` with ``risk_level=low`` so the canary-only verifier
  stays approval-free).  Parser deferred to Cycle 3 ARG-019.

Invariants pinned (any drift fails CI):

* The catalog contains exactly the five §4.10 tool ids — no more, no less.
* Every tool runs behind ``recon-active-tcp``.
* Phase split: ``playwright_xss_verify`` graduates to ``exploitation``
  with ``ToolCategory.BROWSER``; the other four live in
  ``vuln_analysis`` / ``ToolCategory.WEB_VA``.
* Image split: only ``playwright_xss_verify`` uses
  ``argus-kali-browser:latest``; the other four use
  ``argus-kali-web:latest``.
* ``risk_level``:
  - ``passive``  — ``kxss`` (stdin grep wrapper, no traffic).
  - ``low``      — everything else (reflection-only payloads + canary
    headless verifier).
* ``requires_approval`` is False for every §4.10 tool.
* ``parse_strategy`` is pinned per-tool.
* ``cwe_hints`` includes CWE-79 (XSS).
* ``owasp_wstg`` carries at least one WSTG-INPV-* hint (XSS family is
  WSTG-INPV-01 / INPV-02).
* ``default_timeout_s`` ≥ the per-tool floor.
* ``cpu_limit`` / ``memory_limit`` / ``seccomp_profile`` populated.
* ``command_template`` argv carries no shell metacharacters; first
  token is the real binary (never a shell).
* ``description`` includes the upstream author / source URL and
  references ``§4.10``.

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


# §4.10 batch — hard-coded so a silent drop / addition breaks CI.
XSS_TOOL_IDS: Final[tuple[str, ...]] = (
    "dalfox",
    "xsstrike",
    "kxss",
    "xsser",
    "playwright_xss_verify",
)


# ---------------------------------------------------------------------------
# Per-tool taxonomy maps. Pinned so a future YAML edit cannot silently
# flip a tool from one bucket to another.
# ---------------------------------------------------------------------------


PHASE_BY_TOOL: Final[dict[str, ScanPhase]] = {
    "dalfox": ScanPhase.VULN_ANALYSIS,
    "xsstrike": ScanPhase.VULN_ANALYSIS,
    "kxss": ScanPhase.VULN_ANALYSIS,
    "xsser": ScanPhase.VULN_ANALYSIS,
    "playwright_xss_verify": ScanPhase.EXPLOITATION,
}


CATEGORY_BY_TOOL: Final[dict[str, ToolCategory]] = {
    "dalfox": ToolCategory.WEB_VA,
    "xsstrike": ToolCategory.WEB_VA,
    "kxss": ToolCategory.WEB_VA,
    "xsser": ToolCategory.WEB_VA,
    "playwright_xss_verify": ToolCategory.BROWSER,
}


IMAGE_BY_TOOL: Final[dict[str, str]] = {
    "dalfox": "argus-kali-web:latest",
    "xsstrike": "argus-kali-web:latest",
    "kxss": "argus-kali-web:latest",
    "xsser": "argus-kali-web:latest",
    "playwright_xss_verify": "argus-kali-browser:latest",
}


PARSE_STRATEGY_BY_TOOL: Final[dict[str, ParseStrategy]] = {
    "dalfox": ParseStrategy.JSON_OBJECT,
    "xsstrike": ParseStrategy.JSON_OBJECT,
    "kxss": ParseStrategy.TEXT_LINES,
    "xsser": ParseStrategy.JSON_OBJECT,
    "playwright_xss_verify": ParseStrategy.JSON_OBJECT,
}


RISK_LEVEL_BY_TOOL: Final[dict[str, RiskLevel]] = {
    "dalfox": RiskLevel.LOW,
    "xsstrike": RiskLevel.LOW,
    "kxss": RiskLevel.PASSIVE,
    "xsser": RiskLevel.LOW,
    "playwright_xss_verify": RiskLevel.LOW,
}


# Per-tool minimum timeout. Headless Chromium gets a longer floor than
# pure stdin/stdout tools.
DEFAULT_TIMEOUT_S_BY_TOOL: Final[dict[str, int]] = {
    "dalfox": 600,
    "xsstrike": 600,
    "kxss": 300,
    "xsser": 600,
    "playwright_xss_verify": 600,
}


# CWE-79 (XSS) is the cohort floor.  Individual tools may carry
# additional CWEs (e.g. CWE-80 for basic XSS) but every entry must
# surface CWE-79 so the normaliser can group findings.
REQUIRED_CWE: Final[int] = 79


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


def test_inventory_contains_exactly_five_tools() -> None:
    """The §4.10 batch is exactly five tools — drift breaks alignment with
    Backlog/dev1_md §4.10 and the XSS_TOOLS frozenset in
    ``test_tool_catalog_load.py``.
    """
    assert len(XSS_TOOL_IDS) == 5
    assert len(set(XSS_TOOL_IDS)) == 5


def test_per_tool_taxonomy_maps_cover_every_tool() -> None:
    """Each per-tool map covers exactly the §4.10 batch — no extras, no gaps."""
    expected = set(XSS_TOOL_IDS)
    assert set(PHASE_BY_TOOL.keys()) == expected
    assert set(CATEGORY_BY_TOOL.keys()) == expected
    assert set(IMAGE_BY_TOOL.keys()) == expected
    assert set(PARSE_STRATEGY_BY_TOOL.keys()) == expected
    assert set(DEFAULT_TIMEOUT_S_BY_TOOL.keys()) == expected
    assert set(RISK_LEVEL_BY_TOOL.keys()) == expected


# ---------------------------------------------------------------------------
# Phase / category invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
def test_category_matches_per_tool_pin(catalog_dir: Path, tool_id: str) -> None:
    """``playwright_xss_verify`` is BROWSER; the rest are WEB_VA."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = CATEGORY_BY_TOOL[tool_id]
    assert descriptor.category is expected, (
        f"{tool_id}: category={descriptor.category.value!r} "
        f"diverges from pinned {expected.value!r}"
    )


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
def test_phase_matches_per_tool_pin(catalog_dir: Path, tool_id: str) -> None:
    """``playwright_xss_verify`` graduates to exploitation; rest stay vuln_analysis.

    Backlog §4.10 lists the playwright verifier under "validation" — a
    phase that does not exist in :class:`ScanPhase`. ARG-016 maps it to
    ``exploitation`` with ``risk_level=low`` so the canary-only verifier
    stays approval-free.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.phase is PHASE_BY_TOOL[tool_id], (
        f"{tool_id}: phase={descriptor.phase.value!r} "
        f"diverges from pinned {PHASE_BY_TOOL[tool_id].value!r}"
    )


# ---------------------------------------------------------------------------
# Risk + approval invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
def test_risk_level_matches_pin(catalog_dir: Path, tool_id: str) -> None:
    """Risk level matches the documented reflection-only payload profile."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.risk_level is RISK_LEVEL_BY_TOOL[tool_id], (
        f"{tool_id}: risk_level={descriptor.risk_level.value!r} "
        f"diverges from pinned {RISK_LEVEL_BY_TOOL[tool_id].value!r}"
    )


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
def test_no_xss_tool_requires_approval(catalog_dir: Path, tool_id: str) -> None:
    """The §4.10 batch is uniformly approval-free.

    Every entry is reflection-only: dalfox / xsstrike / xsser ride
    low-risk reflection payloads, kxss is a pure stdin grep wrapper,
    and playwright only ever fires the supplied {canary} marker.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.requires_approval is False, (
        f"{tool_id}: §4.10 XSS tools must be approval-free "
        f"(got requires_approval={descriptor.requires_approval})"
    )


# ---------------------------------------------------------------------------
# Image namespace
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
def test_image_matches_per_tool_pin(catalog_dir: Path, tool_id: str) -> None:
    """``playwright_xss_verify`` uses ``argus-kali-browser:latest``;
    the rest use ``argus-kali-web:latest``.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = IMAGE_BY_TOOL[tool_id]
    assert descriptor.image == expected, (
        f"{tool_id}: image must be {expected!r}, got {descriptor.image!r}"
    )


# ---------------------------------------------------------------------------
# Network policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
def test_network_policy_is_recon_active_tcp(catalog_dir: Path, tool_id: str) -> None:
    """All §4.10 tools probe live HTTP(S); they all use ``recon-active-tcp``."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.network_policy.name == "recon-active-tcp"


# ---------------------------------------------------------------------------
# Evidence + CWE/OWASP fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
def test_cwe_hints_include_xss(catalog_dir: Path, tool_id: str) -> None:
    """Every §4.10 tool ships CWE-79 (XSS) — the cohort floor."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert REQUIRED_CWE in descriptor.cwe_hints, (
        f"{tool_id}: must declare CWE-79 (Cross-Site Scripting); "
        f"got {descriptor.cwe_hints}"
    )


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
def test_owasp_wstg_includes_inpv_family(catalog_dir: Path, tool_id: str) -> None:
    """Every §4.10 tool ships at least one OWASP WSTG-INPV-* hint.

    The XSS family lives in WSTG-INPV-01 (Reflected XSS) / INPV-02
    (Stored XSS) / INPV-04 (DOM XSS).
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.owasp_wstg, (
        f"{tool_id}: owasp_wstg must be non-empty for §4.10 tools"
    )
    assert any(tag.startswith("WSTG-INPV") for tag in descriptor.owasp_wstg), (
        f"{tool_id}: owasp_wstg must include at least one WSTG-INPV-* hint; "
        f"got {descriptor.owasp_wstg}"
    )


# ---------------------------------------------------------------------------
# Parser dispatch strategy split
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
def test_parse_strategy_matches_per_tool_split(catalog_dir: Path, tool_id: str) -> None:
    """4 ``json_object`` + 1 ``text_lines`` (kxss) — pinned."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = PARSE_STRATEGY_BY_TOOL[tool_id]
    assert descriptor.parse_strategy is expected, (
        f"{tool_id}: parse_strategy must be {expected.value}, "
        f"got {descriptor.parse_strategy.value!r}"
    )


# ---------------------------------------------------------------------------
# Resource limits + per-tool timeout floor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
def test_default_timeout_matches_per_tool_floor(
    catalog_dir: Path, tool_id: str
) -> None:
    """Every §4.10 tool floors at the per-tool minimum from the cycle plan."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = DEFAULT_TIMEOUT_S_BY_TOOL[tool_id]
    assert descriptor.default_timeout_s >= expected, (
        f"{tool_id}: default_timeout_s={descriptor.default_timeout_s}s "
        f"below floor of {expected}s"
    )


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
def test_command_template_has_no_shell_metachars(
    catalog_dir: Path, tool_id: str
) -> None:
    """No argv token may contain shell metacharacters — defence in depth.

    Note: ``kxss`` is the trickiest entry — it's a stdin-only tool, so
    its YAML must invoke a runtime wrapper script (``kxss-runner {url}``)
    that pipes the URL into kxss's stdin **inside the container**, never
    via a shell pipe in the argv (which the templating layer rejects).
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    for index, token in enumerate(descriptor.command_template):
        for meta in SHELL_METACHARS:
            assert meta not in token, (
                f"{tool_id}: command_template[{index}] {token!r} contains "
                f"shell metacharacter {meta!r} — would break sandbox argv"
            )


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
def test_description_includes_upstream_attribution(
    catalog_dir: Path, tool_id: str
) -> None:
    """Description must include both the upstream author / source URL and
    the §4.10 backlog reference.

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
    assert "§4.10" in descriptor.description, (
        f"{tool_id}: description must reference Backlog §4.10 for traceability"
    )


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
def test_description_within_500_char_limit(catalog_dir: Path, tool_id: str) -> None:
    """``ToolDescriptor`` caps ``description`` at 500 characters."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert len(descriptor.description) <= 500, (
        f"{tool_id}: description length {len(descriptor.description)} > 500 "
        f"(would fail Pydantic validation on load)"
    )


# ---------------------------------------------------------------------------
# Targeting invariant — every §4.10 tool consumes a sanctioned input
# placeholder so the templating layer can reject unknown ones at render
# time.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", XSS_TOOL_IDS)
def test_command_template_consumes_url_placeholder(
    catalog_dir: Path, tool_id: str
) -> None:
    """Every §4.10 tool references the ``{url}`` placeholder."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    rendered = " ".join(descriptor.command_template)
    assert "{url}" in rendered, (
        f"{tool_id}: command_template must reference the {{url}} placeholder "
        f"(the §4.10 cohort takes a single URL target on argv / via wrapper)"
    )


# ---------------------------------------------------------------------------
# playwright_xss_verify-specific contract: must consume the ``{canary}``
# placeholder so the verifier only ever fires the supplied marker (this
# is what keeps the tool approval-free even though it lives in the
# exploitation phase).
# ---------------------------------------------------------------------------


def test_playwright_xss_verify_consumes_canary_placeholder(catalog_dir: Path) -> None:
    """``playwright_xss_verify`` MUST reference the ``{canary}`` placeholder.

    The whole approval-free contract for the headless verifier rests on
    the fact that it only fires the operator-supplied canary marker
    (never an attacker-controlled payload).  A YAML that drops {canary}
    would silently turn the verifier into an open XSS injector — a
    regression we want CI to catch.
    """
    descriptor = _load_descriptor(catalog_dir, "playwright_xss_verify")
    rendered = " ".join(descriptor.command_template)
    assert "{canary}" in rendered, (
        "playwright_xss_verify: must reference {canary} so the verifier "
        "only fires operator-supplied markers "
        f"(got argv: {descriptor.command_template!r})"
    )


def test_playwright_xss_verify_emits_screenshot_evidence(
    catalog_dir: Path,
) -> None:
    """``playwright_xss_verify`` ships a screenshot path in evidence_artifacts.

    The screenshot is the proof-of-execution evidence — without it the
    headless verifier degrades to a "did the JSON say true?" boolean
    that operators cannot manually corroborate.
    """
    descriptor = _load_descriptor(catalog_dir, "playwright_xss_verify")
    screenshot_paths = [p for p in descriptor.evidence_artifacts if p.endswith(".png")]
    assert screenshot_paths, (
        "playwright_xss_verify: must declare at least one PNG screenshot "
        f"in evidence_artifacts (got {descriptor.evidence_artifacts!r})"
    )


# ---------------------------------------------------------------------------
# kxss-specific contract: the wrapper script must take the URL on argv
# (the templating layer forbids shell pipes, so kxss can't be invoked
# directly with `echo {url} | kxss`).
# ---------------------------------------------------------------------------


def test_kxss_wraps_stdin_via_runner_script(catalog_dir: Path) -> None:
    """``kxss`` is stdin-only; the YAML invokes a wrapper that takes argv.

    The runtime wrapper (``kxss-runner``, shipped in the Docker image)
    does the ``echo {url} | kxss`` plumbing inside the container so the
    YAML stays argv-only and the sandbox templating layer can validate
    the placeholders.
    """
    descriptor = _load_descriptor(catalog_dir, "kxss")
    assert descriptor.command_template, "kxss: command_template must be non-empty"
    first_token = descriptor.command_template[0]
    assert first_token != "kxss", (
        f"kxss: command_template[0]={first_token!r} cannot be the bare "
        f"binary (kxss only accepts stdin); use a runtime wrapper script "
        f"that takes the URL on argv"
    )
    rendered = " ".join(descriptor.command_template)
    assert "{url}" in rendered, (
        f"kxss: wrapper must consume {{url}} on argv "
        f"(got {descriptor.command_template!r})"
    )


# ---------------------------------------------------------------------------
# dalfox-specific contract: must request JSON output so the parser has
# stable structured data to work with.
# ---------------------------------------------------------------------------


def test_dalfox_emits_json_output(catalog_dir: Path) -> None:
    """``dalfox`` MUST be invoked with ``--format json`` so the parser
    has structured data to ingest.

    Drift here would leave the parser staring at default text output
    and silently degrade ARG-016's primary XSS coverage to ``unmapped``.
    """
    descriptor = _load_descriptor(catalog_dir, "dalfox")
    rendered = " ".join(descriptor.command_template)
    assert "json" in rendered.lower() or "--format" in rendered, (
        "dalfox: command_template must request JSON output "
        f"(got argv: {descriptor.command_template!r})"
    )
