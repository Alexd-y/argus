"""Per-§4.17/§4.18/§4.19 invariant tests for the ARG-019 tool YAMLs.

Sister suite to ``test_yaml_arg018_semantics.py`` (ARG-018) — that file
pins the §4.14/§4.15/§4.16 contract; this file pins the ARG-019
contract for the three Cycle-2 cohorts that close the long-term
Backlog §4 catalog at exactly 157 tools:

* §4.17 — **Network protocol / AD / poisoning** (10 tools):
  ``responder``, ``ntlmrelayx`` (active LLMNR/NBT-NS poisoning + NTLM
  relay), ``impacket_secretsdump`` (DRSUAPI / NTDS / SAM / LSA secret
  extraction), ``bloodhound_python`` (authenticated AD enumeration),
  ``ldapsearch``, ``snmpwalk``, ``onesixtyone``, ``ike_scan``,
  ``redis_cli_probe``, ``mongodb_probe`` (read-only enumeration of
  AD / SNMP / IKE / DB pre-auth surfaces). After ARG-058 / T03, the 10
  §4.17 network-cohort tools run inside ``argus-kali-network:latest``
  (carved out from ``argus-kali-web`` so the heavier web image stays
  focused on HTTP-stack tooling while the dedicated network image
  bundles every Impacket / BloodHound / SNMP / IKE / Redis / Mongo CLI
  ARGUS supports) behind ``auth-bruteforce`` (the only existing
  policy that opens the specialised AD / SNMP / IKE / DB port set).

* §4.18 — **Binary / mobile / firmware analysis** (5 tools):
  ``mobsf_api`` (mobile static analysis), ``apktool`` (APK
  reverse-engineering), ``jadx`` (Java/Dalvik decompiler), ``binwalk``
  (firmware extraction), ``radare2_info`` (ELF / PE static triage).
  All run inside ``argus-kali-binary:latest`` behind
  ``offline-no-egress`` so a malicious sample cannot phone home or
  exfiltrate the operator's analysis bundle.  Approval-free across
  the board (no live target, no egress).

* §4.19 — **Browser / headless / OAST verifiers** (5 tools):
  ``playwright_runner`` (generic scenario runner), ``puppeteer_screens``
  (passive screenshot harvester), ``chrome_csp_probe``, ``cors_probe``,
  ``cookie_probe`` (targeted misconfig probes for CSP / CORS / cookies).
  All run inside ``argus-kali-browser:latest``.  ``playwright_runner`` is
  approval-gated (cycle-2 reviewer H1 — its operator-supplied
  ``{script}`` can drive arbitrary state-changing browser actions:
  form submissions, OAuth consent flows, multi-step DOM mutations);
  the four targeted probes (puppeteer_screens / chrome_csp_probe /
  cors_probe / cookie_probe) stay approval-free.  The deeper
  exploitation paths (XSS via headless, prototype pollution chains)
  sit on the Cycle 3 backlog.

Invariants pinned (any drift fails CI):

* The catalog contains exactly the 20 ARG-019 tool ids — no more, no
  less.
* Each tool has the pinned ``category``, ``phase``, ``image``,
  ``network_policy``, ``risk_level``, ``requires_approval`` and
  ``parse_strategy`` — no silent flips.
* Cohorts run on the right base image (network → ``argus-kali-network``
  per ARG-058 / T03; binary → ``argus-kali-binary``; browser →
  ``argus-kali-browser``).
* Network policy choice matches behaviour:
  - All §4.17 entries → ``auth-bruteforce``.
  - All §4.18 entries → ``offline-no-egress``.
  - §4.19 ``puppeteer_screens`` → ``recon-passive`` (passive
    screenshot harvester); the rest → ``recon-active-tcp``.
* ``requires_approval=true`` for the four §4.17 tools that produce
  credential material on the wire (``responder``, ``ntlmrelayx``,
  ``impacket_secretsdump``, ``bloodhound_python``) plus the §4.19
  generic browser scenario runner (``playwright_runner`` — cycle-2
  reviewer H1 fix; its operator-supplied ``{script}`` can perform
  arbitrary state-changing actions).
* CWE / OWASP-WSTG hints are non-empty (catalog hygiene).
* Every ``command_template`` argv is shell-meta-free at the **token**
  level outside the documented ``sh -c`` static-redirection
  wrappers.
* Every YAML declares at least one evidence artefact under ``/out``.
* Every ``description`` references the matching Backlog §4.x section
  and the ARG-019 cycle marker so the catalog stays self-documenting.
* Every ``parse_strategy`` value is a known
  :class:`~src.sandbox.adapter_base.ParseStrategy` member.
* Every ``network_policy.name`` is a known template in
  :data:`src.sandbox.network_policies.NETWORK_POLICY_NAMES` (defence
  in depth on top of YAML schema validation).
* Every command_template references the ARG-019-specific input
  placeholders (``interface``, ``binary``, ``file``, ``script``,
  ``domain``, ``basedn``, ``user``, ``pass``) the templating layer
  has been extended to whitelist.

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
from src.sandbox.adapter_base import (
    ParseStrategy,
    ToolCategory,
    ToolDescriptor,
)
from src.sandbox.network_policies import NETWORK_POLICY_NAMES


# ---------------------------------------------------------------------------
# Cohort definitions — pinned hard so a silent drop / addition breaks CI.
# ---------------------------------------------------------------------------


NETWORK_PROTOCOL_TOOL_IDS: Final[tuple[str, ...]] = (
    "responder",
    "ntlmrelayx",
    "impacket_secretsdump",
    "bloodhound_python",
    "ldapsearch",
    "snmpwalk",
    "onesixtyone",
    "ike_scan",
    "redis_cli_probe",
    "mongodb_probe",
)


BINARY_TOOL_IDS: Final[tuple[str, ...]] = (
    "mobsf_api",
    "apktool",
    "jadx",
    "binwalk",
    "radare2_info",
)


BROWSER_TOOL_IDS: Final[tuple[str, ...]] = (
    "playwright_runner",
    "puppeteer_screens",
    "chrome_csp_probe",
    "cors_probe",
    "cookie_probe",
)


ARG019_TOOL_IDS: Final[tuple[str, ...]] = (
    *NETWORK_PROTOCOL_TOOL_IDS,
    *BINARY_TOOL_IDS,
    *BROWSER_TOOL_IDS,
)


# ---------------------------------------------------------------------------
# Per-tool pinning maps — every map must cover every ARG-019 tool id.
# ---------------------------------------------------------------------------


CATEGORY_BY_TOOL: Final[dict[str, ToolCategory]] = {
    # §4.17 — wire-level network probes; credential-extraction
    # post-exploitation tools inherit the NETWORK category from their
    # transport rather than promoting to EXPLOIT (Cycle 3 may introduce
    # a dedicated CREDENTIAL category once the matching scheduling
    # profile lands).
    "responder": ToolCategory.NETWORK,
    "ntlmrelayx": ToolCategory.NETWORK,
    "impacket_secretsdump": ToolCategory.NETWORK,
    "bloodhound_python": ToolCategory.NETWORK,
    "ldapsearch": ToolCategory.NETWORK,
    "snmpwalk": ToolCategory.NETWORK,
    "onesixtyone": ToolCategory.NETWORK,
    "ike_scan": ToolCategory.NETWORK,
    "redis_cli_probe": ToolCategory.NETWORK,
    "mongodb_probe": ToolCategory.NETWORK,
    # §4.18 — binary analysis category lands in ARG-019.
    "mobsf_api": ToolCategory.BINARY,
    "apktool": ToolCategory.BINARY,
    "jadx": ToolCategory.BINARY,
    "binwalk": ToolCategory.BINARY,
    "radare2_info": ToolCategory.BINARY,
    # §4.19 — dedicated browser category.
    "playwright_runner": ToolCategory.BROWSER,
    "puppeteer_screens": ToolCategory.BROWSER,
    "chrome_csp_probe": ToolCategory.BROWSER,
    "cors_probe": ToolCategory.BROWSER,
    "cookie_probe": ToolCategory.BROWSER,
}


PHASE_BY_TOOL: Final[dict[str, ScanPhase]] = {
    # §4.17 — phase split.
    "responder": ScanPhase.EXPLOITATION,
    "ntlmrelayx": ScanPhase.EXPLOITATION,
    "impacket_secretsdump": ScanPhase.POST_EXPLOITATION,
    "bloodhound_python": ScanPhase.POST_EXPLOITATION,
    "ldapsearch": ScanPhase.RECON,
    "snmpwalk": ScanPhase.RECON,
    "onesixtyone": ScanPhase.RECON,
    "ike_scan": ScanPhase.RECON,
    "redis_cli_probe": ScanPhase.RECON,
    "mongodb_probe": ScanPhase.RECON,
    # §4.18 — every entry is offline static analysis.
    "mobsf_api": ScanPhase.VULN_ANALYSIS,
    "apktool": ScanPhase.VULN_ANALYSIS,
    "jadx": ScanPhase.VULN_ANALYSIS,
    "binwalk": ScanPhase.VULN_ANALYSIS,
    "radare2_info": ScanPhase.VULN_ANALYSIS,
    # §4.19 — passive screenshot is recon; everything else is
    # vuln_analysis.
    "playwright_runner": ScanPhase.VULN_ANALYSIS,
    "puppeteer_screens": ScanPhase.RECON,
    "chrome_csp_probe": ScanPhase.VULN_ANALYSIS,
    "cors_probe": ScanPhase.VULN_ANALYSIS,
    "cookie_probe": ScanPhase.VULN_ANALYSIS,
}


IMAGE_BY_TOOL: Final[dict[str, str]] = {
    # §4.17 — ARG-058 / T03: relocated from ``argus-kali-web`` to the
    # dedicated ``argus-kali-network`` image which carves out the
    # Impacket / BloodHound / SNMP / IKE / Redis / Mongo CLI footprint
    # so the heavier web image stays focused on HTTP-stack tooling.
    "responder": "argus-kali-network:latest",
    "ntlmrelayx": "argus-kali-network:latest",
    "impacket_secretsdump": "argus-kali-network:latest",
    "bloodhound_python": "argus-kali-network:latest",
    "ldapsearch": "argus-kali-network:latest",
    "snmpwalk": "argus-kali-network:latest",
    "onesixtyone": "argus-kali-network:latest",
    "ike_scan": "argus-kali-network:latest",
    "redis_cli_probe": "argus-kali-network:latest",
    "mongodb_probe": "argus-kali-network:latest",
    # §4.18 — dedicated binary-analysis image.
    "mobsf_api": "argus-kali-binary:latest",
    "apktool": "argus-kali-binary:latest",
    "jadx": "argus-kali-binary:latest",
    "binwalk": "argus-kali-binary:latest",
    "radare2_info": "argus-kali-binary:latest",
    # §4.19 — Chromium + Playwright runtime image.
    "playwright_runner": "argus-kali-browser:latest",
    "puppeteer_screens": "argus-kali-browser:latest",
    "chrome_csp_probe": "argus-kali-browser:latest",
    "cors_probe": "argus-kali-browser:latest",
    "cookie_probe": "argus-kali-browser:latest",
}


NETWORK_POLICY_BY_TOOL: Final[dict[str, str]] = {
    # §4.17 — every entry sits behind auth-bruteforce.
    "responder": "auth-bruteforce",
    "ntlmrelayx": "auth-bruteforce",
    "impacket_secretsdump": "auth-bruteforce",
    "bloodhound_python": "auth-bruteforce",
    "ldapsearch": "auth-bruteforce",
    "snmpwalk": "auth-bruteforce",
    "onesixtyone": "auth-bruteforce",
    "ike_scan": "auth-bruteforce",
    "redis_cli_probe": "auth-bruteforce",
    "mongodb_probe": "auth-bruteforce",
    # §4.18 — every entry runs offline against operator-mounted samples.
    "mobsf_api": "offline-no-egress",
    "apktool": "offline-no-egress",
    "jadx": "offline-no-egress",
    "binwalk": "offline-no-egress",
    "radare2_info": "offline-no-egress",
    # §4.19 — passive screenshot is recon-passive; everything else
    # talks to the in-scope target over HTTP/HTTPS.
    "playwright_runner": "recon-active-tcp",
    "puppeteer_screens": "recon-passive",
    "chrome_csp_probe": "recon-active-tcp",
    "cors_probe": "recon-active-tcp",
    "cookie_probe": "recon-active-tcp",
}


RISK_LEVEL_BY_TOOL: Final[dict[str, RiskLevel]] = {
    # §4.17 — active poisoning + credential extraction = HIGH;
    # authenticated AD enumeration = MEDIUM (writes session traces);
    # read-only enumerators = LOW.
    "responder": RiskLevel.HIGH,
    "ntlmrelayx": RiskLevel.HIGH,
    "impacket_secretsdump": RiskLevel.HIGH,
    "bloodhound_python": RiskLevel.MEDIUM,
    "ldapsearch": RiskLevel.LOW,
    "snmpwalk": RiskLevel.LOW,
    "onesixtyone": RiskLevel.LOW,
    "ike_scan": RiskLevel.LOW,
    "redis_cli_probe": RiskLevel.LOW,
    "mongodb_probe": RiskLevel.LOW,
    # §4.18 — every entry is LOW (offline static analysis).
    "mobsf_api": RiskLevel.LOW,
    "apktool": RiskLevel.LOW,
    "jadx": RiskLevel.LOW,
    "binwalk": RiskLevel.LOW,
    "radare2_info": RiskLevel.LOW,
    # §4.19 — passive screenshot harvester = PASSIVE; the generic
    # scenario runner = MEDIUM (cycle-2 reviewer H1: arbitrary
    # state-changing browser actions); the targeted misconfig probes
    # (header/CSP/cookie) stay LOW because they don't fire payloads.
    "playwright_runner": RiskLevel.MEDIUM,
    "puppeteer_screens": RiskLevel.PASSIVE,
    "chrome_csp_probe": RiskLevel.LOW,
    "cors_probe": RiskLevel.LOW,
    "cookie_probe": RiskLevel.LOW,
}


# Approval-gated set: the four §4.17 tools that produce credential
# material on the wire (active poisoning + credential extraction +
# authenticated AD enumeration) plus the §4.19 generic browser
# scenario runner (cycle-2 reviewer H1 fix — arbitrary state-changing
# browser actions warrant operator sign-off).  The remaining §4.18 /
# §4.19 entries stay approval-free in Cycle 2.
APPROVAL_REQUIRED: Final[frozenset[str]] = frozenset(
    {
        "responder",
        "ntlmrelayx",
        "impacket_secretsdump",
        "bloodhound_python",
        "playwright_runner",
    }
)


PARSE_STRATEGY_BY_TOOL: Final[dict[str, ParseStrategy]] = {
    # §4.17 — every entry is text_lines (full parsers deferred to
    # Cycle 3; the dispatch layer falls through to ``unmapped_tool``).
    "responder": ParseStrategy.TEXT_LINES,
    "ntlmrelayx": ParseStrategy.TEXT_LINES,
    "impacket_secretsdump": ParseStrategy.TEXT_LINES,
    "bloodhound_python": ParseStrategy.TEXT_LINES,
    "ldapsearch": ParseStrategy.TEXT_LINES,
    "snmpwalk": ParseStrategy.TEXT_LINES,
    "onesixtyone": ParseStrategy.TEXT_LINES,
    "ike_scan": ParseStrategy.TEXT_LINES,
    "redis_cli_probe": ParseStrategy.TEXT_LINES,
    "mongodb_probe": ParseStrategy.TEXT_LINES,
    # §4.18 — JSON-emitting tools (mobsf, radare2) get json_object;
    # the rest are text_lines (decompiler logs).
    "mobsf_api": ParseStrategy.JSON_OBJECT,
    "apktool": ParseStrategy.TEXT_LINES,
    "jadx": ParseStrategy.TEXT_LINES,
    "binwalk": ParseStrategy.TEXT_LINES,
    "radare2_info": ParseStrategy.JSON_OBJECT,
    # §4.19 — every browser tool emits a structured JSON envelope
    # (parsers deferred to Cycle 3).
    "playwright_runner": ParseStrategy.JSON_OBJECT,
    "puppeteer_screens": ParseStrategy.JSON_OBJECT,
    "chrome_csp_probe": ParseStrategy.JSON_OBJECT,
    "cors_probe": ParseStrategy.JSON_OBJECT,
    "cookie_probe": ParseStrategy.JSON_OBJECT,
}


# Per-tool minimum default_timeout_s — heavier samples / live AD
# operations get longer windows.
DEFAULT_TIMEOUT_S_BY_TOOL: Final[dict[str, int]] = {
    # §4.17 — active poisoners run long sessions; read-only probes
    # finish in single-shot timeframes.
    "responder": 1800,
    "ntlmrelayx": 1800,
    "impacket_secretsdump": 1800,
    "bloodhound_python": 1800,
    "ldapsearch": 600,
    "snmpwalk": 600,
    "onesixtyone": 600,
    "ike_scan": 600,
    "redis_cli_probe": 300,
    "mongodb_probe": 300,
    # §4.18 — decompilers get the longest windows.
    "mobsf_api": 1800,
    "apktool": 900,
    "jadx": 1800,
    "binwalk": 1800,
    "radare2_info": 600,
    # §4.19 — Playwright scenarios run long; misconfig probes finish
    # quickly; passive screenshot is mid-range (network-idle wait).
    "playwright_runner": 1800,
    "puppeteer_screens": 900,
    "chrome_csp_probe": 600,
    "cors_probe": 600,
    "cookie_probe": 600,
}


# Shell metacharacters that must NOT appear in a YAML argv outside the
# documented ``sh -c`` static-redirection wrappers.
SHELL_METACHARS: Final[tuple[str, ...]] = (
    ";",
    "|",
    "&&",
    "||",
    "&",
    "`",
    "$(",
    "\n",
    "\r",
)


# Disallow shell binaries as the first argv token, with the documented
# exception of `sh -c` static-redirection wrappers used by tools whose
# upstream CLI writes structured output only to stdout. The wrapper is
# fully argv-templated and uses no untrusted placeholders.
FORBIDDEN_FIRST_TOKENS: Final[frozenset[str]] = frozenset(
    {"bash", "/bin/bash", "zsh", "ksh", "powershell", "pwsh"}
)


# Every ARG-019 tool currently uses the ``sh -c`` wrapper for stdout
# redirection / log tee-ing — the wrapper is fully argv-templated
# through allow-listed placeholders; the templating layer rejects
# unknown placeholders and shell-metachar-bearing arguments.
SH_WRAPPED_TOOLS: Final[frozenset[str]] = frozenset(ARG019_TOOL_IDS)


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


def test_inventory_contains_exactly_20_tools() -> None:
    """The ARG-019 batch is exactly 20 tools — drift breaks Backlog
    §4.17–§4.19 alignment and the EXPECTED_TOOLS / EXPECTED_TOOL_IDS
    pins in ``test_tool_catalog_load.py`` and
    ``test_yaml_schema_per_tool.py``.
    """
    assert len(ARG019_TOOL_IDS) == 20
    assert len(set(ARG019_TOOL_IDS)) == 20


def test_per_cohort_inventory_sizes() -> None:
    """The per-cohort inventories follow the cycle plan: 10 / 5 / 5."""
    assert len(NETWORK_PROTOCOL_TOOL_IDS) == 10
    assert len(BINARY_TOOL_IDS) == 5
    assert len(BROWSER_TOOL_IDS) == 5
    # No cross-cohort duplicates.
    assert (
        set(NETWORK_PROTOCOL_TOOL_IDS) & set(BINARY_TOOL_IDS) & set(BROWSER_TOOL_IDS)
    ) == set()


def test_per_tool_taxonomy_maps_cover_every_tool() -> None:
    """Every per-tool map covers exactly the ARG-019 batch — no gaps,
    no extras.
    """
    expected = set(ARG019_TOOL_IDS)
    assert set(CATEGORY_BY_TOOL.keys()) == expected
    assert set(PHASE_BY_TOOL.keys()) == expected
    assert set(IMAGE_BY_TOOL.keys()) == expected
    assert set(NETWORK_POLICY_BY_TOOL.keys()) == expected
    assert set(RISK_LEVEL_BY_TOOL.keys()) == expected
    assert set(PARSE_STRATEGY_BY_TOOL.keys()) == expected
    assert set(DEFAULT_TIMEOUT_S_BY_TOOL.keys()) == expected
    assert APPROVAL_REQUIRED.issubset(expected)


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_yaml_file_exists(catalog_dir: Path, tool_id: str) -> None:
    """Every ARG-019 tool ships a YAML descriptor under config/tools/."""
    yaml_path = catalog_dir / f"{tool_id}.yaml"
    assert yaml_path.is_file(), f"missing YAML for ARG-019 tool {tool_id}"


# ---------------------------------------------------------------------------
# Category / phase invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_category_matches_pin(catalog_dir: Path, tool_id: str) -> None:
    """Each tool ships the pinned :class:`ToolCategory`."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = CATEGORY_BY_TOOL[tool_id]
    assert descriptor.category is expected, (
        f"{tool_id}: category={descriptor.category.value!r} "
        f"diverges from pinned {expected.value!r}"
    )


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_phase_matches_pin(catalog_dir: Path, tool_id: str) -> None:
    """Each tool runs in the pinned :class:`ScanPhase`."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = PHASE_BY_TOOL[tool_id]
    assert descriptor.phase is expected, (
        f"{tool_id}: phase={descriptor.phase.value!r} "
        f"diverges from pinned {expected.value!r}"
    )


# ---------------------------------------------------------------------------
# Image namespace
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_image_matches_per_cohort_pin(catalog_dir: Path, tool_id: str) -> None:
    """Network → web image (Cycle 2 reuse), binary → binary image,
    browser → browser image.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = IMAGE_BY_TOOL[tool_id]
    assert descriptor.image == expected, (
        f"{tool_id}: image={descriptor.image!r} diverges from pinned {expected!r}"
    )


# ---------------------------------------------------------------------------
# Network policy invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_network_policy_matches_per_tool_pin(catalog_dir: Path, tool_id: str) -> None:
    """Each tool ships the documented network policy for its access pattern."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = NETWORK_POLICY_BY_TOOL[tool_id]
    assert descriptor.network_policy.name == expected, (
        f"{tool_id}: network_policy={descriptor.network_policy.name!r} "
        f"diverges from pinned {expected!r}"
    )


@pytest.mark.parametrize("tool_id", BINARY_TOOL_IDS)
def test_binary_tools_egress_allowlist_is_empty(
    catalog_dir: Path, tool_id: str
) -> None:
    """Every §4.18 entry MUST ship an empty ``egress_allowlist`` because
    they sit behind ``offline-no-egress`` — any populated allowlist
    would silently re-introduce egress for malicious samples.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.network_policy.egress_allowlist == [], (
        f"{tool_id}: §4.18 tools must ship an empty egress_allowlist; "
        f"got {descriptor.network_policy.egress_allowlist!r}"
    )


# ---------------------------------------------------------------------------
# Risk level + approval gating
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_risk_level_matches_pin(catalog_dir: Path, tool_id: str) -> None:
    """Risk level matches the documented behaviour profile."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = RISK_LEVEL_BY_TOOL[tool_id]
    assert descriptor.risk_level is expected, (
        f"{tool_id}: risk_level={descriptor.risk_level.value!r} "
        f"diverges from pinned {expected.value!r}"
    )


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_approval_matches_pinned_set(catalog_dir: Path, tool_id: str) -> None:
    """``requires_approval=True`` only for the four §4.17 active-credential
    tools (responder / ntlmrelayx / impacket_secretsdump /
    bloodhound_python).  Every §4.18 / §4.19 entry stays approval-free.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = tool_id in APPROVAL_REQUIRED
    assert descriptor.requires_approval is expected, (
        f"{tool_id}: requires_approval={descriptor.requires_approval} "
        f"contradicts ARG-019 approval matrix; expected={expected}"
    )


@pytest.mark.parametrize(
    "tool_id",
    BINARY_TOOL_IDS + tuple(t for t in BROWSER_TOOL_IDS if t != "playwright_runner"),
)
def test_binary_and_browser_tools_are_approval_free(
    catalog_dir: Path, tool_id: str
) -> None:
    """Defence in depth on top of the per-tool pin: no §4.18 entry — and
    no §4.19 entry except ``playwright_runner`` (cycle-2 reviewer H1) —
    may opt into ``requires_approval=true``.  The deeper exploit paths
    (XSS via headless, prototype pollution chains) sit on the Cycle 3
    backlog and will land with their own gating.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.requires_approval is False, (
        f"{tool_id}: §4.18 / §4.19 (excl. playwright_runner) "
        f"tools stay approval-free in Cycle 2"
    )


# ---------------------------------------------------------------------------
# Parser dispatch strategy split
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_parse_strategy_matches_per_tool_split(catalog_dir: Path, tool_id: str) -> None:
    """``parse_strategy`` must match the per-tool pinning (no silent flip)."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = PARSE_STRATEGY_BY_TOOL[tool_id]
    assert descriptor.parse_strategy is expected, (
        f"{tool_id}: parse_strategy={descriptor.parse_strategy.value!r} "
        f"diverges from pinned {expected.value!r}"
    )


# ---------------------------------------------------------------------------
# Evidence + CWE/OWASP fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_cwe_hints_non_empty(catalog_dir: Path, tool_id: str) -> None:
    """Every ARG-019 tool ships at least one CWE hint."""
    payload = yaml.safe_load((catalog_dir / f"{tool_id}.yaml").read_bytes())
    assert "cwe_hints" in payload, f"{tool_id}.yaml missing the cwe_hints key"
    assert isinstance(payload["cwe_hints"], list), (
        f"{tool_id}.yaml: cwe_hints must be a list"
    )
    assert payload["cwe_hints"], f"{tool_id}.yaml: cwe_hints must be non-empty"


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_owasp_wstg_non_empty(catalog_dir: Path, tool_id: str) -> None:
    """Every ARG-019 tool ships at least one OWASP-WSTG hint."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.owasp_wstg, (
        f"{tool_id}: owasp_wstg must be non-empty for ARG-019 tools"
    )


# ---------------------------------------------------------------------------
# Resource limits + per-tool timeout floor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_default_timeout_matches_per_tool_floor(
    catalog_dir: Path, tool_id: str
) -> None:
    """Every ARG-019 tool floors at the per-tool minimum from the cycle plan."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = DEFAULT_TIMEOUT_S_BY_TOOL[tool_id]
    assert descriptor.default_timeout_s >= expected, (
        f"{tool_id}: default_timeout_s={descriptor.default_timeout_s}s "
        f"below floor of {expected}s"
    )


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_command_template_first_token_is_real_binary(
    catalog_dir: Path, tool_id: str
) -> None:
    """The first argv token is the real binary (or the documented sh wrapper)."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.command_template, f"{tool_id}: command_template must be non-empty"
    first_token = descriptor.command_template[0]
    assert first_token not in FORBIDDEN_FIRST_TOKENS, (
        f"{tool_id}: command_template[0]={first_token!r} is a forbidden "
        f"shell — only ``sh -c`` static-redirection wrappers are allowed"
    )
    if first_token in {"sh", "/bin/sh"}:
        assert tool_id in SH_WRAPPED_TOOLS, (
            f"{tool_id}: must NOT shell-wrap; only "
            f"{sorted(SH_WRAPPED_TOOLS)} are allowed to use ``sh -c`` "
            f"static-redirection wrappers"
        )


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_sh_wrapped_tools_use_dash_c_form(catalog_dir: Path, tool_id: str) -> None:
    """Every ARG-019 tool that ships an ``sh`` first token MUST use the
    canonical ``["sh", "-c", "<single-payload>"]`` form so the
    redirection payload remains a single, reviewable static string and
    no further argv expansion happens.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    if descriptor.command_template[0] not in {"sh", "/bin/sh"}:
        pytest.skip(f"{tool_id} does not ship an sh wrapper")
    assert len(descriptor.command_template) == 3, (
        f"{tool_id}: sh-wrapped tools MUST be exactly 3 tokens "
        f"['sh', '-c', '<payload>']; got "
        f"{len(descriptor.command_template)} tokens"
    )
    assert descriptor.command_template[1] == "-c", (
        f"{tool_id}: sh-wrapped tools MUST pass '-c' as argv[1]; "
        f"got {descriptor.command_template[1]!r}"
    )


# ---------------------------------------------------------------------------
# Description self-documentation invariant
# ---------------------------------------------------------------------------


_BACKLOG_SECTION_BY_COHORT: Final[dict[str, str]] = {
    **{tid: "§4.17" for tid in NETWORK_PROTOCOL_TOOL_IDS},
    **{tid: "§4.18" for tid in BINARY_TOOL_IDS},
    **{tid: "§4.19" for tid in BROWSER_TOOL_IDS},
}


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_description_references_backlog_section(
    catalog_dir: Path, tool_id: str
) -> None:
    """Description references the matching Backlog §4.17/§4.18/§4.19
    section so future readers can trace the YAML back to the cycle plan.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected_section = _BACKLOG_SECTION_BY_COHORT[tool_id]
    assert expected_section in descriptor.description, (
        f"{tool_id}: description must reference Backlog "
        f"{expected_section} for traceability"
    )


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_description_marks_arg019_cycle(catalog_dir: Path, tool_id: str) -> None:
    """Every ARG-019 description carries the ``ARG-019`` cycle marker so
    grepping the catalog can list every tool that landed in this batch.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert "ARG-019" in descriptor.description, (
        f"{tool_id}: description must reference the ARG-019 cycle marker"
    )


# ---------------------------------------------------------------------------
# Targeting invariant — every ARG-019 tool consumes a sanctioned input
# placeholder so the templating layer can reject unknown ones at render
# time. Pinned per-tool so a YAML edit cannot silently swap input
# source (e.g. an offline-only tool quietly switching to {url}).
# ---------------------------------------------------------------------------


REQUIRED_INPUT_PLACEHOLDERS: Final[dict[str, frozenset[str]]] = {
    # §4.17 — wire-level network probes.
    "responder": frozenset({"interface"}),
    "ntlmrelayx": frozenset({"host"}),
    "impacket_secretsdump": frozenset({"domain", "user", "pass", "dc"}),
    "bloodhound_python": frozenset({"domain", "user", "pass", "dc"}),
    "ldapsearch": frozenset({"host", "basedn"}),
    "snmpwalk": frozenset({"host", "community"}),
    "onesixtyone": frozenset({"wordlist", "in_dir"}),
    "ike_scan": frozenset({"host"}),
    "redis_cli_probe": frozenset({"host", "port"}),
    "mongodb_probe": frozenset({"host", "port"}),
    # §4.18 — every entry consumes an operator-mounted sample.
    "mobsf_api": frozenset({"binary"}),
    "apktool": frozenset({"binary"}),
    "jadx": frozenset({"binary"}),
    "binwalk": frozenset({"file"}),
    "radare2_info": frozenset({"binary"}),
    # §4.19 — browser tools all take {url}; the runner additionally
    # takes {script}.
    "playwright_runner": frozenset({"script", "url"}),
    "puppeteer_screens": frozenset({"url"}),
    "chrome_csp_probe": frozenset({"url"}),
    "cors_probe": frozenset({"url"}),
    "cookie_probe": frozenset({"url"}),
}


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_command_template_references_required_input_placeholders(
    catalog_dir: Path, tool_id: str
) -> None:
    """Each tool's argv references its pinned input placeholder set.

    Locks the contract from the catalog side so edits to a YAML cannot
    silently swap its input source (e.g. a network probe quietly
    switching from {host} to {url} would slip past the templating layer
    if both are allow-listed but break the upstream binary's CLI).
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    rendered = " ".join(descriptor.command_template)
    expected = REQUIRED_INPUT_PLACEHOLDERS[tool_id]
    for placeholder in expected:
        assert "{" + placeholder + "}" in rendered, (
            f"{tool_id}: command_template must reference "
            f"{{{placeholder}}} (pinned input set: {sorted(expected)})"
        )


@pytest.mark.parametrize("tool_id", ARG019_TOOL_IDS)
def test_command_template_writes_into_out_dir(catalog_dir: Path, tool_id: str) -> None:
    """Every ARG-019 tool MUST direct its output into ``{out_dir}`` so
    the sandbox bind-mount captures the artefact stream.  Tools that
    only write to stdout would lose evidence the moment the container
    exits.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    rendered = " ".join(descriptor.command_template)
    assert "{out_dir}" in rendered, (
        f"{tool_id}: command_template must write into {{out_dir}} so "
        f"the sandbox captures evidence"
    )


# ---------------------------------------------------------------------------
# Cohort-level invariants — keep the §4.17 / §4.18 / §4.19 contract
# explicit so a regression that flips the entire cohort surfaces
# immediately (rather than only failing the per-tool tests above).
# ---------------------------------------------------------------------------


def test_network_protocol_cohort_uses_auth_bruteforce_uniformly() -> None:
    """Every §4.17 tool sits behind ``auth-bruteforce`` (cohort-level
    invariant on top of the per-tool pin).
    """
    for tool_id in NETWORK_PROTOCOL_TOOL_IDS:
        assert NETWORK_POLICY_BY_TOOL[tool_id] == "auth-bruteforce"


def test_binary_cohort_uses_offline_no_egress_uniformly() -> None:
    """Every §4.18 tool sits behind ``offline-no-egress`` (cohort-level
    invariant on top of the per-tool pin).
    """
    for tool_id in BINARY_TOOL_IDS:
        assert NETWORK_POLICY_BY_TOOL[tool_id] == "offline-no-egress"


def test_binary_cohort_uses_binary_image_uniformly() -> None:
    """Every §4.18 tool runs in ``argus-kali-binary:latest`` (cohort
    invariant — no leaks into the heavier web/cloud images).
    """
    for tool_id in BINARY_TOOL_IDS:
        assert IMAGE_BY_TOOL[tool_id] == "argus-kali-binary:latest"


def test_browser_cohort_uses_browser_image_uniformly() -> None:
    """Every §4.19 tool runs in ``argus-kali-browser:latest`` (Chromium
    + Playwright runtime).
    """
    for tool_id in BROWSER_TOOL_IDS:
        assert IMAGE_BY_TOOL[tool_id] == "argus-kali-browser:latest"


def test_arg019_approval_set_membership() -> None:
    """The approval-gated set lives inside §4.17 (four credential-noisy
    tools) plus exactly one §4.19 entry: ``playwright_runner``
    (cycle-2 reviewer H1 — its operator-supplied ``{script}`` can
    perform arbitrary state-changing browser actions, OAuth flows,
    form submissions, file uploads).  No §4.18 binary-analysis entry
    requires approval in Cycle 2 (offline static analysis only).
    """
    network_subset = APPROVAL_REQUIRED & set(NETWORK_PROTOCOL_TOOL_IDS)
    browser_subset = APPROVAL_REQUIRED & set(BROWSER_TOOL_IDS)
    assert network_subset == set(NETWORK_PROTOCOL_TOOL_IDS) & APPROVAL_REQUIRED
    assert (APPROVAL_REQUIRED & set(BINARY_TOOL_IDS)) == set()
    assert browser_subset == frozenset({"playwright_runner"})
    assert APPROVAL_REQUIRED == network_subset | browser_subset


def test_arg019_total_count_matches_catalog_target() -> None:
    """ARG-019 closes the long-term Backlog §4 catalog at 157 tools
    (137 from ARG-001..ARG-018 + exactly 20 ARG-019 entries).  Drift
    here is the canary that something has been silently added to or
    removed from the §4.17/§4.18/§4.19 cohorts.
    """
    assert len(ARG019_TOOL_IDS) == 20
    assert len(set(ARG019_TOOL_IDS)) == 20
