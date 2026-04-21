"""Per-§4.11 / §4.12 / §4.13 invariant tests for the ARG-017 YAML batch.

Sister suite to ``test_yaml_xss_semantics.py`` (§4.10) and
``test_yaml_sqli_semantics.py`` (§4.9). This file pins the cohort
contracts for the three batches ARG-017 ships:

* §4.11 SSRF/OAST (5 tools) — interactsh / oastify / ssrfmap / gopherus
  / oast_dns_probe.
* §4.12 Auth/bruteforce (10 tools) — hydra / medusa / patator / ncrack /
  crackmapexec / kerbrute / smbclient / snmp_check / evil_winrm /
  impacket_examples.
* §4.13 Hash/crypto (5 tools) — hashcat / john / ophcrack / hashid /
  hash_analyzer.

Invariants pinned (any drift fails CI):

* The batch contains exactly the documented tool ids — no more, no less.
* Network policy split: §4.11 OAST tools either ride ``oast-egress``
  (active receivers + DNS probe) or ``offline-no-egress`` (gopherus —
  payload generator, no network); §4.12 tools all ride
  ``auth-bruteforce``; §4.13 tools all ride ``offline-no-egress``.
* Image namespace (post-ARG-058 / T03): §4.11 OAST →
  ``argus-kali-web:latest``; §4.12 auth/brute → split between
  ``argus-kali-web:latest`` (hydra, medusa, ncrack, patator) and
  ``argus-kali-network:latest`` (crackmapexec, evil_winrm,
  impacket_examples, kerbrute, smbclient, snmp_check); §4.13 →
  ``argus-kali-cloud:latest`` (heavy-compute crackers).
* Phase split:
  - §4.11: vuln_analysis (every tool — OAST callbacks are evidence of
    SSRF in the vuln-analysis stage).
  - §4.12: split between recon (snmp_check), exploitation
    (hydra/medusa/patator/ncrack/crackmapexec/kerbrute/smbclient/
    impacket_examples) and post_exploitation (evil_winrm).
  - §4.13: post_exploitation (hash cracking only happens after a host
    is owned and credentials harvested).
* ``risk_level`` and ``requires_approval`` align with the documented
  destructiveness of each tool.
* CWE hints carry the cohort floor: §4.11 → CWE-918 (SSRF); §4.12 →
  CWE-287 (Authentication) or CWE-307 (Brute Force); §4.13 → CWE-916
  (Weak Hashing) or CWE-326 (Inadequate Crypto).
* OWASP WSTG hints align with the cohort: §4.11 → WSTG-INPV-19
  (SSRF / OOB); §4.12 → WSTG-ATHN-* (Authentication); §4.13 →
  WSTG-CRYP-* (Cryptography).
* ``parse_strategy`` is pinned per-tool.
* Argv contains no shell-meta in tokens (the ``sh -c`` pattern is
  allowed for the auth + hash tools that need stream redirection
  inside the container — same pattern used by the §4.1 recon
  tools).
* ``description`` references the originating Backlog §x.y for
  traceability.
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


# ---------------------------------------------------------------------------
# Tool-id inventories (hard-coded so silent shrink/grow breaks CI)
# ---------------------------------------------------------------------------


OAST_TOOL_IDS: Final[tuple[str, ...]] = (
    "interactsh_client",
    "oastify_client",
    "ssrfmap",
    "gopherus",
    "oast_dns_probe",
)


AUTH_TOOL_IDS: Final[tuple[str, ...]] = (
    "hydra",
    "medusa",
    "patator",
    "ncrack",
    "crackmapexec",
    "kerbrute",
    "smbclient",
    "snmp_check",
    "evil_winrm",
    "impacket_examples",
)


HASH_TOOL_IDS: Final[tuple[str, ...]] = (
    "hashcat",
    "john",
    "ophcrack",
    "hashid",
    "hash_analyzer",
)


ARG017_TOOL_IDS: Final[tuple[str, ...]] = (
    *OAST_TOOL_IDS,
    *AUTH_TOOL_IDS,
    *HASH_TOOL_IDS,
)


# ---------------------------------------------------------------------------
# Per-tool taxonomy maps. Pinned so a future YAML edit cannot silently
# flip a tool from one bucket to another.
# ---------------------------------------------------------------------------


PHASE_BY_TOOL: Final[dict[str, ScanPhase]] = {
    # §4.11 — every OAST tool stays in vuln_analysis (callbacks are
    # evidence of SSRF in the vuln-analysis stage).
    "interactsh_client": ScanPhase.VULN_ANALYSIS,
    "oastify_client": ScanPhase.VULN_ANALYSIS,
    "ssrfmap": ScanPhase.VULN_ANALYSIS,
    "gopherus": ScanPhase.VULN_ANALYSIS,
    "oast_dns_probe": ScanPhase.VULN_ANALYSIS,
    # §4.12 — recon for default-community SNMP, post_exploitation for
    # evil-winrm (interactive shell on the victim), exploitation for
    # everything else.
    "hydra": ScanPhase.EXPLOITATION,
    "medusa": ScanPhase.EXPLOITATION,
    "patator": ScanPhase.EXPLOITATION,
    "ncrack": ScanPhase.EXPLOITATION,
    "crackmapexec": ScanPhase.EXPLOITATION,
    "kerbrute": ScanPhase.EXPLOITATION,
    "smbclient": ScanPhase.EXPLOITATION,
    "snmp_check": ScanPhase.RECON,
    "evil_winrm": ScanPhase.POST_EXPLOITATION,
    "impacket_examples": ScanPhase.EXPLOITATION,
    # §4.13 — every cracker runs after credentials are in hand, so they
    # all live in post_exploitation.
    "hashcat": ScanPhase.POST_EXPLOITATION,
    "john": ScanPhase.POST_EXPLOITATION,
    "ophcrack": ScanPhase.POST_EXPLOITATION,
    "hashid": ScanPhase.POST_EXPLOITATION,
    "hash_analyzer": ScanPhase.POST_EXPLOITATION,
}


CATEGORY_BY_TOOL: Final[dict[str, ToolCategory]] = {
    # §4.11 — receivers are OAST; ssrfmap/gopherus are web_va (web
    # exploitation tooling); oast_dns_probe is a thin OAST canary.
    "interactsh_client": ToolCategory.OAST,
    "oastify_client": ToolCategory.OAST,
    "ssrfmap": ToolCategory.WEB_VA,
    "gopherus": ToolCategory.WEB_VA,
    "oast_dns_probe": ToolCategory.OAST,
    # §4.12 — uniformly auth.
    "hydra": ToolCategory.AUTH,
    "medusa": ToolCategory.AUTH,
    "patator": ToolCategory.AUTH,
    "ncrack": ToolCategory.AUTH,
    "crackmapexec": ToolCategory.AUTH,
    "kerbrute": ToolCategory.AUTH,
    "smbclient": ToolCategory.AUTH,
    "snmp_check": ToolCategory.AUTH,
    "evil_winrm": ToolCategory.AUTH,
    "impacket_examples": ToolCategory.AUTH,
    # §4.13 — hash crackers fall under MISC (no dedicated CRYPTO category
    # in :class:`ToolCategory` yet; CRYPTO appears only as a finding
    # category).
    "hashcat": ToolCategory.MISC,
    "john": ToolCategory.MISC,
    "ophcrack": ToolCategory.MISC,
    "hashid": ToolCategory.MISC,
    "hash_analyzer": ToolCategory.MISC,
}


IMAGE_BY_TOOL: Final[dict[str, str]] = {
    # §4.11 — OAST + SSRF tooling lives in the standard web image.
    **{tool_id: "argus-kali-web:latest" for tool_id in OAST_TOOL_IDS},
    # §4.12 — auth/brute split per ARG-058 / T03: the 4 generic
    # HTTP/HTTPS-surface brute-forcers stay on ``argus-kali-web``; the
    # 6 AD / SMB / SNMP / Kerberos / WinRM probes moved to the dedicated
    # ``argus-kali-network`` image carved out from the heavier web one.
    **{
        "hydra": "argus-kali-web:latest",
        "medusa": "argus-kali-web:latest",
        "ncrack": "argus-kali-web:latest",
        "patator": "argus-kali-web:latest",
        "crackmapexec": "argus-kali-network:latest",
        "evil_winrm": "argus-kali-network:latest",
        "impacket_examples": "argus-kali-network:latest",
        "kerbrute": "argus-kali-network:latest",
        "smbclient": "argus-kali-network:latest",
        "snmp_check": "argus-kali-network:latest",
    },
    # §4.13 — hash crackers live in the heavy-compute "cloud" image.
    **{tool_id: "argus-kali-cloud:latest" for tool_id in HASH_TOOL_IDS},
}


# Lock-step guard: every §4.12 auth tool MUST have an explicit per-tool
# image pin so an ARG-058-style migration cannot silently drop a tool.
assert {tid for tid in IMAGE_BY_TOOL if tid in AUTH_TOOL_IDS} == set(AUTH_TOOL_IDS), (
    "drift: IMAGE_BY_TOOL must cover exactly AUTH_TOOL_IDS — see ARG-058"
)


NETWORK_POLICY_BY_TOOL: Final[dict[str, str]] = {
    # §4.11 — receivers + DNS probe ride oast-egress; gopherus is an
    # offline payload generator (no network).
    "interactsh_client": "oast-egress",
    "oastify_client": "oast-egress",
    "ssrfmap": "oast-egress",
    "gopherus": "offline-no-egress",
    "oast_dns_probe": "oast-egress",
    # §4.12 — auth-bruteforce policy for every tool.
    **{tool_id: "auth-bruteforce" for tool_id in AUTH_TOOL_IDS},
    # §4.13 — offline-no-egress for every cracker.
    **{tool_id: "offline-no-egress" for tool_id in HASH_TOOL_IDS},
}


PARSE_STRATEGY_BY_TOOL: Final[dict[str, ParseStrategy]] = {
    # §4.11.
    "interactsh_client": ParseStrategy.JSON_LINES,
    "oastify_client": ParseStrategy.JSON_LINES,
    "ssrfmap": ParseStrategy.TEXT_LINES,
    "gopherus": ParseStrategy.TEXT_LINES,
    "oast_dns_probe": ParseStrategy.TEXT_LINES,
    # §4.12 — text_lines for every tool (parsers deferred to Cycle 3).
    **{tool_id: ParseStrategy.TEXT_LINES for tool_id in AUTH_TOOL_IDS},
    # §4.13 — hashid/hash_analyzer emit JSON; the three crackers emit text.
    "hashcat": ParseStrategy.TEXT_LINES,
    "john": ParseStrategy.TEXT_LINES,
    "ophcrack": ParseStrategy.TEXT_LINES,
    "hashid": ParseStrategy.JSON_OBJECT,
    "hash_analyzer": ParseStrategy.JSON_OBJECT,
}


REQUIRES_APPROVAL_BY_TOOL: Final[dict[str, bool]] = {
    # §4.11 — receivers + canary are passive; ssrfmap actively probes
    # internal services through the SSRF entry point so it requires
    # approval; gopherus is a payload generator (offline) so it does NOT
    # require approval.
    "interactsh_client": False,
    "oastify_client": False,
    "ssrfmap": True,
    "gopherus": False,
    "oast_dns_probe": False,
    # §4.12 — every tool that touches authentication endpoints requires
    # approval (lockout / domain audit log noise). snmp_check is the
    # only exception: SNMPv1/v2c walks are read-only on default-community
    # strings and the policy folds them into the recon phase.
    "hydra": True,
    "medusa": True,
    "patator": True,
    "ncrack": True,
    "crackmapexec": True,
    "kerbrute": True,
    "smbclient": True,
    "snmp_check": False,
    "evil_winrm": True,
    "impacket_examples": True,
    # §4.13 — long-running CPU-bound crackers require approval; passive
    # hash classifiers (hashid / hash_analyzer) do not.
    "hashcat": True,
    "john": True,
    "ophcrack": True,
    "hashid": False,
    "hash_analyzer": False,
}


# ---------------------------------------------------------------------------
# CWE / WSTG anchors
# ---------------------------------------------------------------------------


# §4.11 cohort floor: CWE-918 (SSRF).
OAST_REQUIRED_CWE: Final[int] = 918


# §4.12 cohort floor: at least one of CWE-287 (Auth) or CWE-307 (Brute Force).
AUTH_REQUIRED_CWE_SET: Final[frozenset[int]] = frozenset({287, 307})


# §4.13 cohort floor: at least one of CWE-916 (Weak Hash) or CWE-326
# (Inadequate Cryptographic Strength).
HASH_REQUIRED_CWE_SET: Final[frozenset[int]] = frozenset({916, 326})


# Shell metacharacters that must NOT appear in argv tokens. The `sh -c
# "<cmd>"` pattern legitimately puts `>` and similar inside the third
# argv token — we audit each YAML's first two tokens only when the YAML
# uses the sh -c idiom (matching the precedent in §4.1 recon YAMLs).
SHELL_METACHARS_FOR_NON_SHELL_TOKENS: Final[tuple[str, ...]] = (
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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _catalog_dir() -> Path:
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


def test_oast_inventory_contains_exactly_five_tools() -> None:
    assert len(OAST_TOOL_IDS) == 5
    assert len(set(OAST_TOOL_IDS)) == 5


def test_auth_inventory_contains_exactly_ten_tools() -> None:
    assert len(AUTH_TOOL_IDS) == 10
    assert len(set(AUTH_TOOL_IDS)) == 10


def test_hash_inventory_contains_exactly_five_tools() -> None:
    assert len(HASH_TOOL_IDS) == 5
    assert len(set(HASH_TOOL_IDS)) == 5


def test_arg017_inventory_totals_twenty() -> None:
    assert len(ARG017_TOOL_IDS) == 20
    assert len(set(ARG017_TOOL_IDS)) == 20


def test_per_tool_taxonomy_maps_cover_every_arg017_tool() -> None:
    """Each per-tool map covers exactly the ARG-017 batch — no extras, no gaps."""
    expected = set(ARG017_TOOL_IDS)
    assert set(PHASE_BY_TOOL.keys()) == expected
    assert set(CATEGORY_BY_TOOL.keys()) == expected
    assert set(IMAGE_BY_TOOL.keys()) == expected
    assert set(NETWORK_POLICY_BY_TOOL.keys()) == expected
    assert set(PARSE_STRATEGY_BY_TOOL.keys()) == expected
    assert set(REQUIRES_APPROVAL_BY_TOOL.keys()) == expected


# ---------------------------------------------------------------------------
# Per-tool category / phase / image / network_policy / parse_strategy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG017_TOOL_IDS)
def test_category_matches_per_tool_pin(catalog_dir: Path, tool_id: str) -> None:
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = CATEGORY_BY_TOOL[tool_id]
    assert descriptor.category is expected, (
        f"{tool_id}: category={descriptor.category.value!r} "
        f"diverges from pinned {expected.value!r}"
    )


@pytest.mark.parametrize("tool_id", ARG017_TOOL_IDS)
def test_phase_matches_per_tool_pin(catalog_dir: Path, tool_id: str) -> None:
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = PHASE_BY_TOOL[tool_id]
    assert descriptor.phase is expected, (
        f"{tool_id}: phase={descriptor.phase.value!r} "
        f"diverges from pinned {expected.value!r}"
    )


@pytest.mark.parametrize("tool_id", ARG017_TOOL_IDS)
def test_image_matches_per_tool_pin(catalog_dir: Path, tool_id: str) -> None:
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = IMAGE_BY_TOOL[tool_id]
    assert descriptor.image == expected, (
        f"{tool_id}: image must be {expected!r}, got {descriptor.image!r}"
    )


@pytest.mark.parametrize("tool_id", ARG017_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", ARG017_TOOL_IDS)
def test_network_policy_matches_per_tool_pin(catalog_dir: Path, tool_id: str) -> None:
    """ARG-017 tools must use the network policy mandated by the cycle plan."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = NETWORK_POLICY_BY_TOOL[tool_id]
    assert descriptor.network_policy.name == expected, (
        f"{tool_id}: network_policy={descriptor.network_policy.name!r} "
        f"diverges from pinned {expected!r}"
    )


@pytest.mark.parametrize("tool_id", ARG017_TOOL_IDS)
def test_parse_strategy_matches_per_tool_pin(catalog_dir: Path, tool_id: str) -> None:
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = PARSE_STRATEGY_BY_TOOL[tool_id]
    assert descriptor.parse_strategy is expected, (
        f"{tool_id}: parse_strategy={descriptor.parse_strategy.value!r} "
        f"diverges from pinned {expected.value!r}"
    )


# ---------------------------------------------------------------------------
# Approval invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG017_TOOL_IDS)
def test_requires_approval_matches_per_tool_pin(
    catalog_dir: Path, tool_id: str
) -> None:
    """Approval gate matches the documented destructiveness profile."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = REQUIRES_APPROVAL_BY_TOOL[tool_id]
    assert descriptor.requires_approval is expected, (
        f"{tool_id}: requires_approval={descriptor.requires_approval} "
        f"diverges from pinned {expected}"
    )


@pytest.mark.parametrize(
    "tool_id",
    [t for t in ARG017_TOOL_IDS if REQUIRES_APPROVAL_BY_TOOL[t] is True],
)
def test_approval_required_tools_carry_high_or_medium_risk(
    catalog_dir: Path, tool_id: str
) -> None:
    """Every approval-gated tool ships with risk_level ≥ medium.

    Defence-in-depth: the orchestrator's risk-classification check fires
    on (risk_level, requires_approval) tuples; a low-risk tool that
    nevertheless required approval would slip through the
    risk-classification audit silently.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.risk_level in (RiskLevel.HIGH, RiskLevel.MEDIUM), (
        f"{tool_id}: requires_approval=True but "
        f"risk_level={descriptor.risk_level.value!r} below MEDIUM"
    )


# ---------------------------------------------------------------------------
# CWE / WSTG anchors
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", OAST_TOOL_IDS)
def test_oast_tool_carries_cwe918(catalog_dir: Path, tool_id: str) -> None:
    """Every §4.11 tool ships CWE-918 (SSRF) — the cohort floor."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert OAST_REQUIRED_CWE in descriptor.cwe_hints, (
        f"{tool_id}: must declare CWE-918 (Server-Side Request Forgery); "
        f"got {descriptor.cwe_hints}"
    )


@pytest.mark.parametrize("tool_id", OAST_TOOL_IDS)
def test_oast_tool_carries_wstg_inpv19(catalog_dir: Path, tool_id: str) -> None:
    """Every §4.11 tool ships WSTG-INPV-19 (SSRF / OOB)."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert "WSTG-INPV-19" in descriptor.owasp_wstg, (
        f"{tool_id}: must declare WSTG-INPV-19; got {descriptor.owasp_wstg}"
    )


@pytest.mark.parametrize(
    "tool_id",
    [t for t in AUTH_TOOL_IDS if t != "snmp_check"],
)
def test_auth_tool_carries_at_least_one_auth_cwe(
    catalog_dir: Path, tool_id: str
) -> None:
    """Every §4.12 tool except snmp_check ships at least one of CWE-287 / CWE-307.

    snmp_check is the exception: SNMPv1/v2c walks are fundamentally an
    information-disclosure check, not an auth bypass / brute-force, so
    it ships CWE-200 (Information Exposure) instead of an ATHN CWE.
    See ``test_snmp_check_carries_information_disclosure_cwe`` below.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    intersect = set(descriptor.cwe_hints) & AUTH_REQUIRED_CWE_SET
    assert intersect, (
        f"{tool_id}: must declare at least one auth CWE "
        f"(287 / 307); got {descriptor.cwe_hints}"
    )


def test_snmp_check_carries_information_disclosure_cwe(
    catalog_dir: Path,
) -> None:
    """snmp_check is the §4.12 outlier: ships CWE-200 (Info Exposure)
    rather than an ATHN CWE since SNMP walks are read-only.
    """
    descriptor = _load_descriptor(catalog_dir, "snmp_check")
    assert 200 in descriptor.cwe_hints, (
        "snmp_check: must declare CWE-200 (Information Exposure); "
        f"got {descriptor.cwe_hints}"
    )


@pytest.mark.parametrize("tool_id", AUTH_TOOL_IDS)
def test_auth_tool_owasp_wstg_includes_athn_or_info(
    catalog_dir: Path, tool_id: str
) -> None:
    """§4.12 tools surface either WSTG-ATHN-* (auth) or WSTG-INFO-* (info disclosure).

    snmp_check is the lone outlier: it lives in the auth cohort but the
    SNMP walk is fundamentally an information-disclosure check, so it
    surfaces WSTG-INFO-09 instead of WSTG-ATHN-*.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.owasp_wstg, (
        f"{tool_id}: owasp_wstg must be non-empty for §4.12 tools"
    )
    assert any(
        tag.startswith("WSTG-ATHN") or tag.startswith("WSTG-INFO")
        for tag in descriptor.owasp_wstg
    ), (
        f"{tool_id}: owasp_wstg must include at least one WSTG-ATHN-* "
        f"or WSTG-INFO-* hint; got {descriptor.owasp_wstg}"
    )


@pytest.mark.parametrize("tool_id", HASH_TOOL_IDS)
def test_hash_tool_carries_at_least_one_crypto_cwe(
    catalog_dir: Path, tool_id: str
) -> None:
    """Every §4.13 tool ships at least one of CWE-916 / CWE-326."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    intersect = set(descriptor.cwe_hints) & HASH_REQUIRED_CWE_SET
    assert intersect, (
        f"{tool_id}: must declare at least one crypto CWE "
        f"(916 / 326); got {descriptor.cwe_hints}"
    )


@pytest.mark.parametrize("tool_id", HASH_TOOL_IDS)
def test_hash_tool_owasp_wstg_includes_cryp_family(
    catalog_dir: Path, tool_id: str
) -> None:
    """§4.13 tools surface at least one WSTG-CRYP-* hint."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert any(tag.startswith("WSTG-CRYP") for tag in descriptor.owasp_wstg), (
        f"{tool_id}: owasp_wstg must include at least one WSTG-CRYP-* hint; "
        f"got {descriptor.owasp_wstg}"
    )


# ---------------------------------------------------------------------------
# Resource limits + seccomp
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG017_TOOL_IDS)
def test_cpu_and_memory_limits_set(catalog_dir: Path, tool_id: str) -> None:
    """``cpu_limit`` / ``memory_limit`` / ``seccomp_profile`` are populated."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.cpu_limit, f"{tool_id}: empty cpu_limit"
    assert descriptor.memory_limit, f"{tool_id}: empty memory_limit"
    assert descriptor.seccomp_profile == "runtime/default", (
        f"{tool_id}: must use seccomp_profile=runtime/default, "
        f"got {descriptor.seccomp_profile!r}"
    )


@pytest.mark.parametrize("tool_id", HASH_TOOL_IDS)
def test_hash_tool_dns_resolvers_empty_on_offline_no_egress(
    catalog_dir: Path, tool_id: str
) -> None:
    """§4.13 tools ride ``offline-no-egress`` — DNS resolvers must be empty."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.network_policy.dns_resolvers == [], (
        f"{tool_id}: offline-no-egress must NOT declare DNS resolvers; "
        f"got {descriptor.network_policy.dns_resolvers}"
    )


def test_gopherus_offline_dns_resolvers_empty(catalog_dir: Path) -> None:
    """gopherus rides ``offline-no-egress`` — DNS resolvers must be empty."""
    descriptor = _load_descriptor(catalog_dir, "gopherus")
    assert descriptor.network_policy.dns_resolvers == [], (
        f"gopherus: offline-no-egress must NOT declare DNS resolvers; "
        f"got {descriptor.network_policy.dns_resolvers}"
    )


# ---------------------------------------------------------------------------
# Argv shell-metachar audit (defence-in-depth on top of templating)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG017_TOOL_IDS)
def test_command_template_outer_tokens_have_no_shell_metachars(
    catalog_dir: Path, tool_id: str
) -> None:
    """No argv token outside ``sh -c``'s third token may contain shell metas.

    The §4.11/§4.12/§4.13 batch uses the ``sh -c "<cmd>"`` idiom for
    tools that need stdout redirection inside the container (matching
    the §4.1 recon precedent). The audit therefore skips the third
    token of any ``sh -c …`` argv (where the shell-meta is intentional
    and constrained to the inner string).
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    tokens = list(descriptor.command_template)
    assert tokens, f"{tool_id}: command_template must be non-empty"

    skip_indices: set[int] = set()
    if (
        len(tokens) >= 3
        and tokens[0] in ("sh", "/bin/sh", "bash", "/bin/bash")
        and tokens[1] in ("-c", "-lc")
    ):
        skip_indices.add(2)

    for index, token in enumerate(tokens):
        if index in skip_indices:
            continue
        for meta in SHELL_METACHARS_FOR_NON_SHELL_TOKENS:
            assert meta not in token, (
                f"{tool_id}: command_template[{index}] {token!r} contains "
                f"shell metacharacter {meta!r}"
            )


# ---------------------------------------------------------------------------
# Description self-documentation invariant
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", OAST_TOOL_IDS)
def test_oast_description_references_section_4_11(
    catalog_dir: Path, tool_id: str
) -> None:
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert "§4.11" in descriptor.description, (
        f"{tool_id}: description must reference Backlog §4.11 for traceability"
    )


@pytest.mark.parametrize("tool_id", AUTH_TOOL_IDS)
def test_auth_description_references_section_4_12(
    catalog_dir: Path, tool_id: str
) -> None:
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert "§4.12" in descriptor.description, (
        f"{tool_id}: description must reference Backlog §4.12 for traceability"
    )


@pytest.mark.parametrize("tool_id", HASH_TOOL_IDS)
def test_hash_description_references_section_4_13(
    catalog_dir: Path, tool_id: str
) -> None:
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert "§4.13" in descriptor.description, (
        f"{tool_id}: description must reference Backlog §4.13 for traceability"
    )


@pytest.mark.parametrize("tool_id", ARG017_TOOL_IDS)
def test_description_within_500_char_limit(catalog_dir: Path, tool_id: str) -> None:
    """``ToolDescriptor`` caps ``description`` at 500 characters."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert len(descriptor.description) <= 500, (
        f"{tool_id}: description length {len(descriptor.description)} > 500 "
        f"(would fail Pydantic validation on load)"
    )


@pytest.mark.parametrize("tool_id", ARG017_TOOL_IDS)
def test_description_references_arg017(catalog_dir: Path, tool_id: str) -> None:
    """ARG-017 tag in every description for cycle-traceability."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert "ARG-017" in descriptor.description, (
        f"{tool_id}: description must reference ARG-017 for cycle traceability"
    )


# ---------------------------------------------------------------------------
# Evidence artefact paths
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG017_TOOL_IDS)
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


# ---------------------------------------------------------------------------
# §4.11 tool-specific: interactsh / oastify must emit JSON Lines
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ("interactsh_client", "oastify_client"))
def test_oast_receivers_emit_canonical_jsonl_artifact(
    catalog_dir: Path, tool_id: str
) -> None:
    """interactsh / oastify must declare ``/out/interactsh.jsonl`` —
    that's the canonical artifact :func:`parse_interactsh_jsonl` looks
    for first.
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert "/out/interactsh.jsonl" in descriptor.evidence_artifacts, (
        f"{tool_id}: must declare /out/interactsh.jsonl as evidence "
        f"so the parser's canonical-artifact resolution short-circuits "
        f"the stdout fallback"
    )


# ---------------------------------------------------------------------------
# §4.13 tool-specific: hashes_file is the cohort entry-point placeholder
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", HASH_TOOL_IDS)
def test_hash_tool_consumes_hashes_file_placeholder(
    catalog_dir: Path, tool_id: str
) -> None:
    """Every §4.13 tool reads its hashes from ``{hashes_file}``."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    rendered = " ".join(descriptor.command_template)
    assert "{hashes_file}" in rendered, (
        f"{tool_id}: command_template must reference {{hashes_file}} "
        f"(the §4.13 cohort entry-point placeholder)"
    )


# ---------------------------------------------------------------------------
# §4.12 tool-specific: hydra must consume {target_proto}
# ---------------------------------------------------------------------------


def test_hydra_consumes_target_proto_placeholder(catalog_dir: Path) -> None:
    """Hydra's auth scheme is selected via ``{target_proto}``.

    The whole approval-gated contract for hydra rests on the validator
    refusing unknown / unsupported protocols at template-render time —
    so the YAML must reference {target_proto} (not {proto} which is the
    free-form layer-7 label used elsewhere).
    """
    descriptor = _load_descriptor(catalog_dir, "hydra")
    rendered = " ".join(descriptor.command_template)
    assert "{target_proto}" in rendered, (
        "hydra: must reference {target_proto} so the auth-protocol "
        f"validator gates the scheme (got argv: {descriptor.command_template!r})"
    )
