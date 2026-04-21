"""Per-§4.14/§4.15/§4.16 invariant tests for the ARG-018 tool YAMLs.

Sister suite to ``test_yaml_web_vuln_semantics.py`` (ARG-015) — that file
pins the §4.8 web-VA contract; this file pins the ARG-018 contract for
the three Cycle-2 cohorts that ship together:

* §4.14 — **API / GraphQL** (7 tools): ``openapi_scanner``,
  ``graphw00f``, ``clairvoyance``, ``inql``, ``graphql_cop``,
  ``grpcurl_probe``, ``postman_newman``. All probe live HTTP / gRPC
  endpoints behind ``recon-active-tcp``.
* §4.15 — **Cloud / IaC / container** (12 tools): cloud auditors
  (``prowler``, ``scoutsuite``, ``cloudsploit``), the offensive cloud
  tool ``pacu`` (RISK=high, requires_approval=true), three Trivy / Syft
  / Grype SCA scanners, the container linter ``dockle``, two Kubernetes
  scanners (``kube_bench`` offline, ``kube_hunter`` active TCP +
  approval-gated), and the IaC scanner ``checkov``.
* §4.16 — **IaC / code / secrets** (8 tools): ``terrascan``, ``tfsec``,
  ``kics``, ``semgrep``, ``bandit``, ``gitleaks``, ``trufflehog``,
  ``detect_secrets`` — all offline, passive, no approval required.

Invariants pinned (any drift fails CI):

* The catalog contains exactly the 27 ARG-018 tool ids — no more, no less.
* Each tool has the pinned ``category``, ``phase``, ``image``,
  ``network_policy``, ``risk_level``, ``requires_approval`` and
  ``parse_strategy`` — no silent flips.
* Cohorts run on the right base image (web cohort →
  ``argus-kali-web:latest``; cloud / IaC / SAST cohort →
  ``argus-kali-cloud:latest``).
* Network-policy choice matches behaviour:
  - Cloud auditors → ``recon-passive`` (egress to AWS / GCP / Azure
    public APIs only; pinned at sandbox layer in Cycle 4).
  - Active K8s probing → ``recon-active-tcp``.
  - Local config / SCA / SAST / secret scanning → ``offline-no-egress``.
  - API / GraphQL / gRPC probing → ``recon-active-tcp``.
* ``requires_approval=true`` only for tools that touch live cloud
  control planes (``prowler`` / ``scoutsuite`` / ``cloudsploit`` /
  ``pacu``) or actively probe live K8s (``kube_hunter``).
* CWE / OWASP-WSTG hints are non-empty (catalog hygiene).
* Every ``command_template`` argv is shell-meta-free at the **token**
  level (the only tokens allowed to contain shell metacharacters are
  the explicit ``-c`` payloads of static, well-formed redirections —
  enforced by the templating layer).
* Every YAML declares at least one evidence artefact under ``/out``.
* Every ``description`` references the upstream binary author / source
  URL and the matching Backlog section so the catalog stays
  self-documenting.
* Every ``parse_strategy`` value is a known
  :class:`~src.sandbox.adapter_base.ParseStrategy` member.
* Every ``network_policy.name`` is a known template in
  :data:`src.sandbox.network_policies.NETWORK_POLICY_NAMES` (defence
  in depth on top of YAML schema validation).

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


API_GRAPHQL_TOOL_IDS: Final[tuple[str, ...]] = (
    "openapi_scanner",
    "graphw00f",
    "clairvoyance",
    "inql",
    "graphql_cop",
    "grpcurl_probe",
    "postman_newman",
)


CLOUD_IAC_TOOL_IDS: Final[tuple[str, ...]] = (
    "prowler",
    "scoutsuite",
    "cloudsploit",
    "pacu",
    "trivy_image",
    "trivy_fs",
    "grype",
    "syft",
    "dockle",
    "kube_bench",
    "kube_hunter",
    "checkov",
)


CODE_SECRETS_TOOL_IDS: Final[tuple[str, ...]] = (
    "terrascan",
    "tfsec",
    "kics",
    "semgrep",
    "bandit",
    "gitleaks",
    "trufflehog",
    "detect_secrets",
)


ARG018_TOOL_IDS: Final[tuple[str, ...]] = (
    *API_GRAPHQL_TOOL_IDS,
    *CLOUD_IAC_TOOL_IDS,
    *CODE_SECRETS_TOOL_IDS,
)


# ---------------------------------------------------------------------------
# Per-tool pinning maps — every map must cover every ARG-018 tool id.
# ---------------------------------------------------------------------------


CATEGORY_BY_TOOL: Final[dict[str, ToolCategory]] = {
    # §4.14 — API/GraphQL
    "openapi_scanner": ToolCategory.WEB_VA,
    "graphw00f": ToolCategory.WEB_VA,
    "clairvoyance": ToolCategory.WEB_VA,
    "inql": ToolCategory.WEB_VA,
    "graphql_cop": ToolCategory.WEB_VA,
    "grpcurl_probe": ToolCategory.NETWORK,
    "postman_newman": ToolCategory.WEB_VA,
    # §4.15 — Cloud / IaC / container
    "prowler": ToolCategory.CLOUD,
    "scoutsuite": ToolCategory.CLOUD,
    "cloudsploit": ToolCategory.CLOUD,
    "pacu": ToolCategory.CLOUD,
    "trivy_image": ToolCategory.CLOUD,
    "trivy_fs": ToolCategory.CLOUD,
    "grype": ToolCategory.CLOUD,
    "syft": ToolCategory.CLOUD,
    "dockle": ToolCategory.CLOUD,
    "kube_bench": ToolCategory.CLOUD,
    "kube_hunter": ToolCategory.CLOUD,
    "checkov": ToolCategory.IAC,
    # §4.16 — IaC / code / secrets
    "terrascan": ToolCategory.IAC,
    "tfsec": ToolCategory.IAC,
    "kics": ToolCategory.IAC,
    "semgrep": ToolCategory.MISC,
    "bandit": ToolCategory.MISC,
    "gitleaks": ToolCategory.MISC,
    "trufflehog": ToolCategory.MISC,
    "detect_secrets": ToolCategory.MISC,
}


PHASE_BY_TOOL: Final[dict[str, ScanPhase]] = {
    # §4.14
    "openapi_scanner": ScanPhase.VULN_ANALYSIS,
    "graphw00f": ScanPhase.RECON,
    "clairvoyance": ScanPhase.VULN_ANALYSIS,
    "inql": ScanPhase.VULN_ANALYSIS,
    "graphql_cop": ScanPhase.VULN_ANALYSIS,
    "grpcurl_probe": ScanPhase.RECON,
    "postman_newman": ScanPhase.VULN_ANALYSIS,
    # §4.15
    "prowler": ScanPhase.VULN_ANALYSIS,
    "scoutsuite": ScanPhase.VULN_ANALYSIS,
    "cloudsploit": ScanPhase.VULN_ANALYSIS,
    "pacu": ScanPhase.EXPLOITATION,
    "trivy_image": ScanPhase.VULN_ANALYSIS,
    "trivy_fs": ScanPhase.VULN_ANALYSIS,
    "grype": ScanPhase.VULN_ANALYSIS,
    "syft": ScanPhase.VULN_ANALYSIS,
    "dockle": ScanPhase.VULN_ANALYSIS,
    "kube_bench": ScanPhase.VULN_ANALYSIS,
    "kube_hunter": ScanPhase.VULN_ANALYSIS,
    "checkov": ScanPhase.VULN_ANALYSIS,
    # §4.16
    "terrascan": ScanPhase.VULN_ANALYSIS,
    "tfsec": ScanPhase.VULN_ANALYSIS,
    "kics": ScanPhase.VULN_ANALYSIS,
    "semgrep": ScanPhase.VULN_ANALYSIS,
    "bandit": ScanPhase.VULN_ANALYSIS,
    "gitleaks": ScanPhase.VULN_ANALYSIS,
    "trufflehog": ScanPhase.VULN_ANALYSIS,
    "detect_secrets": ScanPhase.VULN_ANALYSIS,
}


IMAGE_BY_TOOL: Final[dict[str, str]] = {
    # §4.14 — web sandbox
    "openapi_scanner": "argus-kali-web:latest",
    "graphw00f": "argus-kali-web:latest",
    "clairvoyance": "argus-kali-web:latest",
    "inql": "argus-kali-web:latest",
    "graphql_cop": "argus-kali-web:latest",
    "grpcurl_probe": "argus-kali-web:latest",
    "postman_newman": "argus-kali-web:latest",
    # §4.15 + §4.16 — cloud / SAST / IaC sandbox
    "prowler": "argus-kali-cloud:latest",
    "scoutsuite": "argus-kali-cloud:latest",
    "cloudsploit": "argus-kali-cloud:latest",
    "pacu": "argus-kali-cloud:latest",
    "trivy_image": "argus-kali-cloud:latest",
    "trivy_fs": "argus-kali-cloud:latest",
    "grype": "argus-kali-cloud:latest",
    "syft": "argus-kali-cloud:latest",
    "dockle": "argus-kali-cloud:latest",
    "kube_bench": "argus-kali-cloud:latest",
    "kube_hunter": "argus-kali-cloud:latest",
    "checkov": "argus-kali-cloud:latest",
    "terrascan": "argus-kali-cloud:latest",
    "tfsec": "argus-kali-cloud:latest",
    "kics": "argus-kali-cloud:latest",
    "semgrep": "argus-kali-cloud:latest",
    "bandit": "argus-kali-cloud:latest",
    "gitleaks": "argus-kali-cloud:latest",
    "trufflehog": "argus-kali-cloud:latest",
    "detect_secrets": "argus-kali-cloud:latest",
}


NETWORK_POLICY_BY_TOOL: Final[dict[str, str]] = {
    # §4.14 — all touch live HTTP / gRPC endpoints
    "openapi_scanner": "recon-active-tcp",
    "graphw00f": "recon-active-tcp",
    "clairvoyance": "recon-active-tcp",
    "inql": "recon-active-tcp",
    "graphql_cop": "recon-active-tcp",
    "grpcurl_probe": "recon-active-tcp",
    "postman_newman": "recon-active-tcp",
    # §4.15 — cloud auditors / image pulls / package DB → recon-passive;
    # local k8s config scan → offline-no-egress; live k8s probe → active-tcp
    "prowler": "recon-passive",
    "scoutsuite": "recon-passive",
    "cloudsploit": "recon-passive",
    "pacu": "recon-passive",
    "trivy_image": "recon-passive",
    "trivy_fs": "recon-passive",
    "grype": "recon-passive",
    "syft": "recon-passive",
    "dockle": "recon-passive",
    "kube_bench": "offline-no-egress",
    "kube_hunter": "recon-active-tcp",
    "checkov": "offline-no-egress",
    # §4.16 — IaC scanners / SAST / secret scanners are all offline
    "terrascan": "offline-no-egress",
    "tfsec": "offline-no-egress",
    "kics": "offline-no-egress",
    "semgrep": "offline-no-egress",
    "bandit": "offline-no-egress",
    "gitleaks": "offline-no-egress",
    "trufflehog": "offline-no-egress",
    "detect_secrets": "offline-no-egress",
}


RISK_LEVEL_BY_TOOL: Final[dict[str, RiskLevel]] = {
    # §4.14 — all low (no payload injection)
    "openapi_scanner": RiskLevel.LOW,
    "graphw00f": RiskLevel.LOW,
    "clairvoyance": RiskLevel.LOW,
    "inql": RiskLevel.LOW,
    "graphql_cop": RiskLevel.LOW,
    "grpcurl_probe": RiskLevel.LOW,
    "postman_newman": RiskLevel.LOW,
    # §4.15 — cloud auditors bumped to MEDIUM in ARG-020 to satisfy the
    # "requires_approval=True implies risk_level >= MEDIUM" invariant.
    # The tools are read-only at the API level but their operational impact
    # (live cloud creds, cross-account API noise, IAM/CloudTrail/S3
    # enumeration) already justified the approval gate they shipped with.
    # ``pacu`` stays HIGH (offensive cloud framework), ``kube_hunter`` stays
    # MEDIUM (live K8s probe); SCA / image scan / SBOM / linter / kube_bench
    # all PASSIVE.
    "prowler": RiskLevel.MEDIUM,
    "scoutsuite": RiskLevel.MEDIUM,
    "cloudsploit": RiskLevel.MEDIUM,
    "pacu": RiskLevel.HIGH,
    "trivy_image": RiskLevel.PASSIVE,
    "trivy_fs": RiskLevel.PASSIVE,
    "grype": RiskLevel.PASSIVE,
    "syft": RiskLevel.PASSIVE,
    "dockle": RiskLevel.PASSIVE,
    "kube_bench": RiskLevel.PASSIVE,
    "kube_hunter": RiskLevel.MEDIUM,
    "checkov": RiskLevel.PASSIVE,
    # §4.16 — all passive (offline, no egress, read-only)
    "terrascan": RiskLevel.PASSIVE,
    "tfsec": RiskLevel.PASSIVE,
    "kics": RiskLevel.PASSIVE,
    "semgrep": RiskLevel.PASSIVE,
    "bandit": RiskLevel.PASSIVE,
    "gitleaks": RiskLevel.PASSIVE,
    "trufflehog": RiskLevel.PASSIVE,
    "detect_secrets": RiskLevel.PASSIVE,
}


# Approval-gated set: live cloud-control-plane callers + active K8s probe.
APPROVAL_REQUIRED: Final[frozenset[str]] = frozenset(
    {"prowler", "scoutsuite", "cloudsploit", "pacu", "kube_hunter"}
)


PARSE_STRATEGY_BY_TOOL: Final[dict[str, ParseStrategy]] = {
    # §4.14 — JSON object outputs (parsers deferred to Cycle 3); except
    # gRPC text probe.
    "openapi_scanner": ParseStrategy.JSON_OBJECT,
    "graphw00f": ParseStrategy.JSON_OBJECT,
    "clairvoyance": ParseStrategy.JSON_OBJECT,
    "inql": ParseStrategy.JSON_OBJECT,
    "graphql_cop": ParseStrategy.JSON_OBJECT,
    "grpcurl_probe": ParseStrategy.TEXT_LINES,
    "postman_newman": ParseStrategy.JSON_OBJECT,
    # §4.15 — JSON object outputs (parsers deferred to Cycle 3) except
    # ``trivy_*`` (live ARG-018 parsers) and ``pacu`` (text-only).
    "prowler": ParseStrategy.JSON_OBJECT,
    "scoutsuite": ParseStrategy.JSON_OBJECT,
    "cloudsploit": ParseStrategy.JSON_OBJECT,
    "pacu": ParseStrategy.TEXT_LINES,
    "trivy_image": ParseStrategy.JSON_OBJECT,
    "trivy_fs": ParseStrategy.JSON_OBJECT,
    "grype": ParseStrategy.JSON_OBJECT,
    "syft": ParseStrategy.JSON_OBJECT,
    "dockle": ParseStrategy.JSON_OBJECT,
    "kube_bench": ParseStrategy.JSON_OBJECT,
    "kube_hunter": ParseStrategy.JSON_OBJECT,
    "checkov": ParseStrategy.JSON_OBJECT,
    # §4.16 — JSON outputs; trufflehog uses NDJSON.
    "terrascan": ParseStrategy.JSON_OBJECT,
    "tfsec": ParseStrategy.JSON_OBJECT,
    "kics": ParseStrategy.JSON_OBJECT,
    "semgrep": ParseStrategy.JSON_OBJECT,
    "bandit": ParseStrategy.JSON_OBJECT,
    "gitleaks": ParseStrategy.JSON_OBJECT,
    "trufflehog": ParseStrategy.JSON_LINES,
    "detect_secrets": ParseStrategy.JSON_OBJECT,
}


# Per-tool minimum default_timeout_s — heavy scanners get longer windows.
DEFAULT_TIMEOUT_S_BY_TOOL: Final[dict[str, int]] = {
    "openapi_scanner": 600,
    "graphw00f": 300,
    "clairvoyance": 900,
    "inql": 900,
    "graphql_cop": 600,
    "grpcurl_probe": 120,
    "postman_newman": 1200,
    "prowler": 3600,
    "scoutsuite": 3600,
    "cloudsploit": 3600,
    "pacu": 1800,
    "trivy_image": 1800,
    "trivy_fs": 1800,
    "grype": 1800,
    "syft": 1800,
    "dockle": 600,
    "kube_bench": 600,
    "kube_hunter": 1800,
    "checkov": 1800,
    "terrascan": 1200,
    "tfsec": 1200,
    "kics": 1800,
    "semgrep": 3600,
    "bandit": 1800,
    "gitleaks": 1800,
    "trufflehog": 1800,
    "detect_secrets": 1200,
}


# Shell metacharacters that must NOT appear in a YAML argv. ``-c`` style
# `sh -c "cmd > file.json"` redirections are explicitly accepted by the
# templating layer (see ``backend/src/sandbox/templating.py``); the
# dedicated test below treats redirection-bearing tokens separately.
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


# Tools that legitimately use ``sh -c "<binary> ... > /out/...json"``
# wrappers for stdout redirection only. The ``sh -c`` payload is fully
# argv-templated through allow-listed placeholders; templating layer
# rejects unknown placeholders and shell-metachar-bearing arguments.
# Pinned so unrelated YAMLs cannot silently shell out.
SH_WRAPPED_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "graphql_cop",
        "grpcurl_probe",
        "grype",
        "syft",
        "checkov",
        "kube_bench",
        "kube_hunter",
        "terrascan",
        "tfsec",
        "trufflehog",
        "detect_secrets",
    }
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


def test_inventory_contains_exactly_27_tools() -> None:
    """The ARG-018 batch is exactly 27 tools — drift breaks Backlog §4.14–§4.16
    alignment and the EXPECTED_TOOLS / EXPECTED_TOOL_IDS pins in
    ``test_tool_catalog_load.py`` and ``test_yaml_schema_per_tool.py``.
    """
    assert len(ARG018_TOOL_IDS) == 27
    assert len(set(ARG018_TOOL_IDS)) == 27


def test_per_tool_taxonomy_maps_cover_every_tool() -> None:
    """Every per-tool map covers exactly the ARG-018 batch — no gaps, no extras."""
    expected = set(ARG018_TOOL_IDS)
    assert set(CATEGORY_BY_TOOL.keys()) == expected
    assert set(PHASE_BY_TOOL.keys()) == expected
    assert set(IMAGE_BY_TOOL.keys()) == expected
    assert set(NETWORK_POLICY_BY_TOOL.keys()) == expected
    assert set(RISK_LEVEL_BY_TOOL.keys()) == expected
    assert set(PARSE_STRATEGY_BY_TOOL.keys()) == expected
    assert set(DEFAULT_TIMEOUT_S_BY_TOOL.keys()) == expected
    assert APPROVAL_REQUIRED.issubset(expected)


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
def test_yaml_file_exists(catalog_dir: Path, tool_id: str) -> None:
    """Every ARG-018 tool ships a YAML descriptor under config/tools/."""
    yaml_path = catalog_dir / f"{tool_id}.yaml"
    assert yaml_path.is_file(), f"missing YAML for ARG-018 tool {tool_id}"


# ---------------------------------------------------------------------------
# Category / phase invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
def test_category_matches_pin(catalog_dir: Path, tool_id: str) -> None:
    """Each tool ships the pinned :class:`ToolCategory`."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = CATEGORY_BY_TOOL[tool_id]
    assert descriptor.category is expected, (
        f"{tool_id}: category={descriptor.category.value!r} "
        f"diverges from pinned {expected.value!r}"
    )


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
def test_image_matches_per_cohort_pin(catalog_dir: Path, tool_id: str) -> None:
    """API/GraphQL → web image, Cloud/IaC/SAST → cloud image."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = IMAGE_BY_TOOL[tool_id]
    assert descriptor.image == expected, (
        f"{tool_id}: image={descriptor.image!r} diverges from pinned {expected!r}"
    )


# ---------------------------------------------------------------------------
# Network policy invariants
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
def test_network_policy_matches_per_tool_pin(catalog_dir: Path, tool_id: str) -> None:
    """Each tool ships the documented network policy for its access pattern."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = NETWORK_POLICY_BY_TOOL[tool_id]
    assert descriptor.network_policy.name == expected, (
        f"{tool_id}: network_policy={descriptor.network_policy.name!r} "
        f"diverges from pinned {expected!r}"
    )


# ---------------------------------------------------------------------------
# Risk level + approval gating
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
def test_risk_level_matches_pin(catalog_dir: Path, tool_id: str) -> None:
    """Risk level matches the documented behaviour profile."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = RISK_LEVEL_BY_TOOL[tool_id]
    assert descriptor.risk_level is expected, (
        f"{tool_id}: risk_level={descriptor.risk_level.value!r} "
        f"diverges from pinned {expected.value!r}"
    )


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
def test_approval_matches_pinned_set(catalog_dir: Path, tool_id: str) -> None:
    """``requires_approval=True`` only for live cloud / active-K8s tools."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = tool_id in APPROVAL_REQUIRED
    assert descriptor.requires_approval is expected, (
        f"{tool_id}: requires_approval={descriptor.requires_approval} "
        f"contradicts ARG-018 approval matrix; expected={expected}"
    )


# ---------------------------------------------------------------------------
# Parser dispatch strategy split
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
def test_cwe_hints_non_empty(catalog_dir: Path, tool_id: str) -> None:
    """Every ARG-018 tool ships at least one CWE hint."""
    payload = yaml.safe_load((catalog_dir / f"{tool_id}.yaml").read_bytes())
    assert "cwe_hints" in payload, f"{tool_id}.yaml missing the cwe_hints key"
    assert isinstance(payload["cwe_hints"], list), (
        f"{tool_id}.yaml: cwe_hints must be a list"
    )
    assert payload["cwe_hints"], f"{tool_id}.yaml: cwe_hints must be non-empty"


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
def test_owasp_wstg_non_empty(catalog_dir: Path, tool_id: str) -> None:
    """Every ARG-018 tool ships at least one OWASP-WSTG hint."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.owasp_wstg, (
        f"{tool_id}: owasp_wstg must be non-empty for ARG-018 tools"
    )


# ---------------------------------------------------------------------------
# Resource limits + per-tool timeout floor
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
def test_default_timeout_matches_per_tool_floor(
    catalog_dir: Path, tool_id: str
) -> None:
    """Every ARG-018 tool floors at the per-tool minimum from the cycle plan."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected = DEFAULT_TIMEOUT_S_BY_TOOL[tool_id]
    assert descriptor.default_timeout_s >= expected, (
        f"{tool_id}: default_timeout_s={descriptor.default_timeout_s}s "
        f"below floor of {expected}s"
    )


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
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


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
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
            f"{tool_id}: must NOT shell-wrap; only {sorted(SH_WRAPPED_TOOLS)} "
            f"are allowed to use ``sh -c`` static-redirection wrappers"
        )


@pytest.mark.parametrize(
    "tool_id",
    [t for t in ARG018_TOOL_IDS if t not in SH_WRAPPED_TOOLS],
)
def test_command_template_argv_has_no_shell_metachars(
    catalog_dir: Path, tool_id: str
) -> None:
    """Non-wrapper tools must have argv tokens free of shell metacharacters."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    for index, token in enumerate(descriptor.command_template):
        for meta in SHELL_METACHARS:
            assert meta not in token, (
                f"{tool_id}: command_template[{index}]={token!r} contains "
                f"shell metacharacter {meta!r} — would break sandbox argv"
            )


# ---------------------------------------------------------------------------
# Description self-documentation invariant
# ---------------------------------------------------------------------------


_BACKLOG_SECTION_BY_COHORT: Final[dict[str, str]] = {
    **{tid: "§4.14" for tid in API_GRAPHQL_TOOL_IDS},
    **{tid: "§4.15" for tid in CLOUD_IAC_TOOL_IDS},
    **{tid: "§4.16" for tid in CODE_SECRETS_TOOL_IDS},
}


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
def test_description_has_upstream_attribution(catalog_dir: Path, tool_id: str) -> None:
    """Description includes the upstream author / source URL or marks the
    tool as an internal ARGUS component (catalog hygiene).
    """
    descriptor = _load_descriptor(catalog_dir, tool_id)
    assert descriptor.description, f"{tool_id}: empty description"
    text = descriptor.description.lower()
    markers = ("author", "https://", "github", "internal")
    assert any(marker in text for marker in markers), (
        f"{tool_id}: description must include upstream author / source URL "
        f"or 'internal' marker so the catalog stays self-documenting"
    )


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
def test_description_references_backlog_section(
    catalog_dir: Path, tool_id: str
) -> None:
    """Description references the matching Backlog §4.14/§4.15/§4.16 section."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    expected_section = _BACKLOG_SECTION_BY_COHORT[tool_id]
    assert expected_section in descriptor.description, (
        f"{tool_id}: description must reference Backlog {expected_section} "
        f"for traceability"
    )


# ---------------------------------------------------------------------------
# Targeting invariant — every ARG-018 tool consumes a sanctioned input
# placeholder so the templating layer can reject unknown ones at render
# time. Pinned per-tool so a YAML edit cannot silently swap input source
# (e.g. a path-scanning tool quietly switching to an unvalidated {url}).
# ---------------------------------------------------------------------------


# Required input placeholders per tool. ``out_dir`` is implicit on every
# tool and not asserted here.
REQUIRED_INPUT_PLACEHOLDERS: Final[dict[str, frozenset[str]]] = {
    # §4.14 API/GraphQL — most are URL-based (HTTP/GraphQL/OpenAPI scan
    # targets); ``grpcurl_probe`` is a host:port gRPC reflection probe;
    # ``postman_newman`` runs an uploaded collection from {path}.
    "openapi_scanner": frozenset({"url"}),
    "graphw00f": frozenset({"url"}),
    "clairvoyance": frozenset({"url"}),
    "inql": frozenset({"url"}),
    "graphql_cop": frozenset({"url"}),
    "grpcurl_probe": frozenset({"host", "port"}),
    "postman_newman": frozenset({"path"}),
    # §4.15 — cloud auditors take {profile}; SCA / image scanners take
    # {image}; the IaC config scan takes {path}; ``pacu`` takes a session
    # name and module; ``kube_hunter`` takes the cluster {host};
    # ``cloudsploit`` reads its config from {path}; ``kube_bench`` runs
    # against the local node and only emits to ``{out_dir}``.
    "prowler": frozenset({"profile"}),
    "scoutsuite": frozenset(),  # uses local AWS env; no input placeholder
    "cloudsploit": frozenset({"path"}),
    "pacu": frozenset({"s", "module"}),
    "trivy_image": frozenset({"image"}),
    "trivy_fs": frozenset({"path"}),
    "grype": frozenset({"image"}),
    "syft": frozenset({"image"}),
    "dockle": frozenset({"image"}),
    "kube_bench": frozenset(),  # local node scan, only out_dir
    "kube_hunter": frozenset({"host"}),
    "checkov": frozenset({"path"}),
    # §4.16 — IaC / SAST / secret scanners all consume a code tree at
    # {path}.
    "terrascan": frozenset({"path"}),
    "tfsec": frozenset({"path"}),
    "kics": frozenset({"path"}),
    "semgrep": frozenset({"path"}),
    "bandit": frozenset({"path"}),
    "gitleaks": frozenset({"path"}),
    "trufflehog": frozenset({"path"}),
    "detect_secrets": frozenset({"path"}),
}


@pytest.mark.parametrize("tool_id", ARG018_TOOL_IDS)
def test_command_template_references_required_input_placeholders(
    catalog_dir: Path, tool_id: str
) -> None:
    """Each tool's argv references its pinned input placeholder set."""
    descriptor = _load_descriptor(catalog_dir, tool_id)
    rendered = " ".join(descriptor.command_template)
    expected = REQUIRED_INPUT_PLACEHOLDERS[tool_id]
    for placeholder in expected:
        assert "{" + placeholder + "}" in rendered, (
            f"{tool_id}: command_template must reference {{{placeholder}}} "
            f"(pinned input set: {sorted(expected)})"
        )
