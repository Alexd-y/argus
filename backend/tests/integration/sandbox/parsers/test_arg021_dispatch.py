"""Integration test: ARG-021 batch-1 JSON_OBJECT dispatch (Backlog/dev1_md §4.15 + §4.16 + §4.18).

Sister suite to ``test_trivy_semgrep_dispatch.py``. Pins the ARG-021
contract that the **ten** new IaC / SAST / Cloud / Mobile / Secret /
Container / SCA parsers shipped in Cycle 3 batch-1:

* ``bandit``       — Python SAST,
* ``gitleaks``     — secret scanner (with mandatory redaction),
* ``kube_bench``   — Kubernetes CIS benchmark,
* ``checkov``      — multi-IaC,
* ``kics``         — multi-IaC,
* ``terrascan``    — Tenable IaC,
* ``tfsec``        — Aqua Terraform IaC,
* ``dockle``       — CIS Docker benchmark,
* ``mobsf_api``    — Mobile Security Framework,
* ``grype``        — Anchore SCA / CVE matcher,

all route through :class:`~src.sandbox.adapter_base.ParseStrategy.JSON_OBJECT`
and produce findings with the source ``tool_id`` stamped onto the
sidecar evidence record.

Guardrails enforced in this suite:

* Each ARG-021 tool is registered in the per-tool dispatch table.
* Dispatch from a representative payload yields ``len(findings) >= 1``.
* Each parser writes its own dedicated sidecar file (no overwrites
  between parsers in a shared ``/out`` directory).
* Cross-tool routing isolation: a payload shaped for tool A pushed
  through tool B's ``tool_id`` produces 0 real findings (defence in depth
  against shape-confusion).
* Determinism: re-running the same payload twice produces byte-identical
  sidecars.
* gitleaks must NEVER write the raw secret value to the sidecar.
* Prior cycle parsers (trivy_image / trivy_fs / semgrep + ARG-018 + earlier)
  survive ARG-021 wiring.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import (
    dispatch_parse,
    get_registered_tool_parsers,
    reset_registry,
)
from src.sandbox.parsers.bandit_parser import (
    EVIDENCE_SIDECAR_NAME as BANDIT_SIDECAR,
)
from src.sandbox.parsers.checkov_parser import (
    EVIDENCE_SIDECAR_NAME as CHECKOV_SIDECAR,
)
from src.sandbox.parsers.dockle_parser import (
    EVIDENCE_SIDECAR_NAME as DOCKLE_SIDECAR,
)
from src.sandbox.parsers.gitleaks_parser import (
    EVIDENCE_SIDECAR_NAME as GITLEAKS_SIDECAR,
)
from src.sandbox.parsers.grype_parser import (
    EVIDENCE_SIDECAR_NAME as GRYPE_SIDECAR,
)
from src.sandbox.parsers.kics_parser import (
    EVIDENCE_SIDECAR_NAME as KICS_SIDECAR,
)
from src.sandbox.parsers.kube_bench_parser import (
    EVIDENCE_SIDECAR_NAME as KUBE_BENCH_SIDECAR,
)
from src.sandbox.parsers.mobsf_parser import (
    EVIDENCE_SIDECAR_NAME as MOBSF_SIDECAR,
)
from src.sandbox.parsers.terrascan_parser import (
    EVIDENCE_SIDECAR_NAME as TERRASCAN_SIDECAR,
)
from src.sandbox.parsers.tfsec_parser import (
    EVIDENCE_SIDECAR_NAME as TFSEC_SIDECAR,
)


# ---------------------------------------------------------------------------
# Hermetic registry fixture
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_registry() -> Iterator[None]:
    yield
    reset_registry()


# ---------------------------------------------------------------------------
# Pinned tool_id sets
# ---------------------------------------------------------------------------


# Every ARG-021 tool that MUST have a parser registered post-Cycle 3 batch 1.
ARG021_TOOL_IDS: Final[tuple[str, ...]] = (
    "bandit",
    "gitleaks",
    "kube_bench",
    "checkov",
    "kics",
    "terrascan",
    "tfsec",
    "dockle",
    "mobsf_api",
    "grype",
)


# Each ARG-021 tool's canonical sidecar filename.  Keeps the assertion
# block compact and makes the shared-/out invariant obvious at a glance.
ARG021_TOOL_SIDECARS: Final[dict[str, str]] = {
    "bandit": BANDIT_SIDECAR,
    "gitleaks": GITLEAKS_SIDECAR,
    "kube_bench": KUBE_BENCH_SIDECAR,
    "checkov": CHECKOV_SIDECAR,
    "kics": KICS_SIDECAR,
    "terrascan": TERRASCAN_SIDECAR,
    "tfsec": TFSEC_SIDECAR,
    "dockle": DOCKLE_SIDECAR,
    "mobsf_api": MOBSF_SIDECAR,
    "grype": GRYPE_SIDECAR,
}


# ---------------------------------------------------------------------------
# Per-tool minimal-but-realistic payloads
# ---------------------------------------------------------------------------


def _bandit_payload() -> bytes:
    return json.dumps(
        {
            "results": [
                {
                    "filename": "src/utils.py",
                    "test_id": "B602",
                    "test_name": "subprocess_popen_with_shell_equals_true",
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "issue_text": "subprocess call with shell=True identified, security issue.",
                    "line_number": 42,
                    "line_range": [42, 44],
                    "issue_cwe": {
                        "id": 78,
                        "link": "https://cwe.mitre.org/data/definitions/78.html",
                    },
                    "code": "subprocess.run(cmd, shell=True)",
                }
            ],
            "errors": [],
            "metrics": {"_totals": {"loc": 100, "nosec": 0}},
        }
    ).encode("utf-8")


_RAW_GITLEAKS_SECRET: Final[str] = "AKIAIOSFODNN7TESTONLY"


def _gitleaks_payload() -> bytes:
    return json.dumps(
        [
            {
                "Description": "AWS Access Key ID",
                "RuleID": "aws-access-token",
                "StartLine": 12,
                "EndLine": 12,
                "StartColumn": 17,
                "EndColumn": 57,
                "Match": f"aws_access_key_id = {_RAW_GITLEAKS_SECRET}",
                "Secret": _RAW_GITLEAKS_SECRET,
                "File": "src/config/dev.env",
                "SymlinkFile": "",
                "Commit": "abc123def456abc123def456abc123def456abc1",
                "Entropy": 4.81,
                "Author": "alice",
                "Email": "alice@example.com",
                "Date": "2026-04-19T11:00:00Z",
                "Message": "wip: local dev creds",
                "Tags": ["aws", "key"],
                "Fingerprint": "abc123:dev.env:aws-access-token:12",
            }
        ]
    ).encode("utf-8")


def _kube_bench_payload() -> bytes:
    return json.dumps(
        {
            "Controls": [
                {
                    "id": "1",
                    "version": "1.7",
                    "text": "Master Node Configuration Files",
                    "node_type": "master",
                    "tests": [
                        {
                            "section": "1.1",
                            "desc": "Master Node Configuration",
                            "results": [
                                {
                                    "test_number": "1.1.1",
                                    "test_desc": "API server pod spec file permissions 644",
                                    "audit": "stat -c %a /etc/kubernetes/...",
                                    "remediation": "chmod 644 ...",
                                    "test_info": [],
                                    "status": "FAIL",
                                    "scored": True,
                                    "actual_value": "660",
                                    "expected_result": "permissions has permission 644",
                                }
                            ],
                        }
                    ],
                }
            ],
            "Totals": {"total_pass": 0, "total_fail": 1, "total_warn": 0},
        }
    ).encode("utf-8")


def _checkov_payload() -> bytes:
    return json.dumps(
        {
            "check_type": "terraform",
            "results": {
                "passed_checks": [],
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_20",
                        "bc_check_id": "BC_AWS_S3_1",
                        "check_name": "S3 bucket has an ACL of public-read",
                        "check_class": "checkov.terraform.checks.resource.aws.S3PublicACLRead",
                        "file_path": "/main.tf",
                        "file_abs_path": "/repo/main.tf",
                        "file_line_range": [10, 20],
                        "resource": "aws_s3_bucket.public",
                        "severity": "HIGH",
                        "guideline": "https://docs.bridgecrew.io/aws/s3-public",
                    }
                ],
                "skipped_checks": [],
                "parsing_errors": [],
            },
            "summary": {"passed": 0, "failed": 1},
        }
    ).encode("utf-8")


def _kics_payload() -> bytes:
    return json.dumps(
        {
            "kics_version": "v1.7.0",
            "files_scanned": 1,
            "lines_scanned": 100,
            "queries_total": 1,
            "queries": [
                {
                    "query_name": "Privileged Container",
                    "query_id": "1c5e0e6f-cce7-44ee-bc28-001ec27c8f64",
                    "query_url": "https://docs.kics.io/...",
                    "severity": "HIGH",
                    "platform": "Kubernetes",
                    "category": "Insecure Configurations",
                    "description": "Run as privileged container",
                    "cwe": "250",
                    "files": [
                        {
                            "file_name": "deployment.yaml",
                            "similarity_id": "abc123",
                            "line": 42,
                            "issue_type": "MissingAttribute",
                            "search_key": "metadata.name=frontend",
                            "search_line": 42,
                            "search_value": "",
                            "expected_value": "false",
                            "actual_value": "true",
                            "resource_type": "Deployment",
                            "resource_name": "frontend",
                        }
                    ],
                }
            ],
            "severity_counters": {"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 1},
        }
    ).encode("utf-8")


def _terrascan_payload() -> bytes:
    return json.dumps(
        {
            "results": {
                "violations": [
                    {
                        "rule_name": "ensureSecurityGroupNotOpenToInternet",
                        "description": "SG allows unrestricted ingress",
                        "rule_id": "AC_AWS_0319",
                        "severity": "HIGH",
                        "category": "Network Ports Security",
                        "resource_name": "main",
                        "resource_type": "aws_security_group",
                        "module_name": "root",
                        "file": "main.tf",
                        "plan_root": "./",
                        "line": 25,
                    }
                ],
                "skipped_violations": [],
                "scan_summary": {"file_folder": "./"},
            }
        }
    ).encode("utf-8")


def _tfsec_payload() -> bytes:
    return json.dumps(
        {
            "results": [
                {
                    "rule_id": "AVD-AWS-0001",
                    "long_id": "aws-s3-enable-bucket-encryption",
                    "rule_description": "Bucket should be encrypted",
                    "rule_provider": "aws",
                    "rule_service": "s3",
                    "impact": "Confidential data is unencrypted",
                    "resolution": "Enable encryption with KMS",
                    "links": ["https://aquasecurity.github.io/tfsec/"],
                    "description": "Bucket does not have encryption enabled",
                    "severity": "HIGH",
                    "warning": False,
                    "status": 1,
                    "resource": "aws_s3_bucket.example",
                    "location": {
                        "filename": "/repo/main.tf",
                        "start_line": 10,
                        "end_line": 15,
                    },
                }
            ]
        }
    ).encode("utf-8")


def _dockle_payload() -> bytes:
    return json.dumps(
        {
            "summary": {"fatal": 1, "warn": 0, "info": 0, "skip": 0, "pass": 0},
            "details": [
                {
                    "code": "CIS-DI-0001",
                    "title": "Create a user for the container",
                    "level": "FATAL",
                    "alerts": ["Last user should not be root"],
                }
            ],
        }
    ).encode("utf-8")


def _mobsf_payload() -> bytes:
    return json.dumps(
        {
            "code_analysis": {
                "android_logging": {
                    "severity": "warning",
                    "title": "Logger present",
                    "description": "Logger could leak data",
                }
            }
        }
    ).encode("utf-8")


def _grype_payload() -> bytes:
    return json.dumps(
        {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2024-12345",
                        "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
                        "namespace": "nvd:cpe",
                        "severity": "Critical",
                        "urls": ["https://example.com"],
                        "description": "Out-of-bounds write",
                        "cvss": [
                            {
                                "version": "3.1",
                                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "metrics": {
                                    "baseScore": 9.8,
                                    "exploitabilityScore": 3.9,
                                    "impactScore": 5.9,
                                },
                            }
                        ],
                        "fix": {"versions": ["1.2.4"], "state": "fixed"},
                    },
                    "relatedVulnerabilities": [{"id": "GHSA-x", "cwes": ["CWE-787"]}],
                    "matchDetails": [
                        {
                            "type": "exact-direct-match",
                            "matcher": "rpm-matcher",
                            "searchedBy": {},
                            "found": {"versionConstraint": "< 1.2.4 (rpm)"},
                        }
                    ],
                    "artifact": {
                        "name": "openssl",
                        "version": "1.2.3-1.el9",
                        "type": "rpm",
                        "purl": "pkg:rpm/redhat/openssl@1.2.3-1.el9",
                        "locations": [{"path": "/var/lib/rpm/Packages"}],
                    },
                }
            ],
            "source": {"target": "alpine:3.18", "type": "image"},
            "distro": {"name": "alpine", "version": "3.18"},
            "descriptor": {"name": "grype", "version": "0.74.0"},
        }
    ).encode("utf-8")


_PAYLOAD_BY_TOOL: Final[dict[str, Any]] = {
    "bandit": _bandit_payload,
    "gitleaks": _gitleaks_payload,
    "kube_bench": _kube_bench_payload,
    "checkov": _checkov_payload,
    "kics": _kics_payload,
    "terrascan": _terrascan_payload,
    "tfsec": _tfsec_payload,
    "dockle": _dockle_payload,
    "mobsf_api": _mobsf_payload,
    "grype": _grype_payload,
}


def _read_sidecar(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# Per-tool registration surface
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG021_TOOL_IDS)
def test_arg021_tool_is_registered(tool_id: str) -> None:
    """Every ARG-021 tool must be wired into the per-tool dispatch table."""
    registered = get_registered_tool_parsers()
    assert tool_id in registered, (
        f"{tool_id} missing from per-tool parser registry — broken wiring "
        f"in src.sandbox.parsers.__init__._DEFAULT_TOOL_PARSERS"
    )


def test_arg021_does_not_drop_prior_cycle_registrations() -> None:
    """Sanity: ARG-018 + earlier wirings survive the ARG-021 batch."""
    registered = get_registered_tool_parsers()
    legacy_tools = (
        # Cycle 1
        "httpx",
        "ffuf_dir",
        "katana",
        "wpscan",
        "nuclei",
        "nikto",
        "wapiti",
        # Cycle 2 / ARG-018
        "trivy_image",
        "trivy_fs",
        "semgrep",
        # Cycle 2 / ARG-016 / 017 / 019
        "sqlmap_safe",
        "dalfox",
        "interactsh_client",
        "nmap_tcp_top",
    )
    for legacy in legacy_tools:
        assert legacy in registered, f"{legacy} slot must survive ARG-021 registration"


# ---------------------------------------------------------------------------
# Routing — happy path for every ARG-021 tool
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG021_TOOL_IDS)
def test_dispatch_routes_each_arg021_tool(tool_id: str, tmp_path: Path) -> None:
    """Every ARG-021 tool routes via JSON_OBJECT and yields ≥1 finding."""
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    payload = _PAYLOAD_BY_TOOL[tool_id]()
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        payload,
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id}: dispatch produced no findings"
    assert all(isinstance(f, FindingDTO) for f in findings)


@pytest.mark.parametrize("tool_id", ARG021_TOOL_IDS)
def test_dispatch_writes_per_tool_sidecar(tool_id: str, tmp_path: Path) -> None:
    """Each ARG-021 dispatch writes its dedicated sidecar tagged with tool_id."""
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    payload = _PAYLOAD_BY_TOOL[tool_id]()
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        payload,
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings
    sidecar = artifacts_dir / ARG021_TOOL_SIDECARS[tool_id]
    assert sidecar.is_file(), (
        f"{tool_id}: parser must write evidence sidecar at {sidecar}"
    )
    parsed = _read_sidecar(sidecar)
    assert parsed, f"{tool_id}: sidecar is empty"
    assert all(rec["tool_id"] == tool_id for rec in parsed), (
        f"{tool_id}: every sidecar record must tag its source tool_id"
    )


def test_arg021_tools_use_distinct_sidecar_filenames() -> None:
    """All ten ARG-021 sidecar filenames must be unique across the batch."""
    sidecars = list(ARG021_TOOL_SIDECARS.values())
    assert len(set(sidecars)) == len(sidecars), (
        "ARG-021 parsers collide on sidecar filenames; one tool would "
        "overwrite another in shared /out"
    )


# ---------------------------------------------------------------------------
# CRITICAL — gitleaks redaction guardrail
# ---------------------------------------------------------------------------


def test_gitleaks_redacts_secret_in_sidecar(tmp_path: Path) -> None:
    """The raw gitleaks ``Secret`` value MUST never reach the sidecar."""
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _gitleaks_payload(),
        b"",
        tmp_path,
        tool_id="gitleaks",
    )
    assert findings, "gitleaks dispatch must yield ≥1 finding"
    sidecar = tmp_path / GITLEAKS_SIDECAR
    text = sidecar.read_text(encoding="utf-8")
    assert _RAW_GITLEAKS_SECRET not in text, (
        "RAW SECRET LEAKED through gitleaks sidecar — redaction broken"
    )
    assert "***REDACTED" in text, "expected redaction marker in gitleaks sidecar"


def test_gitleaks_finding_has_secret_leak_category(tmp_path: Path) -> None:
    """gitleaks → SECRET_LEAK + CWE-798 + CONFIRMED, not a sentinel."""
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _gitleaks_payload(),
        b"",
        tmp_path,
        tool_id="gitleaks",
    )
    assert findings[0].category is FindingCategory.SECRET_LEAK
    assert 798 in findings[0].cwe
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED


# ---------------------------------------------------------------------------
# Cross-tool routing isolation — defence in depth
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload_tool", "wrong_tool"),
    [
        ("checkov", "tfsec"),
        ("kics", "terrascan"),
        ("dockle", "kube_bench"),
        ("grype", "bandit"),
        ("gitleaks", "checkov"),
        ("mobsf_api", "grype"),
    ],
)
def test_cross_routing_is_inert(
    payload_tool: str, wrong_tool: str, tmp_path: Path
) -> None:
    """A payload from tool X dispatched as tool Y must not produce findings."""
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _PAYLOAD_BY_TOOL[payload_tool](),
        b"",
        tmp_path,
        tool_id=wrong_tool,
    )
    assert findings == [], (
        f"{wrong_tool} parser produced findings on a {payload_tool}-shaped "
        f"payload — defence in depth broken"
    )


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG021_TOOL_IDS)
def test_arg021_dispatch_is_deterministic(tool_id: str, tmp_path: Path) -> None:
    """Two dispatches on the same payload produce byte-identical sidecars."""
    payload = _PAYLOAD_BY_TOOL[tool_id]()
    artifacts_a = tmp_path / "a"
    artifacts_b = tmp_path / "b"
    artifacts_a.mkdir()
    artifacts_b.mkdir()
    dispatch_parse(
        ParseStrategy.JSON_OBJECT, payload, b"", artifacts_a, tool_id=tool_id
    )
    dispatch_parse(
        ParseStrategy.JSON_OBJECT, payload, b"", artifacts_b, tool_id=tool_id
    )
    sidecar_name = ARG021_TOOL_SIDECARS[tool_id]
    a_bytes = (artifacts_a / sidecar_name).read_bytes()
    b_bytes = (artifacts_b / sidecar_name).read_bytes()
    assert a_bytes == b_bytes, (
        f"{tool_id}: sidecar bytes drift between runs — non-deterministic parser"
    )


# ---------------------------------------------------------------------------
# Multi-tool same /out directory — sidecar isolation
# ---------------------------------------------------------------------------


def test_all_arg021_parsers_in_single_artifacts_dir_keeps_sidecars_intact(
    tmp_path: Path,
) -> None:
    """Running all ten ARG-021 parsers in the same dir leaves all sidecars intact."""
    for tool_id in ARG021_TOOL_IDS:
        dispatch_parse(
            ParseStrategy.JSON_OBJECT,
            _PAYLOAD_BY_TOOL[tool_id](),
            b"",
            tmp_path,
            tool_id=tool_id,
        )

    for tool_id, sidecar_name in ARG021_TOOL_SIDECARS.items():
        sidecar = tmp_path / sidecar_name
        assert sidecar.is_file(), (
            f"{tool_id}: sidecar {sidecar_name} missing after multi-tool run"
        )
        records = _read_sidecar(sidecar)
        assert records, f"{tool_id}: sidecar {sidecar_name} is empty"
        assert all(r["tool_id"] == tool_id for r in records), (
            f"{tool_id}: cross-tool contamination in {sidecar_name}"
        )
