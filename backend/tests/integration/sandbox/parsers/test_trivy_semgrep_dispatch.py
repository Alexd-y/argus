"""Integration test: trivy + semgrep JSON_OBJECT dispatch (Backlog/dev1_md §4.15 + §4.16 — ARG-018).

Sister suite to ``test_nuclei_dispatch.py``; this one pins the ARG-018
contract that:

* The ``trivy_image`` and ``trivy_fs`` SCA scanners (§4.15) AND the
  ``semgrep`` SAST tool (§4.16) all route through
  :class:`~src.sandbox.adapter_base.ParseStrategy.JSON_OBJECT` to their
  dedicated parsers in :mod:`src.sandbox.parsers.trivy_parser` and
  :mod:`src.sandbox.parsers.semgrep_parser`, with the source ``tool_id``
  stamped onto every sidecar record.
* Both Trivy callers (``trivy_image`` / ``trivy_fs``) share the same
  ``parse_trivy_json`` implementation while keeping their tool_id
  demultiplexable downstream — analogous to the nuclei caller fan-in.
* Trivy and Semgrep use **distinct** sidecar filenames so the two
  parsers never overwrite each other when both run inside the same
  artifacts directory.
* Cross-tool inertness: a Trivy-shaped envelope routed through the
  ``semgrep`` tool_id (and vice-versa) yields ``[]`` rather than
  silently corrupting findings — defence in depth against
  shape-confusion attacks.
* Prior cycle registrations (httpx, ffuf_dir, katana, wpscan, nuclei,
  nikto, wapiti) must survive ARG-018's registration batch so that
  Cycle 2 catalog growth never regresses Cycle 1 / earlier ARG-XXX
  wirings.
* The §4.14 / §4.15 tools whose parsers are still deferred to Cycle
  4 (graphw00f, clairvoyance, inql, grpcurl_probe, scoutsuite, pacu,
  kube_hunter) MUST NOT have a parser registered yet; pinned
  explicitly so a future silent move into ``_DEFAULT_TOOL_PARSERS``
  lights up the diff in CI.  The list shrinks one cycle at a time —
  ARG-021 retired ten entries (IaC/secret-scanner batch), ARG-029
  retired eight more (API/GraphQL + cloud + secrets batch).
"""

from __future__ import annotations

import json
import logging
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
    get_registered_strategies,
    get_registered_tool_parsers,
    reset_registry,
)
from src.sandbox.parsers.semgrep_parser import (
    EVIDENCE_SIDECAR_NAME as SEMGREP_SIDECAR_NAME,
)
from src.sandbox.parsers.trivy_parser import (
    EVIDENCE_SIDECAR_NAME as TRIVY_SIDECAR_NAME,
)


# ---------------------------------------------------------------------------
# Hermetic registry fixture
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_registry() -> Iterator[None]:
    yield
    reset_registry()


# ---------------------------------------------------------------------------
# Inputs — pinned tool_id sets
# ---------------------------------------------------------------------------


# §4.15 SCA — both callers share ``parse_trivy_json``.
TRIVY_TOOL_IDS: Final[tuple[str, ...]] = ("trivy_image", "trivy_fs")

# §4.16 SAST — single caller for ``parse_semgrep_json``.
SEMGREP_TOOL_IDS: Final[tuple[str, ...]] = ("semgrep",)

# §4.14 / §4.15 / §4.16 tools whose parsers are still deferred — pinned
# explicitly so adding a parser without updating this list breaks CI
# with a self-documenting "Cycle 3 work landed early; update
# DEFERRED_ARG018_TOOL_IDS" assertion.
#
# Cycle 3 wired the following originally-deferred tools (their
# dispatch contracts now live in the per-batch test modules):
#
# * ARG-021 (batch 1, IaC/code/secrets/containers): ``bandit``,
#   ``gitleaks``, ``kube_bench``, ``checkov``, ``kics``, ``terrascan``,
#   ``tfsec``, ``dockle``, ``mobsf_api``, ``grype``.
# * ARG-029 (batch 3, API/GraphQL + cloud + secrets): ``openapi_scanner``,
#   ``graphql_cop``, ``postman_newman``, ``prowler``, ``cloudsploit``,
#   ``syft``, ``trufflehog``, ``detect_secrets``.
#
# The remaining entries are the §4.14/§4.15 tools whose parsers stay
# deferred to Cycle 4 (see ``ai_docs/develop/issues/ISS-cycle4-carry-over.md``,
# ARG-032 — heartbeat parsers batch 4).
DEFERRED_ARG018_TOOL_IDS: Final[tuple[str, ...]] = (
    # §4.14 API/GraphQL (parsers deferred to Cycle 4)
    "graphw00f",
    "clairvoyance",
    "inql",
    "grpcurl_probe",
    # §4.15 Cloud / IaC / container (parsers deferred to Cycle 4)
    "scoutsuite",
    "pacu",
    "kube_hunter",
)


def _trivy_payload(*, tool_id: str = "trivy_image") -> bytes:
    """Representative Trivy envelope exercising vuln + misconfig + secret paths."""
    return json.dumps(
        {
            "ArtifactName": "registry.example/foo:1.2.3"
            if tool_id == "trivy_image"
            else "/in/repo",
            "ArtifactType": "container_image"
            if tool_id == "trivy_image"
            else "filesystem",
            "Results": [
                {
                    "Target": "registry.example/foo:1.2.3 (debian 12.5)",
                    "Class": "os-pkgs",
                    "Type": "debian",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1337",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.0.11",
                            "FixedVersion": "3.0.12",
                            "Severity": "CRITICAL",
                            "Title": "openssl: RCE",
                            "Description": "Critical RCE in OpenSSL TLS handshake",
                            "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2024-1337",
                            "CweIDs": ["CWE-787"],
                            "CVSS": {
                                "nvd": {
                                    "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    "V3Score": 9.8,
                                }
                            },
                        }
                    ],
                },
                {
                    "Target": "Dockerfile",
                    "Class": "config",
                    "Type": "dockerfile",
                    "Misconfigurations": [
                        {
                            "ID": "DS002",
                            "AVDID": "AVD-DS-0002",
                            "Title": "Image user should not be 'root'",
                            "Description": "Image runs as root by default",
                            "Message": "Specify at least 1 USER command",
                            "Severity": "HIGH",
                            "Status": "FAIL",
                            "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
                            "CauseMetadata": {"StartLine": 5, "EndLine": 5},
                        }
                    ],
                },
            ],
        }
    ).encode("utf-8")


def _semgrep_payload() -> bytes:
    """Representative Semgrep envelope exercising security category routing."""
    return json.dumps(
        {
            "version": "1.59.0",
            "results": [
                {
                    "check_id": "python.lang.security.audit.dangerous-subprocess",
                    "path": "src/utils.py",
                    "start": {"line": 42, "col": 9},
                    "end": {"line": 44, "col": 35},
                    "extra": {
                        "message": "subprocess called with shell=True permits OS injection.",
                        "severity": "ERROR",
                        "metadata": {
                            "cwe": ["CWE-78: Improper Neutralization of OS Command"],
                            "owasp": ["A03:2021 - Injection"],
                            "category": "security",
                            "confidence": "HIGH",
                            "likelihood": "HIGH",
                            "impact": "HIGH",
                        },
                        "lines": "subprocess.run(cmd, shell=True)",
                        "fingerprint": "deadbeefcafe",
                    },
                }
            ],
            "errors": [],
            "paths": {"scanned": ["src/utils.py"], "skipped": []},
        }
    ).encode("utf-8")


def _read_sidecar(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# Strategy + per-tool registration surface
# ---------------------------------------------------------------------------


def test_json_object_strategy_is_registered() -> None:
    """``ParseStrategy.JSON_OBJECT`` must have a default handler."""
    assert ParseStrategy.JSON_OBJECT in get_registered_strategies(), (
        "JSON_OBJECT strategy missing from default registry — broken wiring "
        "in src.sandbox.parsers.__init__._build_default_strategy_handlers"
    )


@pytest.mark.parametrize("tool_id", TRIVY_TOOL_IDS)
def test_default_per_tool_registry_includes_each_trivy_caller(
    tool_id: str,
) -> None:
    """Both §4.15 Trivy callers must be registered for dispatch."""
    registered = get_registered_tool_parsers()
    assert tool_id in registered, (
        f"{tool_id} missing from per-tool parser registry — broken "
        f"wiring in src.sandbox.parsers.__init__"
    )


@pytest.mark.parametrize("tool_id", SEMGREP_TOOL_IDS)
def test_default_per_tool_registry_includes_semgrep(tool_id: str) -> None:
    """The §4.16 Semgrep caller must be registered for dispatch."""
    registered = get_registered_tool_parsers()
    assert tool_id in registered, (
        f"{tool_id} missing from per-tool parser registry — broken "
        f"wiring in src.sandbox.parsers.__init__"
    )


def test_arg018_does_not_drop_prior_cycle_registrations() -> None:
    """Sanity: §4.4–§4.8 wirings survive the ARG-018 batch of registrations."""
    registered = get_registered_tool_parsers()
    legacy_tools = (
        "httpx",
        "ffuf_dir",
        "katana",
        "wpscan",
        "nuclei",
        "nikto",
        "wapiti",
    )
    for legacy in legacy_tools:
        assert legacy in registered, f"{legacy} slot must survive ARG-018 registration"


# ---------------------------------------------------------------------------
# Routing — happy path for trivy callers (shared parser)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", TRIVY_TOOL_IDS)
def test_dispatch_routes_each_trivy_tool_to_shared_parser(
    tool_id: str, tmp_path: Path
) -> None:
    """Both Trivy tool_ids route via JSON_OBJECT and produce findings."""
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _trivy_payload(tool_id=tool_id),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id}: dispatch produced no findings"
    assert all(isinstance(f, FindingDTO) for f in findings)


def test_dispatch_trivy_fs_reads_canonical_artifact_file(tmp_path: Path) -> None:
    """Production shape: ``trivy_fs`` writes ``/out/trivy_fs.json``, stdout empty.

    Mirrors the real sandbox flow where the wrapper runs ``trivy fs ...
    -o /out/trivy_fs.json {path}`` and the parser must read that file.
    Regression for C1: pre-fix the parser hard-coded ``trivy.json`` and
    silently returned ``[]`` for every ``trivy_fs`` job, breaking the
    entire filesystem SCA / IaC / secret pipeline.
    """
    artifacts_dir = tmp_path / "trivy_fs_run"
    artifacts_dir.mkdir()
    (artifacts_dir / "trivy_fs.json").write_bytes(_trivy_payload(tool_id="trivy_fs"))
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        b"",  # production shape: stdout is empty when -o was used
        b"",
        artifacts_dir,
        tool_id="trivy_fs",
    )
    assert findings, "trivy_fs must produce findings from the canonical artifact file"
    sidecar = artifacts_dir / TRIVY_SIDECAR_NAME
    assert sidecar.is_file()
    parsed = _read_sidecar(sidecar)
    assert all(rec["tool_id"] == "trivy_fs" for rec in parsed)


def test_dispatch_trivy_image_ignores_sibling_trivy_fs_artifact(
    tmp_path: Path,
) -> None:
    """Cross-tool isolation under shared ``/out``: ``trivy_image`` parser
    must never silently consume a sibling ``trivy_fs.json`` left behind
    by an earlier filesystem scan in the same artifacts directory.
    """
    artifacts_dir = tmp_path / "shared_out"
    artifacts_dir.mkdir()
    (artifacts_dir / "trivy_fs.json").write_bytes(_trivy_payload(tool_id="trivy_fs"))
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        b"",
        b"",
        artifacts_dir,
        tool_id="trivy_image",
    )
    assert findings == [], (
        "trivy_image must not pick up trivy_fs.json — distinct canonical "
        "filenames are how the two callers stay isolated under one /out"
    )


@pytest.mark.parametrize("tool_id", TRIVY_TOOL_IDS)
def test_dispatch_writes_trivy_sidecar_with_correct_tool_id(
    tool_id: str, tmp_path: Path
) -> None:
    """Each Trivy dispatch emits ``trivy_findings.jsonl`` tagged with tool_id."""
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _trivy_payload(tool_id=tool_id),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings

    sidecar = artifacts_dir / TRIVY_SIDECAR_NAME
    assert sidecar.is_file(), (
        f"{tool_id}: trivy parser must write evidence sidecar at {sidecar}"
    )
    parsed = _read_sidecar(sidecar)
    assert len(parsed) == len(findings)
    assert all(rec["tool_id"] == tool_id for rec in parsed), (
        f"{tool_id}: every sidecar record must tag its source tool_id"
    )


def test_trivy_dispatch_attaches_supply_chain_for_critical_cve(
    tmp_path: Path,
) -> None:
    """A CRITICAL Trivy vuln record → SUPPLY_CHAIN classified at LIKELY."""
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _trivy_payload(tool_id="trivy_image"),
        b"",
        tmp_path,
        tool_id="trivy_image",
    )
    sca = [f for f in findings if f.category is FindingCategory.SUPPLY_CHAIN]
    assert sca, "expected at least one SUPPLY_CHAIN finding for the critical CVE"
    assert sca[0].confidence is ConfidenceLevel.LIKELY
    assert sca[0].cvss_v3_score == pytest.approx(9.8)


# ---------------------------------------------------------------------------
# Routing — happy path for semgrep
# ---------------------------------------------------------------------------


def test_dispatch_routes_semgrep_via_json_object(tmp_path: Path) -> None:
    """``semgrep`` routes via JSON_OBJECT to ``parse_semgrep_json``."""
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _semgrep_payload(),
        b"",
        tmp_path,
        tool_id="semgrep",
    )
    assert findings, "semgrep: dispatch produced no findings"
    sidecar = tmp_path / SEMGREP_SIDECAR_NAME
    assert sidecar.is_file()
    parsed = _read_sidecar(sidecar)
    assert all(rec["tool_id"] == "semgrep" for rec in parsed)


def test_semgrep_dispatch_routes_cwe78_to_rce(tmp_path: Path) -> None:
    """A CWE-78 Semgrep result lands in RCE (top-25) with LIKELY confidence."""
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _semgrep_payload(),
        b"",
        tmp_path,
        tool_id="semgrep",
    )
    rce = [f for f in findings if f.category is FindingCategory.RCE]
    assert rce, "expected at least one RCE finding for CWE-78"
    assert rce[0].confidence is ConfidenceLevel.LIKELY


# ---------------------------------------------------------------------------
# Sidecar isolation — trivy vs semgrep do not collide
# ---------------------------------------------------------------------------


def test_trivy_and_semgrep_use_distinct_sidecar_filenames() -> None:
    """The two §4.15/§4.16 parsers must never overwrite each other's evidence."""
    assert TRIVY_SIDECAR_NAME != SEMGREP_SIDECAR_NAME, (
        "trivy and semgrep must use distinct sidecar filenames so a "
        "single artifacts dir can hold both without overwrites"
    )


def test_trivy_then_semgrep_in_same_artifacts_dir_keeps_both_sidecars(
    tmp_path: Path,
) -> None:
    """Running trivy then semgrep in the same dir leaves both sidecars intact."""
    trivy_findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _trivy_payload(tool_id="trivy_fs"),
        b"",
        tmp_path,
        tool_id="trivy_fs",
    )
    semgrep_findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _semgrep_payload(),
        b"",
        tmp_path,
        tool_id="semgrep",
    )
    assert trivy_findings and semgrep_findings

    trivy_sidecar = tmp_path / TRIVY_SIDECAR_NAME
    semgrep_sidecar = tmp_path / SEMGREP_SIDECAR_NAME
    assert trivy_sidecar.is_file()
    assert semgrep_sidecar.is_file()

    trivy_records = _read_sidecar(trivy_sidecar)
    semgrep_records = _read_sidecar(semgrep_sidecar)
    assert all(rec["tool_id"] == "trivy_fs" for rec in trivy_records)
    assert all(rec["tool_id"] == "semgrep" for rec in semgrep_records)


# ---------------------------------------------------------------------------
# Negative path — deferred ARG-018 tools must NOT be registered
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", DEFERRED_ARG018_TOOL_IDS)
def test_deferred_arg018_tools_have_no_parser(
    tool_id: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The deferred §4.14/§4.15/§4.16 tools must NOT route to any parser yet.

    Strategy-level: a JSON_OBJECT dispatch with one of these tool_ids
    fail-softs to the ``parsers.dispatch.unmapped_tool`` warning AND
    emits one ARG-020 heartbeat finding so the orchestrator can
    distinguish "tool ran but parser deferred" from a silent skip.
    """
    registered = get_registered_tool_parsers()
    assert tool_id not in registered, (
        f"{tool_id} unexpectedly has a parser — Cycle 3 work landed early; "
        f"update DEFERRED_ARG018_TOOL_IDS in this test"
    )

    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = dispatch_parse(
            ParseStrategy.JSON_OBJECT,
            _trivy_payload(),
            b"",
            tmp_path,
            tool_id=tool_id,
        )

    assert len(findings) == 1, (
        f"{tool_id}: expected one heartbeat via JSON_OBJECT misroute, "
        f"got {len(findings)} findings"
    )
    heartbeat = findings[0]
    assert heartbeat.category is FindingCategory.INFO
    assert "ARGUS-HEARTBEAT" in heartbeat.owasp_wstg
    assert f"HEARTBEAT-{tool_id}" in heartbeat.owasp_wstg
    assert any(
        getattr(record, "event", "") == "parsers_dispatch_unmapped_tool"
        and getattr(record, "tool_id", None) == tool_id
        for record in caplog.records
    ), f"{tool_id}: missing parsers.dispatch.unmapped_tool warning"


# ---------------------------------------------------------------------------
# Cross-routing safety — semgrep payload + trivy tool_id must stay inert
# ---------------------------------------------------------------------------


def test_semgrep_payload_misrouted_via_trivy_tool_id_is_inert(
    tmp_path: Path,
) -> None:
    """Pushing a semgrep envelope through the ``trivy_image`` tool_id → ``[]``.

    The per-tool table is keyed by ``tool_id``, so a semgrep envelope routed
    with ``tool_id="trivy_image"`` calls ``parse_trivy_json``. The Trivy
    parser is shape-aware (looks for ``Results[]`` with
    ``Vulnerabilities`` / ``Misconfigurations`` / ``Secrets``) and yields
    nothing on the Semgrep ``results[]`` shape — defence in depth against
    accidental shape-confusion.
    """
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _semgrep_payload(),
        b"",
        tmp_path,
        tool_id="trivy_image",
    )
    assert findings == [], (
        "trivy parser must produce no findings on a semgrep-shaped envelope"
    )


def test_trivy_payload_misrouted_via_semgrep_tool_id_is_inert(
    tmp_path: Path,
) -> None:
    """Pushing a trivy envelope through the ``semgrep`` tool_id → ``[]``.

    Symmetric to the above — the Semgrep parser is shape-aware and finds
    no ``results[]`` array in a Trivy envelope, yielding ``[]`` rather
    than crashing or silently emitting bad findings.
    """
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _trivy_payload(),
        b"",
        tmp_path,
        tool_id="semgrep",
    )
    assert findings == [], (
        "semgrep parser must produce no findings on a trivy-shaped envelope"
    )


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", TRIVY_TOOL_IDS)
def test_trivy_dispatch_is_deterministic_across_repeated_runs(
    tool_id: str, tmp_path: Path
) -> None:
    """Two trivy dispatches on the same payload produce identical sidecars."""
    artifacts_a = tmp_path / "a"
    artifacts_b = tmp_path / "b"
    artifacts_a.mkdir()
    artifacts_b.mkdir()
    payload = _trivy_payload(tool_id=tool_id)
    dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        payload,
        b"",
        artifacts_a,
        tool_id=tool_id,
    )
    dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        payload,
        b"",
        artifacts_b,
        tool_id=tool_id,
    )
    sidecar_a = (artifacts_a / TRIVY_SIDECAR_NAME).read_bytes()
    sidecar_b = (artifacts_b / TRIVY_SIDECAR_NAME).read_bytes()
    assert sidecar_a == sidecar_b, (
        f"{tool_id}: sidecar bytes drift between runs — non-deterministic parser"
    )


def test_semgrep_dispatch_is_deterministic_across_repeated_runs(
    tmp_path: Path,
) -> None:
    """Two semgrep dispatches on the same payload produce identical sidecars."""
    artifacts_a = tmp_path / "a"
    artifacts_b = tmp_path / "b"
    artifacts_a.mkdir()
    artifacts_b.mkdir()
    payload = _semgrep_payload()
    dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        payload,
        b"",
        artifacts_a,
        tool_id="semgrep",
    )
    dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        payload,
        b"",
        artifacts_b,
        tool_id="semgrep",
    )
    sidecar_a = (artifacts_a / SEMGREP_SIDECAR_NAME).read_bytes()
    sidecar_b = (artifacts_b / SEMGREP_SIDECAR_NAME).read_bytes()
    assert sidecar_a == sidecar_b, (
        "semgrep: sidecar bytes drift between runs — non-deterministic parser"
    )
