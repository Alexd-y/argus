"""End-to-end integration test: ARG-015 §4.8 ``nuclei`` vertical slice.

Wires up the three subsystems ARG-015 ships in lockstep — YAML descriptor,
templating-rendered argv, parser dispatch — against the real
:mod:`src.sandbox.tool_registry` and the real :mod:`src.sandbox.parsers`
registry. No mocks for the registry layers; only the *raw* nuclei JSONL
output is synthesised.

Concretely the test verifies:

1.  Loading the production catalog through :class:`ToolRegistry` yields a
    descriptor for ``nuclei`` whose ``parse_strategy`` is NUCLEI_JSONL,
    image is ``argus-kali-web:latest`` and network policy is
    ``recon-active-tcp``.
2.  Rendering ``descriptor.command_template`` with ``url=...`` /
    ``out_dir=/out`` produces a clean argv whose tokens are free of any
    shell metacharacters or unrendered placeholders.
3.  Feeding a synthetic nuclei JSONL stream (one info-tag + one critical
    RCE with full CVSS / CVE / EPSS metadata) into :func:`dispatch_parse`
    with the descriptor's strategy yields exactly the expected number of
    FindingDTOs with the correct categories, CWEs, OWASP-WSTG hints,
    confidence levels, CVSS scores and EPSS scores.
4.  The shared evidence sidecar (``nuclei_findings.jsonl``) is written to
    the artefacts directory with one record per finding, each stamped
    with the source ``tool_id`` (so the ``nuclei`` flagship and its
    three §4.7 wrappers stay demultiplexable downstream).
5.  The same JSONL pipeline driven through each of the three §4.7 nuclei
    wrappers (``nextjs_check``, ``spring_boot_actuator``, ``jenkins_enum``)
    yields findings tagged with the wrapper's ``tool_id`` — the
    ARG-015 graduation contract for the three CMS templates that shipped
    in cycle 2 awaiting a parser.

Hard isolation: the ``loaded_registry`` fixture builds an *isolated* tool
catalog under ``tmp_path`` containing only the seven §4.8 YAMLs + the
three §4.7 nuclei wrappers (plus a fresh dev signing key) so the test
cannot be flaked by parallel batches that may land broken descriptors in
the production ``backend/config/tools/`` tree (the registry is
fail-closed: ANY broken peer aborts the whole load).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any, Final

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import dispatch_parse
from src.sandbox.parsers.nuclei_parser import EVIDENCE_SIDECAR_NAME
from src.sandbox.signing import (
    KeyManager,
    SignatureRecord,
    SignaturesFile,
    compute_yaml_hash,
    load_private_key_bytes,
    sign_blob,
)
from src.sandbox.templating import render_argv
from src.sandbox.tool_registry import ToolRegistry


_SHELL_METACHARS: Final[tuple[str, ...]] = (
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


# Seven §4.8 active web-vuln scanners + three §4.7 nuclei template
# wrappers that ARG-015 ships in lockstep. The isolated catalog mirrors
# only this set so the e2e test is robust against parallel batches
# landing broken peers.
_ARG015_TOOL_IDS: Final[tuple[str, ...]] = (
    # §4.8 active web-vuln scanners
    "nuclei",
    "nikto",
    "wapiti",
    "arachni",
    "skipfish",
    "w3af_console",
    "zap_baseline",
    # §4.7 nuclei wrappers — the three CMS templates that graduate to
    # producing findings in ARG-015 (parser ships here).
    "nextjs_check",
    "spring_boot_actuator",
    "jenkins_enum",
)


# Tool ids that route through ``parse_nuclei_jsonl`` — the four nuclei
# callers must yield findings against the same JSONL payload.
_NUCLEI_CALLER_IDS: Final[tuple[str, ...]] = (
    "nuclei",
    "nextjs_check",
    "spring_boot_actuator",
    "jenkins_enum",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def production_catalog_dir() -> Path:
    """Resolve ``backend/config/tools/`` from this test file's location.

    Used only as the *source* of YAML descriptors that we copy into the
    isolated tmp catalog; never loaded directly through ``ToolRegistry``.
    """
    here = Path(__file__).resolve()
    backend_dir = here.parents[3]
    catalog = backend_dir / "config" / "tools"
    assert catalog.is_dir(), f"expected catalog dir at {catalog}"
    return catalog


@pytest.fixture(scope="module")
def isolated_catalog(
    tmp_path_factory: pytest.TempPathFactory,
    production_catalog_dir: Path,
) -> Path:
    """Build an isolated, freshly-signed mirror of the ten ARG-015 YAMLs.

    Defence-in-depth: copy ``nuclei.yaml`` and the nine other §4.7+§4.8
    descriptors into ``tmp_path / tools``, generate a one-shot dev
    keypair, sign the ten YAMLs, and write a clean ``SIGNATURES``
    manifest. The result is a self-contained registry directory that
    the test can load with :class:`ToolRegistry` regardless of the state
    of the production catalog.
    """
    catalog_root = tmp_path_factory.mktemp("arg015_catalog")
    tools_dir = catalog_root / "tools"
    keys_dir = tools_dir / "_keys"
    tools_dir.mkdir(parents=True)
    keys_dir.mkdir(parents=True)

    for tool_id in _ARG015_TOOL_IDS:
        src = production_catalog_dir / f"{tool_id}.yaml"
        assert src.is_file(), f"source YAML missing: {src}"
        shutil.copy2(src, tools_dir / f"{tool_id}.yaml")

    priv_path, _, key_id = KeyManager.generate_dev_keypair(
        keys_dir, name="arg015_e2e_signing"
    )
    private_key = load_private_key_bytes(priv_path.read_bytes())
    priv_path.unlink()  # private material lives only in this test process

    signatures = SignaturesFile()
    for tool_id in _ARG015_TOOL_IDS:
        rel = f"{tool_id}.yaml"
        yaml_path = tools_dir / rel
        signatures.upsert(
            SignatureRecord(
                sha256_hex=compute_yaml_hash(yaml_path),
                relative_path=rel,
                signature_b64=sign_blob(private_key, yaml_path.read_bytes()),
                public_key_id=key_id,
            )
        )
    signatures.write(tools_dir / "SIGNATURES")
    return tools_dir


@pytest.fixture(scope="module")
def loaded_registry(isolated_catalog: Path) -> ToolRegistry:
    """Load the isolated ARG-015 catalog and return the registry instance."""
    registry = ToolRegistry(tools_dir=isolated_catalog)
    registry.load()
    return registry


@pytest.fixture(scope="module")
def registry_summary(isolated_catalog: Path):  # type: ignore[no-untyped-def]
    """Return the :class:`RegistrySummary` captured from a fresh ``load()``."""
    return ToolRegistry(tools_dir=isolated_catalog).load()


# ---------------------------------------------------------------------------
# Synthetic nuclei JSONL payload
# ---------------------------------------------------------------------------


def _nuclei_record(
    *,
    template_id: str,
    matched_at: str,
    severity: str,
    tags: list[str],
    cves: list[str] | None = None,
    cvss_score: float | None = None,
    cvss_vector: str | None = None,
    epss_score: float | None = None,
    references: list[str] | None = None,
) -> dict[str, Any]:
    info: dict[str, Any] = {"name": template_id, "severity": severity, "tags": tags}
    classification: dict[str, Any] = {}
    if cves is not None:
        classification["cve-id"] = cves
    if cvss_score is not None:
        classification["cvss-score"] = cvss_score
    if cvss_vector is not None:
        classification["cvss-metrics"] = cvss_vector
    if epss_score is not None:
        classification["epss-score"] = epss_score
    if classification:
        info["classification"] = classification
    if references is not None:
        info["reference"] = references
    return {
        "template-id": template_id,
        "info": info,
        "host": matched_at,
        "matched-at": matched_at,
        "matcher-status": True,
    }


def _nuclei_payload() -> bytes:
    """Synthesise a representative nuclei JSONL stream with two findings.

    Drives the test through the full classification ladder:

    * ``apache-detect`` → INFO category, SUSPECTED confidence (info severity).
    * ``cve-2024-1337-rce`` → RCE category, LIKELY confidence (critical),
      CVSS 9.8, EPSS 0.97231, CVE-2024-1337, references attached.
    """
    records = [
        _nuclei_record(
            template_id="apache-detect",
            matched_at="https://target.example/",
            severity="info",
            tags=["tech"],
        ),
        _nuclei_record(
            template_id="cve-2024-1337-rce",
            matched_at="https://target.example/admin",
            severity="critical",
            tags=["cve", "rce"],
            cves=["CVE-2024-1337"],
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            epss_score=0.97231,
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-1337",
                "https://example.com/advisory/AC-1337",
            ],
        ),
    ]
    return ("\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n").encode(
        "utf-8"
    )


# ---------------------------------------------------------------------------
# YAML → render
# ---------------------------------------------------------------------------


def test_nuclei_descriptor_loads_with_nuclei_jsonl_strategy(
    loaded_registry: ToolRegistry,
) -> None:
    """The catalog must expose ``nuclei`` with NUCLEI_JSONL dispatch strategy."""
    descriptor = loaded_registry.get("nuclei")
    assert descriptor is not None, "nuclei missing from loaded catalog"
    assert descriptor.parse_strategy is ParseStrategy.NUCLEI_JSONL
    assert descriptor.image == "argus-kali-web:latest"
    assert descriptor.network_policy.name == "recon-active-tcp"


def test_nuclei_argv_renders_clean_with_url_out_placeholders(
    loaded_registry: ToolRegistry,
) -> None:
    """Render with sandbox-internal /out + url placeholders and audit the argv.

    ``render_argv`` validates every placeholder value and refuses any that
    contains shell-meaningful characters. We then re-audit the output as
    defence-in-depth: rendered tokens must contain no metacharacter and no
    leftover ``{...}`` sequence (a bug class where a placeholder name is
    misspelled and silently survives substitution would otherwise hide).
    """
    descriptor = loaded_registry.get("nuclei")
    assert descriptor is not None

    argv = render_argv(
        list(descriptor.command_template),
        {"url": "https://target.example", "out_dir": "/out"},
    )

    assert argv, "rendered argv must be non-empty"
    assert argv[0] == "nuclei", f"first token must be the binary, got {argv[0]!r}"

    offenders: list[tuple[str, str]] = []
    for token in argv:
        if "{" in token or "}" in token:
            offenders.append((token, "unrendered placeholder"))
        for meta in _SHELL_METACHARS:
            if meta in token:
                offenders.append((token, meta))
    assert not offenders, (
        f"rendered nuclei argv contains shell metachars / placeholders: {offenders}"
    )


# ---------------------------------------------------------------------------
# Render → dispatch → findings
# ---------------------------------------------------------------------------


def test_dispatch_parse_yields_expected_finding_breakdown(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """Synthetic nuclei JSONL → 1 INFO + 1 RCE = 2 findings, with full
    CVSS / CVE / EPSS round-trip on the RCE finding.

    Splits captured below by category so a future regression in the
    classification logic lights up the diff in CI immediately.
    """
    descriptor = loaded_registry.get("nuclei")
    assert descriptor is not None

    raw_stdout = _nuclei_payload()
    findings = dispatch_parse(
        descriptor.parse_strategy,
        raw_stdout,
        b"",
        tmp_path,
        tool_id="nuclei",
    )

    assert len(findings) == 2, (
        f"expected 2 findings (1 INFO + 1 RCE), got {len(findings)}"
    )

    by_category = {f.category: f for f in findings}
    assert FindingCategory.INFO in by_category
    assert FindingCategory.RCE in by_category

    info_finding = by_category[FindingCategory.INFO]
    assert info_finding.confidence is ConfidenceLevel.SUSPECTED

    rce_finding = by_category[FindingCategory.RCE]
    assert rce_finding.confidence is ConfidenceLevel.LIKELY
    assert rce_finding.cvss_v3_score == pytest.approx(9.8)
    assert rce_finding.cvss_v3_vector == (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    )
    assert rce_finding.epss_score == pytest.approx(0.97231)


def test_dispatch_parse_writes_evidence_sidecar(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """The nuclei parser must persist a JSONL sidecar in ``artifacts_dir``."""
    descriptor = loaded_registry.get("nuclei")
    assert descriptor is not None

    raw_stdout = _nuclei_payload()
    findings = dispatch_parse(
        descriptor.parse_strategy,
        raw_stdout,
        b"",
        tmp_path,
        tool_id="nuclei",
    )
    assert findings

    sidecar = tmp_path / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file(), "nuclei parser must write an evidence sidecar"

    parsed = [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(parsed) == len(findings), (
        f"sidecar must hold one record per finding, got {len(parsed)}"
    )
    assert all(rec["tool_id"] == "nuclei" for rec in parsed), (
        "every sidecar record must tag tool_id=nuclei"
    )

    rce_records = [r for r in parsed if r["template_id"] == "cve-2024-1337-rce"]
    assert rce_records, "expected RCE template record in sidecar"
    assert rce_records[0]["cve"] == ["CVE-2024-1337"]
    assert (
        "https://nvd.nist.gov/vuln/detail/CVE-2024-1337" in rce_records[0]["references"]
    )


def test_dispatch_parse_canonical_artifact_round_trip(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """Writing the canonical ``nuclei.jsonl`` artefact short-circuits stdout
    and produces the same finding set — proves the dispatch flow respects
    the ``-output /out/nuclei.jsonl`` contract documented in the YAML.
    """
    descriptor = loaded_registry.get("nuclei")
    assert descriptor is not None

    canonical_path = tmp_path / "nuclei.jsonl"
    canonical_path.write_bytes(_nuclei_payload())

    findings = dispatch_parse(
        descriptor.parse_strategy,
        b'{"<<<garbage>>>": true}',
        b"",
        tmp_path,
        tool_id="nuclei",
    )
    assert len(findings) == 2

    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "cve-2024-1337-rce" in sidecar
    assert "garbage" not in sidecar


# ---------------------------------------------------------------------------
# Multi-caller dispatch — every nuclei caller routes through the same parser
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", _NUCLEI_CALLER_IDS)
def test_every_nuclei_caller_yields_findings_against_same_payload(
    loaded_registry: ToolRegistry, tmp_path: Path, tool_id: str
) -> None:
    """All four nuclei callers (1 §4.8 flagship + 3 §4.7 wrappers) emit
    findings stamped with their own ``tool_id`` against the same JSONL.

    This is the ARG-015 graduation contract for the three §4.7 wrappers
    (``nextjs_check``, ``spring_boot_actuator``, ``jenkins_enum``) — they
    shipped to YAML in cycle 2 awaiting a parser; ARG-015 wires them.
    """
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None, f"{tool_id} missing from isolated catalog"
    assert descriptor.parse_strategy is ParseStrategy.NUCLEI_JSONL

    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()

    findings = dispatch_parse(
        descriptor.parse_strategy,
        _nuclei_payload(),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )

    assert findings, f"{tool_id}: dispatch produced no findings"

    sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file()
    parsed = [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert all(rec["tool_id"] == tool_id for rec in parsed), (
        f"{tool_id}: every sidecar record must carry the source tool_id"
    )


# ---------------------------------------------------------------------------
# Nikto + Wapiti dispatch
# ---------------------------------------------------------------------------


def test_nikto_descriptor_loads_with_json_object_strategy(
    loaded_registry: ToolRegistry,
) -> None:
    """``nikto`` must load with JSON_OBJECT dispatch and route to its parser."""
    descriptor = loaded_registry.get("nikto")
    assert descriptor is not None
    assert descriptor.parse_strategy is ParseStrategy.JSON_OBJECT

    payload = json.dumps(
        {
            "vulnerabilities": [
                {
                    "id": "001234",
                    "msg": "Server header reveals Apache/2.4.41",
                    "url": "/",
                    "method": "GET",
                }
            ]
        }
    ).encode("utf-8")

    findings = dispatch_parse(
        descriptor.parse_strategy,
        payload,
        b"",
        Path("."),  # tmp not needed; sidecar dest is overridden below
        tool_id="nikto",
    )
    assert findings
    assert findings[0].category is FindingCategory.MISCONFIG


def test_wapiti_descriptor_loads_with_json_object_strategy(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """``wapiti`` must load with JSON_OBJECT dispatch and route to its parser."""
    descriptor = loaded_registry.get("wapiti")
    assert descriptor is not None
    assert descriptor.parse_strategy is ParseStrategy.JSON_OBJECT

    payload = json.dumps(
        {
            "vulnerabilities": {
                "SQL Injection": [
                    {
                        "method": "POST",
                        "path": "/login",
                        "info": "SQLi via username param",
                        "parameter": "username",
                    }
                ]
            }
        }
    ).encode("utf-8")

    findings = dispatch_parse(
        descriptor.parse_strategy,
        payload,
        b"",
        tmp_path,
        tool_id="wapiti",
    )
    assert findings
    assert findings[0].category is FindingCategory.SQLI


# ---------------------------------------------------------------------------
# Catalog inventory invariant (isolated)
# ---------------------------------------------------------------------------


def test_isolated_catalog_loads_exactly_ten_arg015_tools(registry_summary) -> None:  # type: ignore[no-untyped-def]
    """The isolated ARG-015 catalog must hold exactly the ten tools we copied.

    The whole-catalog ``>= 77 tools`` invariant lives in the production
    inventory tests (:mod:`tests.unit.sandbox.test_yaml_schema_per_tool` and
    :mod:`tests.integration.sandbox.test_tool_catalog_load`); this e2e
    suite runs against an isolated tmp catalog so it can never be flaked
    by parallel batches landing broken peers.
    """
    assert registry_summary.total == len(_ARG015_TOOL_IDS), (
        f"isolated catalog expected exactly {len(_ARG015_TOOL_IDS)} ARG-015 tools, "
        f"got {registry_summary.total}; per-phase breakdown: "
        f"{registry_summary.by_phase}"
    )


def test_isolated_catalog_includes_all_ten_arg015_tools(
    loaded_registry: ToolRegistry,
) -> None:
    """Every ARG-015 tool must be discoverable by ``tool_id`` after the load."""
    missing = [tid for tid in _ARG015_TOOL_IDS if loaded_registry.get(tid) is None]
    assert not missing, f"missing ARG-015 tool descriptors after load: {missing}"
