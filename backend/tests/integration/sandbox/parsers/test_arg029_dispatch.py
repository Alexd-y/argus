"""Integration test: ARG-029 batch-3 dispatch (Backlog/dev1_md §4.4).

Sister suite to ``test_arg021_dispatch.py`` and ``test_arg022_dispatch.py``.
Pins the ARG-029 contract that the **fifteen** new parsers shipped in
Cycle 3 batch-3 — covering 4 JSON_LINES + 5 custom + 6 mixed JSON_OBJECT
tools — route through the dispatch table, write per-tool sidecars,
preserve cross-tool isolation, and meet the security gates the
security-auditor will enforce.

Tools covered:

* JSON_LINES family ::
    trufflehog, naabu, masscan (json_object envelope), prowler
    (json_object envelope)
* Custom family ::
    detect_secrets, openapi_scanner, graphql_cop, postman_newman,
    zap_baseline (TEXT_LINES strategy, JSON canonical artefact)
* Mixed JSON_OBJECT family ::
    syft, cloudsploit, hashid, hash_analyzer, jarm, wappalyzer_cli

Guardrails enforced in this suite:

* Every ARG-029 tool is registered in the per-tool dispatch table.
* Dispatch from a representative payload yields ``len(findings) >= 1``
  for every tool.
* Each parser writes its own dedicated sidecar file (no overwrites
  between parsers in a shared ``/out`` directory).
* Cross-tool routing isolation: a payload shaped for tool A pushed
  through tool B's ``tool_id`` produces 0 real findings.
* Determinism: re-running the same payload twice produces byte-identical
  sidecars.
* CRITICAL: ``trufflehog`` must NEVER write a raw ``Raw`` / ``RawV2``
  secret payload to its sidecar. Every long opaque token must be replaced
  with the redaction marker before persistence.
* CRITICAL: ``hashid`` and ``hash_analyzer`` must NEVER write raw
  hash bytes; only the 12-char ``stable_hash_12`` reference can leak.
* ``prowler`` must PRESERVE AWS account IDs in resource ARNs (12-digit
  numeric block) — they are not secrets, they are required pivot data
  for follow-up findings.
* Heartbeat fallback survives — unmapped tools still produce one
  observability finding through the strategy handler.
* Prior-cycle parsers (ARG-021/-022/-023/etc.) survive ARG-029 wiring.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

import pytest

from src.pipeline.contracts.finding_dto import FindingDTO
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import (
    dispatch_parse,
    get_registered_tool_parsers,
    reset_registry,
)
from src.sandbox.parsers.cloudsploit_parser import (
    EVIDENCE_SIDECAR_NAME as CLOUDSPLOIT_SIDECAR,
)
from src.sandbox.parsers.detect_secrets_parser import (
    EVIDENCE_SIDECAR_NAME as DETECT_SECRETS_SIDECAR,
)
from src.sandbox.parsers.graphql_cop_parser import (
    EVIDENCE_SIDECAR_NAME as GRAPHQL_COP_SIDECAR,
)
from src.sandbox.parsers.hash_analyzer_parser import (
    EVIDENCE_SIDECAR_NAME as HASH_ANALYZER_SIDECAR,
)
from src.sandbox.parsers.hashid_parser import (
    EVIDENCE_SIDECAR_NAME as HASHID_SIDECAR,
)
from src.sandbox.parsers.jarm_parser import (
    EVIDENCE_SIDECAR_NAME as JARM_SIDECAR,
)
from src.sandbox.parsers.masscan_parser import (
    EVIDENCE_SIDECAR_NAME as MASSCAN_SIDECAR,
)
from src.sandbox.parsers.naabu_parser import (
    EVIDENCE_SIDECAR_NAME as NAABU_SIDECAR,
)
from src.sandbox.parsers.openapi_scanner_parser import (
    EVIDENCE_SIDECAR_NAME as OPENAPI_SIDECAR,
)
from src.sandbox.parsers.postman_newman_parser import (
    EVIDENCE_SIDECAR_NAME as POSTMAN_SIDECAR,
)
from src.sandbox.parsers.prowler_parser import (
    EVIDENCE_SIDECAR_NAME as PROWLER_SIDECAR,
)
from src.sandbox.parsers.syft_parser import (
    EVIDENCE_SIDECAR_NAME as SYFT_SIDECAR,
)
from src.sandbox.parsers.trufflehog_parser import (
    EVIDENCE_SIDECAR_NAME as TRUFFLEHOG_SIDECAR,
)
from src.sandbox.parsers.wappalyzer_cli_parser import (
    EVIDENCE_SIDECAR_NAME as WAPPALYZER_SIDECAR,
)
from src.sandbox.parsers.zap_baseline_parser import (
    EVIDENCE_SIDECAR_NAME as ZAP_BASELINE_SIDECAR,
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


# Every ARG-029 tool that MUST have a parser registered post-Cycle 3 batch 3.
ARG029_TOOL_IDS: Final[tuple[str, ...]] = (
    # JSON_LINES family
    "trufflehog",
    "naabu",
    "masscan",
    "prowler",
    # Custom family
    "detect_secrets",
    "openapi_scanner",
    "graphql_cop",
    "postman_newman",
    "zap_baseline",
    # Mixed JSON_OBJECT family
    "syft",
    "cloudsploit",
    "hashid",
    "hash_analyzer",
    "jarm",
    "wappalyzer_cli",
)


# Each ARG-029 tool's canonical sidecar filename.
ARG029_TOOL_SIDECARS: Final[dict[str, str]] = {
    "trufflehog": TRUFFLEHOG_SIDECAR,
    "naabu": NAABU_SIDECAR,
    "masscan": MASSCAN_SIDECAR,
    "prowler": PROWLER_SIDECAR,
    "detect_secrets": DETECT_SECRETS_SIDECAR,
    "openapi_scanner": OPENAPI_SIDECAR,
    "graphql_cop": GRAPHQL_COP_SIDECAR,
    "postman_newman": POSTMAN_SIDECAR,
    "zap_baseline": ZAP_BASELINE_SIDECAR,
    "syft": SYFT_SIDECAR,
    "cloudsploit": CLOUDSPLOIT_SIDECAR,
    "hashid": HASHID_SIDECAR,
    "hash_analyzer": HASH_ANALYZER_SIDECAR,
    "jarm": JARM_SIDECAR,
    "wappalyzer_cli": WAPPALYZER_SIDECAR,
}


# YAML-declared parse strategy per tool (matches backend/config/tools/*.yaml).
ARG029_TOOL_STRATEGIES: Final[dict[str, ParseStrategy]] = {
    "trufflehog": ParseStrategy.JSON_LINES,
    "naabu": ParseStrategy.JSON_LINES,
    "masscan": ParseStrategy.JSON_OBJECT,
    "prowler": ParseStrategy.JSON_OBJECT,
    "detect_secrets": ParseStrategy.JSON_OBJECT,
    "openapi_scanner": ParseStrategy.JSON_OBJECT,
    "graphql_cop": ParseStrategy.JSON_OBJECT,
    "postman_newman": ParseStrategy.JSON_OBJECT,
    "zap_baseline": ParseStrategy.TEXT_LINES,
    "syft": ParseStrategy.JSON_OBJECT,
    "cloudsploit": ParseStrategy.JSON_OBJECT,
    "hashid": ParseStrategy.JSON_OBJECT,
    "hash_analyzer": ParseStrategy.JSON_OBJECT,
    "jarm": ParseStrategy.JSON_OBJECT,
    "wappalyzer_cli": ParseStrategy.JSON_OBJECT,
}


# ---------------------------------------------------------------------------
# Per-tool minimal-but-realistic payloads (loaded from fixtures/sandbox_outputs)
# ---------------------------------------------------------------------------


_FIXTURES_ROOT: Final[Path] = (
    Path(__file__).resolve().parents[4] / "tests" / "fixtures" / "sandbox_outputs"
)


def _payload(tool_id: str) -> bytes:
    return (_FIXTURES_ROOT / tool_id / "sample.txt").read_bytes()


def _read_sidecar(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# Per-tool registration surface
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG029_TOOL_IDS)
def test_arg029_tool_is_registered(tool_id: str) -> None:
    """Every ARG-029 tool must be wired into the per-tool dispatch table."""
    registered = get_registered_tool_parsers()
    assert tool_id in registered, (
        f"{tool_id} missing from per-tool parser registry — broken wiring "
        f"in src.sandbox.parsers.__init__._DEFAULT_TOOL_PARSERS"
    )


def test_arg029_does_not_drop_prior_cycle_registrations() -> None:
    """Sanity: every prior-cycle tool slot survives the ARG-029 batch."""
    registered = get_registered_tool_parsers()
    legacy_tools = (
        "httpx",
        "ffuf_dir",
        "katana",
        "wpscan",
        "nuclei",
        "nikto",
        "wapiti",
        "trivy_image",
        "trivy_fs",
        "semgrep",
        "sqlmap_safe",
        "dalfox",
        "interactsh_client",
        "nmap_tcp_top",
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
        "impacket_secretsdump",
        "evil_winrm",
        "kerbrute",
        "bloodhound_python",
        "snmpwalk",
        "ldapsearch",
        "smbclient",
        "smbmap",
        "enum4linux_ng",
        "rpcclient_enum",
    )
    for legacy in legacy_tools:
        assert legacy in registered, f"{legacy} slot must survive ARG-029 registration"


def test_registered_count_is_at_least_68() -> None:
    """ARG-029 brought the mapped-parser count from 53 to 68 (cumulative).

    Cycle 4 follow-ups (ARG-032) and Cycle 6 T05 ratcheted the count
    further to 118 — the strict ``==`` assertion is owned by
    :func:`tests.integration.sandbox.parsers.test_arg032_dispatch.test_registered_count_matches_catalog_ratchet`.
    This sister test only guarantees that
    the ARG-029 contribution did NOT regress (i.e. that no future cycle
    accidentally unregistered one of the fifteen ARG-029 parsers and
    masked it by adding a different one).  The per-tool presence sweep
    above (:func:`test_arg029_does_not_drop_prior_cycle_registrations`)
    already covers individual tool drops; this is the cheap aggregate
    sentinel.
    """
    assert len(get_registered_tool_parsers()) >= 68, (
        "Mapped-parser count regressed below ARG-029 level (68); a "
        "Cycle 4+ task likely unregistered a parser without bumping the "
        "ARG-032 ratchet."
    )


# ---------------------------------------------------------------------------
# Routing — happy path for every ARG-029 tool
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG029_TOOL_IDS)
def test_dispatch_routes_each_arg029_tool(tool_id: str, tmp_path: Path) -> None:
    """Every ARG-029 tool routes via its strategy and yields >=1 finding."""
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    findings = dispatch_parse(
        ARG029_TOOL_STRATEGIES[tool_id],
        _payload(tool_id),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id}: dispatch produced no findings"
    assert all(isinstance(f, FindingDTO) for f in findings)


@pytest.mark.parametrize("tool_id", ARG029_TOOL_IDS)
def test_dispatch_writes_per_tool_sidecar(tool_id: str, tmp_path: Path) -> None:
    """Each ARG-029 dispatch writes its dedicated sidecar tagged with tool_id."""
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    findings = dispatch_parse(
        ARG029_TOOL_STRATEGIES[tool_id],
        _payload(tool_id),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings
    sidecar = artifacts_dir / ARG029_TOOL_SIDECARS[tool_id]
    assert sidecar.is_file(), (
        f"{tool_id}: parser must write evidence sidecar at {sidecar}"
    )
    parsed = _read_sidecar(sidecar)
    assert parsed, f"{tool_id}: sidecar is empty"
    assert all(rec["tool_id"] == tool_id for rec in parsed), (
        f"{tool_id}: every sidecar record must tag its source tool_id"
    )


def test_arg029_tools_use_distinct_sidecar_filenames() -> None:
    """All fifteen ARG-029 sidecar filenames must be unique across the batch."""
    sidecars = list(ARG029_TOOL_SIDECARS.values())
    assert len(set(sidecars)) == len(sidecars), (
        "ARG-029 parsers collide on sidecar filenames; one tool would "
        "overwrite another in shared /out"
    )


# ---------------------------------------------------------------------------
# CRITICAL — trufflehog secret-redaction guardrail (security gate)
# ---------------------------------------------------------------------------


# Long opaque alnum runs are the canonical shape of an unredacted secret.
# Acceptable exceptions in the sidecar:
#   * git commit SHAs (we strip them), 12-char stable_hash IDs, hashed
#     fingerprints from detectors. None of those are 40+ alnum without
#     non-alnum delimiters when isolated.
_LONG_ALNUM_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"[A-Za-z0-9/+]{40,}")
_RAW_AWS_KEY_RE: Final[re.Pattern[str]] = re.compile(r"AKIA[0-9A-Z]{16}")
_RAW_GH_PAT_RE: Final[re.Pattern[str]] = re.compile(r"ghp_[A-Za-z0-9]{36,}")


def test_trufflehog_redacts_raw_secrets_in_sidecar(tmp_path: Path) -> None:
    """Raw AWS / GitHub / RSA secrets MUST NOT reach the trufflehog sidecar.

    This is the ARG-029 critical security gate.  We feed three verified
    detector hits (AWS Access Key, GitHub PAT, RSA private key) and
    assert that:

    1. dispatch produces >=1 finding;
    2. the sidecar contains 0 ``AKIA[0-9A-Z]{16}`` strings;
    3. the sidecar contains 0 ``ghp_`` GitHub personal access tokens;
    4. no opaque base64 run >=40 chars survives in the persisted bytes
       (this catches the RSA private key payload as well as any Raw /
       RawV2 leakage we missed);
    5. the canonical redaction marker is present.
    """
    findings = dispatch_parse(
        ParseStrategy.JSON_LINES,
        _payload("trufflehog"),
        b"",
        tmp_path,
        tool_id="trufflehog",
    )
    assert findings, "trufflehog dispatch must yield >=1 finding"
    sidecar = tmp_path / TRUFFLEHOG_SIDECAR
    text = sidecar.read_text(encoding="utf-8")
    aws_hits = _RAW_AWS_KEY_RE.findall(text)
    gh_hits = _RAW_GH_PAT_RE.findall(text)
    long_alnum_hits = _LONG_ALNUM_TOKEN_RE.findall(text)
    assert aws_hits == [], (
        f"RAW AWS key LEAKED through trufflehog sidecar — redaction broken. "
        f"Hits: {aws_hits[:3]}"
    )
    assert gh_hits == [], (
        f"RAW GitHub PAT LEAKED through trufflehog sidecar. Hits: {gh_hits[:3]}"
    )
    assert long_alnum_hits == [], (
        f"Opaque long token LEAKED through trufflehog sidecar — likely raw "
        f"secret survived redaction. Hits: {long_alnum_hits[:3]}"
    )
    assert "***REDACTED(" in text, (
        "expected secret redaction marker `***REDACTED(<len>)***` in trufflehog sidecar"
    )


# ---------------------------------------------------------------------------
# CRITICAL — hashid / hash_analyzer cleartext-hash guardrail
# ---------------------------------------------------------------------------


_RAW_MD5_RE: Final[re.Pattern[str]] = re.compile(r"\b[a-f0-9]{32}\b")
_RAW_SHA1_RE: Final[re.Pattern[str]] = re.compile(r"\b[a-f0-9]{40}\b")
_RAW_BCRYPT_RE: Final[re.Pattern[str]] = re.compile(
    r"\$2[abxy]\$\d{2}\$[A-Za-z0-9./]{53}"
)


@pytest.mark.parametrize("tool_id", ["hashid", "hash_analyzer"])
def test_hash_classifiers_never_persist_raw_hash(tool_id: str, tmp_path: Path) -> None:
    """Hash-classifier parsers must persist only ``stable_hash_12`` references.

    Raw MD5 / SHA-1 / bcrypt hashes have non-trivial reversibility for
    weak inputs (rainbow tables, GPU bruteforce).  Storing them in
    sidecars would re-introduce the very vulnerability the classifier
    was meant to flag.  We feed the canonical sample, dispatch through
    the per-tool parser and assert that no MD5 / SHA-1 / bcrypt bytes
    remain in the sidecar.
    """
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    findings = dispatch_parse(
        ARG029_TOOL_STRATEGIES[tool_id],
        _payload(tool_id),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id} dispatch must yield >=1 finding"
    sidecar = artifacts_dir / ARG029_TOOL_SIDECARS[tool_id]
    text = sidecar.read_text(encoding="utf-8")
    md5_hits = _RAW_MD5_RE.findall(text)
    sha1_hits = _RAW_SHA1_RE.findall(text)
    bcrypt_hits = _RAW_BCRYPT_RE.findall(text)
    assert md5_hits == [], f"{tool_id}: RAW MD5 hash LEAKED. Hits: {md5_hits[:3]}"
    assert sha1_hits == [], f"{tool_id}: RAW SHA-1 hash LEAKED. Hits: {sha1_hits[:3]}"
    assert bcrypt_hits == [], (
        f"{tool_id}: RAW bcrypt hash LEAKED. Hits: {bcrypt_hits[:3]}"
    )


# ---------------------------------------------------------------------------
# Prowler — AWS account IDs MUST NOT be redacted
# ---------------------------------------------------------------------------


_AWS_ACCOUNT_ID_RE: Final[re.Pattern[str]] = re.compile(r"\b\d{12}\b")


def test_prowler_preserves_aws_account_ids(tmp_path: Path) -> None:
    """Prowler resource ARNs contain 12-digit AWS account IDs we MUST preserve.

    Account IDs are pivot data, not secrets.  Aggressive numeric redaction
    would break downstream IAM lookups, blast-radius scoring, and tenant
    correlation in the multi-account reporter.  This test pins that
    every AWS account ID in the prowler fixture survives into the sidecar.
    """
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _payload("prowler"),
        b"",
        tmp_path,
        tool_id="prowler",
    )
    assert findings, "prowler dispatch must yield >=1 finding"
    sidecar = tmp_path / PROWLER_SIDECAR
    text = sidecar.read_text(encoding="utf-8")
    assert "123456789012" in text, (
        "prowler sidecar dropped AWS account ID 123456789012; ARN "
        "preservation broken — IAM blast-radius pivot will fail"
    )
    account_ids = _AWS_ACCOUNT_ID_RE.findall(text)
    assert account_ids, "prowler sidecar contains zero 12-digit AWS account IDs"


# ---------------------------------------------------------------------------
# detect_secrets — hashed_secret preserved, no cleartext leak
# ---------------------------------------------------------------------------


def test_detect_secrets_preserves_hashed_secret(tmp_path: Path) -> None:
    """detect_secrets persists ``hashed_secret`` (SHA-1 fingerprint) verbatim.

    Unlike trufflehog, detect_secrets emits SHA-1 fingerprints rather
    than raw secrets — they are safe to persist, low-reversibility, and
    required for cross-scan correlation.  This test pins that:

    1. dispatch produces >=1 finding;
    2. at least one ``hashed_secret`` value from the fixture is present
       in the sidecar (e.g., d033e22ae348aeb5660fc2140aec35850c4da997
       from the AWS detector record);
    3. no ``cleartext`` field name appears in the sidecar (would
       indicate a future regression).
    """
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _payload("detect_secrets"),
        b"",
        tmp_path,
        tool_id="detect_secrets",
    )
    assert findings, "detect_secrets dispatch must yield >=1 finding"
    sidecar = tmp_path / DETECT_SECRETS_SIDECAR
    text = sidecar.read_text(encoding="utf-8")
    assert "d033e22ae348aeb5660fc2140aec35850c4da997" in text, (
        "detect_secrets sidecar dropped hashed_secret fingerprint — "
        "would break cross-scan correlation"
    )
    assert "cleartext" not in text, (
        "detect_secrets sidecar contains 'cleartext' label — possible "
        "future regression that bypassed the redaction gate"
    )


# ---------------------------------------------------------------------------
# Cross-tool routing isolation — defence in depth
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload_tool", "wrong_tool"),
    [
        # JSON_LINES vs JSON_OBJECT — different envelope shapes
        ("trufflehog", "naabu"),
        ("naabu", "trufflehog"),
        ("masscan", "prowler"),
        ("prowler", "masscan"),
        # Different JSON_OBJECT parsers should refuse foreign payloads
        ("syft", "cloudsploit"),
        ("cloudsploit", "syft"),
        ("hashid", "hash_analyzer"),
        ("hash_analyzer", "hashid"),
        ("jarm", "wappalyzer_cli"),
        ("wappalyzer_cli", "jarm"),
        # Custom parsers vs hash classifiers
        ("graphql_cop", "openapi_scanner"),
        ("postman_newman", "graphql_cop"),
        ("zap_baseline", "postman_newman"),
        ("openapi_scanner", "zap_baseline"),
        ("detect_secrets", "trufflehog"),
    ],
)
def test_cross_routing_is_inert(
    payload_tool: str, wrong_tool: str, tmp_path: Path
) -> None:
    """A payload from tool X dispatched as tool Y produces 0 real findings.

    Defence-in-depth check that every ARG-029 parser refuses to
    invent findings from a wrongly-shaped input.  We deliberately mix
    JSON_LINES, JSON_OBJECT, custom and hash-classifier parsers to
    cover the cartesian product of envelope shapes within the batch.
    """
    findings = dispatch_parse(
        ARG029_TOOL_STRATEGIES[wrong_tool],
        _payload(payload_tool),
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


@pytest.mark.parametrize("tool_id", ARG029_TOOL_IDS)
def test_arg029_dispatch_is_deterministic(tool_id: str, tmp_path: Path) -> None:
    """Two dispatches on the same payload produce byte-identical sidecars."""
    payload = _payload(tool_id)
    artifacts_a = tmp_path / "a"
    artifacts_b = tmp_path / "b"
    artifacts_a.mkdir()
    artifacts_b.mkdir()
    dispatch_parse(
        ARG029_TOOL_STRATEGIES[tool_id],
        payload,
        b"",
        artifacts_a,
        tool_id=tool_id,
    )
    dispatch_parse(
        ARG029_TOOL_STRATEGIES[tool_id],
        payload,
        b"",
        artifacts_b,
        tool_id=tool_id,
    )
    sidecar_name = ARG029_TOOL_SIDECARS[tool_id]
    a_bytes = (artifacts_a / sidecar_name).read_bytes()
    b_bytes = (artifacts_b / sidecar_name).read_bytes()
    assert a_bytes == b_bytes, (
        f"{tool_id}: sidecar bytes drift between runs — non-deterministic parser"
    )


# ---------------------------------------------------------------------------
# Multi-tool same /out directory — sidecar isolation
# ---------------------------------------------------------------------------


def test_all_arg029_parsers_in_single_artifacts_dir_keeps_sidecars_intact(
    tmp_path: Path,
) -> None:
    """Running all fifteen ARG-029 parsers in the same dir leaves sidecars intact."""
    for tool_id in ARG029_TOOL_IDS:
        dispatch_parse(
            ARG029_TOOL_STRATEGIES[tool_id],
            _payload(tool_id),
            b"",
            tmp_path,
            tool_id=tool_id,
        )

    for tool_id, sidecar_name in ARG029_TOOL_SIDECARS.items():
        sidecar = tmp_path / sidecar_name
        assert sidecar.is_file(), (
            f"{tool_id}: sidecar {sidecar_name} missing after multi-tool run"
        )
        records = _read_sidecar(sidecar)
        assert records, f"{tool_id}: sidecar {sidecar_name} is empty"
        assert all(r["tool_id"] == tool_id for r in records), (
            f"{tool_id}: cross-tool contamination in {sidecar_name}"
        )


# ---------------------------------------------------------------------------
# Heartbeat fallback survives — unmapped tools still observable
# ---------------------------------------------------------------------------


def test_heartbeat_fallback_for_unmapped_tool_id(tmp_path: Path) -> None:
    """Unmapped tool_id over a known strategy still emits one heartbeat finding.

    Guards the §11 evidence pipeline contract that any executed tool
    leaves a finding behind even when no per-tool parser exists.
    """
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        b'{"foo": "bar"}',
        b"",
        tmp_path,
        tool_id="unknown_tool_arg029_xyz",
    )
    assert len(findings) == 1
    assert findings[0].cvss_v3_score == 0.0
