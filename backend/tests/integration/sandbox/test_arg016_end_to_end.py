"""End-to-end integration test: ARG-016 §4.9 / §4.10 vertical slice.

Wires up the three subsystems ARG-016 ships in lockstep — YAML
descriptors, templating-rendered argv, parser dispatch — against the
real :mod:`src.sandbox.tool_registry` and the real
:mod:`src.sandbox.parsers` registry.  No mocks for the registry layers;
only the *raw* sqlmap / dalfox payloads are synthesised.

Concretely the test verifies:

1.  Loading the production catalog through :class:`ToolRegistry` yields
    descriptors for the eleven §4.9 / §4.10 tools, each with the
    documented per-tool ``parse_strategy`` / ``image`` / ``phase`` /
    ``risk_level`` / ``requires_approval`` contract.
2.  Rendering each descriptor's ``command_template`` with sandbox-
    internal placeholders (``url`` / ``out_dir`` / ``safe`` / ``canary``)
    produces a clean argv whose tokens are free of any shell
    metacharacters or unrendered placeholders.
3.  Feeding a synthetic sqlmap log into :func:`dispatch_parse` with the
    descriptor's strategy yields the expected SQLi finding(s) — the
    ARG-016 first-class parser contract for the sqlmap variants.
4.  Feeding a synthetic dalfox JSON envelope yields the expected XSS
    findings, classified per the ``V``/``S``/``R`` ladder
    (Verified/Stored/Reflected → CONFIRMED/LIKELY/SUSPECTED).
5.  Both parsers write deterministic JSONL evidence sidecars next to the
    artefact directory (``sqlmap_findings.jsonl`` /
    ``dalfox_findings.jsonl``) tagged with the source ``tool_id``.

Hard isolation: the ``loaded_registry`` fixture builds an *isolated*
tool catalog under ``tmp_path`` containing only the eleven ARG-016
YAMLs (plus a fresh dev signing key) so the test cannot be flaked by
parallel batches that may land broken descriptors in the production
``backend/config/tools/`` tree (the registry is fail-closed: ANY broken
peer aborts the whole load).
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Final

import pytest

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import dispatch_parse
from src.sandbox.parsers.dalfox_parser import (
    EVIDENCE_SIDECAR_NAME as DALFOX_SIDECAR,
)
from src.sandbox.parsers.sqlmap_parser import (
    EVIDENCE_SIDECAR_NAME as SQLMAP_SIDECAR,
)
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


# Eleven §4.9 SQLi + §4.10 XSS tools that ARG-016 ships in lockstep.
# The isolated catalog mirrors only this set so the e2e test is robust
# against parallel batches landing broken peers.
_ARG016_SQLI_TOOL_IDS: Final[tuple[str, ...]] = (
    "sqlmap_safe",
    "sqlmap_confirm",
    "ghauri",
    "jsql",
    "tplmap",
    "nosqlmap",
)
_ARG016_XSS_TOOL_IDS: Final[tuple[str, ...]] = (
    "dalfox",
    "xsstrike",
    "kxss",
    "xsser",
    "playwright_xss_verify",
)
_ARG016_TOOL_IDS: Final[tuple[str, ...]] = (
    *_ARG016_SQLI_TOOL_IDS,
    *_ARG016_XSS_TOOL_IDS,
)


# Per-tool placeholder kits.  Every §4.9 tool consumes ``{url}`` and
# most also write under ``{out_dir}``; sqlmap_safe additionally uses
# ``{safe}`` (to point at the safe-url throttle endpoint), and the
# Playwright verifier uses ``{canary}`` to fire the operator-supplied
# marker.
_PLACEHOLDER_KIT: Final[dict[str, dict[str, str]]] = {
    "sqlmap_safe": {
        "url": "https://target.example/login",
        "out_dir": "/out",
        "safe": "https://target.example/health",
    },
    "sqlmap_confirm": {
        "url": "https://target.example/login",
        "out_dir": "/out",
    },
    "ghauri": {
        "url": "https://target.example/login",
        "out_dir": "/out",
    },
    "jsql": {
        "url": "https://target.example/login",
        "out_dir": "/out",
    },
    "tplmap": {
        "url": "https://target.example/render",
        "out_dir": "/out",
    },
    "nosqlmap": {
        "url": "https://target.example/api/login",
        "out_dir": "/out",
    },
    "dalfox": {
        "url": "https://target.example/search",
        "out_dir": "/out",
    },
    "xsstrike": {
        "url": "https://target.example/search",
        "out_dir": "/out",
    },
    "kxss": {
        "url": "https://target.example/search",
        "out_dir": "/out",
    },
    "xsser": {
        "url": "https://target.example/search",
        "out_dir": "/out",
    },
    "playwright_xss_verify": {
        "url": "https://target.example/comments",
        "out_dir": "/out",
        # ``canary`` is constrained to lowercase hex, 16..64 chars
        # (see src/sandbox/templating._validate_canary).
        "canary": "deadbeef0123456789abcdef0123456789abcdef",
    },
}


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
    """Build an isolated, freshly-signed mirror of the eleven ARG-016 YAMLs.

    Defence-in-depth: copy the eleven §4.9/§4.10 descriptors into
    ``tmp_path / tools``, generate a one-shot dev keypair, sign them,
    and write a clean ``SIGNATURES`` manifest.  The result is a
    self-contained registry directory that the test can load with
    :class:`ToolRegistry` regardless of the state of the production
    catalog.
    """
    catalog_root = tmp_path_factory.mktemp("arg016_catalog")
    tools_dir = catalog_root / "tools"
    keys_dir = tools_dir / "_keys"
    tools_dir.mkdir(parents=True)
    keys_dir.mkdir(parents=True)

    for tool_id in _ARG016_TOOL_IDS:
        src = production_catalog_dir / f"{tool_id}.yaml"
        assert src.is_file(), f"source YAML missing: {src}"
        shutil.copy2(src, tools_dir / f"{tool_id}.yaml")

    priv_path, _, key_id = KeyManager.generate_dev_keypair(
        keys_dir, name="arg016_e2e_signing"
    )
    private_key = load_private_key_bytes(priv_path.read_bytes())
    priv_path.unlink()  # private material lives only in this test process

    signatures = SignaturesFile()
    for tool_id in _ARG016_TOOL_IDS:
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
    """Load the isolated ARG-016 catalog and return the registry instance."""
    registry = ToolRegistry(tools_dir=isolated_catalog)
    registry.load()
    return registry


@pytest.fixture(scope="module")
def registry_summary(isolated_catalog: Path):  # type: ignore[no-untyped-def]
    """Return the :class:`RegistrySummary` captured from a fresh ``load()``."""
    return ToolRegistry(tools_dir=isolated_catalog).load()


# ---------------------------------------------------------------------------
# Catalog inventory invariant (isolated)
# ---------------------------------------------------------------------------


def test_isolated_catalog_loads_exactly_eleven_arg016_tools(
    registry_summary,  # type: ignore[no-untyped-def]
) -> None:
    """The isolated ARG-016 catalog must hold exactly the eleven tools we copied."""
    assert registry_summary.total == len(_ARG016_TOOL_IDS), (
        f"isolated catalog expected exactly {len(_ARG016_TOOL_IDS)} ARG-016 tools, "
        f"got {registry_summary.total}; per-phase breakdown: "
        f"{registry_summary.by_phase}"
    )


def test_isolated_catalog_includes_all_eleven_arg016_tools(
    loaded_registry: ToolRegistry,
) -> None:
    """Every ARG-016 tool must be discoverable by ``tool_id`` after the load."""
    missing = [tid for tid in _ARG016_TOOL_IDS if loaded_registry.get(tid) is None]
    assert not missing, f"missing ARG-016 tool descriptors after load: {missing}"


# ---------------------------------------------------------------------------
# YAML → render — every ARG-016 tool template must round-trip cleanly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", _ARG016_TOOL_IDS)
def test_argv_renders_clean_with_sandbox_placeholders(
    loaded_registry: ToolRegistry, tool_id: str
) -> None:
    """Render each descriptor's command_template with sandbox-internal
    placeholders and audit the rendered argv.

    ``render_argv`` validates every placeholder value and refuses any
    that contains shell-meaningful characters.  We then re-audit the
    output as defence-in-depth: rendered tokens must contain no
    metacharacter and no leftover ``{...}`` sequence (a bug class where
    a placeholder name is misspelled and silently survives substitution
    would otherwise hide).
    """
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None, f"{tool_id} missing from isolated catalog"

    placeholders = _PLACEHOLDER_KIT[tool_id]
    argv = render_argv(list(descriptor.command_template), placeholders)

    assert argv, f"{tool_id}: rendered argv must be non-empty"

    offenders: list[tuple[str, str]] = []
    for token in argv:
        if "{" in token or "}" in token:
            offenders.append((token, "unrendered placeholder"))
        for meta in _SHELL_METACHARS:
            if meta in token:
                offenders.append((token, meta))
    assert not offenders, (
        f"{tool_id}: rendered argv contains shell metachars / placeholders: {offenders}"
    )


# ---------------------------------------------------------------------------
# Per-tool descriptor contract (image / phase / risk / approval)
# ---------------------------------------------------------------------------


def test_sqli_descriptors_carry_correct_phase_and_image(
    loaded_registry: ToolRegistry,
) -> None:
    """§4.9 SQLi descriptors must carry the right phase / image / approval."""
    for tool_id in _ARG016_SQLI_TOOL_IDS:
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.image == "argus-kali-web:latest", (
            f"{tool_id}: must run on argus-kali-web:latest"
        )
        if tool_id == "sqlmap_confirm":
            assert descriptor.phase is ScanPhase.EXPLOITATION, (
                f"{tool_id}: must escalate to exploitation phase"
            )
            assert descriptor.risk_level is RiskLevel.HIGH
            assert descriptor.requires_approval is True
        elif tool_id == "sqlmap_safe":
            # Reviewer M1 (cycle 2): even the safe-profile sqlmap (BT-only,
            # level 2, risk 1) generates WAF noise + DB log churn that
            # violates the ARGUS default-deny security policy, so it
            # joins every other §4.9 entry under approval-gating.
            #
            # ARG-020 (cycle 2 capstone): the catalog-wide invariant
            # ``requires_approval=True ⇒ risk_level >= MEDIUM`` (enforced by
            # :func:`tests.test_tool_catalog_coverage.test_tool_approval_implies_medium_risk_floor`)
            # bumped this descriptor from LOW → MEDIUM.  The justification
            # above (WAF + DB log churn) already met the medium-risk bar in
            # spirit; the bump just makes the policy machine-checkable.
            assert descriptor.phase is ScanPhase.VULN_ANALYSIS
            assert descriptor.risk_level is RiskLevel.MEDIUM
            assert descriptor.requires_approval is True
        else:
            assert descriptor.phase is ScanPhase.VULN_ANALYSIS
            assert descriptor.requires_approval is True, (
                f"{tool_id}: active SQLi/SSTI/NoSQLi tools require approval"
            )


def test_xss_descriptors_carry_correct_phase_and_image(
    loaded_registry: ToolRegistry,
) -> None:
    """§4.10 XSS descriptors must carry the right phase / image / approval."""
    for tool_id in _ARG016_XSS_TOOL_IDS:
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.requires_approval is False, (
            f"{tool_id}: §4.10 XSS tools must be approval-free"
        )
        if tool_id == "playwright_xss_verify":
            assert descriptor.phase is ScanPhase.EXPLOITATION
            assert descriptor.image == "argus-kali-browser:latest", (
                f"{tool_id}: must run on argus-kali-browser:latest"
            )
        else:
            assert descriptor.phase is ScanPhase.VULN_ANALYSIS
            assert descriptor.image == "argus-kali-web:latest"


# ---------------------------------------------------------------------------
# sqlmap parser dispatch — text_lines → SQLi findings
# ---------------------------------------------------------------------------


_SQLMAP_LOG: Final[str] = """\
[14:20:31] [INFO] testing connection to the target URL
[14:20:32] [INFO] testing if the target URL content is stable
[14:20:34] [INFO] target URL content is stable
[14:20:35] [INFO] testing if GET parameter 'id' is dynamic
[14:20:36] [INFO] confirming that GET parameter 'id' is dynamic
[14:20:38] [INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable
[14:20:39] [INFO] testing for SQL injection on GET parameter 'id'
sqlmap identified the following injection point(s) with a total of 27 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5573=5573

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND (SELECT 5040 FROM (SELECT(SLEEP(5)))mlEM)
---
[14:21:10] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
"""


def _sqlmap_log_payload() -> bytes:
    return _SQLMAP_LOG.encode("utf-8")


@pytest.mark.parametrize("tool_id", ("sqlmap_safe", "sqlmap_confirm"))
def test_sqlmap_dispatch_yields_sqli_finding(
    loaded_registry: ToolRegistry, tmp_path: Path, tool_id: str
) -> None:
    """Synthetic sqlmap log → exactly one SQLi finding per parameter, with
    folded technique evidence and DBMS metadata.

    Both sqlmap variants share the parser, so the same payload must
    produce equivalent findings under either ``tool_id``.  The expected
    fold is one finding per parameter regardless of how many techniques
    sqlmap discovered (boolean + time-based above → still one finding).
    """
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None
    assert descriptor.parse_strategy is ParseStrategy.TEXT_LINES

    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()

    findings = dispatch_parse(
        descriptor.parse_strategy,
        _sqlmap_log_payload(),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id}: sqlmap parser produced no findings"
    assert len(findings) == 1, (
        f"{tool_id}: techniques must fold into one finding per parameter, "
        f"got {len(findings)}"
    )

    finding = findings[0]
    assert finding.category is FindingCategory.SQLI, (
        f"{tool_id}: expected SQLi category, got {finding.category}"
    )
    assert finding.confidence is ConfidenceLevel.CONFIRMED, (
        f"{tool_id}: sqlmap injections must produce CONFIRMED findings, "
        f"got {finding.confidence}"
    )
    assert 89 in finding.cwe, (
        f"{tool_id}: SQLi finding must declare CWE-89, got {finding.cwe}"
    )


@pytest.mark.parametrize("tool_id", ("sqlmap_safe", "sqlmap_confirm"))
def test_sqlmap_dispatch_writes_evidence_sidecar(
    loaded_registry: ToolRegistry, tmp_path: Path, tool_id: str
) -> None:
    """Both sqlmap variants must persist a JSONL sidecar."""
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None

    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()

    findings = dispatch_parse(
        descriptor.parse_strategy,
        _sqlmap_log_payload(),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings

    sidecar = artifacts_dir / SQLMAP_SIDECAR
    assert sidecar.is_file(), (
        f"{tool_id}: sqlmap parser must write the {SQLMAP_SIDECAR} sidecar"
    )
    parsed = [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(parsed) == len(findings)
    assert all(rec.get("tool_id") == tool_id for rec in parsed), (
        f"{tool_id}: every sidecar record must carry the source tool_id"
    )


# ---------------------------------------------------------------------------
# dalfox parser dispatch — JSON envelope → XSS findings
# ---------------------------------------------------------------------------


def _dalfox_payload() -> bytes:
    """Synthesise a dalfox JSON envelope with three findings:

    * Verified DOM-XSS (V) → CONFIRMED, ``FindingCategory.XSS``.
    * Stored XSS    (S)    → LIKELY,    ``FindingCategory.XSS``.
    * Reflected XSS (R)    → SUSPECTED, ``FindingCategory.INFO``.
    """
    payload = [
        {
            "type": "V",
            "severity": "high",
            "url": "https://target.example/search?q=test",
            "method": "GET",
            "param": "q",
            "payload": '"><script>alert(1)</script>',
            "cwe": "CWE-79",
            "evidence": "<script>alert(1)</script>",
        },
        {
            "type": "S",
            "severity": "medium",
            "url": "https://target.example/comment",
            "method": "POST",
            "param": "body",
            "payload": "<svg onload=alert(2)>",
            "cwe": ["CWE-79", "CWE-80"],
            "evidence": "Stored XSS via comment body field.",
        },
        {
            "type": "R",
            "severity": "low",
            "url": "https://target.example/profile?name=foo",
            "method": "GET",
            "param": "name",
            "payload": "<b>reflected</b>",
            "cwe": "CWE-79",
        },
    ]
    return json.dumps(payload).encode("utf-8")


def test_dalfox_dispatch_yields_xss_findings(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """Synthetic dalfox JSON → 3 findings (V/S/R) with the correct ladder.

    Verified → ``XSS / CONFIRMED``, Stored → ``XSS / LIKELY``, Reflected →
    ``INFO / SUSPECTED``.  Every finding must declare CWE-79.
    """
    descriptor = loaded_registry.get("dalfox")
    assert descriptor is not None
    assert descriptor.parse_strategy is ParseStrategy.JSON_OBJECT

    artifacts_dir = tmp_path / "dalfox"
    artifacts_dir.mkdir()

    findings = dispatch_parse(
        descriptor.parse_strategy,
        _dalfox_payload(),
        b"",
        artifacts_dir,
        tool_id="dalfox",
    )
    assert len(findings) == 3, f"expected 3 findings (V/S/R), got {len(findings)}"

    assert all(79 in f.cwe for f in findings), (
        "every dalfox finding must declare CWE-79"
    )

    confidences = sorted(f.confidence.value for f in findings)
    assert confidences == sorted(
        [
            ConfidenceLevel.CONFIRMED.value,
            ConfidenceLevel.LIKELY.value,
            ConfidenceLevel.SUSPECTED.value,
        ]
    ), f"confidence ladder mismatch: {confidences}"

    categories = {f.category for f in findings}
    assert FindingCategory.XSS in categories, (
        "Verified + Stored XSS must classify as FindingCategory.XSS"
    )
    assert FindingCategory.INFO in categories, (
        "Reflected XSS must classify as FindingCategory.INFO"
    )

    # The exact V/S/R → category/confidence pairing pinned from the
    # dalfox parser contract (src/sandbox/parsers/dalfox_parser._TYPE_MAP).
    pairs = {(f.category, f.confidence) for f in findings}
    assert (FindingCategory.XSS, ConfidenceLevel.CONFIRMED) in pairs, (
        "Verified XSS must yield (XSS, CONFIRMED)"
    )
    assert (FindingCategory.XSS, ConfidenceLevel.LIKELY) in pairs, (
        "Stored XSS must yield (XSS, LIKELY)"
    )
    assert (FindingCategory.INFO, ConfidenceLevel.SUSPECTED) in pairs, (
        "Reflected XSS must yield (INFO, SUSPECTED)"
    )


def test_dalfox_dispatch_writes_evidence_sidecar(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """The dalfox parser must persist a JSONL sidecar."""
    descriptor = loaded_registry.get("dalfox")
    assert descriptor is not None

    artifacts_dir = tmp_path / "dalfox"
    artifacts_dir.mkdir()

    findings = dispatch_parse(
        descriptor.parse_strategy,
        _dalfox_payload(),
        b"",
        artifacts_dir,
        tool_id="dalfox",
    )
    assert findings

    sidecar = artifacts_dir / DALFOX_SIDECAR
    assert sidecar.is_file(), f"dalfox parser must write the {DALFOX_SIDECAR} sidecar"
    parsed = [
        json.loads(line)
        for line in sidecar.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(parsed) == len(findings)
    assert all(rec.get("tool_id") == "dalfox" for rec in parsed)


def test_dalfox_canonical_artifact_round_trip(
    loaded_registry: ToolRegistry, tmp_path: Path
) -> None:
    """Writing the canonical ``dalfox.json`` artefact short-circuits stdout
    and produces the same finding set — proves the dispatch flow respects
    the ``--output {out_dir}/dalfox.json`` contract documented in the YAML.
    """
    descriptor = loaded_registry.get("dalfox")
    assert descriptor is not None

    artifacts_dir = tmp_path / "dalfox"
    artifacts_dir.mkdir()
    canonical = artifacts_dir / "dalfox.json"
    canonical.write_bytes(_dalfox_payload())

    findings = dispatch_parse(
        descriptor.parse_strategy,
        b'{"<<<garbage>>>": true}',
        b"",
        artifacts_dir,
        tool_id="dalfox",
    )
    assert len(findings) == 3, (
        "dalfox parser must prefer canonical artefact over stdout"
    )
