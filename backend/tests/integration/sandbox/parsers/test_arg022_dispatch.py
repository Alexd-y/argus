"""Integration test: ARG-022 batch-2 TEXT_LINES dispatch (Backlog/dev1_md §4.2 + §4.12 + §4.17).

Sister suite to ``test_arg021_dispatch.py``. Pins the ARG-022 contract
that the **ten** new Active Directory / SMB / SNMP / LDAP parsers
shipped in Cycle 3 batch-2:

* ``impacket_secretsdump`` — NTDS.dit / SAM / LSA dump (CRITICAL hash
  redaction gate),
* ``evil_winrm``           — interactive PS post-ex marker,
* ``kerbrute``             — Kerberos username enumeration,
* ``bloodhound_python``    — BloodHound collector ZIP marker,
* ``snmpwalk``             — SNMPv2 OID walk + default community,
* ``ldapsearch``           — LDIF block enumeration,
* ``smbclient``            — SMB share listing,
* ``smbmap``               — SMB access-rights matrix,
* ``enum4linux_ng``        — legacy enum4linux text path,
* ``rpcclient_enum``       — null-session RPC enumeration,

route through :class:`~src.sandbox.adapter_base.ParseStrategy.TEXT_LINES`
(and :class:`~src.sandbox.adapter_base.ParseStrategy.JSON_OBJECT` for
``enum4linux_ng`` whose YAML wraps ``-oJ`` JSON output but whose
canonical text format is what we parse on stdout).

Guardrails enforced in this suite:

* Each ARG-022 tool is registered in the per-tool dispatch table.
* Dispatch from a representative payload yields ``len(findings) >= 1``.
* Each parser writes its own dedicated sidecar file (no overwrites
  between parsers in a shared ``/out`` directory).
* Cross-tool routing isolation: a payload shaped for tool A pushed
  through tool B's ``tool_id`` produces 0 real findings.
* Determinism: re-running the same payload twice produces byte-identical
  sidecars.
* CRITICAL: ``impacket_secretsdump`` must NEVER write a raw
  ``[a-fA-F0-9]{32}:[a-fA-F0-9]{32}`` LM:NT pair to the sidecar.
* Heartbeat fallback survives — unmapped tools still produce one
  observability finding through the strategy handler.
* Prior cycle parsers (ARG-021 + earlier) survive ARG-022 wiring.
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
from src.sandbox.parsers.bloodhound_python_parser import (
    EVIDENCE_SIDECAR_NAME as BLOODHOUND_SIDECAR,
)
from src.sandbox.parsers.enum4linux_ng_parser import (
    EVIDENCE_SIDECAR_NAME as ENUM4LINUX_SIDECAR,
)
from src.sandbox.parsers.evil_winrm_parser import (
    EVIDENCE_SIDECAR_NAME as EVIL_WINRM_SIDECAR,
)
from src.sandbox.parsers.impacket_secretsdump_parser import (
    EVIDENCE_SIDECAR_NAME as IMPACKET_SIDECAR,
)
from src.sandbox.parsers.kerbrute_parser import (
    EVIDENCE_SIDECAR_NAME as KERBRUTE_SIDECAR,
)
from src.sandbox.parsers.ldapsearch_parser import (
    EVIDENCE_SIDECAR_NAME as LDAPSEARCH_SIDECAR,
)
from src.sandbox.parsers.rpcclient_enum_parser import (
    EVIDENCE_SIDECAR_NAME as RPCCLIENT_SIDECAR,
)
from src.sandbox.parsers.smbclient_check_parser import (
    EVIDENCE_SIDECAR_NAME as SMBCLIENT_SIDECAR,
)
from src.sandbox.parsers.smbmap_parser import (
    EVIDENCE_SIDECAR_NAME as SMBMAP_SIDECAR,
)
from src.sandbox.parsers.snmpwalk_parser import (
    EVIDENCE_SIDECAR_NAME as SNMPWALK_SIDECAR,
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


# Every ARG-022 tool that MUST have a parser registered post-Cycle 3 batch 2.
ARG022_TOOL_IDS: Final[tuple[str, ...]] = (
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


# Each ARG-022 tool's canonical sidecar filename.
ARG022_TOOL_SIDECARS: Final[dict[str, str]] = {
    "impacket_secretsdump": IMPACKET_SIDECAR,
    "evil_winrm": EVIL_WINRM_SIDECAR,
    "kerbrute": KERBRUTE_SIDECAR,
    "bloodhound_python": BLOODHOUND_SIDECAR,
    "snmpwalk": SNMPWALK_SIDECAR,
    "ldapsearch": LDAPSEARCH_SIDECAR,
    "smbclient": SMBCLIENT_SIDECAR,
    "smbmap": SMBMAP_SIDECAR,
    "enum4linux_ng": ENUM4LINUX_SIDECAR,
    "rpcclient_enum": RPCCLIENT_SIDECAR,
}


# YAML-declared parse strategy per tool (9× TEXT_LINES + 1× JSON_OBJECT).
ARG022_TOOL_STRATEGIES: Final[dict[str, ParseStrategy]] = {
    "impacket_secretsdump": ParseStrategy.TEXT_LINES,
    "evil_winrm": ParseStrategy.TEXT_LINES,
    "kerbrute": ParseStrategy.TEXT_LINES,
    "bloodhound_python": ParseStrategy.TEXT_LINES,
    "snmpwalk": ParseStrategy.TEXT_LINES,
    "ldapsearch": ParseStrategy.TEXT_LINES,
    "smbclient": ParseStrategy.TEXT_LINES,
    "smbmap": ParseStrategy.TEXT_LINES,
    "enum4linux_ng": ParseStrategy.JSON_OBJECT,
    "rpcclient_enum": ParseStrategy.TEXT_LINES,
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


@pytest.mark.parametrize("tool_id", ARG022_TOOL_IDS)
def test_arg022_tool_is_registered(tool_id: str) -> None:
    """Every ARG-022 tool must be wired into the per-tool dispatch table."""
    registered = get_registered_tool_parsers()
    assert tool_id in registered, (
        f"{tool_id} missing from per-tool parser registry — broken wiring "
        f"in src.sandbox.parsers.__init__._DEFAULT_TOOL_PARSERS"
    )


def test_arg022_does_not_drop_prior_cycle_registrations() -> None:
    """Sanity: every prior-cycle tool slot survives the ARG-022 batch."""
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
    )
    for legacy in legacy_tools:
        assert legacy in registered, f"{legacy} slot must survive ARG-022 registration"


def test_arg022_contribution_is_intact() -> None:
    """All ten ARG-022 batch-2 tools must be present in the registry.

    The absolute mapped-parser count was pinned to 53 immediately after
    ARG-022 landed; the global count is now owned by the ARG-029 ratchet
    in ``tests/test_tool_catalog_coverage.py::MAPPED_PARSER_COUNT`` (68
    as of Cycle 3 close).  Pinning the absolute total here as well
    forced the assertion to drift every time a new parser batch landed,
    which masked the real signal we want — "ARG-022's ten parsers stay
    in the registry".  Re-framed accordingly so this gate stays
    cycle-stable while still catching a regression that drops one of
    the AD/SMB/SNMP/LDAP tools.
    """
    registered = get_registered_tool_parsers()
    missing = [tool_id for tool_id in ARG022_TOOL_IDS if tool_id not in registered]
    assert not missing, (
        f"ARG-022 batch-2 tools missing from registry after later cycles: "
        f"{missing!r} — check src.sandbox.parsers.__init__._DEFAULT_TOOL_PARSERS"
    )
    assert len(registered) >= len(ARG022_TOOL_IDS), (
        "registry shrank below the ARG-022 contribution"
    )


# ---------------------------------------------------------------------------
# Routing — happy path for every ARG-022 tool
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG022_TOOL_IDS)
def test_dispatch_routes_each_arg022_tool(tool_id: str, tmp_path: Path) -> None:
    """Every ARG-022 tool routes via its strategy and yields ≥1 finding."""
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    findings = dispatch_parse(
        ARG022_TOOL_STRATEGIES[tool_id],
        _payload(tool_id),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id}: dispatch produced no findings"
    assert all(isinstance(f, FindingDTO) for f in findings)


@pytest.mark.parametrize("tool_id", ARG022_TOOL_IDS)
def test_dispatch_writes_per_tool_sidecar(tool_id: str, tmp_path: Path) -> None:
    """Each ARG-022 dispatch writes its dedicated sidecar tagged with tool_id."""
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    findings = dispatch_parse(
        ARG022_TOOL_STRATEGIES[tool_id],
        _payload(tool_id),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings
    sidecar = artifacts_dir / ARG022_TOOL_SIDECARS[tool_id]
    assert sidecar.is_file(), (
        f"{tool_id}: parser must write evidence sidecar at {sidecar}"
    )
    parsed = _read_sidecar(sidecar)
    assert parsed, f"{tool_id}: sidecar is empty"
    assert all(rec["tool_id"] == tool_id for rec in parsed), (
        f"{tool_id}: every sidecar record must tag its source tool_id"
    )


def test_arg022_tools_use_distinct_sidecar_filenames() -> None:
    """All ten ARG-022 sidecar filenames must be unique across the batch."""
    sidecars = list(ARG022_TOOL_SIDECARS.values())
    assert len(set(sidecars)) == len(sidecars), (
        "ARG-022 parsers collide on sidecar filenames; one tool would "
        "overwrite another in shared /out"
    )


# ---------------------------------------------------------------------------
# CRITICAL — impacket_secretsdump hash-redaction guardrail (security gate)
# ---------------------------------------------------------------------------


_NT_HASH_PAIR_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b"
)
_LONG_HEX_RE: Final[re.Pattern[str]] = re.compile(r"\b[a-fA-F0-9]{32,}\b")


def test_impacket_secretsdump_redacts_hashes_in_sidecar(tmp_path: Path) -> None:
    """Raw NT/LM/AES hashes from secretsdump MUST never reach the sidecar.

    This is the ARG-022 critical security gate.  We feed the canonical
    NTDS.dit dump fixture (5 principals with valid 32-hex hashes) and
    assert that:

    1. the dispatch produces ≥1 finding;
    2. the sidecar contains 0 LM:NT pairs (``[a-f0-9]{32}:[a-f0-9]{32}``);
    3. the sidecar contains 0 lone ≥32-hex blobs (would catch SHA-1 /
       SHA-256 / AES key leakage);
    4. the canonical redaction marker is present.
    """
    findings = dispatch_parse(
        ParseStrategy.TEXT_LINES,
        _payload("impacket_secretsdump"),
        b"",
        tmp_path,
        tool_id="impacket_secretsdump",
    )
    assert findings, "impacket_secretsdump dispatch must yield ≥1 finding"
    sidecar = tmp_path / IMPACKET_SIDECAR
    text = sidecar.read_text(encoding="utf-8")
    pair_hits = _NT_HASH_PAIR_RE.findall(text)
    long_hex_hits = _LONG_HEX_RE.findall(text)
    assert pair_hits == [], (
        f"RAW LM:NT PAIR LEAKED through impacket sidecar — redaction broken. "
        f"Hits: {pair_hits[:3]}"
    )
    assert long_hex_hits == [], (
        f"RAW long hash hex LEAKED through impacket sidecar. Hits: {long_hex_hits[:3]}"
    )
    assert "[REDACTED-NT-HASH]" in text, (
        "expected NT redaction marker in impacket sidecar"
    )


# ---------------------------------------------------------------------------
# Cross-tool routing isolation — defence in depth
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload_tool", "wrong_tool"),
    [
        ("kerbrute", "smbmap"),
        ("smbmap", "kerbrute"),
        ("ldapsearch", "snmpwalk"),
        ("snmpwalk", "ldapsearch"),
        ("rpcclient_enum", "smbclient"),
        ("evil_winrm", "bloodhound_python"),
        ("impacket_secretsdump", "evil_winrm"),
    ],
)
def test_cross_routing_is_inert(
    payload_tool: str, wrong_tool: str, tmp_path: Path
) -> None:
    """A payload from tool X dispatched as tool Y produces 0 real findings.

    Defence-in-depth check that every ARG-022 parser refuses to
    invent findings from a wrongly-shaped input.  ``impacket`` and
    ``smbmap`` happen to share an unbroken NT-hash regex pattern with
    no other tool — so we explicitly mix them with non-matching peers.
    """
    findings = dispatch_parse(
        ARG022_TOOL_STRATEGIES[wrong_tool],
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


@pytest.mark.parametrize("tool_id", ARG022_TOOL_IDS)
def test_arg022_dispatch_is_deterministic(tool_id: str, tmp_path: Path) -> None:
    """Two dispatches on the same payload produce byte-identical sidecars."""
    payload = _payload(tool_id)
    artifacts_a = tmp_path / "a"
    artifacts_b = tmp_path / "b"
    artifacts_a.mkdir()
    artifacts_b.mkdir()
    dispatch_parse(
        ARG022_TOOL_STRATEGIES[tool_id], payload, b"", artifacts_a, tool_id=tool_id
    )
    dispatch_parse(
        ARG022_TOOL_STRATEGIES[tool_id], payload, b"", artifacts_b, tool_id=tool_id
    )
    sidecar_name = ARG022_TOOL_SIDECARS[tool_id]
    a_bytes = (artifacts_a / sidecar_name).read_bytes()
    b_bytes = (artifacts_b / sidecar_name).read_bytes()
    assert a_bytes == b_bytes, (
        f"{tool_id}: sidecar bytes drift between runs — non-deterministic parser"
    )


# ---------------------------------------------------------------------------
# Multi-tool same /out directory — sidecar isolation
# ---------------------------------------------------------------------------


def test_all_arg022_parsers_in_single_artifacts_dir_keeps_sidecars_intact(
    tmp_path: Path,
) -> None:
    """Running all ten ARG-022 parsers in the same dir leaves all sidecars intact."""
    for tool_id in ARG022_TOOL_IDS:
        dispatch_parse(
            ARG022_TOOL_STRATEGIES[tool_id],
            _payload(tool_id),
            b"",
            tmp_path,
            tool_id=tool_id,
        )

    for tool_id, sidecar_name in ARG022_TOOL_SIDECARS.items():
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
        ParseStrategy.TEXT_LINES,
        b"some output\n",
        b"",
        tmp_path,
        tool_id="unknown_tool_arg022_xyz",
    )
    assert len(findings) == 1
    assert findings[0].cvss_v3_score == 0.0
