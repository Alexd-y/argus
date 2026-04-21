"""Integration test: nuclei JSONL family + nikto/wapiti dispatch (Backlog/dev1_md §4.7 + §4.8).

Sister suite to ``test_wpscan_dispatch.py``; this one pins the ARG-015
contract that:

* ``nuclei`` (§4.8 flagship) AND the three §4.7 CMS wrappers
  (``nextjs_check`` / ``spring_boot_actuator`` / ``jenkins_enum``) all
  route through :class:`~src.sandbox.adapter_base.ParseStrategy.NUCLEI_JSONL`
  to a single shared :func:`src.sandbox.parsers.nuclei_parser.parse_nuclei_jsonl`,
  with the source ``tool_id`` stamped onto every sidecar record so the
  four callers stay demultiplexable downstream.
* The two §4.8 active-scan adapters (``nikto`` / ``wapiti``) route via
  ``ParseStrategy.JSON_OBJECT`` to their dedicated parsers in the same
  module, and every emitted FindingDTO is well-formed.
* The four deferred §4.8 web-vuln scanners (``arachni``, ``skipfish``,
  ``w3af_console``, ``zap_baseline``) have NO parser registration by
  design — pinned so a future silent move into ``_DEFAULT_TOOL_PARSERS``
  lights up the diff in CI.
* Cross-tool coexistence: the §4.4–§4.7 wirings (httpx, ffuf_dir,
  katana, wpscan) survive ARG-015's batch of registrations.
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
from src.sandbox.parsers.nuclei_parser import EVIDENCE_SIDECAR_NAME


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


# §4.7 + §4.8 nuclei callers — all route through ``parse_nuclei_jsonl``.
NUCLEI_TOOL_IDS: Final[tuple[str, ...]] = (
    "nuclei",
    "nextjs_check",
    "spring_boot_actuator",
    "jenkins_enum",
)


# §4.8 JSON_OBJECT adapters — share dispatch with the §4.5/§4.7 ffuf/wpscan
# tools but route to their own parsers via the per-tool registry.
JSON_OBJECT_WEB_VULN_TOOL_IDS: Final[tuple[str, ...]] = ("nikto", "wapiti")


# §4.8 still-deferred web-vuln scanners — text/binary outputs, no JSON
# parser yet. Pinned explicitly so adding a parser without updating
# this list breaks CI with a "Cycle X work landed early; update
# DEFERRED_WEB_VULN_TOOL_IDS" assertion.  ARG-029 wired ``zap_baseline``
# (its dispatch contract now lives under tests/integration/sandbox/parsers/
# test_arg029_dispatch.py); the remaining three stay deferred to Cycle
# 4 (see ai_docs/develop/issues/ISS-cycle4-carry-over.md, ARG-032).
DEFERRED_WEB_VULN_TOOL_IDS: Final[tuple[str, ...]] = (
    "arachni",
    "skipfish",
    "w3af_console",
)


def _nuclei_record(
    *,
    template_id: str,
    matched_at: str,
    severity: str,
    tags: list[str] | None = None,
    cves: list[str] | None = None,
    cvss_score: float | None = None,
    cvss_vector: str | None = None,
) -> dict[str, Any]:
    info: dict[str, Any] = {"name": template_id, "severity": severity}
    if tags is not None:
        info["tags"] = tags
    classification: dict[str, Any] = {}
    if cves is not None:
        classification["cve-id"] = cves
    if cvss_score is not None:
        classification["cvss-score"] = cvss_score
    if cvss_vector is not None:
        classification["cvss-metrics"] = cvss_vector
    if classification:
        info["classification"] = classification
    return {
        "template-id": template_id,
        "info": info,
        "host": matched_at,
        "matched-at": matched_at,
        "matcher-status": True,
    }


def _nuclei_payload() -> bytes:
    """A representative payload that exercises severity + tag routing."""
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
        ),
    ]
    return ("\n".join(json.dumps(r, sort_keys=True) for r in records) + "\n").encode(
        "utf-8"
    )


def _nikto_payload() -> bytes:
    return json.dumps(
        {
            "vulnerabilities": [
                {
                    "id": "001234",
                    "msg": "Server header reveals Apache/2.4.41",
                    "url": "/",
                    "method": "GET",
                },
                {
                    "id": "005678",
                    "msg": "Outdated jQuery present in /static/jquery.js",
                    "url": "/static/jquery.js",
                    "method": "GET",
                },
            ]
        }
    ).encode("utf-8")


def _wapiti_payload() -> bytes:
    return json.dumps(
        {
            "vulnerabilities": {
                "SQL Injection": [
                    {
                        "method": "POST",
                        "path": "/login",
                        "info": "SQLi via username param",
                        "parameter": "username",
                    }
                ],
                "Cross Site Scripting": [
                    {
                        "method": "GET",
                        "path": "/search",
                        "info": "Reflected XSS via q",
                        "parameter": "q",
                    }
                ],
            }
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


def test_nuclei_jsonl_strategy_is_registered() -> None:
    """``ParseStrategy.NUCLEI_JSONL`` must have a default handler."""
    assert ParseStrategy.NUCLEI_JSONL in get_registered_strategies(), (
        "NUCLEI_JSONL strategy missing from default registry — broken wiring "
        "in src.sandbox.parsers.__init__._build_default_strategy_handlers"
    )


@pytest.mark.parametrize("tool_id", NUCLEI_TOOL_IDS)
def test_default_per_tool_registry_includes_each_nuclei_caller(tool_id: str) -> None:
    """All four §4.7+§4.8 nuclei callers must be registered for dispatch."""
    registered = get_registered_tool_parsers()
    assert tool_id in registered, (
        f"{tool_id} missing from per-tool parser registry — broken "
        f"wiring in src.sandbox.parsers.__init__"
    )


@pytest.mark.parametrize("tool_id", JSON_OBJECT_WEB_VULN_TOOL_IDS)
def test_default_per_tool_registry_includes_nikto_and_wapiti(tool_id: str) -> None:
    """Both §4.8 JSON_OBJECT adapters must be registered for dispatch."""
    registered = get_registered_tool_parsers()
    assert tool_id in registered, f"{tool_id} missing from per-tool parser registry"


def test_arg015_does_not_drop_prior_cycle_registrations() -> None:
    """Sanity: §4.4–§4.7 wirings survive the ARG-015 batch of registrations."""
    registered = get_registered_tool_parsers()
    for legacy in ("httpx", "ffuf_dir", "katana", "wpscan"):
        assert legacy in registered, f"{legacy} slot must survive ARG-015 registration"


# ---------------------------------------------------------------------------
# Routing — happy path for every nuclei caller
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", NUCLEI_TOOL_IDS)
def test_dispatch_routes_each_nuclei_tool_to_shared_parser(
    tool_id: str, tmp_path: Path
) -> None:
    """All four nuclei tool_ids route via NUCLEI_JSONL and produce findings."""
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    findings = dispatch_parse(
        ParseStrategy.NUCLEI_JSONL,
        _nuclei_payload(),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id}: dispatch produced no findings"
    assert all(isinstance(f, FindingDTO) for f in findings)


@pytest.mark.parametrize("tool_id", NUCLEI_TOOL_IDS)
def test_dispatch_writes_shared_sidecar_with_correct_tool_id(
    tool_id: str, tmp_path: Path
) -> None:
    """Each nuclei dispatch emits a sidecar tagged with its tool_id."""
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    findings = dispatch_parse(
        ParseStrategy.NUCLEI_JSONL,
        _nuclei_payload(),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings

    sidecar = artifacts_dir / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file(), (
        f"{tool_id}: nuclei parser must write evidence sidecar at {sidecar}"
    )
    parsed = _read_sidecar(sidecar)
    assert len(parsed) == len(findings)
    assert all(rec["tool_id"] == tool_id for rec in parsed), (
        f"{tool_id}: every sidecar record must tag its source tool_id"
    )


def test_nuclei_dispatch_attaches_high_severity_for_rce_template(
    tmp_path: Path,
) -> None:
    """A critical+rce nuclei record → at least one RCE-classified finding."""
    findings = dispatch_parse(
        ParseStrategy.NUCLEI_JSONL,
        _nuclei_payload(),
        b"",
        tmp_path,
        tool_id="nuclei",
    )
    rce = [f for f in findings if f.category is FindingCategory.RCE]
    assert rce, "expected at least one RCE finding for the critical+rce record"
    assert rce[0].confidence is ConfidenceLevel.LIKELY
    assert rce[0].cvss_v3_score == pytest.approx(9.8)


# ---------------------------------------------------------------------------
# Routing — happy path for nikto / wapiti
# ---------------------------------------------------------------------------


def test_dispatch_routes_nikto_via_json_object(tmp_path: Path) -> None:
    """``nikto`` routes via JSON_OBJECT to ``parse_nikto_json``."""
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _nikto_payload(),
        b"",
        tmp_path,
        tool_id="nikto",
    )
    assert findings, "nikto: dispatch produced no findings"
    assert all(f.category is FindingCategory.MISCONFIG for f in findings)
    sidecar = tmp_path / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file()
    parsed = _read_sidecar(sidecar)
    assert all(rec["tool_id"] == "nikto" for rec in parsed)


def test_dispatch_routes_wapiti_via_json_object(tmp_path: Path) -> None:
    """``wapiti`` routes via JSON_OBJECT to ``parse_wapiti_json``."""
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _wapiti_payload(),
        b"",
        tmp_path,
        tool_id="wapiti",
    )
    assert findings
    cats = {f.category for f in findings}
    assert FindingCategory.SQLI in cats
    assert FindingCategory.XSS in cats
    sidecar = tmp_path / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file()
    parsed = _read_sidecar(sidecar)
    assert all(rec["tool_id"] == "wapiti" for rec in parsed)


# ---------------------------------------------------------------------------
# Negative path — deferred §4.8 tools must NOT be registered
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", DEFERRED_WEB_VULN_TOOL_IDS)
def test_deferred_web_vuln_tools_have_no_parser(
    tool_id: str, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The four deferred §4.8 tools must NOT route to any parser yet.

    Strategy-level: dispatching them via JSON_OBJECT fails soft with the
    ``parsers.dispatch.unmapped_tool`` warning AND emits one ARG-020
    heartbeat finding so the orchestrator can distinguish "tool ran but
    parser deferred" from a silent skip (defence-in-depth).
    """
    registered = get_registered_tool_parsers()
    assert tool_id not in registered, (
        f"{tool_id} unexpectedly has a parser — Cycle 3 work landed early; "
        f"update DEFERRED_WEB_VULN_TOOL_IDS in this test"
    )

    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = dispatch_parse(
            ParseStrategy.JSON_OBJECT,
            _nuclei_payload(),
            b"",
            tmp_path,
            tool_id=tool_id,
        )

    assert len(findings) == 1, (
        f"{tool_id}: expected exactly one heartbeat via JSON_OBJECT misroute, "
        f"got {len(findings)}"
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
# Cross-routing safety — wpscan/ffuf payloads pushed through NUCLEI_JSONL
# must stay inert (tool_id is the strong key, not strategy)
# ---------------------------------------------------------------------------


def test_wpscan_payload_misrouted_via_nuclei_jsonl_is_inert(tmp_path: Path) -> None:
    """Pushing a wpscan-shaped JSON object through NUCLEI_JSONL → ``[]``.

    The per-tool table is keyed by ``tool_id``, so a wpscan envelope routed
    through NUCLEI_JSONL still calls ``parse_wpscan_json`` (because the
    tool_id "wpscan" maps to it). The wpscan parser, however, is shape-aware
    and yields findings — meaning misrouting BY STRATEGY is harmless,
    but misrouting BY TOOL_ID is what the per-tool guarantees defend against.
    Pinning the inverse (a nuclei payload + the nikto tool_id) ensures the
    nikto parser fail-softs on the nuclei envelope: no nikto-shaped
    ``vulnerabilities`` block ⇒ no findings.
    """
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        _nuclei_payload(),
        b"",
        tmp_path,
        tool_id="nikto",
    )
    assert findings == [], (
        "nikto parser must produce no findings on nuclei-shaped JSONL payload"
    )


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", NUCLEI_TOOL_IDS)
def test_dispatch_is_deterministic_across_repeated_runs(
    tool_id: str, tmp_path: Path
) -> None:
    """Two dispatch calls on the same payload produce identical sidecars."""
    artifacts_a = tmp_path / "a"
    artifacts_b = tmp_path / "b"
    artifacts_a.mkdir()
    artifacts_b.mkdir()
    payload = _nuclei_payload()
    dispatch_parse(
        ParseStrategy.NUCLEI_JSONL,
        payload,
        b"",
        artifacts_a,
        tool_id=tool_id,
    )
    dispatch_parse(
        ParseStrategy.NUCLEI_JSONL,
        payload,
        b"",
        artifacts_b,
        tool_id=tool_id,
    )
    sidecar_a = (artifacts_a / EVIDENCE_SIDECAR_NAME).read_bytes()
    sidecar_b = (artifacts_b / EVIDENCE_SIDECAR_NAME).read_bytes()
    assert sidecar_a == sidecar_b, (
        f"{tool_id}: sidecar bytes drift between runs — non-deterministic parser"
    )
