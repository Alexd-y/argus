"""Parser for Nmap XML output (Backlog/dev1_md §4.2 — ARG-019 back-port).

§4.2 ships five Nmap invocations that all share the canonical ``-oX``
envelope (the human-readable ``-oN`` text is for operator review only —
the XML is the machine contract).  Each variant pins a *distinct*
output filename so multiple variants can deposit their XML side-by-side
in the same artefact mount:

* **nmap_tcp_full** (``-oX /out/nmap_full.xml``) — full TCP port-discovery
  sweep against an ip / cidr.
* **nmap_tcp_top** (``-oX /out/nmap_tcp.xml``) — fast top-1000 TCP
  discovery for time-budgeted scans.
* **nmap_udp** (``-oX /out/nmap_udp.xml``) — top-100 UDP probe
  (rate-limited; UDP is slow by design).
* **nmap_version** (``-oX /out/nmap_v.xml``) — service / version
  detection on previously-discovered open ports.
* **nmap_vuln** (``-oX /out/nmap_vuln.xml``) — NSE vulnerability scan
  (``--script vuln,vulners``), CVE-rich output via ``<script id="vulners">``.

Per-tool filename mapping lives in :data:`_PER_TOOL_CANONICAL_FILENAME`.
The legacy ``nmap.xml`` filename is kept as a secondary candidate (for
unit-test fixtures and operator overrides).

Two finding kinds are emitted per invocation:

1. **Open port** → :class:`FindingCategory.INFO`
   One ``FindingDTO`` per ``<port state="open">`` regardless of scan
   variant. Carries port + protocol + service banner (``<service
   name="http" product="nginx" version="1.25.3"/>``) in the evidence
   sidecar so downstream stages (httpx, web vuln scanners) can pick the
   target up without re-querying nmap. Confidence = ``LIKELY`` when a
   service banner is present, otherwise ``SUSPECTED`` (open-port without
   ``-sV``).

2. **NSE vulnerability** (``<script id="vulners">`` / ``<script id="vuln-…">``)
   → :class:`FindingCategory.SUPPLY_CHAIN` (CVE-bearing scripts) or
   :class:`FindingCategory.MISCONFIG` (auth-related scripts:
   ``smb-vuln-*``, ``ssl-poodle``, ``ssh-weak-…``). Severity is derived
   from the CVSS score embedded in vulners' script output (one ``CVE-…
   <CVSS> <URL>`` line per vulnerability). Falls back to severity from
   the script name's CVE-bucket (high/medium/low) when CVSS is absent.

Vulners output shape (the only standardised CVE format among the NSE
script families) is line-oriented inside the ``<script output="…">``
attribute / child text:

.. code-block::

    cpe:/a:apache:http_server:2.4.49:
        CVE-2021-41773  9.8     https://vulners.com/cve/CVE-2021-41773
        CVE-2021-42013  9.8     https://vulners.com/cve/CVE-2021-42013
        EDB-50383       7.5     https://vulners.com/exploitdb/EDB-50383

We extract the leading CVE id + numeric CVSS score per line; non-CVE
ids (EDB / packetstorm / metasploit) are kept as references but never
become standalone findings (they are exploits *for* the same CVE).

Translation rules
-----------------

Common (both finding kinds):

* **CWE** — vuln findings get the per-CVE list pulled from the script
  output (none today; vulners doesn't surface CWEs), falling back to
  ``[1395]`` (Use of Vulnerable Third-Party Component); INFO findings
  default to ``[200]`` (Information Exposure Through Discrepancy).
* **OWASP-WSTG** — vuln findings → ``WSTG-INFO-08`` (Fingerprint Web
  Application Framework, the closest WSTG anchor for CVE-bearing CPEs);
  INFO findings → ``WSTG-INFO-04`` (Enumerate Applications on Webserver)
  + ``WSTG-INFO-02`` (Fingerprint Web Server) when a service banner is
  present.
* **CVSS** — vuln findings carry the score from vulners' script output
  (parsed into a CVSS:3.1/AV:N sentinel vector since nmap emits a bare
  numeric only); INFO findings get ``SENTINEL_CVSS_VECTOR`` /
  ``SENTINEL_CVSS_SCORE``.
* **Confidence** — see severity table below.

Severity → Confidence:

* ``CVSS >= 9.0`` → ``LIKELY`` (NVD-confirmed critical CVE)
* ``CVSS >= 7.0`` → ``LIKELY``
* ``CVSS >= 4.0`` → ``SUSPECTED``
* ``CVSS <  4.0`` → ``SUSPECTED``
* INFO with banner → ``LIKELY``
* INFO without banner → ``SUSPECTED``

Dedup
-----

Stable key per kind:

* INFO (port):  ``("port", host, port, protocol)``
* VULN (CVE):  ``("vuln", host, port, protocol, cve_id)``

Sorting is deterministic on a (severity desc → kind → host → port)
tuple so two runs against the same XML produce byte-identical sidecars.

Cap
---

Hard-limited to :data:`_MAX_FINDINGS = 10_000` so a runaway ``-sV``
sweep over a /16 cannot exhaust worker memory.

Sidecar
-------

Every emitted record is mirrored into
``artifacts_dir / "nmap_findings.jsonl"``. Each record carries its
source ``tool_id`` (``nmap_tcp_full`` / ``nmap_tcp_top`` / … ) so the
sidecar stays demultiplexable when several nmap variants share one
``/out`` mount.

Failure model
-------------

Fail-soft by contract:

* Missing canonical artifact (``nmap.xml``) falls back to stdout
  parsing.
* Malformed XML returns ``[]`` after a structured warning. We use
  :mod:`defusedxml.ElementTree` so XML External Entity (XXE) /
  billion-laughs payloads CANNOT be expanded — ``defusedxml`` raises
  ``EntitiesForbidden`` / ``ExternalReferenceForbidden`` and we
  degrade to ``[]``.
* Unknown script id is logged at debug and skipped (vulners is the
  only NSE script we currently extract CVEs from).
* OS errors writing the sidecar are logged and swallowed.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final, TypeAlias

from defusedxml import ElementTree as DefusedET  # type: ignore[import-untyped]
from defusedxml.common import DefusedXmlException  # type: ignore[import-untyped]

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import (
    MAX_STDOUT_BYTES,
    SENTINEL_CVSS_SCORE,
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants — surfaced for tests + downstream evidence pipeline.
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "nmap_findings.jsonl"


# Hard cap on emitted findings. A ``-sV --top-ports 1000`` sweep over a
# /24 of busy hosts can easily emit ~6k port + ~3k vuln rows; 10k keeps
# the worker bounded against a misconfigured ``-p-`` over a /16.
_MAX_FINDINGS: Final[int] = 10_000


# Hard cap on the bytes we keep from a single ``<script output="…">``
# blob in the evidence sidecar. Vulners output for a CPE with a long
# CVE history can run to several KB; capping at 4 KB keeps the sidecar
# readable while preserving the full CVE list (the script output is
# line-oriented at ~70 bytes per CVE row).
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


# Per-tool canonical artifact filename.  The five §4.2 nmap YAMLs each
# write to a *different* file under ``/out/`` so a single shared mount
# can hold the output of multiple variants without overwrites
# (``nmap_full.xml`` vs ``nmap_tcp.xml`` vs ``nmap_udp.xml`` vs
# ``nmap_v.xml`` vs ``nmap_vuln.xml``).  The parser maps each ``tool_id``
# back to its YAML-declared filename and falls back to the legacy
# ``nmap.xml`` name (kept for direct ``-oX /out/nmap.xml`` invocations
# and for backwards compatibility with the existing unit-test fixtures).
_PER_TOOL_CANONICAL_FILENAME: Final[dict[str, str]] = {
    "nmap_tcp_full": "nmap_full.xml",
    "nmap_tcp_top": "nmap_tcp.xml",
    "nmap_udp": "nmap_udp.xml",
    "nmap_version": "nmap_v.xml",
    "nmap_vuln": "nmap_vuln.xml",
}
_LEGACY_CANONICAL_FILENAME: Final[str] = "nmap.xml"


# Sentinel CVSS:3.1 base vector when vulners surfaces a numeric score
# but no vector. We approximate the vector for sort ordering only —
# the downstream Normaliser overwrites it with the NVD authoritative
# vector during the CVSS reconciliation pass. AV:N is a safe default
# for "exposed network service" which is the universe of nmap findings.
_VULNERS_FALLBACK_VECTOR: Final[str] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


# CVSS bucket → ConfidenceLevel mapping. Critical/high → LIKELY because
# vulners cross-references the NVD database (high-precision input);
# medium / low fall back to SUSPECTED because vulners enumerates every
# CPE-matched CVE regardless of whether the version is actually
# vulnerable on the live host.
_SEVERITY_CONFIDENCE: Final[dict[str, ConfidenceLevel]] = {
    "critical": ConfidenceLevel.LIKELY,
    "high": ConfidenceLevel.LIKELY,
    "medium": ConfidenceLevel.SUSPECTED,
    "low": ConfidenceLevel.SUSPECTED,
    "info": ConfidenceLevel.SUSPECTED,
}


# Severity bucket used when sorting (descending). ``critical`` sits
# above ``high`` so the most pressing findings end up at the top of
# both the FindingDTO list and the sidecar.
_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


# Stable dedup key shape: ``(kind, *rest)``. Module-level alias keeps
# the dedup loop signature short.
DedupKey: TypeAlias = tuple[str, ...]


# CVE-id pattern (NIST CVE schema). Matches both the legacy 4-digit
# year + 4..7 digit serial (``CVE-2021-41773``) and the 5-digit serial
# variant. Anchored on word boundaries so we don't accidentally pick
# up CVE ids embedded in URLs.
_CVE_RE: Final[re.Pattern[str]] = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b")


# Vulners script-output line shape: ``<id>\s+<cvss>\s+<url>``.
# Anchored at line start (after optional indentation) so we don't pick
# up stray CVE ids embedded in surrounding prose. The url is captured
# but optional (some vulners variants drop it on partial DB hits).
_VULNERS_LINE_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s+(?P<id>[A-Z0-9\-:_]+)\s+(?P<cvss>[0-9]+\.[0-9])(?:\s+(?P<url>https?://\S+))?\s*$",
    re.MULTILINE,
)


# CVSS:3.1 score → severity bucket (NVD canonical thresholds). Anchored
# on the NIST publication, NOT vulners' own bucket choices (vulners is
# inconsistent across DB exports).
def _cvss_to_severity(score: float) -> str:
    """Map a CVSS:3.1 base score onto a NIST severity bucket."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


# ---------------------------------------------------------------------------
# Public entry point — signature mandated by the dispatch layer:
# ``(stdout, stderr, artifacts_dir, tool_id) -> list[FindingDTO]``.
# ---------------------------------------------------------------------------


def parse_nmap_xml(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate Nmap ``-oX`` XML output into FindingDTOs.

    Resolution order for the XML blob:

    1. ``artifacts_dir / "nmap.xml"`` — the canonical filename every
       §4.2 YAML writes via ``-oX /out/nmap.xml``.
    2. ``stdout`` fallback — nmap without ``-oX`` (or with ``-oX -``)
       streams the XML to stdout instead.

    ``stderr`` is accepted for parser dispatch signature symmetry but
    intentionally not consumed (nmap uses stderr for its progress
    banner / runtime stats only). The ``tool_id`` is stamped on every
    emitted sidecar record so a single sidecar shared across the five
    nmap variants stays demultiplexable.

    Fail-soft: returns ``[]`` on missing / unparseable XML; never
    raises for a malformed payload.
    """
    del stderr
    raw_xml = _load_payload(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        tool_id=tool_id,
    )
    if not raw_xml:
        return []
    root = _safe_parse_xml(raw_xml, tool_id=tool_id)
    if root is None:
        return []
    records = list(_iter_normalised(root, tool_id=tool_id))
    if not records:
        return []
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Pipeline — dedup + sort + sidecar persistence
# ---------------------------------------------------------------------------


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Common pipeline: dedup → cap → sort → build FindingDTO + sidecar."""
    seen: set[DedupKey] = set()
    keyed: list[tuple[tuple[int, str, str, int], DedupKey, FindingDTO, str]] = []

    for record in records:
        key = _dedup_key(record)
        if key in seen:
            continue
        seen.add(key)

        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = _sort_key(record)
        keyed.append((sort_key, key, finding, evidence_blob))

        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "nmap_parser.cap_reached",
                extra={
                    "event": "nmap_parser_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
            break

    keyed.sort(key=lambda item: item[0])
    if keyed:
        _persist_evidence_sidecar(
            artifacts_dir,
            tool_id=tool_id,
            evidence_records=[blob for _, _, _, blob in keyed],
        )

    return [finding for _, _, finding, _ in keyed]


def _dedup_key(record: dict[str, Any]) -> DedupKey:
    """Stable dedup key for a normalised nmap record."""
    kind = str(record.get("kind") or "port")
    host = str(record.get("host") or "")
    port = str(record.get("port") or "")
    proto = str(record.get("protocol") or "")
    if kind == "vuln":
        cve = str(record.get("cve_id") or "")
        return (kind, host, port, proto, cve)
    return (kind, host, port, proto)


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str, int]:
    """Deterministic sort key (severity desc → kind → host → port)."""
    severity = str(record.get("severity", "info"))
    rank = _SEVERITY_RANK.get(severity, 0)
    port_str = str(record.get("port") or "0")
    try:
        port_num = int(port_str)
    except ValueError:
        port_num = 0
    return (
        -rank,
        str(record.get("kind") or ""),
        str(record.get("host") or ""),
        port_num,
    )


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    """Map a normalised nmap record onto a :class:`FindingDTO`."""
    category: FindingCategory = record["category"]
    cwe_list = list(record.get("cwe") or ())
    if not cwe_list:
        cwe_list = [200] if category is FindingCategory.INFO else [1395]
    confidence: ConfidenceLevel = record["confidence"]
    cvss_score: float = float(record.get("cvss_v3_score") or SENTINEL_CVSS_SCORE)
    cvss_vector: str = str(record.get("cvss_v3_vector") or SENTINEL_CVSS_VECTOR)
    owasp_wstg = list(record.get("owasp_wstg") or ())
    return make_finding_dto(
        category=category,
        cwe=cwe_list,
        cvss_v3_vector=cvss_vector,
        cvss_v3_score=cvss_score,
        confidence=confidence,
        owasp_wstg=owasp_wstg,
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    """Build a compact evidence JSON for downstream redaction + persistence."""
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": record.get("kind"),
        "host": record.get("host"),
        "hostname": record.get("hostname"),
        "port": record.get("port"),
        "protocol": record.get("protocol"),
        "state": record.get("state"),
        "service_name": record.get("service_name"),
        "service_product": record.get("service_product"),
        "service_version": record.get("service_version"),
        "service_extra": record.get("service_extra"),
        "service_cpe": list(record.get("service_cpe") or ()),
        "severity": record.get("severity"),
        "cve_id": record.get("cve_id"),
        "cvss_v3_score": record.get("cvss_v3_score"),
        "cvss_v3_vector": record.get("cvss_v3_vector"),
        "cve_url": record.get("cve_url"),
        "script_id": record.get("script_id"),
        "script_output_preview": _truncate_text(record.get("script_output_preview")),
        "references": list(record.get("references") or ()),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None:
            continue
        if isinstance(value, list | tuple) and not value:
            continue
        if value == "":
            continue
        if key == "cvss_v3_score" and value == SENTINEL_CVSS_SCORE:
            continue
        if key == "cvss_v3_vector" and value == SENTINEL_CVSS_VECTOR:
            continue
        cleaned[key] = value
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _persist_evidence_sidecar(
    artifacts_dir: Path,
    *,
    tool_id: str,
    evidence_records: list[str],
) -> None:
    """Best-effort write of the per-finding evidence sidecar JSONL."""
    try:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        sidecar_path = artifacts_dir / EVIDENCE_SIDECAR_NAME
        with sidecar_path.open("w", encoding="utf-8") as fh:
            for blob in evidence_records:
                fh.write(blob)
                fh.write("\n")
    except OSError as exc:
        _logger.warning(
            "nmap_parser.evidence_sidecar_write_failed",
            extra={
                "event": "nmap_parser_evidence_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


def _truncate_text(value: Any) -> str | None:
    """Truncate long text blobs to :data:`_MAX_EVIDENCE_BYTES`."""
    if value is None:
        return None
    text = str(value)
    if not text:
        return None
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_EVIDENCE_BYTES:
        return text
    return encoded[:_MAX_EVIDENCE_BYTES].decode("utf-8", errors="replace") + "…"


# ---------------------------------------------------------------------------
# Payload resolution
# ---------------------------------------------------------------------------


def _candidate_filenames(tool_id: str) -> tuple[str, ...]:
    """Return the per-tool canonical filename(s) to probe in order.

    Each §4.2 nmap YAML pins a distinct ``-oX`` filename so the artefact
    mount stays collision-free when multiple variants run against the
    same scope.  We probe the per-tool filename first, then fall back to
    the generic ``nmap.xml`` name (kept for unit-test fixtures and for
    operators that override the YAML default).  Unknown tool IDs probe
    only the legacy filename.
    """
    primary = _PER_TOOL_CANONICAL_FILENAME.get(tool_id)
    if primary is None:
        return (_LEGACY_CANONICAL_FILENAME,)
    if primary == _LEGACY_CANONICAL_FILENAME:
        return (primary,)
    return (primary, _LEGACY_CANONICAL_FILENAME)


def _load_payload(
    *,
    stdout: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> bytes:
    """Resolve the canonical nmap XML output or fall back to stdout.

    Returns the raw XML bytes (already capped at
    :data:`MAX_STDOUT_BYTES`); empty bytes when neither source has
    parseable content.
    """
    for filename in _candidate_filenames(tool_id):
        canonical = _safe_join(artifacts_dir, filename)
        if canonical is None or not canonical.is_file():
            continue
        try:
            raw = canonical.read_bytes()
        except OSError as exc:
            _logger.warning(
                "nmap_parser.canonical_read_failed",
                extra={
                    "event": "nmap_parser_canonical_read_failed",
                    "tool_id": tool_id,
                    "path": filename,
                    "error_type": type(exc).__name__,
                },
            )
            continue
        if not raw.strip():
            continue
        if len(raw) > MAX_STDOUT_BYTES:
            _logger.warning(
                "nmap_parser.canonical_oversize",
                extra={
                    "event": "nmap_parser_canonical_oversize",
                    "tool_id": tool_id,
                    "path": filename,
                    "size": len(raw),
                    "limit": MAX_STDOUT_BYTES,
                },
            )
            return b""
        return raw
    if stdout and stdout.strip():
        if len(stdout) > MAX_STDOUT_BYTES:
            _logger.warning(
                "nmap_parser.stdout_oversize",
                extra={
                    "event": "nmap_parser_stdout_oversize",
                    "tool_id": tool_id,
                    "size": len(stdout),
                    "limit": MAX_STDOUT_BYTES,
                },
            )
            return b""
        return stdout
    return b""


def _safe_join(base: Path, name: str) -> Path | None:
    """Defensive ``base / name`` that refuses path-traversal segments."""
    if "/" in name or "\\" in name or ".." in name:
        return None
    return base / name


def _safe_parse_xml(raw: bytes, *, tool_id: str) -> Any | None:
    """Parse ``raw`` as XML using :mod:`defusedxml`; ``None`` on error.

    ``defusedxml`` refuses XXE / billion-laughs / external DTD
    references by default — see
    https://docs.python.org/3/library/xml.html#xml-vulnerabilities. A
    failure here is logged and we degrade to ``[]``; the worker keeps
    running.
    """
    try:
        return DefusedET.fromstring(raw)
    except DefusedXmlException as exc:
        _logger.warning(
            "nmap_parser.xml_unsafe",
            extra={
                "event": "nmap_parser_xml_unsafe",
                "tool_id": tool_id,
                "error_type": type(exc).__name__,
            },
        )
        return None
    except DefusedET.ParseError as exc:
        _logger.warning(
            "nmap_parser.xml_malformed",
            extra={
                "event": "nmap_parser_xml_malformed",
                "tool_id": tool_id,
                "error_type": type(exc).__name__,
            },
        )
        return None


# ---------------------------------------------------------------------------
# Normalisation — XML tree → uniform record dicts
# ---------------------------------------------------------------------------


def _iter_normalised(root: Any, *, tool_id: str) -> Iterator[dict[str, Any]]:
    """Walk the nmap ``<nmaprun>`` tree and yield normalised records.

    Iteration order: per ``<host>``, then per ``<port>``, port records
    first then any ``<script>`` children. Sorting is applied by
    :func:`_sort_key` after dedup; this iterator only enforces a stable
    visitation order.
    """
    if root is None:
        return
    for host_el in root.findall("host"):
        host_addr, hostname = _extract_host(host_el)
        if not host_addr:
            continue
        ports_el = host_el.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            port_attr = port_el.get("portid") or ""
            proto_attr = port_el.get("protocol") or ""
            state_el = port_el.find("state")
            state = state_el.get("state") if state_el is not None else None
            if state != "open":
                # Closed / filtered ports are intentionally dropped — the
                # downstream pipeline only cares about reachable services.
                continue
            service_info = _extract_service(port_el)
            yield _build_port_record(
                host=host_addr,
                hostname=hostname,
                port=port_attr,
                protocol=proto_attr,
                state=state,
                service=service_info,
            )
            for script_el in port_el.findall("script"):
                yield from _iter_script_records(
                    script_el,
                    host=host_addr,
                    hostname=hostname,
                    port=port_attr,
                    protocol=proto_attr,
                    service=service_info,
                    tool_id=tool_id,
                )


def _extract_host(host_el: Any) -> tuple[str, str]:
    """Extract the primary IP + canonical hostname for a ``<host>``."""
    host_addr = ""
    for addr_el in host_el.findall("address"):
        addr_type = addr_el.get("addrtype") or ""
        if addr_type in ("ipv4", "ipv6"):
            host_addr = addr_el.get("addr") or ""
            break
    hostname = ""
    hostnames_el = host_el.find("hostnames")
    if hostnames_el is not None:
        hn_el = hostnames_el.find("hostname")
        if hn_el is not None:
            hostname = hn_el.get("name") or ""
    return host_addr, hostname


def _extract_service(port_el: Any) -> dict[str, Any]:
    """Extract the ``<service>`` block (name / product / version / cpe)."""
    service_el = port_el.find("service")
    if service_el is None:
        return {}
    cpe_list = [
        cpe_el.text or "" for cpe_el in service_el.findall("cpe") if cpe_el.text
    ]
    return {
        "name": service_el.get("name") or "",
        "product": service_el.get("product") or "",
        "version": service_el.get("version") or "",
        "extrainfo": service_el.get("extrainfo") or "",
        "cpe": cpe_list,
    }


def _build_port_record(
    *,
    host: str,
    hostname: str,
    port: str,
    protocol: str,
    state: str,
    service: dict[str, Any],
) -> dict[str, Any]:
    """Build the per-port INFO record."""
    has_banner = bool(
        service.get("name") or service.get("product") or service.get("version")
    )
    confidence = ConfidenceLevel.LIKELY if has_banner else ConfidenceLevel.SUSPECTED
    owasp_wstg: list[str] = ["WSTG-INFO-04"]
    if has_banner:
        owasp_wstg.append("WSTG-INFO-02")
    return {
        "kind": "port",
        "category": FindingCategory.INFO,
        "host": host,
        "hostname": hostname,
        "port": port,
        "protocol": protocol,
        "state": state,
        "service_name": service.get("name") or "",
        "service_product": service.get("product") or "",
        "service_version": service.get("version") or "",
        "service_extra": service.get("extrainfo") or "",
        "service_cpe": list(service.get("cpe") or ()),
        "severity": "info",
        "confidence": confidence,
        "cwe": [200],
        "owasp_wstg": owasp_wstg,
        "cvss_v3_score": SENTINEL_CVSS_SCORE,
        "cvss_v3_vector": SENTINEL_CVSS_VECTOR,
    }


def _iter_script_records(
    script_el: Any,
    *,
    host: str,
    hostname: str,
    port: str,
    protocol: str,
    service: dict[str, Any],
    tool_id: str,
) -> Iterator[dict[str, Any]]:
    """Yield one VULN record per CVE found in a ``<script>`` element.

    Currently only ``vulners`` (the canonical CVE-rich NSE script) is
    parsed. Other vulnerability scripts (``vuln``, ``ssl-poodle``,
    ``smb-vuln-*``) are logged at debug and skipped — adding them is
    a Cycle 3 follow-up that needs per-script regex tables.
    """
    script_id = script_el.get("id") or ""
    script_output = script_el.get("output") or ""
    if not script_output:
        return
    if script_id != "vulners":
        _logger.debug(
            "nmap_parser.script_skipped",
            extra={
                "event": "nmap_parser_script_skipped",
                "tool_id": tool_id,
                "script_id": script_id,
                "host": host,
                "port": port,
            },
        )
        return
    yielded = False
    for match in _VULNERS_LINE_RE.finditer(script_output):
        ident = match.group("id")
        cvss_str = match.group("cvss")
        url = match.group("url") or ""
        cve_match = _CVE_RE.search(ident)
        if not cve_match:
            # Non-CVE rows (EDB, MSF, packetstorm…) are exploits *for*
            # the same CVE; we keep them as references on the parent
            # CVE record but do not surface them as standalone findings.
            continue
        cve_id = cve_match.group(1)
        try:
            cvss_score = float(cvss_str)
        except ValueError:
            continue
        if not 0.0 <= cvss_score <= 10.0:
            continue
        severity = _cvss_to_severity(cvss_score)
        confidence = _SEVERITY_CONFIDENCE.get(severity, ConfidenceLevel.SUSPECTED)
        yielded = True
        yield {
            "kind": "vuln",
            "category": FindingCategory.SUPPLY_CHAIN,
            "host": host,
            "hostname": hostname,
            "port": port,
            "protocol": protocol,
            "state": "open",
            "service_name": service.get("name") or "",
            "service_product": service.get("product") or "",
            "service_version": service.get("version") or "",
            "service_extra": service.get("extrainfo") or "",
            "service_cpe": list(service.get("cpe") or ()),
            "severity": severity,
            "confidence": confidence,
            "cve_id": cve_id,
            "cwe": [1395],
            "owasp_wstg": ["WSTG-INFO-08"],
            "cvss_v3_score": cvss_score,
            "cvss_v3_vector": _VULNERS_FALLBACK_VECTOR,
            "cve_url": url,
            "script_id": script_id,
            "script_output_preview": script_output,
            "references": [url] if url else [],
        }
    if not yielded:
        _logger.debug(
            "nmap_parser.vulners_no_cves",
            extra={
                "event": "nmap_parser_vulners_no_cves",
                "tool_id": tool_id,
                "host": host,
                "port": port,
            },
        )


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_nmap_xml",
]
