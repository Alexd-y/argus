"""Parser for ``censys`` CLI JSON output (ARG-032 batch 4c).

The ``censys search ... --output /out/censys.json`` command serialises a
list of host records.  Canonical record shape (Censys v2 search API)::

    {
      "ip": "10.0.0.1",
      "services": [
        {
          "port": 443,
          "service_name": "HTTP",
          "transport_protocol": "TCP",
          "tls": {"certificates": {"leaf_data": {"subject_dn": "CN=example.com"}}},
          "extended_service_name": "HTTPS",
          "software": [{"vendor": "nginx", "product": "nginx", "version": "1.18.0"}]
        }
      ],
      "location": {"country": "US"},
      "autonomous_system": {"asn": 64500, "name": "ExampleAS"}
    }

Findings:

* One INFO finding per ``(ip, port, service_name)`` tuple.  The
  software record is folded into the evidence so downstream
  enrichment can pivot on technology fingerprint.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
    stable_hash_12,
)
from src.sandbox.parsers._jsonl_base import (
    load_canonical_or_stdout_json,
    persist_jsonl_sidecar,
)
from src.sandbox.parsers._text_base import scrub_evidence_strings

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "censys_findings.jsonl"
_CANONICAL_NAME: Final[str] = "censys.json"
_MAX_FINDINGS: Final[int] = 5_000


_DedupKey: TypeAlias = tuple[str, int, str]


def parse_censys(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate Censys CLI JSON output into INFO FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_NAME,
        tool_id=tool_id,
    )
    records = _coerce_records(payload)
    if not records:
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for record in records:
        for normalised in _iter_services(record):
            ip = str(normalised["ip"])
            service_name = str(normalised["service"])
            port_value = normalised["port"]
            if not isinstance(port_value, int):
                continue
            key: _DedupKey = (ip, port_value, service_name)
            if key in seen:
                continue
            seen.add(key)
            finding = _build_finding()
            evidence = _build_evidence(normalised, tool_id=tool_id)
            keyed.append((key, finding, evidence))
            if len(keyed) >= _MAX_FINDINGS:
                _logger.warning(
                    "censys.cap_reached",
                    extra={
                        "event": "censys_cap_reached",
                        "tool_id": tool_id,
                        "cap": _MAX_FINDINGS,
                    },
                )
                break
        if len(keyed) >= _MAX_FINDINGS:
            break

    keyed.sort(key=lambda item: item[0])
    if keyed:
        persist_jsonl_sidecar(
            artifacts_dir,
            sidecar_name=EVIDENCE_SIDECAR_NAME,
            evidence_records=[blob for _, _, blob in keyed],
            tool_id=tool_id,
        )
    return [finding for _, finding, _ in keyed]


def _coerce_records(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        nested = payload.get("hits") or payload.get("results")
        if isinstance(nested, list):
            return [r for r in nested if isinstance(r, dict)]
        return [payload]
    return []


def _iter_services(record: dict[str, Any]) -> Iterator[dict[str, object]]:
    raw_ip = record.get("ip")
    if not isinstance(raw_ip, str) or not raw_ip:
        return
    services = record.get("services")
    if not isinstance(services, list):
        return
    raw_asn = record.get("autonomous_system")
    asn: dict[str, Any] = raw_asn if isinstance(raw_asn, dict) else {}
    raw_location = record.get("location")
    location: dict[str, Any] = raw_location if isinstance(raw_location, dict) else {}
    for svc in services:
        if not isinstance(svc, dict):
            continue
        port = svc.get("port")
        if not isinstance(port, int):
            continue
        service_name = svc.get("extended_service_name") or svc.get("service_name")
        if not isinstance(service_name, str) or not service_name:
            continue
        raw_software = svc.get("software")
        software: list[Any] = raw_software if isinstance(raw_software, list) else []
        software_summary: list[dict[str, str]] = []
        for entry in software:
            if not isinstance(entry, dict):
                continue
            product = entry.get("product")
            version = entry.get("version")
            if isinstance(product, str) and product:
                software_summary.append(
                    {
                        "product": product,
                        "version": version if isinstance(version, str) else "",
                    }
                )
        transport = svc.get("transport_protocol")
        asn_value = asn.get("asn")
        as_name = asn.get("name")
        country = location.get("country")
        yield {
            "ip": raw_ip,
            "port": port,
            "service": service_name,
            "transport": transport if isinstance(transport, str) else "",
            "asn": asn_value if isinstance(asn_value, int) else 0,
            "as_name": as_name if isinstance(as_name, str) else "",
            "country": country if isinstance(country, str) else "",
            "software": software_summary,
        }


def _build_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200, 668],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-INFO-02", "WSTG-INFO-08"],
    )


def _build_evidence(record: dict[str, object], *, tool_id: str) -> str:
    payload: dict[str, object] = {
        "tool_id": tool_id,
        "ip": record["ip"],
        "port": record["port"],
        "service": record["service"],
        "transport": record["transport"],
        "asn": record["asn"],
        "as_name": record["as_name"],
        "country": record["country"],
        "software": record["software"],
        "fingerprint_hash": stable_hash_12(
            f"censys|{record['ip']}|{record['port']}|{record['service']}"
        ),
    }
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_censys",
]
