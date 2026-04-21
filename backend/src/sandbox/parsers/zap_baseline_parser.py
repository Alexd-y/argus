"""Parser for ``zap-baseline.py`` JSON report (Backlog §4.8 — ARG-029).

OWASP ZAP's baseline scan emits three artefacts (JSON, HTML, XML); we
parse the JSON one — its canonical structure is::

    {
      "@version": "2.14.0",
      "@generated": "Mon, 19 May 2025 10:00:00",
      "site": [
        {
          "@name":  "https://target.example.com",
          "alerts": [
            {
              "pluginid": "10202",
              "alertRef": "10202-1",
              "alert":    "Absence of Anti-CSRF Tokens",
              "name":     "Absence of Anti-CSRF Tokens",
              "riskcode": "1",
              "riskdesc": "Low (Medium)",
              "confidence": "2",
              "cweid":    "352",
              "wascid":   "9",
              "instances": [
                {
                  "uri":    "https://target.example.com/login",
                  "method": "GET",
                  "param":  "",
                  "evidence": "<form action=...>"
                }
              ],
              "desc":      "<p>No Anti-CSRF tokens were found ...</p>",
              "solution":  "<p>Use a CSRF synchroniser token...</p>",
              "reference": "https://owasp.org/...",
              "sourceid":  "3"
            }
          ]
        }
      ]
    }

Translation rules
-----------------

* ``riskcode`` (0 informational, 1 low, 2 medium, 3 high) drives the
  category default + base CVSS v3 score (mapped through
  ``_RISK_TO_SEVERITY`` / ``_SEVERITY_TO_CVSS``).
* ``confidence`` (0 false-positive, 1 low, 2 medium, 3 high, 4 user
  confirmed) is normalised to :class:`ConfidenceLevel` — false-positive
  alerts are dropped entirely (they are noise the operator already
  marked).
* ``cweid`` is parsed defensively (ZAP sometimes emits ``"-1"`` or
  ``""``) and folded into the FindingDTO.cwe list.
* ``alert`` keywords route the finding into the most specific ARGUS
  category (XSS / SQLi / SSRF / Open Redirect / CSRF / Info / Crypto /
  Misconfig) when the cweid is missing or generic.

Each ``(alert × instance)`` pair becomes a separate FindingDTO so the
operator can triage per URL without losing context.  De-duplication is
keyed on ``(pluginid, uri, method, param)``.

Sidecar lives at ``artifacts_dir / "zap_baseline_findings.jsonl"`` and
strips the noisy raw HTML description / solution down to a short
plain-text preview.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Iterator
from html.parser import HTMLParser
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
)
from src.sandbox.parsers._jsonl_base import (
    load_canonical_or_stdout_json,
    persist_jsonl_sidecar,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "zap_baseline_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "zap_baseline.json"
_MAX_FINDINGS: Final[int] = 5_000
_MAX_DESC_PREVIEW: Final[int] = 280


_RISK_TO_SEVERITY: Final[dict[str, str]] = {
    "0": "info",
    "1": "low",
    "2": "medium",
    "3": "high",
}


_CONFIDENCE_TO_LEVEL: Final[dict[str, ConfidenceLevel]] = {
    "1": ConfidenceLevel.SUSPECTED,
    "2": ConfidenceLevel.LIKELY,
    "3": ConfidenceLevel.LIKELY,
    "4": ConfidenceLevel.CONFIRMED,
}


_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
}


_SEVERITY_RANK: Final[dict[str, int]] = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


_KEYWORD_CATEGORY: Final[tuple[tuple[str, FindingCategory, tuple[int, ...]], ...]] = (
    ("sql injection", FindingCategory.SQLI, (89,)),
    ("cross-site scripting", FindingCategory.XSS, (79,)),
    ("xss", FindingCategory.XSS, (79,)),
    ("server side request forgery", FindingCategory.SSRF, (918,)),
    ("ssrf", FindingCategory.SSRF, (918,)),
    ("open redirect", FindingCategory.OPEN_REDIRECT, (601,)),
    ("anti-csrf", FindingCategory.CSRF, (352,)),
    ("csrf", FindingCategory.CSRF, (352,)),
    ("clickjack", FindingCategory.MISCONFIG, (1021,)),
    ("x-frame-options", FindingCategory.MISCONFIG, (1021,)),
    ("strict-transport-security", FindingCategory.CRYPTO, (319,)),
    ("hsts", FindingCategory.CRYPTO, (319,)),
    ("cookie no httponly", FindingCategory.MISCONFIG, (1004,)),
    ("cookie no samesite", FindingCategory.MISCONFIG, (1275,)),
    ("cookie without secure", FindingCategory.CRYPTO, (614,)),
    ("information disclosure", FindingCategory.INFO, (200,)),
    ("retrieved from cache", FindingCategory.INFO, (525,)),
    ("server leaks", FindingCategory.INFO, (200,)),
    ("directory browsing", FindingCategory.MISCONFIG, (548,)),
    ("cors", FindingCategory.CORS, (942,)),
    ("content-type", FindingCategory.MISCONFIG, (16,)),
    ("session id", FindingCategory.AUTH, (384,)),
)


_HTML_TAG_RE: Final[re.Pattern[str]] = re.compile(r"<[^>]+>")
_WHITESPACE_RE: Final[re.Pattern[str]] = re.compile(r"\s+")


DedupKey: TypeAlias = tuple[str, str, str, str]


class _HTMLStripper(HTMLParser):
    """Minimal HTML→text converter for ZAP descriptions."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._chunks: list[str] = []

    def handle_data(self, data: str) -> None:
        self._chunks.append(data)

    def text(self) -> str:
        return "".join(self._chunks)


def parse_zap_baseline_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate ZAP baseline JSON into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    if not isinstance(payload, dict):
        if payload is not None:
            _logger.warning(
                "zap_baseline_parser.envelope_not_object",
                extra={
                    "event": "zap_baseline_parser_envelope_not_object",
                    "tool_id": tool_id,
                    "actual_type": type(payload).__name__,
                },
            )
        return []
    records = list(_iter_records(payload, tool_id=tool_id))
    if not records:
        return []
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    seen: set[DedupKey] = set()
    keyed: list[tuple[tuple[int, str, str, str], FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (
            str(record.get("pluginid") or ""),
            str(record.get("uri") or ""),
            str(record.get("method") or ""),
            str(record.get("param") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            -_SEVERITY_RANK.get(str(record.get("severity") or "info"), 0),
            str(record.get("pluginid") or ""),
            str(record.get("uri") or ""),
            str(record.get("param") or ""),
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "zap_baseline_parser.cap_reached",
                extra={
                    "event": "zap_baseline_parser_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
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


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    category: FindingCategory = record.get("_category", FindingCategory.MISCONFIG)
    cwes = list(record.get("_cwes") or [])
    if not cwes:
        cwes = [16]
    severity = str(record.get("severity") or "info")
    confidence: ConfidenceLevel = record.get("_confidence", ConfidenceLevel.LIKELY)
    return make_finding_dto(
        category=category,
        cwe=cwes,
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=_SEVERITY_TO_CVSS.get(severity, 0.0),
        confidence=confidence,
        owasp_wstg=["WSTG-CONF-04", "WSTG-CONF-07", "WSTG-INFO-08"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "pluginid": record.get("pluginid"),
        "alert": record.get("alert"),
        "site": record.get("site"),
        "uri": record.get("uri"),
        "method": record.get("method"),
        "param": record.get("param"),
        "severity": record.get("severity"),
        "confidence": record.get("confidence_label"),
        "cweid": record.get("cweid"),
        "description": record.get("description_preview"),
        "solution": record.get("solution_preview"),
        "evidence": record.get("evidence"),
        "reference": record.get("reference"),
    }
    cleaned: dict[str, Any] = {
        key: value
        for key, value in payload.items()
        if value is not None and value != ""
    }
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _iter_records(payload: dict[str, Any], *, tool_id: str) -> Iterable[dict[str, Any]]:
    sites = payload.get("site")
    if not isinstance(sites, list):
        return
    for site in sites:
        if not isinstance(site, dict):
            continue
        site_name = _string_field(site, "@name") or _string_field(site, "name")
        alerts = site.get("alerts")
        if not isinstance(alerts, list):
            continue
        for alert_index, alert in enumerate(alerts):
            if not isinstance(alert, dict):
                _logger.debug(
                    "zap_baseline_parser.alert_not_object",
                    extra={
                        "event": "zap_baseline_parser_alert_not_object",
                        "tool_id": tool_id,
                        "site": site_name,
                        "index": alert_index,
                    },
                )
                continue
            normalised = _normalise_alert(alert, site_name=site_name)
            if normalised is None:
                continue
            yield from _expand_instances(normalised, alert)


def _normalise_alert(
    alert: dict[str, Any], *, site_name: str | None
) -> dict[str, Any] | None:
    riskcode = _string_field(alert, "riskcode") or "0"
    confidence_raw = _string_field(alert, "confidence") or "2"
    if confidence_raw == "0":
        return None
    severity = _RISK_TO_SEVERITY.get(riskcode, "info")
    confidence = _CONFIDENCE_TO_LEVEL.get(confidence_raw, ConfidenceLevel.LIKELY)
    title = _string_field(alert, "alert") or _string_field(alert, "name") or "ZAP alert"
    cweid_raw = _string_field(alert, "cweid")
    cweid = _coerce_cwe(cweid_raw)
    category, default_cwes = _classify(title, cweid=cweid)
    cwes: tuple[int, ...] = (cweid,) if cweid is not None else default_cwes
    description_preview = _strip_html(_string_field(alert, "desc"))
    solution_preview = _strip_html(_string_field(alert, "solution"))
    return {
        "pluginid": _string_field(alert, "pluginid"),
        "alert": title,
        "site": site_name,
        "severity": severity,
        "confidence_label": confidence.value,
        "cweid": cweid,
        "description_preview": description_preview,
        "solution_preview": solution_preview,
        "reference": _string_field(alert, "reference"),
        "_category": category,
        "_cwes": cwes,
        "_confidence": confidence,
    }


def _expand_instances(
    base: dict[str, Any], alert: dict[str, Any]
) -> Iterable[dict[str, Any]]:
    instances = alert.get("instances")
    if not isinstance(instances, list) or not instances:
        yield {**base, "uri": None, "method": None, "param": None, "evidence": None}
        return
    for instance in instances:
        if not isinstance(instance, dict):
            continue
        yield {
            **base,
            "uri": _string_field(instance, "uri"),
            "method": _string_field(instance, "method"),
            "param": _string_field(instance, "param"),
            "evidence": _strip_html(_string_field(instance, "evidence")),
        }


def _classify(
    title: str, *, cweid: int | None
) -> tuple[FindingCategory, tuple[int, ...]]:
    lowered = title.lower()
    for keyword, category, default_cwes in _KEYWORD_CATEGORY:
        if keyword in lowered:
            return category, default_cwes
    if cweid is not None:
        return FindingCategory.MISCONFIG, ()
    return FindingCategory.MISCONFIG, (16,)


def _coerce_cwe(raw: str | None) -> int | None:
    if raw is None:
        return None
    try:
        value = int(raw)
    except ValueError:
        return None
    if value <= 0:
        return None
    return value


def _strip_html(value: str | None) -> str | None:
    if value is None:
        return None
    if "<" not in value and "&" not in value:
        cleaned = _WHITESPACE_RE.sub(" ", value).strip()
        return _truncate(cleaned)
    parser = _HTMLStripper()
    try:
        parser.feed(value)
        parser.close()
    except Exception:
        text = _HTML_TAG_RE.sub(" ", value)
    else:
        text = parser.text()
    cleaned = _WHITESPACE_RE.sub(" ", text).strip()
    return _truncate(cleaned)


def _truncate(value: str) -> str:
    if len(value) <= _MAX_DESC_PREVIEW:
        return value
    return value[:_MAX_DESC_PREVIEW] + "…"


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_zap_baseline_json",
]


def _typecheck_iterator() -> None:  # pragma: no cover - mypy seam
    _: Iterator[dict[str, Any]] = iter([])
    del _
