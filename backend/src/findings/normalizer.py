"""Tool output normaliser.

Translates raw bytes from a sandbox tool run into a deduplicated list of
strict :class:`FindingDTO` objects. Dispatch is keyed on the canonical
:class:`src.sandbox.adapter_base.ParseStrategy` enum so the normaliser and
tool descriptors share a single source of truth for output formats.

Supported strategies:

* ``JSON_LINES`` — one JSON object per line (``ndjson``)
* ``JSON_OBJECT`` — one root JSON document
* ``XML_NMAP`` — nmap's XML output (stdlib ElementTree, no lxml)
* ``NUCLEI_JSONL`` — nuclei's JSONL output (specialised over JSON_LINES)
* ``CSV`` — comma-separated rows with a header
* ``TEXT_LINES`` — regex-based fallback for unstructured stdout
* ``JSON_GENERIC`` — best-effort parse of an unknown JSON shape

Strategies are pure functions ``(raw_bytes, ctx) -> list[NormalizedFinding]``.
The ``Normalizer`` lifts those into :class:`FindingDTO` and deduplicates by
``sha256(asset_id|category|root_cause_hash|parameter)`` so reruns are
idempotent across the same scan.

Security notes
--------------
* XML parsing uses :mod:`xml.etree.ElementTree` from stdlib only — no
  ``lxml`` (which has multiple historical XXE / XML-bomb CVEs). Stdlib's
  default parser does NOT expand external entities; we further bound the
  input length so an oversized blob cannot exhaust memory.
* CSV parsing uses :class:`csv.DictReader` over an in-memory string buffer;
  no shell expansion, no file I/O.
* No regex from raw output is ever evaluated as code; every match is just
  string extraction.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import logging
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import urlparse
from uuid import UUID, uuid5
from xml.etree import ElementTree as ET  # noqa: N817 - stdlib alias is conventional

from src.core.observability import record_finding_emitted
from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    SSVCDecision,
)
from src.sandbox.adapter_base import ParseStrategy

if TYPE_CHECKING:
    from src.findings.enrichment import FindingEnricher


_logger = logging.getLogger(__name__)


def _severity_from_cvss(score: float) -> str:
    """Map a CVSS v3/v4 score to the ``severity`` label used by metrics."""
    if score <= 0.0:
        return "info"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _emit_finding_metric(dto: FindingDTO) -> None:
    """ARG-041 — emit ``argus_findings_emitted_total`` for one finding.

    Wrapped in a single try/except so a metric failure NEVER blocks the
    finding pipeline. ``tier`` is hardcoded to ``"midgard"`` because the
    normalizer always emits the canonical (untransformed) tier; tier
    classification happens later in the report renderer.
    """
    try:
        kev = bool(getattr(dto, "kev_listed", False))
        severity = _severity_from_cvss(float(getattr(dto, "cvss_v3_score", 0.0)))
        record_finding_emitted(tier="midgard", severity=severity, kev_listed=kev)
    except Exception:  # pragma: no cover — defensive
        _logger.debug("normalizer.metrics_emit_failed", exc_info=True)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


# Bound XML input to avoid memory exhaustion (nmap output for typical recon
# scans is well under 1 MB; we cap at 50 MB to leave headroom for full-port
# scans across /24 ranges).
_MAX_XML_BYTES: Final[int] = 50 * 1024 * 1024
_MAX_TEXT_BYTES: Final[int] = 25 * 1024 * 1024
_MAX_JSON_BYTES: Final[int] = 25 * 1024 * 1024


# Default CWE assignment per finding category (used when the tool does not
# emit an explicit CWE). Keep this map small + closed; new categories MUST
# be added explicitly.
_DEFAULT_CWE_BY_CATEGORY: Final[dict[FindingCategory, int]] = {
    FindingCategory.SQLI: 89,
    FindingCategory.XSS: 79,
    FindingCategory.RCE: 94,
    FindingCategory.LFI: 22,
    FindingCategory.SSRF: 918,
    FindingCategory.SSTI: 1336,
    FindingCategory.XXE: 611,
    FindingCategory.NOSQLI: 943,
    FindingCategory.LDAPI: 90,
    FindingCategory.CMDI: 78,
    FindingCategory.OPEN_REDIRECT: 601,
    FindingCategory.CSRF: 352,
    FindingCategory.CORS: 942,
    FindingCategory.AUTH: 287,
    FindingCategory.IDOR: 639,
    FindingCategory.JWT: 345,
    FindingCategory.MISCONFIG: 16,
    FindingCategory.INFO: 200,
    FindingCategory.SUPPLY_CHAIN: 829,
    FindingCategory.CRYPTO: 327,
    FindingCategory.SECRET_LEAK: 798,
    FindingCategory.DOS: 400,
    FindingCategory.OTHER: 200,
}


# Severity strings to FindingDTO defaults. Tools use varied vocab (e.g.
# nuclei: info/low/medium/high/critical, nmap NSE: info/warning/critical).
_SEVERITY_TO_CVSS: Final[dict[str, tuple[str, float]]] = {
    "info": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    "informational": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    "unknown": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    "low": ("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 3.1),
    "medium": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4),
    "moderate": ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4),
    "high": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", 8.2),
    "critical": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
}


_NAMESPACE_FINDING: Final[UUID] = UUID("c9a47540-2c8d-4b3f-9c14-1f5a0c9d1234")


# ---------------------------------------------------------------------------
# DTOs / context
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NormalizationContext:
    """Per-tool-run identity carried alongside parsed findings."""

    tool_run_id: UUID
    tool_id: str
    tenant_id: UUID
    scan_id: UUID
    asset_id: UUID


@dataclass(frozen=True)
class NormalizedFinding:
    """Intermediate representation produced by a parse strategy."""

    category: FindingCategory
    cwe: tuple[int, ...]
    title: str
    description: str
    severity: str
    raw_payload_hash: str
    asset_url: str | None
    parameter: str | None
    root_cause_hash: str
    cve_ids: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Strategy registry
# ---------------------------------------------------------------------------


_StrategyFn = Callable[[bytes, NormalizationContext], list[NormalizedFinding]]


def _strategy_json_lines(
    raw: bytes, ctx: NormalizationContext
) -> list[NormalizedFinding]:
    """Parse one JSON object per non-empty line."""
    text = _safe_decode(raw, _MAX_JSON_BYTES)
    if not text:
        return []
    out: list[NormalizedFinding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            _logger.warning(
                "normalizer.json_lines.malformed",
                extra={
                    "event": "normalizer_json_lines_malformed",
                    "tool_id": ctx.tool_id,
                    "line_no": line_no,
                },
            )
            continue
        if isinstance(payload, dict):
            out.extend(_finding_from_generic_dict(payload, ctx, source="json_lines"))
    return out


def _strategy_json(raw: bytes, ctx: NormalizationContext) -> list[NormalizedFinding]:
    """Parse one JSON document; flatten common top-level shapes."""
    text = _safe_decode(raw, _MAX_JSON_BYTES)
    if not text:
        return []
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        _logger.warning(
            "normalizer.json.malformed",
            extra={"event": "normalizer_json_malformed", "tool_id": ctx.tool_id},
        )
        return []
    return _findings_from_arbitrary_json(payload, ctx)


def _strategy_nmap_xml(
    raw: bytes, ctx: NormalizationContext
) -> list[NormalizedFinding]:
    """Parse nmap XML; extract one INFO finding per open port."""
    if not raw:
        return []
    if len(raw) > _MAX_XML_BYTES:
        _logger.warning(
            "normalizer.nmap_xml.oversize",
            extra={
                "event": "normalizer_nmap_xml_oversize",
                "tool_id": ctx.tool_id,
                "size": len(raw),
            },
        )
        return []
    try:
        root = ET.fromstring(raw)  # noqa: S314 - stdlib ElementTree is the documented choice
    except ET.ParseError:
        _logger.warning(
            "normalizer.nmap_xml.malformed",
            extra={"event": "normalizer_nmap_xml_malformed", "tool_id": ctx.tool_id},
        )
        return []
    out: list[NormalizedFinding] = []
    for host in root.findall("./host"):
        host_address = _nmap_host_address(host)
        for port in host.findall("./ports/port"):
            state_el = port.find("./state")
            if state_el is None or state_el.get("state") != "open":
                continue
            port_id = port.get("portid") or "?"
            protocol = port.get("protocol") or "tcp"
            service = port.find("./service")
            service_name = service.get("name") if service is not None else "unknown"
            product = service.get("product") if service is not None else None
            version = service.get("version") if service is not None else None
            asset_url = (
                f"{protocol}://{host_address}:{port_id}" if host_address else None
            )
            title = f"Open port {port_id}/{protocol} ({service_name})"
            description_parts: list[str] = []
            if host_address:
                description_parts.append(f"host={host_address}")
            description_parts.append(f"port={port_id}/{protocol}")
            description_parts.append(f"service={service_name}")
            if product:
                description_parts.append(f"product={product}")
            if version:
                description_parts.append(f"version={version}")
            description = "; ".join(description_parts)
            root_cause = (
                f"open_port:{host_address or '?'}:{port_id}/{protocol}:{service_name}"
            )
            out.append(
                NormalizedFinding(
                    category=FindingCategory.INFO,
                    cwe=(_DEFAULT_CWE_BY_CATEGORY[FindingCategory.INFO],),
                    title=title,
                    description=description,
                    severity="info",
                    raw_payload_hash=_sha256_hex(ET.tostring(port)),
                    asset_url=asset_url,
                    parameter=None,
                    root_cause_hash=_sha256_hex(root_cause.encode("utf-8")),
                )
            )
    return out


def _strategy_nuclei_jsonl(
    raw: bytes, ctx: NormalizationContext
) -> list[NormalizedFinding]:
    """Parse nuclei JSONL output (specialised over generic JSON_LINES)."""
    text = _safe_decode(raw, _MAX_JSON_BYTES)
    if not text:
        return []
    out: list[NormalizedFinding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError:
            _logger.warning(
                "normalizer.nuclei.malformed",
                extra={
                    "event": "normalizer_nuclei_malformed",
                    "tool_id": ctx.tool_id,
                    "line_no": line_no,
                },
            )
            continue
        if not isinstance(payload, dict):
            continue
        finding = _finding_from_nuclei_dict(payload, ctx)
        if finding is not None:
            out.append(finding)
    return out


def _strategy_csv(raw: bytes, ctx: NormalizationContext) -> list[NormalizedFinding]:
    """Parse a CSV with a header row using :class:`csv.DictReader`."""
    text = _safe_decode(raw, _MAX_TEXT_BYTES)
    if not text:
        return []
    out: list[NormalizedFinding] = []
    try:
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            if not isinstance(row, dict):
                continue
            cleaned = {
                str(k).strip(): (v if v is not None else "")
                for k, v in row.items()
                if k is not None
            }
            out.extend(_finding_from_generic_dict(cleaned, ctx, source="csv"))
    except csv.Error:
        _logger.warning(
            "normalizer.csv.malformed",
            extra={"event": "normalizer_csv_malformed", "tool_id": ctx.tool_id},
        )
        return []
    return out


_SEVERITY_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(critical|high|medium|moderate|low|info(?:rmational)?)\b", re.IGNORECASE
)
_CWE_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"CWE-(\d{1,5})", re.IGNORECASE)
_CVE_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"CVE-\d{4}-\d{4,7}")
_URL_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"https?://[^\s<>\"]{1,2048}", re.IGNORECASE
)


def _strategy_text(raw: bytes, ctx: NormalizationContext) -> list[NormalizedFinding]:
    """Regex fallback for unstructured stdout."""
    text = _safe_decode(raw, _MAX_TEXT_BYTES)
    if not text:
        return []
    out: list[NormalizedFinding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        sev_match = _SEVERITY_TOKEN_RE.search(stripped)
        cwe_match = _CWE_TOKEN_RE.search(stripped)
        cve_matches = tuple(_CVE_TOKEN_RE.findall(stripped))
        url_match = _URL_TOKEN_RE.search(stripped)
        if not (sev_match or cwe_match or cve_matches or url_match):
            continue
        severity = sev_match.group(1).lower() if sev_match else "info"
        cwe_id = (
            int(cwe_match.group(1))
            if cwe_match
            else _DEFAULT_CWE_BY_CATEGORY[FindingCategory.INFO]
        )
        category = FindingCategory.INFO
        title = stripped[:240]
        description = stripped[:2000]
        asset_url = url_match.group(0) if url_match else None
        root_cause = f"text:{ctx.tool_id}:{line_no}:{stripped[:120]}"
        out.append(
            NormalizedFinding(
                category=category,
                cwe=(cwe_id,),
                title=title,
                description=description,
                severity=severity,
                raw_payload_hash=_sha256_hex(stripped.encode("utf-8")),
                asset_url=asset_url,
                parameter=None,
                root_cause_hash=_sha256_hex(root_cause.encode("utf-8")),
                cve_ids=cve_matches,
            )
        )
    return out


def _strategy_json_generic(
    raw: bytes, ctx: NormalizationContext
) -> list[NormalizedFinding]:
    """Best-effort parse of an unknown JSON document shape."""
    return _strategy_json(raw, ctx)


_STRATEGIES: Final[dict[ParseStrategy, _StrategyFn]] = {
    ParseStrategy.JSON_LINES: _strategy_json_lines,
    ParseStrategy.JSON_OBJECT: _strategy_json,
    ParseStrategy.XML_NMAP: _strategy_nmap_xml,
    ParseStrategy.NUCLEI_JSONL: _strategy_nuclei_jsonl,
    ParseStrategy.CSV: _strategy_csv,
    ParseStrategy.TEXT_LINES: _strategy_text,
    ParseStrategy.JSON_GENERIC: _strategy_json_generic,
}


SUPPORTED_STRATEGIES: Final[frozenset[ParseStrategy]] = frozenset(_STRATEGIES.keys())
"""Subset of :class:`ParseStrategy` values currently dispatched by the normaliser.

Strategies declared by :class:`~src.sandbox.adapter_base.ToolDescriptor` but
absent from this set (e.g. ``BINARY_BLOB``, ``CUSTOM``, ``XML_GENERIC``) are
the responsibility of dedicated adapters added in later cycles and will raise
``ValueError`` when passed to :meth:`Normalizer.normalize`.
"""


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------


class Normalizer:
    """Public entry point for tool-output normalisation.

    ARG-044 — an optional :class:`FindingEnricher` may be injected at
    construction time (or set later via :meth:`set_enricher`). When
    present, :meth:`normalize_with_enrichment` decorates each emitted
    DTO with EPSS / KEV / SSVC fields. The legacy synchronous
    :meth:`normalize` path is unchanged so existing callers (unit tests,
    sync orchestration glue) keep working.
    """

    def __init__(
        self,
        *,
        enricher: "FindingEnricher | None" = None,
    ) -> None:
        self._enricher = enricher
        self._cve_ids_by_finding: dict[str, list[str]] = {}

    def set_enricher(self, enricher: "FindingEnricher | None") -> None:
        """Late-binding setter for the enricher (FastAPI / Celery wiring)."""
        self._enricher = enricher

    def normalize(
        self,
        *,
        tool_run_id: UUID,
        tool_id: str,
        tenant_id: UUID,
        scan_id: UUID,
        asset_id: UUID,
        raw_output: bytes,
        parse_strategy: ParseStrategy,
    ) -> list[FindingDTO]:
        """Parse ``raw_output`` and return a deduplicated list of findings.

        Output is sorted by (category, root_cause_hash, parameter) so callers
        get stable ordering for snapshot tests and DB upserts.

        ARG-044 — the per-finding CVE bag extracted from the raw output is
        cached on ``self._cve_ids_by_finding`` so a follow-up call to
        :meth:`normalize_with_enrichment` can hand it to the enricher.
        """
        if not isinstance(raw_output, (bytes, bytearray)):
            raise TypeError(
                f"raw_output must be bytes-like, got {type(raw_output).__name__}"
            )
        ctx = NormalizationContext(
            tool_run_id=tool_run_id,
            tool_id=tool_id,
            tenant_id=tenant_id,
            scan_id=scan_id,
            asset_id=asset_id,
        )
        strategy_fn = _STRATEGIES.get(parse_strategy)
        if strategy_fn is None:
            raise ValueError(f"unknown parse strategy: {parse_strategy!r}")
        try:
            normalised = strategy_fn(bytes(raw_output), ctx)
        except (json.JSONDecodeError, ET.ParseError, csv.Error, ValueError) as exc:
            _logger.warning(
                "normalizer.strategy_failed",
                extra={
                    "event": "normalizer_strategy_failed",
                    "tool_id": tool_id,
                    "parse_strategy": parse_strategy.value,
                    "error_type": type(exc).__name__,
                },
            )
            return []

        deduped = self._deduplicate(normalised, ctx)
        cve_bag: dict[str, list[str]] = {}
        dtos: list[FindingDTO] = []
        for item in deduped:
            dto = self._to_dto(item, ctx)
            dtos.append(dto)
            if item.cve_ids:
                cve_bag[str(dto.id)] = [c.upper() for c in item.cve_ids]
            _emit_finding_metric(dto)
        self._cve_ids_by_finding = cve_bag
        return dtos

    async def normalize_with_enrichment(
        self,
        *,
        tool_run_id: UUID,
        tool_id: str,
        tenant_id: UUID,
        scan_id: UUID,
        asset_id: UUID,
        raw_output: bytes,
        parse_strategy: ParseStrategy,
    ) -> list[FindingDTO]:
        """Same as :meth:`normalize` but runs the injected enricher.

        Returns the original DTO list unchanged when no enricher is set
        or when enrichment raises (degraded mode — never block the
        pipeline on intel availability).
        """
        dtos = self.normalize(
            tool_run_id=tool_run_id,
            tool_id=tool_id,
            tenant_id=tenant_id,
            scan_id=scan_id,
            asset_id=asset_id,
            raw_output=raw_output,
            parse_strategy=parse_strategy,
        )
        if self._enricher is None or not dtos:
            return dtos
        try:
            return await self._enricher.enrich(
                dtos,
                cve_ids_by_finding=self._cve_ids_by_finding,
            )
        except Exception:
            _logger.warning(
                "normalizer.enrichment_failed",
                extra={
                    "event": "normalizer_enrichment_failed",
                    "tool_id": tool_id,
                },
            )
            return dtos

    def _deduplicate(
        self,
        items: Sequence[NormalizedFinding],
        ctx: NormalizationContext,
    ) -> list[NormalizedFinding]:
        """Collapse duplicates by ``(asset, category, root_cause, parameter)``.

        Order preserved: first occurrence wins. The output is also sorted by
        the dedup key for deterministic downstream consumers.
        """
        seen: dict[str, NormalizedFinding] = {}
        for item in items:
            key = _dedup_key(ctx.asset_id, item)
            if key not in seen:
                seen[key] = item
        return sorted(
            seen.values(),
            key=lambda f: (f.category.value, f.root_cause_hash, f.parameter or ""),
        )

    def _to_dto(self, item: NormalizedFinding, ctx: NormalizationContext) -> FindingDTO:
        """Lift a :class:`NormalizedFinding` into a strict :class:`FindingDTO`."""
        cvss_vector, cvss_score = _SEVERITY_TO_CVSS.get(
            item.severity.lower(),
            _SEVERITY_TO_CVSS["info"],
        )
        finding_id = uuid5(_NAMESPACE_FINDING, _dedup_key(ctx.asset_id, item))
        cwe_list = (
            list(item.cwe) if item.cwe else [_DEFAULT_CWE_BY_CATEGORY[item.category]]
        )
        return FindingDTO(
            id=finding_id,
            tenant_id=ctx.tenant_id,
            scan_id=ctx.scan_id,
            asset_id=ctx.asset_id,
            tool_run_id=ctx.tool_run_id,
            category=item.category,
            cwe=cwe_list,
            cvss_v3_vector=cvss_vector,
            cvss_v3_score=cvss_score,
            ssvc_decision=SSVCDecision.TRACK,
            confidence=ConfidenceLevel.SUSPECTED,
            status=FindingStatus.NEW,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _dedup_key(asset_id: UUID, item: NormalizedFinding) -> str:
    """Deterministic dedup key (Backlog/dev1_md §10)."""
    parameter = item.parameter or ""
    raw = f"{asset_id}|{item.category.value}|{item.root_cause_hash}|{parameter}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sha256_hex(data: bytes) -> str:
    """Return SHA-256 hex digest of ``data``."""
    return hashlib.sha256(data).hexdigest()


def _safe_decode(raw: bytes, limit: int) -> str:
    """Decode bytes as UTF-8 (errors replaced); return empty string on overflow."""
    if not raw:
        return ""
    if len(raw) > limit:
        _logger.warning(
            "normalizer.decode.oversize",
            extra={"event": "normalizer_decode_oversize", "size": len(raw)},
        )
        return ""
    return raw.decode("utf-8", errors="replace")


def _nmap_host_address(host: ET.Element) -> str | None:
    """Return the first ``<address>`` value from an nmap host element."""
    for addr in host.findall("./address"):
        value = addr.get("addr")
        if value:
            return value
    return None


_NUCLEI_SEVERITY_TO_CATEGORY: Final[dict[str, FindingCategory]] = {
    "info": FindingCategory.INFO,
    "low": FindingCategory.MISCONFIG,
    "medium": FindingCategory.MISCONFIG,
    "high": FindingCategory.MISCONFIG,
    "critical": FindingCategory.MISCONFIG,
}


_NUCLEI_TAG_TO_CATEGORY: Final[dict[str, FindingCategory]] = {
    "sqli": FindingCategory.SQLI,
    "sql-injection": FindingCategory.SQLI,
    "xss": FindingCategory.XSS,
    "ssrf": FindingCategory.SSRF,
    "rce": FindingCategory.RCE,
    "lfi": FindingCategory.LFI,
    "xxe": FindingCategory.XXE,
    "ssti": FindingCategory.SSTI,
    "open-redirect": FindingCategory.OPEN_REDIRECT,
    "redirect": FindingCategory.OPEN_REDIRECT,
    "csrf": FindingCategory.CSRF,
    "cors": FindingCategory.CORS,
    "auth": FindingCategory.AUTH,
    "idor": FindingCategory.IDOR,
    "jwt": FindingCategory.JWT,
    "exposure": FindingCategory.SECRET_LEAK,
    "exposed": FindingCategory.SECRET_LEAK,
    "default-login": FindingCategory.AUTH,
    "misconfig": FindingCategory.MISCONFIG,
    "misconfiguration": FindingCategory.MISCONFIG,
}


def _finding_from_nuclei_dict(
    payload: dict[str, Any], ctx: NormalizationContext
) -> NormalizedFinding | None:
    """Build a :class:`NormalizedFinding` from a nuclei JSONL row."""
    template_id_raw = payload.get("template-id") or payload.get("template_id")
    template_id = template_id_raw if isinstance(template_id_raw, str) else "unknown"
    info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
    severity_raw = info.get("severity") if isinstance(info, dict) else None
    severity = severity_raw.lower() if isinstance(severity_raw, str) else "info"
    if severity not in _SEVERITY_TO_CVSS:
        severity = "info"

    name = info.get("name") if isinstance(info, dict) else None
    title = str(name) if isinstance(name, str) and name else f"nuclei:{template_id}"
    matched_at = payload.get("matched-at") or payload.get("matched_at")
    asset_url = matched_at if isinstance(matched_at, str) else None
    matcher_name = payload.get("matcher-name") or payload.get("matcher_name")
    matcher = matcher_name if isinstance(matcher_name, str) else None

    tags_raw = info.get("tags") if isinstance(info, dict) else None
    tags: tuple[str, ...] = ()
    if isinstance(tags_raw, list):
        tags = tuple(t.lower() for t in tags_raw if isinstance(t, str))
    elif isinstance(tags_raw, str):
        tags = tuple(t.strip().lower() for t in tags_raw.split(",") if t.strip())
    category = _category_from_tags(tags) or _NUCLEI_SEVERITY_TO_CATEGORY.get(
        severity, FindingCategory.INFO
    )

    cwe_ids = tuple(_extract_cwe_ids(info))
    cve_ids: tuple[str, ...] = ()
    classification = info.get("classification") if isinstance(info, dict) else None
    if isinstance(classification, dict):
        cve_list = classification.get("cve-id") or classification.get("cve_id")
        if isinstance(cve_list, list):
            cve_ids = tuple(c for c in cve_list if isinstance(c, str))

    root_cause = (
        f"nuclei:{template_id}:{matcher or 'default'}:{asset_url or 'no-target'}"
    )
    description_parts = [f"template={template_id}", f"severity={severity}"]
    if matcher:
        description_parts.append(f"matcher={matcher}")
    if asset_url:
        description_parts.append(f"target={asset_url}")
    description = "; ".join(description_parts)

    return NormalizedFinding(
        category=category,
        cwe=cwe_ids or (_DEFAULT_CWE_BY_CATEGORY[category],),
        title=title[:240],
        description=description[:2000],
        severity=severity,
        raw_payload_hash=_sha256_hex(
            json.dumps(payload, sort_keys=True).encode("utf-8")
        ),
        asset_url=asset_url,
        parameter=_extract_parameter_from_url(asset_url),
        root_cause_hash=_sha256_hex(root_cause.encode("utf-8")),
        cve_ids=cve_ids,
    )


def _category_from_tags(tags: Iterable[str]) -> FindingCategory | None:
    """First-match category lookup from a list of nuclei tags."""
    for tag in tags:
        cat = _NUCLEI_TAG_TO_CATEGORY.get(tag)
        if cat is not None:
            return cat
    return None


def _extract_cwe_ids(info: object) -> list[int]:
    """Extract CWE IDs from a nuclei ``info`` dict."""
    if not isinstance(info, dict):
        return []
    classification = info.get("classification")
    if not isinstance(classification, dict):
        return []
    raw = classification.get("cwe-id") or classification.get("cwe_id")
    if isinstance(raw, str):
        match = re.search(r"\d+", raw)
        return [int(match.group(0))] if match else []
    if isinstance(raw, list):
        out: list[int] = []
        for entry in raw:
            if isinstance(entry, str):
                match = re.search(r"\d+", entry)
                if match:
                    out.append(int(match.group(0)))
            elif isinstance(entry, int):
                out.append(entry)
        return out
    return []


def _extract_parameter_from_url(url: str | None) -> str | None:
    """Extract the first query parameter name from ``url`` (or ``None``)."""
    if not url:
        return None
    try:
        parsed = urlparse(url)
    except ValueError:
        return None
    if not parsed.query:
        return None
    first_pair = parsed.query.split("&", 1)[0]
    name = first_pair.split("=", 1)[0]
    return name or None


_GENERIC_CATEGORY_KEYS: Final[tuple[str, ...]] = (
    "category",
    "type",
    "vuln_type",
    "vulnerability_type",
    "kind",
)
_GENERIC_TITLE_KEYS: Final[tuple[str, ...]] = (
    "title",
    "name",
    "summary",
    "issue",
    "vulnerability",
)
_GENERIC_DESCRIPTION_KEYS: Final[tuple[str, ...]] = (
    "description",
    "details",
    "info",
    "message",
)
_GENERIC_URL_KEYS: Final[tuple[str, ...]] = (
    "url",
    "target",
    "endpoint",
    "matched-at",
    "matched_at",
    "affected_url",
    "host",
)
_GENERIC_SEVERITY_KEYS: Final[tuple[str, ...]] = (
    "severity",
    "risk",
    "level",
)
_GENERIC_PARAM_KEYS: Final[tuple[str, ...]] = (
    "parameter",
    "param",
    "param_name",
    "field",
)


_CATEGORY_TOKENS: Final[dict[str, FindingCategory]] = {
    "sqli": FindingCategory.SQLI,
    "sql injection": FindingCategory.SQLI,
    "sql-injection": FindingCategory.SQLI,
    "xss": FindingCategory.XSS,
    "cross-site scripting": FindingCategory.XSS,
    "rce": FindingCategory.RCE,
    "remote code execution": FindingCategory.RCE,
    "lfi": FindingCategory.LFI,
    "local file inclusion": FindingCategory.LFI,
    "ssrf": FindingCategory.SSRF,
    "ssti": FindingCategory.SSTI,
    "xxe": FindingCategory.XXE,
    "nosqli": FindingCategory.NOSQLI,
    "ldapi": FindingCategory.LDAPI,
    "cmdi": FindingCategory.CMDI,
    "command injection": FindingCategory.CMDI,
    "open redirect": FindingCategory.OPEN_REDIRECT,
    "open-redirect": FindingCategory.OPEN_REDIRECT,
    "csrf": FindingCategory.CSRF,
    "cors": FindingCategory.CORS,
    "auth": FindingCategory.AUTH,
    "idor": FindingCategory.IDOR,
    "jwt": FindingCategory.JWT,
    "misconfig": FindingCategory.MISCONFIG,
    "misconfiguration": FindingCategory.MISCONFIG,
    "info": FindingCategory.INFO,
    "supply-chain": FindingCategory.SUPPLY_CHAIN,
    "supply chain": FindingCategory.SUPPLY_CHAIN,
    "crypto": FindingCategory.CRYPTO,
    "secret": FindingCategory.SECRET_LEAK,
    "secret leak": FindingCategory.SECRET_LEAK,
    "secret-leak": FindingCategory.SECRET_LEAK,
    "dos": FindingCategory.DOS,
}


def _finding_from_generic_dict(
    payload: dict[str, Any], ctx: NormalizationContext, *, source: str
) -> list[NormalizedFinding]:
    """Translate a free-form dict into one or zero :class:`NormalizedFinding`."""
    category = _category_from_dict(payload)
    title = _first_str(payload, _GENERIC_TITLE_KEYS) or f"{ctx.tool_id} finding"
    description = _first_str(payload, _GENERIC_DESCRIPTION_KEYS) or title
    severity_raw = _first_str(payload, _GENERIC_SEVERITY_KEYS) or "info"
    severity = severity_raw.lower()
    if severity not in _SEVERITY_TO_CVSS:
        severity = "info"
    asset_url = _first_str(payload, _GENERIC_URL_KEYS)
    parameter = _first_str(payload, _GENERIC_PARAM_KEYS)
    if parameter is None:
        parameter = _extract_parameter_from_url(asset_url)
    cwe_ids = tuple(_extract_cwe_ids(payload))
    if not cwe_ids:
        cwe_field = payload.get("cwe")
        if isinstance(cwe_field, int):
            cwe_ids = (cwe_field,)
        elif isinstance(cwe_field, str):
            match = re.search(r"\d+", cwe_field)
            if match:
                cwe_ids = (int(match.group(0)),)
        elif isinstance(cwe_field, list):
            extracted: list[int] = []
            for entry in cwe_field:
                if isinstance(entry, int):
                    extracted.append(entry)
                elif isinstance(entry, str):
                    match = re.search(r"\d+", entry)
                    if match:
                        extracted.append(int(match.group(0)))
            cwe_ids = tuple(extracted)

    root_cause = (
        f"{source}:{category.value}:{title[:120]}:{asset_url or ''}:{parameter or ''}"
    )
    payload_blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return [
        NormalizedFinding(
            category=category,
            cwe=cwe_ids or (_DEFAULT_CWE_BY_CATEGORY[category],),
            title=title[:240],
            description=description[:2000],
            severity=severity,
            raw_payload_hash=_sha256_hex(payload_blob),
            asset_url=asset_url,
            parameter=parameter,
            root_cause_hash=_sha256_hex(root_cause.encode("utf-8")),
        )
    ]


def _category_from_dict(payload: dict[str, Any]) -> FindingCategory:
    """Resolve a :class:`FindingCategory` from arbitrary string fields."""
    for key in _GENERIC_CATEGORY_KEYS:
        value = payload.get(key)
        if isinstance(value, str):
            normalised = value.strip().lower()
            cat = _CATEGORY_TOKENS.get(normalised)
            if cat is not None:
                return cat
            try:
                return FindingCategory(normalised)
            except ValueError:
                continue
    title_text = " ".join(str(payload.get(k, "")).lower() for k in _GENERIC_TITLE_KEYS)
    for token, cat in _CATEGORY_TOKENS.items():
        if token in title_text:
            return cat
    return FindingCategory.INFO


def _first_str(payload: dict[str, Any], keys: Iterable[str]) -> str | None:
    """Return the first string value from ``payload`` matching one of ``keys``."""
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _findings_from_arbitrary_json(
    payload: object, ctx: NormalizationContext
) -> list[NormalizedFinding]:
    """Walk an arbitrary JSON shape; emit findings for dict-shaped leaves."""
    if isinstance(payload, dict):
        for key in ("findings", "results", "issues", "vulnerabilities", "alerts"):
            value = payload.get(key)
            if isinstance(value, list):
                out: list[NormalizedFinding] = []
                for entry in value:
                    if isinstance(entry, dict):
                        out.extend(
                            _finding_from_generic_dict(entry, ctx, source="json")
                        )
                return out
        return _finding_from_generic_dict(payload, ctx, source="json")
    if isinstance(payload, list):
        out_list: list[NormalizedFinding] = []
        for entry in payload:
            if isinstance(entry, dict):
                out_list.extend(_finding_from_generic_dict(entry, ctx, source="json"))
        return out_list
    return []


__all__ = [
    "SUPPORTED_STRATEGIES",
    "NormalizationContext",
    "NormalizedFinding",
    "Normalizer",
    "ParseStrategy",
]
