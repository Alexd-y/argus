"""Parser for Nuclei JSONL output (Backlog/dev1_md §4.8 + §4.7 wrappers).

Powers four ARGUS catalog entries that all run ``nuclei -jsonl`` under the
hood:

* ``nuclei``               — flagship template engine; canonical
  ``--target {url} -jsonl -o /out/nuclei.jsonl`` invocation against the
  full Project Discovery template repository.
* ``nextjs_check``         — §4.7 wrapper, ``-tags nextjs`` template
  filter (CVE-2025-29927 middleware bypass + framework misconfigs).
* ``spring_boot_actuator`` — §4.7 wrapper, ``-tags springboot`` filter
  (actuator exposure, env / heapdump leaks, CVE-2022-22965).
* ``jenkins_enum``         — §4.7 wrapper, ``-tags jenkins`` filter
  (script console, unauthenticated exposure, vulnerable plugins).

Every record is a JSON object on its own line with the canonical Nuclei
``-jsonl`` shape (Project Discovery v3+):

.. code-block:: json

    {
      "template-id":  "CVE-2024-12345",
      "template-path":"/templates/cves/2024/CVE-2024-12345.yaml",
      "info": {
        "name":        "Acme Corp Auth Bypass",
        "severity":    "critical",
        "tags":        ["cve", "rce", "auth", "exposure"],
        "classification": {
          "cve-id":   ["CVE-2024-12345"],
          "cwe-id":   ["CWE-287", "CWE-288"],
          "cvss-score": 9.8,
          "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "epss-score": 0.97231
        },
        "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2024-12345"]
      },
      "matcher-status": true,
      "matcher-name":   "auth-bypass-200",
      "host":           "https://target.example",
      "matched-at":     "https://target.example/api/login",
      "request":        "POST /api/login HTTP/1.1\\r\\n...",
      "response":       "HTTP/1.1 200 OK\\r\\nServer: ...\\r\\n..."
    }

Translation rules (per ARG-015 cycle plan):

* **Severity → category**: ``critical`` / ``high`` are tag-driven; the
  parser inspects ``info.tags`` to pick the most relevant
  :class:`~src.pipeline.contracts.finding_dto.FindingCategory` (sqli,
  xss, rce, ssrf, ssti, ldapi, …); falls back to ``MISCONFIG`` for
  exposure-class records and ``INFO`` for ``severity=info``.
* **Severity → confidence**:
  - ``critical`` / ``high`` with ``matcher-status=True`` → ``LIKELY``.
  - ``medium`` with at least one CVE → ``LIKELY``; without → ``SUSPECTED``.
  - ``low`` / ``info`` → ``SUSPECTED``.
  - ``matcher-status=False`` (template ran but did not match) is dropped
    — Nuclei occasionally emits these as discovery-aid records and they
    are not findings.
* **CVE / CWE extraction**: pulled from ``info.classification.cve-id``
  and ``info.classification.cwe-id`` and normalised
  (``CVE-YYYY-NNNN`` / integer CWE id). Top-level ``info.cve`` is
  honoured for legacy templates.
* **CVSS / EPSS**: ``info.classification.cvss-score`` / ``cvss-metrics``
  populate :attr:`FindingDTO.cvss_v3_score` / ``cvss_v3_vector``;
  ``info.classification.epss-score`` populates ``epss_score``. Vectors
  that fail the FindingDTO regex (``CVSS:3.x/...``) degrade to the
  sentinel.
* **References**: pulled from ``info.reference`` and folded into the
  evidence sidecar (no FindingDTO field carries a list of free-text
  references; the downstream Normalizer attaches them via the CVE
  lookup).
* **Evidence**: ``host``, ``matched-at``, ``template-id``, and the
  truncated request / response (capped at 4 KiB each) land in the
  shared sidecar ``nuclei_findings.jsonl``.
* **Dedup key**: ``(template-id, matched-at)`` — the same template
  matching twice on different URLs is two findings; the same template
  matching twice on the same URL (Nuclei retry / duplicate workflow) is
  one.
* **Cap**: hard-limited to :data:`_MAX_FINDINGS = 10_000` so a template
  pack misconfiguration cannot blow up the worker.
* **Failure model**: fail-soft. Malformed JSONL lines are logged via
  ``parsers.jsonl.malformed`` (from :mod:`src.sandbox.parsers._base`)
  and skipped. Empty / oversized payloads return ``[]`` after a
  structured warning. The sidecar write is best-effort (OS errors are
  logged and swallowed).
* **Determinism**: emitted findings + sidecar lines are sorted by the
  dedup key so two runs against the same fixture produce identical
  bytes.

This module is the parser shared by the four Nuclei tool_ids; the
dispatch layer (:mod:`src.sandbox.parsers`) routes them to
:func:`parse_nuclei_jsonl` via ``ParseStrategy.NUCLEI_JSONL``.

Thin Nikto / Wapiti adapters (:func:`parse_nikto_json`,
:func:`parse_wapiti_json`) live next to the Nuclei parser because both
tools also belong to §4.8 and emit a stable JSON shape. Their parsers
collapse onto the shared ``_emit`` pipeline (so dedup / cap / sidecar
behaviour stays uniform across §4.8) and route through
``ParseStrategy.JSON_OBJECT`` per-tool registration.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_SCORE,
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
    safe_load_json,
    safe_load_jsonl,
)

_logger = logging.getLogger(__name__)


def _stable_hash(text: str) -> str:
    """Return a cross-process deterministic 12-char hex digest of ``text``.

    ``hash()`` is randomised per Python interpreter via ``PYTHONHASHSEED``,
    so the same Nikto fixture would produce a different synthesized
    template_id between processes — breaking sidecar byte determinism in
    CI. Anchored on SHA-256 (truncated to 12 hex chars / 48 bits) the
    digest stays constant across interpreters and OSes; collisions are
    cosmetic (sidecar template_id) and 2^48 wide enough for any realistic
    Nikto run.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Public constants — surfaced for tests + downstream evidence pipeline.
# ---------------------------------------------------------------------------


# Single sidecar shared across all four Nuclei-driven tool_ids and the
# minimal Nikto / Wapiti adapters; mirrors the wpscan_parser /
# katana_parser pattern (one filename per parser family).
EVIDENCE_SIDECAR_NAME: Final[str] = "nuclei_findings.jsonl"


# Hard cap on emitted findings. A misconfigured template pack scanning
# a wildcard subdomain target legitimately produces tens of thousands
# of records; capping defends the worker even on a 200 MB stdout.
_MAX_FINDINGS: Final[int] = 10_000


# Hard cap on the bytes we keep from a single ``request`` / ``response``
# string in the evidence sidecar. 4 KiB matches the ARG-015 cycle plan
# guidance and is large enough to retain the request line + header
# block; bodies are intentionally truncated.
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


# CVSS regex — mirrors the FindingDTO contract (``CVSS:[34]\.[0-9]/...``).
# Templates that surface a CVSS:2.0 vector are treated as missing data
# (the FindingDTO would reject them anyway).
_CVSS_VECTOR_PREFIXES: Final[tuple[str, ...]] = ("CVSS:3.", "CVSS:4.")


# ---------------------------------------------------------------------------
# Severity / confidence / category mapping tables.
# ---------------------------------------------------------------------------


# Nuclei severity strings that we recognise. ``unknown`` / ``none`` are
# normalised to ``info`` so a template author who forgot to set the
# severity does not crash the parser.
_NORMALISED_SEVERITY: Final[dict[str, str]] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "unknown": "info",
    "none": "info",
}


# Tag → FindingCategory routing. Walked in priority order so a template
# tagged both ``rce`` and ``exposure`` lands as RCE (the more severe
# class). Exposure / config / panel / misconfig collapse onto MISCONFIG.
# Unknown tags fall through to a severity-driven default.
_TAG_TO_CATEGORY: Final[tuple[tuple[str, FindingCategory], ...]] = (
    ("rce", FindingCategory.RCE),
    ("cmdi", FindingCategory.CMDI),
    ("sqli", FindingCategory.SQLI),
    ("nosqli", FindingCategory.NOSQLI),
    ("ldap-injection", FindingCategory.LDAPI),
    ("ldapi", FindingCategory.LDAPI),
    ("ssti", FindingCategory.SSTI),
    ("ssrf", FindingCategory.SSRF),
    ("xxe", FindingCategory.XXE),
    ("xss", FindingCategory.XSS),
    ("lfi", FindingCategory.LFI),
    ("rfi", FindingCategory.LFI),
    ("path-traversal", FindingCategory.LFI),
    ("open-redirect", FindingCategory.OPEN_REDIRECT),
    ("redirect", FindingCategory.OPEN_REDIRECT),
    ("auth-bypass", FindingCategory.AUTH),
    ("default-login", FindingCategory.AUTH),
    ("idor", FindingCategory.IDOR),
    ("jwt", FindingCategory.JWT),
    ("crypto", FindingCategory.CRYPTO),
    ("secret", FindingCategory.SECRET_LEAK),
    ("token", FindingCategory.SECRET_LEAK),
    ("dos", FindingCategory.DOS),
    ("denial-of-service", FindingCategory.DOS),
    ("cors", FindingCategory.CORS),
    ("csrf", FindingCategory.CSRF),
    ("supply-chain", FindingCategory.SUPPLY_CHAIN),
    ("dependency", FindingCategory.SUPPLY_CHAIN),
    # Generic exposure / misconfig classes — drop-through targets.
    ("exposure", FindingCategory.MISCONFIG),
    ("misconfig", FindingCategory.MISCONFIG),
    ("misconfiguration", FindingCategory.MISCONFIG),
    ("config", FindingCategory.MISCONFIG),
    ("panel", FindingCategory.MISCONFIG),
    ("debug", FindingCategory.MISCONFIG),
    # Discovery / fingerprinting tags — INFO bucket.
    ("tech", FindingCategory.INFO),
    ("technologies", FindingCategory.INFO),
    ("fingerprint", FindingCategory.INFO),
    ("detect", FindingCategory.INFO),
)


# When the tag set yields no concrete bucket the severity drives the
# fallback. ``critical`` / ``high`` without a known tag default to
# MISCONFIG (the common case for "exposed admin endpoint" templates),
# ``low`` and ``info`` collapse to INFO.
_SEVERITY_FALLBACK_CATEGORY: Final[dict[str, FindingCategory]] = {
    "critical": FindingCategory.MISCONFIG,
    "high": FindingCategory.MISCONFIG,
    "medium": FindingCategory.MISCONFIG,
    "low": FindingCategory.INFO,
    "info": FindingCategory.INFO,
}


# CVE-bearing template? → at least LIKELY confidence (the upstream
# tracker accepted the vuln). Otherwise severity-driven.
_SEVERITY_CONFIDENCE: Final[dict[str, ConfidenceLevel]] = {
    "critical": ConfidenceLevel.LIKELY,
    "high": ConfidenceLevel.LIKELY,
    "medium": ConfidenceLevel.SUSPECTED,
    "low": ConfidenceLevel.SUSPECTED,
    "info": ConfidenceLevel.SUSPECTED,
}


# Per-category CWE backstop when the template did not surface a CWE id
# (about half of the public template pack). Anchored on the OWASP / CWE
# top-25 mapping so the FindingDTO never ends up CWE-empty (Pydantic
# requires ``cwe`` to be non-empty).
_CATEGORY_DEFAULT_CWE: Final[dict[FindingCategory, tuple[int, ...]]] = {
    FindingCategory.RCE: (78, 94),
    FindingCategory.CMDI: (78,),
    FindingCategory.SQLI: (89,),
    FindingCategory.NOSQLI: (943,),
    FindingCategory.LDAPI: (90,),
    FindingCategory.SSTI: (1336, 94),
    FindingCategory.SSRF: (918,),
    FindingCategory.XXE: (611,),
    FindingCategory.XSS: (79,),
    FindingCategory.LFI: (22, 73),
    FindingCategory.OPEN_REDIRECT: (601,),
    FindingCategory.AUTH: (287,),
    FindingCategory.IDOR: (639,),
    FindingCategory.JWT: (345, 287),
    FindingCategory.CRYPTO: (327,),
    FindingCategory.SECRET_LEAK: (798, 200),
    FindingCategory.DOS: (400,),
    FindingCategory.CORS: (942,),
    FindingCategory.CSRF: (352,),
    FindingCategory.SUPPLY_CHAIN: (1395,),
    FindingCategory.MISCONFIG: (200, 16),
    FindingCategory.INFO: (200,),
}


# Stable dedup key shape. Module-level alias keeps the signature short
# in the dedup loop and ``_dedup_key`` types.
DedupKey: TypeAlias = tuple[str, str, str]


# ---------------------------------------------------------------------------
# Public entry points — signature mandated by the dispatch layer:
# ``(stdout, stderr, artifacts_dir, tool_id) -> list[FindingDTO]``.
# ---------------------------------------------------------------------------


def parse_nuclei_jsonl(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate a Nuclei JSONL stream into a deduplicated FindingDTO list.

    Resolution order for the JSONL blob:

    1. ``artifacts_dir / "nuclei.jsonl"`` (canonical: every YAML in the
       Nuclei family writes there via ``-output {out_dir}/nuclei.jsonl``).
    2. ``stdout`` fallback — operators sometimes invoke nuclei without
       ``-output`` so the JSONL streams to stdout.

    ``stderr`` is accepted for parser dispatch signature symmetry but
    intentionally not consumed (nuclei emits banners + per-template status
    lines on stderr that are not parser-relevant). The ``tool_id`` is
    stamped on every emitted sidecar record so a single sidecar shared
    across the four Nuclei-driven tool_ids stays demultiplexable.
    """
    del stderr
    raw_jsonl = _resolve_jsonl_payload(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        tool_id=tool_id,
    )
    if not raw_jsonl:
        return []
    records = list(_iter_nuclei_records(raw_jsonl, tool_id=tool_id))
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


def parse_nikto_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate Nikto ``-Format json`` output into a list of FindingDTOs.

    Nikto's JSON envelope is a single top-level object with a
    ``vulnerabilities`` list (canonical: Nikto 2.5+); each entry exposes
    ``id`` / ``OSVDB`` / ``msg`` / ``url`` / ``method``. The parser maps
    every entry onto :class:`FindingCategory.MISCONFIG` (Nikto's bread
    and butter is exposed config files / dangerous methods) with
    ``confidence=SUSPECTED`` (Nikto matches are signature-based and
    historically false-positive-prone).

    Resolution order matches :func:`parse_nuclei_jsonl` (canonical
    ``nikto.json`` first, stdout fallback). ``stderr`` is accepted for
    signature symmetry but not consumed.
    """
    del stderr
    payload = _load_primary_payload(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name="nikto.json",
        tool_id=tool_id,
    )
    if payload is None:
        return []
    records = list(_iter_nikto_records(payload, tool_id=tool_id))
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


def parse_wapiti_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate Wapiti ``-f json`` output into a list of FindingDTOs.

    Wapiti's JSON envelope groups findings by category under a top-level
    ``vulnerabilities`` dict (e.g. ``{"SQL Injection": [...], "Cross
    Site Scripting": [...], "Backup file": [...]}``). The parser maps
    each category to a :class:`FindingCategory` via :data:`_WAPITI_CATEGORY`
    and reads ``info`` / ``method`` / ``path`` / ``parameter`` /
    ``http_request`` / ``http_response`` from each entry.

    Resolution order matches the other §4.8 parsers (canonical
    ``wapiti.json`` first, stdout fallback). ``stderr`` is accepted for
    signature symmetry but not consumed.
    """
    del stderr
    payload = _load_primary_payload(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name="wapiti.json",
        tool_id=tool_id,
    )
    if payload is None:
        return []
    records = list(_iter_wapiti_records(payload, tool_id=tool_id))
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Wapiti category mapping — pinned constant so the routing stays
# greppable and testable.
# ---------------------------------------------------------------------------


_WAPITI_CATEGORY: Final[dict[str, FindingCategory]] = {
    "SQL Injection": FindingCategory.SQLI,
    "Blind SQL Injection": FindingCategory.SQLI,
    "Cross Site Scripting": FindingCategory.XSS,
    "Stored Cross Site Scripting": FindingCategory.XSS,
    "Permanent XSS": FindingCategory.XSS,
    "Reflected Cross Site Scripting": FindingCategory.XSS,
    "Command execution": FindingCategory.RCE,
    "Commands Execution": FindingCategory.RCE,
    "Server Side Request Forgery": FindingCategory.SSRF,
    "Path Traversal": FindingCategory.LFI,
    "File Handling": FindingCategory.LFI,
    "Cross Site Request Forgery": FindingCategory.CSRF,
    "CRLF Injection": FindingCategory.MISCONFIG,
    "HTML Injection": FindingCategory.XSS,
    "Open Redirect": FindingCategory.OPEN_REDIRECT,
    "XML External Entity": FindingCategory.XXE,
    "XXE": FindingCategory.XXE,
    "Backup file": FindingCategory.MISCONFIG,
    "Backup files": FindingCategory.MISCONFIG,
    "Htaccess Bypass": FindingCategory.MISCONFIG,
    "Potentially dangerous file": FindingCategory.MISCONFIG,
    "Internal Server Error": FindingCategory.INFO,
    "Resource consumption": FindingCategory.DOS,
    "Secure Flag cookie": FindingCategory.MISCONFIG,
    "HttpOnly Flag cookie": FindingCategory.MISCONFIG,
    "Content Security Policy Configuration": FindingCategory.MISCONFIG,
    "X-Frame-Options Header": FindingCategory.MISCONFIG,
    "Strict-Transport-Security Header": FindingCategory.CRYPTO,
    "Fingerprint web technology": FindingCategory.INFO,
    "Fingerprint web application framework": FindingCategory.INFO,
}


# Wapiti category → severity bucket. Pinned so a future Wapiti category
# rename does not silently demote an injection finding to the default
# ``medium`` bucket. Categories that are operator-relevant but not
# directly exploitable (fingerprint / informational error pages /
# missing security header) collapse onto ``info`` / ``low``; injection
# / RCE / file disclosure classes climb to ``high`` / ``critical``.
# Anything not listed falls through to ``_WAPITI_DEFAULT_SEVERITY``.
_WAPITI_SEVERITY: Final[dict[str, str]] = {
    # Informational fingerprint / probing surface.
    "Fingerprint web technology": "info",
    "Fingerprint web application framework": "info",
    "Internal Server Error": "info",
    "Buster (DirBuster like)": "info",
    # Missing-header / cookie-flag misconfig — low-impact disclosure
    # without an active exploit primitive.
    "Strict-Transport-Security Header": "low",
    "Backup file": "low",
    "Backup files": "low",
    "Content Security Policy Configuration": "low",
    "Content Security Policy": "low",
    "X-Frame-Options Header": "low",
    "Secure Flag cookie": "low",
    "HttpOnly Flag cookie": "low",
    "Cookie": "low",
    "HTTP Header": "low",
    "Subresource Integrity": "low",
    # Direct injection / exploitation primitives — high or critical.
    "SQL Injection": "high",
    "Blind SQL Injection": "high",
    "Cross Site Scripting": "high",
    "Stored Cross Site Scripting": "high",
    "Permanent XSS": "high",
    "Reflected Cross Site Scripting": "high",
    "HTML Injection": "high",
    "XML External Entity": "high",
    "XXE": "high",
    "Server Side Request Forgery": "high",
    "Path Traversal": "high",
    "File Handling": "high",
    "File disclosure": "high",
    "LDAP Injection": "high",
    "Command execution": "critical",
    "Commands Execution": "critical",
    # Mid-impact request-forgery / bypass surface.
    "Cross Site Request Forgery": "medium",
    "Open Redirect": "medium",
    "Htaccess Bypass": "medium",
    "CRLF Injection": "medium",
    "Potentially dangerous file": "medium",
    "Resource consumption": "medium",
}


# Default severity for any Wapiti category not present in the map above
# — keeps backwards compatibility with the prior hard-coded behaviour
# (``medium`` for everything) while letting the catalogued classes
# escalate / de-escalate appropriately.
_WAPITI_DEFAULT_SEVERITY: Final[str] = "medium"


# ---------------------------------------------------------------------------
# Shared pipeline — dedup + sort + sidecar persistence
# ---------------------------------------------------------------------------


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Common pipeline: dedup → cap → sort → build FindingDTO + sidecar.

    Stable across Nuclei / Nikto / Wapiti so all three tool families
    share a single canonical contract: identical dedup semantics, the
    same hard cap, the same sidecar filename.
    """

    seen: set[DedupKey] = set()
    keyed: list[tuple[DedupKey, FindingDTO, str]] = []

    for record in records:
        key = _dedup_key(record)
        if key in seen:
            continue
        seen.add(key)

        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        keyed.append((key, finding, evidence_blob))

        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "nuclei_parser.cap_reached",
                extra={
                    "event": "nuclei_parser_cap_reached",
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
            evidence_records=[blob for _, _, blob in keyed],
        )

    return [finding for _, finding, _ in keyed]


def _dedup_key(record: dict[str, Any]) -> DedupKey:
    """Return a stable dedup key for a normalised record.

    Shape: ``(template_id, matched_at, kind)``. ``kind`` lets two
    different families collapsed into the same sidecar (Nuclei +
    Nikto + Wapiti) coexist without false dedup. Empty fields default
    to ``""`` so a malformed record without ``matched-at`` still
    produces a deterministic key.
    """
    template_id = str(record.get("template_id") or "")
    matched_at = str(record.get("matched_at") or "")
    kind = str(record.get("kind") or "")
    return (template_id, matched_at, kind)


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    """Map a normalised record onto a :class:`FindingDTO`.

    The CWE list, OWASP-WSTG hints, severity → confidence mapping, and
    CVSS / EPSS surfacing all happen here. Records that lack a CWE
    inherit the per-category default from :data:`_CATEGORY_DEFAULT_CWE`
    so the FindingDTO contract (``cwe`` non-empty) holds.
    """
    category: FindingCategory = record["category"]
    cwe_list = list(record.get("cwe") or ())
    if not cwe_list:
        cwe_list = list(_CATEGORY_DEFAULT_CWE.get(category, (200,)))
    confidence: ConfidenceLevel = record["confidence"]
    cvss_score: float = record.get("cvss_v3_score") or SENTINEL_CVSS_SCORE
    cvss_vector: str = record.get("cvss_v3_vector") or SENTINEL_CVSS_VECTOR
    epss_score: float | None = record.get("epss_score")
    owasp_wstg = list(record.get("owasp_wstg") or ())
    return make_finding_dto(
        category=category,
        cwe=cwe_list,
        cvss_v3_vector=cvss_vector,
        cvss_v3_score=cvss_score,
        confidence=confidence,
        owasp_wstg=owasp_wstg,
        epss_score=epss_score,
    )


# ---------------------------------------------------------------------------
# Nuclei record extraction
# ---------------------------------------------------------------------------


def _iter_nuclei_records(raw_jsonl: bytes, *, tool_id: str) -> Iterable[dict[str, Any]]:
    """Yield normalised records from a Nuclei JSONL stream.

    Filters out matcher-status=False records (template ran but did not
    match) — these are emitted by some templates as discovery aids and
    are not findings.
    """
    for record in safe_load_jsonl(raw_jsonl, tool_id=tool_id):
        normalised = _normalise_nuclei_record(record)
        if normalised is None:
            continue
        yield normalised


def _normalise_nuclei_record(record: dict[str, Any]) -> dict[str, Any] | None:
    """Return a normalised intermediate record or ``None`` to skip.

    Skip rules:
    * ``matcher-status`` is explicitly ``False`` (template did not match).
    * ``template-id`` missing — Nuclei records are useless without one.
    """
    matcher_status = record.get("matcher-status")
    if matcher_status is False:
        return None

    template_id = _string_field(record, "template-id")
    if template_id is None:
        return None

    info = record.get("info")
    info = info if isinstance(info, dict) else {}
    classification = info.get("classification")
    classification = classification if isinstance(classification, dict) else {}

    severity = _normalise_severity(_string_field(info, "severity"))
    tags = _normalise_tags(info.get("tags"))
    category = _classify_category(tags=tags, severity=severity)
    confidence = _classify_confidence(severity=severity, has_cve=False)

    cve_list = _extract_cve_list(classification, info.get("cve"))
    cwe_list = _extract_cwe_list(classification, info.get("cwe"))
    references = _extract_references(info.get("reference"))
    cvss_score, cvss_vector = _extract_cvss(classification)
    epss_score = _extract_epss(classification)

    confidence = _classify_confidence(severity=severity, has_cve=bool(cve_list))

    matched_at = (
        _string_field(record, "matched-at") or _string_field(record, "host") or ""
    )
    host = _string_field(record, "host") or ""
    request_blob = _truncate_text(_string_field(record, "request"))
    response_blob = _truncate_text(_string_field(record, "response"))

    return {
        "kind": "nuclei",
        "template_id": template_id,
        "template_path": _string_field(record, "template-path"),
        "matched_at": matched_at,
        "host": host,
        "name": _string_field(info, "name") or template_id,
        "severity": severity,
        "tags": tags,
        "category": category,
        "confidence": confidence,
        "cve": cve_list,
        "cwe": cwe_list,
        "references": references,
        "cvss_v3_score": cvss_score,
        "cvss_v3_vector": cvss_vector,
        "epss_score": epss_score,
        "matcher_name": _string_field(record, "matcher-name"),
        "request": request_blob,
        "response": response_blob,
        "owasp_wstg": _owasp_for(category),
    }


# ---------------------------------------------------------------------------
# Nikto record extraction (minimal — Cycle 2 tier-1 surface only)
# ---------------------------------------------------------------------------


def _iter_nikto_records(
    payload: dict[str, Any], *, tool_id: str
) -> Iterable[dict[str, Any]]:
    """Yield normalised records from a Nikto ``-Format json`` payload.

    Nikto's JSON layout (2.5+):

    .. code-block:: json

       {
         "vulnerabilities": [
           {"id": "001234", "OSVDB": "0", "msg": "Server header leaks ...",
            "url": "/", "method": "GET"}
         ]
       }
    """
    items = payload.get("vulnerabilities")
    if not isinstance(items, list):
        _logger.warning(
            "nuclei_parser.nikto_missing_vulnerabilities",
            extra={
                "event": "nuclei_parser_nikto_missing_vulnerabilities",
                "tool_id": tool_id,
            },
        )
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        msg = _string_field(item, "msg")
        if msg is None:
            continue
        url = _string_field(item, "url") or ""
        nikto_id = _string_field(item, "id") or ""
        template_id = f"nikto-{nikto_id}" if nikto_id else f"nikto-{_stable_hash(msg)}"
        yield {
            "kind": "nikto",
            "template_id": template_id,
            "template_path": None,
            "matched_at": url,
            "host": _string_field(item, "host") or "",
            "name": msg,
            "severity": "medium",
            "tags": ("nikto", "misconfig"),
            "category": FindingCategory.MISCONFIG,
            "confidence": ConfidenceLevel.SUSPECTED,
            "cve": (),
            "cwe": list(_CATEGORY_DEFAULT_CWE[FindingCategory.MISCONFIG]),
            "references": (),
            "cvss_v3_score": SENTINEL_CVSS_SCORE,
            "cvss_v3_vector": SENTINEL_CVSS_VECTOR,
            "epss_score": None,
            "matcher_name": _string_field(item, "method"),
            "request": None,
            "response": None,
            "owasp_wstg": _owasp_for(FindingCategory.MISCONFIG),
        }


# ---------------------------------------------------------------------------
# Wapiti record extraction (minimal)
# ---------------------------------------------------------------------------


def _iter_wapiti_records(
    payload: dict[str, Any], *, tool_id: str
) -> Iterable[dict[str, Any]]:
    """Yield normalised records from a Wapiti ``-f json`` payload.

    Wapiti's JSON layout (3.x):

    .. code-block:: json

       {
         "vulnerabilities": {
           "SQL Injection": [
             {"method": "GET", "path": "/login.php", "info": "...", ...}
           ],
           "Cross Site Scripting": [...]
         }
       }
    """
    block = payload.get("vulnerabilities")
    if not isinstance(block, dict):
        _logger.warning(
            "nuclei_parser.wapiti_missing_vulnerabilities",
            extra={
                "event": "nuclei_parser_wapiti_missing_vulnerabilities",
                "tool_id": tool_id,
            },
        )
        return
    for category_name, items in block.items():
        if not isinstance(category_name, str) or not isinstance(items, list):
            continue
        category = _WAPITI_CATEGORY.get(category_name, FindingCategory.OTHER)
        confidence = (
            ConfidenceLevel.LIKELY
            if category not in {FindingCategory.INFO, FindingCategory.OTHER}
            else ConfidenceLevel.SUSPECTED
        )
        severity = _WAPITI_SEVERITY.get(category_name, _WAPITI_DEFAULT_SEVERITY)
        for item in items:
            if not isinstance(item, dict):
                continue
            path = _string_field(item, "path") or _string_field(item, "url") or ""
            method = _string_field(item, "method") or "GET"
            info_text = _string_field(item, "info") or category_name
            yield {
                "kind": "wapiti",
                "template_id": f"wapiti-{category_name}",
                "template_path": None,
                "matched_at": f"{method} {path}".strip(),
                "host": _string_field(item, "url") or "",
                "name": f"{category_name}: {info_text}",
                "severity": severity,
                "tags": ("wapiti", category_name.lower().replace(" ", "-")),
                "category": category,
                "confidence": confidence,
                "cve": (),
                "cwe": list(_CATEGORY_DEFAULT_CWE.get(category, (200,))),
                "references": (),
                "cvss_v3_score": SENTINEL_CVSS_SCORE,
                "cvss_v3_vector": SENTINEL_CVSS_VECTOR,
                "epss_score": None,
                "matcher_name": _string_field(item, "parameter"),
                "request": _truncate_text(_string_field(item, "http_request")),
                "response": _truncate_text(_string_field(item, "http_response")),
                "owasp_wstg": _owasp_for(category),
            }


# ---------------------------------------------------------------------------
# Helpers — payload loading
# ---------------------------------------------------------------------------


def _resolve_jsonl_payload(
    *,
    stdout: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> bytes:
    """Resolve the canonical ``nuclei.jsonl`` blob or fall back to stdout.

    Returns the raw JSONL bytes (caller is responsible for parsing).
    Empty / missing payloads return ``b""`` so the caller can short
    circuit to ``[]``.
    """
    canonical = _safe_join(artifacts_dir, "nuclei.jsonl")
    if canonical is not None and canonical.is_file():
        try:
            raw = canonical.read_bytes()
        except OSError as exc:
            _logger.warning(
                "nuclei_parser.canonical_read_failed",
                extra={
                    "event": "nuclei_parser_canonical_read_failed",
                    "tool_id": tool_id,
                    "path": "nuclei.jsonl",
                    "error_type": type(exc).__name__,
                },
            )
            raw = b""
        if raw.strip():
            return raw
    if stdout and stdout.strip():
        return stdout
    return b""


def _load_primary_payload(
    *,
    stdout: bytes,
    artifacts_dir: Path,
    canonical_name: str,
    tool_id: str,
) -> dict[str, Any] | None:
    """Resolve and parse the canonical JSON file or fall back to stdout.

    Mirrors :func:`_resolve_jsonl_payload` but for top-level JSON
    objects (Nikto / Wapiti). Returns ``None`` for empty / missing /
    malformed payloads.
    """
    canonical = _safe_join(artifacts_dir, canonical_name)
    if canonical is not None and canonical.is_file():
        try:
            raw = canonical.read_bytes()
        except OSError as exc:
            _logger.warning(
                "nuclei_parser.canonical_read_failed",
                extra={
                    "event": "nuclei_parser_canonical_read_failed",
                    "tool_id": tool_id,
                    "path": canonical_name,
                    "error_type": type(exc).__name__,
                },
            )
            raw = b""
        if raw.strip():
            payload = safe_load_json(raw, tool_id=tool_id)
            if isinstance(payload, dict):
                return payload
            if payload is not None:
                _logger.warning(
                    "nuclei_parser.canonical_not_object",
                    extra={
                        "event": "nuclei_parser_canonical_not_object",
                        "tool_id": tool_id,
                        "path": canonical_name,
                    },
                )

    if stdout and stdout.strip():
        payload = safe_load_json(stdout, tool_id=tool_id)
        if isinstance(payload, dict):
            return payload
        if payload is not None:
            _logger.warning(
                "nuclei_parser.stdout_not_object",
                extra={
                    "event": "nuclei_parser_stdout_not_object",
                    "tool_id": tool_id,
                },
            )
    return None


def _safe_join(base: Path, name: str) -> Path | None:
    """Defensive ``base / name`` that refuses path-traversal segments."""
    if "/" in name or "\\" in name or ".." in name:
        return None
    return base / name


# ---------------------------------------------------------------------------
# Helpers — sidecar persistence
# ---------------------------------------------------------------------------


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
            "nuclei_parser.evidence_sidecar_write_failed",
            extra={
                "event": "nuclei_parser_evidence_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    """Build a compact evidence JSON for downstream redaction + persistence."""
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": record.get("kind"),
        "template_id": record.get("template_id"),
        "template_path": record.get("template_path"),
        "matched_at": record.get("matched_at"),
        "host": record.get("host"),
        "name": record.get("name"),
        "severity": record.get("severity"),
        "tags": list(record.get("tags") or ()),
        "cve": list(record.get("cve") or ()),
        "cwe": list(record.get("cwe") or ()),
        "references": list(record.get("references") or ()),
        "cvss_v3_score": record.get("cvss_v3_score"),
        "cvss_v3_vector": record.get("cvss_v3_vector"),
        "epss_score": record.get("epss_score"),
        "matcher_name": record.get("matcher_name"),
        "request": record.get("request"),
        "response": record.get("response"),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None:
            continue
        if isinstance(value, list | tuple) and not value:
            continue
        if value == "":
            continue
        # Drop sentinel CVSS metadata so a missing-data record stays
        # demonstrably "missing" instead of "0.0" / sentinel vector.
        if key == "cvss_v3_score" and value == SENTINEL_CVSS_SCORE:
            continue
        if key == "cvss_v3_vector" and value == SENTINEL_CVSS_VECTOR:
            continue
        cleaned[key] = value
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Helpers — field accessors / classifiers
# ---------------------------------------------------------------------------


def _string_field(record: dict[str, Any], key: str) -> str | None:
    """Return ``record[key]`` if it is a non-empty string, else ``None``."""
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _normalise_severity(raw: str | None) -> str:
    """Coerce a Nuclei severity string into the canonical bucket."""
    if raw is None:
        return "info"
    return _NORMALISED_SEVERITY.get(raw.strip().lower(), "info")


def _normalise_tags(raw: Any) -> tuple[str, ...]:
    """Normalise Nuclei's ``info.tags`` (list of strings or comma string)."""
    if isinstance(raw, list):
        items = [t.strip().lower() for t in raw if isinstance(t, str) and t.strip()]
    elif isinstance(raw, str):
        items = [t.strip().lower() for t in raw.split(",") if t.strip()]
    else:
        return ()
    seen: list[str] = []
    for item in items:
        if item not in seen:
            seen.append(item)
    return tuple(seen)


def _classify_category(
    *,
    tags: tuple[str, ...],
    severity: str,
) -> FindingCategory:
    """Pick the most specific :class:`FindingCategory` for a record.

    Walks :data:`_TAG_TO_CATEGORY` in priority order: the first tag
    that matches wins. Falls back to a severity-driven default when no
    tag carries semantic information.
    """
    tag_set = frozenset(tags)
    for tag, category in _TAG_TO_CATEGORY:
        if tag in tag_set:
            return category
    return _SEVERITY_FALLBACK_CATEGORY.get(severity, FindingCategory.MISCONFIG)


def _classify_confidence(*, severity: str, has_cve: bool) -> ConfidenceLevel:
    """Pick the :class:`ConfidenceLevel` for a record.

    ``critical`` / ``high`` always count as ``LIKELY`` regardless of
    CVE; ``medium`` is bumped from ``SUSPECTED`` to ``LIKELY`` when a
    CVE is present.
    """
    base = _SEVERITY_CONFIDENCE.get(severity, ConfidenceLevel.SUSPECTED)
    if severity == "medium" and has_cve:
        return ConfidenceLevel.LIKELY
    return base


def _extract_cve_list(
    classification: dict[str, Any],
    inline: Any,
) -> tuple[str, ...]:
    """Return a sorted, deduplicated tuple of normalised CVE ids."""
    collected: list[str] = []
    cve_ref = classification.get("cve-id") or classification.get("cve_id")
    if isinstance(cve_ref, list):
        collected.extend(v for v in cve_ref if isinstance(v, str))
    elif isinstance(cve_ref, str):
        collected.append(cve_ref)
    if isinstance(inline, list):
        collected.extend(v for v in inline if isinstance(v, str))
    elif isinstance(inline, str):
        collected.append(inline)
    normalised = {_normalise_cve(c) for c in collected if c}
    return tuple(sorted(c for c in normalised if c))


def _normalise_cve(raw: str) -> str:
    """Coerce a CVE token into the canonical ``CVE-YYYY-NNNN+`` form.

    Validates the shape (year is a 4-digit number ≥ 1999, sequence is at
    least 4 digits) so garbage tokens such as ``CVE-ABC`` or
    ``CVE-12-34`` are rejected — they would otherwise leak into the
    evidence sidecar and confuse downstream NVD lookups.
    """
    candidate = raw.strip().upper()
    if not candidate:
        return ""
    if candidate.startswith("CVE-"):
        body = candidate[4:]
    elif candidate[:4].isdigit() and "-" in candidate[4:]:
        body = candidate
    else:
        return ""
    parts = body.split("-", 1)
    if len(parts) != 2:
        return ""
    year, sequence = parts
    if not (year.isdigit() and len(year) == 4 and int(year) >= 1999):
        return ""
    if not (sequence.isdigit() and len(sequence) >= 4):
        return ""
    return f"CVE-{year}-{sequence}"


def _extract_cwe_list(
    classification: dict[str, Any],
    inline: Any,
) -> list[int]:
    """Return a sorted, deduplicated list of CWE ids (positive integers).

    Nuclei stores CWEs as ``CWE-XXX`` strings or as ``["CWE-79"]`` /
    ``["79"]`` lists; the parser tolerates all three shapes.
    """
    collected: list[int] = []
    raw = classification.get("cwe-id") or classification.get("cwe_id")
    if isinstance(raw, list):
        for item in raw:
            cwe_id = _coerce_cwe(item)
            if cwe_id is not None:
                collected.append(cwe_id)
    elif isinstance(raw, str):
        cwe_id = _coerce_cwe(raw)
        if cwe_id is not None:
            collected.append(cwe_id)
    if isinstance(inline, list):
        for item in inline:
            cwe_id = _coerce_cwe(item)
            if cwe_id is not None:
                collected.append(cwe_id)
    elif isinstance(inline, str | int):
        cwe_id = _coerce_cwe(inline)
        if cwe_id is not None:
            collected.append(cwe_id)
    return sorted(set(collected))


def _coerce_cwe(value: Any) -> int | None:
    """Coerce a CWE token (``"CWE-79"`` / ``"79"`` / ``79``) into an int."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value > 0:
        return value
    if isinstance(value, str):
        candidate = value.strip().upper()
        if candidate.startswith("CWE-"):
            candidate = candidate[4:]
        if candidate.isdigit():
            cwe_id = int(candidate)
            return cwe_id if cwe_id > 0 else None
    return None


def _extract_references(raw: Any) -> tuple[str, ...]:
    """Return a sorted, deduplicated tuple of reference URLs / strings."""
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, list):
        items = [v for v in raw if isinstance(v, str)]
    else:
        return ()
    cleaned = {v.strip() for v in items if v.strip()}
    return tuple(sorted(cleaned))


def _extract_cvss(classification: dict[str, Any]) -> tuple[float, str]:
    """Return ``(score, vector)`` from ``info.classification``.

    Falls back to the sentinel score / vector when fields are missing
    or fail validation. Scores out of [0.0, 10.0] are clamped to the
    sentinel.
    """
    score_raw = classification.get("cvss-score") or classification.get("cvss_score")
    score = _coerce_float(score_raw)
    if score is None or not (0.0 <= score <= 10.0):
        score = SENTINEL_CVSS_SCORE

    vector_raw = classification.get("cvss-metrics") or classification.get(
        "cvss_metrics"
    )
    vector = (
        vector_raw.strip()
        if isinstance(vector_raw, str) and vector_raw.strip()
        else SENTINEL_CVSS_VECTOR
    )
    if not any(vector.startswith(prefix) for prefix in _CVSS_VECTOR_PREFIXES):
        vector = SENTINEL_CVSS_VECTOR
    return score, vector


def _extract_epss(classification: dict[str, Any]) -> float | None:
    """Return ``info.classification.epss-score`` clamped to [0.0, 1.0]."""
    raw = classification.get("epss-score") or classification.get("epss_score")
    score = _coerce_float(raw)
    if score is None or not (0.0 <= score <= 1.0):
        return None
    return score


def _coerce_float(value: Any) -> float | None:
    """Coerce ``value`` into a float (or ``None`` for non-numeric input)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _truncate_text(value: str | None) -> str | None:
    """Truncate a request / response blob to :data:`_MAX_EVIDENCE_BYTES`.

    Returns ``None`` for ``None`` / empty input. Truncation is byte-safe
    (UTF-8 substrings can split mid-codepoint, so we measure encoded
    length and re-decode with replacement).
    """
    if not value:
        return None
    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_EVIDENCE_BYTES:
        return value
    truncated = encoded[:_MAX_EVIDENCE_BYTES].decode("utf-8", errors="replace")
    return truncated + "...[truncated]"


# ---------------------------------------------------------------------------
# OWASP-WSTG mapping per category. Light-weight: one or two hints per
# category, chosen from the category-most-relevant WSTG bucket.
# ---------------------------------------------------------------------------


_OWASP_BY_CATEGORY: Final[dict[FindingCategory, tuple[str, ...]]] = {
    FindingCategory.RCE: ("WSTG-INPV-12",),
    FindingCategory.CMDI: ("WSTG-INPV-12",),
    FindingCategory.SQLI: ("WSTG-INPV-05",),
    FindingCategory.NOSQLI: ("WSTG-INPV-05",),
    FindingCategory.LDAPI: ("WSTG-INPV-06",),
    FindingCategory.SSTI: ("WSTG-INPV-18",),
    FindingCategory.SSRF: ("WSTG-INPV-19",),
    FindingCategory.XXE: ("WSTG-INPV-07",),
    FindingCategory.XSS: ("WSTG-INPV-01", "WSTG-INPV-02"),
    FindingCategory.LFI: ("WSTG-ATHZ-01",),
    FindingCategory.OPEN_REDIRECT: ("WSTG-CLNT-04",),
    FindingCategory.AUTH: ("WSTG-ATHN-01",),
    FindingCategory.IDOR: ("WSTG-ATHZ-04",),
    FindingCategory.JWT: ("WSTG-SESS-09",),
    FindingCategory.CRYPTO: ("WSTG-CRYP-01",),
    FindingCategory.SECRET_LEAK: ("WSTG-INFO-08",),
    FindingCategory.DOS: ("WSTG-BUSL-01",),
    FindingCategory.CORS: ("WSTG-CLNT-07",),
    FindingCategory.CSRF: ("WSTG-SESS-05",),
    FindingCategory.SUPPLY_CHAIN: ("WSTG-INFO-08",),
    FindingCategory.MISCONFIG: ("WSTG-CONF-04", "WSTG-INFO-08"),
    FindingCategory.INFO: ("WSTG-INFO-08",),
}


def _owasp_for(category: FindingCategory) -> tuple[str, ...]:
    """Return the canonical OWASP-WSTG hint tuple for ``category``."""
    return _OWASP_BY_CATEGORY.get(category, ("WSTG-INFO-08",))


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_nikto_json",
    "parse_nuclei_jsonl",
    "parse_wapiti_json",
]
