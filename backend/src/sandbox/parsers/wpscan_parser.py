"""Parser for WPScan / droopescan CMS scanner JSON output (Backlog/dev1_md §4.7).

§4.7 ships eight CMS / platform-specific scanners; this module covers the
two that emit a stable, parseable JSON shape on disk:

* **wpscan** (``--format json --output /out/wpscan.json``) — flagship
  WordPress scanner. Top-level object with ``interesting_findings``,
  ``version``, ``main_theme``, ``themes``, ``plugins``, ``users``.
* **droopescan** (``-o json``) — Drupal / Joomla / SilverStripe scanner.
  Lighter shape: ``version`` (list of candidates), ``themes``, ``plugins``,
  ``modules``, ``users``.

Three §4.7 tools (``joomscan``, ``cmsmap``, ``magescan``) emit text-only or
unstable JSON shapes and intentionally have no parser entry — they will
register against ``ParseStrategy.TEXT_LINES`` in Cycle 3. Three more
(``nextjs_check``, ``spring_boot_actuator``, ``jenkins_enum``) are nuclei
template wrappers that flow through ``ParseStrategy.NUCLEI_JSONL`` and
ship in ARG-015.

Output shape per parsed record:

* ``interesting_findings[*]`` → :class:`FindingCategory.INFO`,
  ``confidence=SUSPECTED``. Server-side fingerprints, exposed config files
  and similar information disclosure surface.
* ``version.vulnerabilities[*]`` / ``main_theme.vulnerabilities[*]`` /
  ``themes[*].vulnerabilities[*]`` / ``plugins[*].vulnerabilities[*]`` →
  :class:`FindingCategory.MISCONFIG` (third-party CMS component
  vulnerability), severity escalates with CVE presence:
  - WPScan record cites at least one CVE → ``confidence=LIKELY`` (the CVE
    proves the upstream tracker accepted the vuln; WPScan still depends on
    a version match for confirmation).
  - No CVE → ``confidence=SUSPECTED``.
* ``users[*]`` → :class:`FindingCategory.INFO` (user enumeration).

Severity is held implicitly through the CVSS sentinel: parsers operate in
the contract layer where ``cvss_v3_score=0.0`` is "info-tier"; downstream
``Normalizer`` lifts the score using NVD / EPSS data when CVE references
land in :class:`FindingDTO.epss_score` / ``kev_listed``.

Dedup
-----
Records collapse on a stable key:

* interesting findings: ``("interesting", to_s, type)``
* CMS / theme / plugin vulns: ``(component, slug or "", title, cve_tuple)``
* users: ``("user", username)``

Hard cap at :data:`_MAX_FINDINGS` defends the worker against a runaway
WPScan run against a heavily plugin-enumerated site.

Sidecar
-------
A compact projection of every emitted record is written to
``artifacts_dir / "wpscan_findings.jsonl"`` for the downstream evidence
pipeline. Each record carries its source ``tool_id`` (``wpscan`` or
``droopescan``).

Failure model
-------------
The parser is fail-soft: malformed JSON returns ``[]`` after a structured
log; missing inner fields are tolerated; OS errors on the sidecar write
are logged and swallowed.
"""

from __future__ import annotations

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
    make_finding_dto,
    safe_load_json,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants — surfaced for test introspection.
# ---------------------------------------------------------------------------


# CMS plugin / theme vulnerabilities map to CWE-1395 (Dependency on
# Vulnerable Third-Party Component) plus CWE-200 when the parser also
# picks up an information disclosure surface (interesting_findings,
# users[]). The downstream Normalizer keeps both hints; report writers
# pick the most relevant per-finding.
_CWE_VULN_COMPONENT: Final[tuple[int, ...]] = (1395,)
_CWE_INFO_DISCLOSURE: Final[tuple[int, ...]] = (200,)

# OWASP WSTG hints — INFO-08 covers fingerprinting (component versions),
# CONF-04 covers exposed backup / config files, IDNT-04 covers user
# enumeration. The hint set per emitted finding is chosen below in the
# per-record extractors so a vulnerability finding carries CONF-04 +
# INFO-08 (component identification → versioned component vuln).
_WSTG_VULN_COMPONENT: Final[tuple[str, ...]] = ("WSTG-INFO-08", "WSTG-CONF-04")
_WSTG_INFO_DISCLOSURE: Final[tuple[str, ...]] = ("WSTG-INFO-08", "WSTG-CONF-04")
_WSTG_USER_ENUM: Final[tuple[str, ...]] = ("WSTG-IDNT-04",)


# Single sidecar shared across the two §4.7 JSON parsers (mirrors the
# katana_parser pattern: one filename per parser family).
EVIDENCE_SIDECAR_NAME: Final[str] = "wpscan_findings.jsonl"


# Soft cap on emitted findings. WPScan against a heavily-enumerated site
# can legitimately surface thousands of plugin / theme records; capping
# keeps the worker bounded.
_MAX_FINDINGS: Final[int] = 5_000


# Stable dedup key shape: (kind, component, slug, title, *cve_ids). Exposed
# as a module-level alias so the dedup loop and ``_dedup_key`` share a
# single canonical type instead of repeating ``tuple[str, ...]`` inline.
DedupKey: TypeAlias = tuple[str, ...]


# Shape of a normalised intermediate record carried through the pipeline.
# Documented as a TypedDict-equivalent dict literal for clarity; the
# parser keeps it as a plain dict to stay zero-cost.
#
#   {
#       "kind":           "interesting" | "vuln" | "user",
#       "component":      "wordpress" | "main_theme" | "theme" | "plugin"
#                         | "interesting" | "user",
#       "slug":           str | None,                # plugin/theme slug or None
#       "title":          str,                       # short description
#       "to_s":           str,                       # raw "to_s" / printable
#       "url":            str | None,                # affected URL
#       "cve":            tuple[str, ...],           # zero or more CVE ids
#       "references":     dict[str, list[str]],     # raw refs blob
#       "fixed_in":       str | None,
#       "version":        str | None,                # affected component version
#   }


# ---------------------------------------------------------------------------
# Public entry points — signature mandated by the dispatch layer:
# ``(stdout, stderr, artifacts_dir, tool_id) -> list[FindingDTO]``.
# ---------------------------------------------------------------------------


def parse_wpscan_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate WPScan ``--format json`` output into FindingDTOs.

    Resolution order for the JSON blob:

    1. ``artifacts_dir / "wpscan.json"`` (canonical: WPScan writes there
       when invoked with ``--output /out/wpscan.json``).
    2. ``stdout`` fallback (some operators run wpscan without ``--output``
       so the JSON lands on stdout instead).

    ``stderr`` is accepted for parser dispatch signature symmetry but
    intentionally not consumed (WPScan emits banners + per-step status
    lines on stderr that are not parser-relevant).
    """
    del stderr
    payload = _load_primary_payload(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name="wpscan.json",
        tool_id=tool_id,
    )
    if payload is None:
        return []
    records = list(_iter_wpscan_records(payload))
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


def parse_droopescan_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate droopescan ``-o json`` output into FindingDTOs.

    Droopescan emits a lighter shape than WPScan — only candidate version
    list, themes, plugins / modules, and users; vulnerabilities are not
    enumerated inline (they are surfaced via NVD lookups out-of-band).
    The parser therefore only emits info-class findings:

    * Detected CMS version → ``component=cms_version`` with
      ``confidence=SUSPECTED`` (always — droopescan returns multiple
      candidate versions, so confirmation needs an external check).
    * Discovered themes / plugins / modules → ``component=theme|plugin``
      with no vulnerability metadata (just the slug / version pair).
    * Enumerated users → ``component=user`` (CWE-200 user enumeration).

    Resolution order matches :func:`parse_wpscan_json` (canonical file
    first, stdout fallback).
    """
    del stderr
    payload = _load_primary_payload(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name="droopescan.json",
        tool_id=tool_id,
    )
    if payload is None:
        return []
    records = list(_iter_droopescan_records(payload))
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Shared pipeline — dedup + sort + sidecar persistence
# ---------------------------------------------------------------------------


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Common pipeline: dedup → cap → sort → build FindingDTO + sidecar."""

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
                "wpscan_parser.cap_reached",
                extra={
                    "event": "wpscan_parser_cap_reached",
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
    """Build a stable dedup key for a normalised record.

    Component + slug + title + sorted CVE list keeps the key stable across
    reruns regardless of WPScan's emission order, while still distinguishing
    e.g. two distinct vulns in the same plugin.
    """
    component = str(record.get("component", ""))
    slug = str(record.get("slug") or "")
    title = str(record.get("title") or record.get("to_s") or "")
    cve_tuple = tuple(record.get("cve", ()))
    kind = str(record.get("kind", ""))
    return (kind, component, slug, title, *cve_tuple)


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    """Map a normalised record to its FindingDTO category / confidence."""
    kind = record.get("kind")
    cve_tuple = record.get("cve") or ()

    if kind == "vuln":
        confidence = ConfidenceLevel.LIKELY if cve_tuple else ConfidenceLevel.SUSPECTED
        return make_finding_dto(
            category=FindingCategory.MISCONFIG,
            cwe=list(_CWE_VULN_COMPONENT),
            owasp_wstg=list(_WSTG_VULN_COMPONENT),
            confidence=confidence,
        )
    if kind == "user":
        return make_finding_dto(
            category=FindingCategory.INFO,
            cwe=list(_CWE_INFO_DISCLOSURE),
            owasp_wstg=list(_WSTG_USER_ENUM),
            confidence=ConfidenceLevel.SUSPECTED,
        )
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=list(_CWE_INFO_DISCLOSURE),
        owasp_wstg=list(_WSTG_INFO_DISCLOSURE),
        confidence=ConfidenceLevel.SUSPECTED,
    )


# ---------------------------------------------------------------------------
# WPScan record extraction
# ---------------------------------------------------------------------------


def _iter_wpscan_records(payload: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Yield normalised records covering every WPScan finding family."""
    yield from _iter_interesting_findings(payload)
    yield from _iter_core_version_vulns(payload)
    yield from _iter_main_theme_vulns(payload)
    yield from _iter_themes_vulns(payload)
    yield from _iter_plugins_vulns(payload)
    yield from _iter_users(payload)


def _iter_interesting_findings(
    payload: dict[str, Any],
) -> Iterable[dict[str, Any]]:
    """Yield records for ``interesting_findings[*]`` (info disclosure)."""
    items = payload.get("interesting_findings")
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        to_s = _string_field(item, "to_s") or _string_field(item, "url")
        if to_s is None:
            continue
        yield {
            "kind": "interesting",
            "component": "interesting",
            "slug": _string_field(item, "type"),
            "title": _string_field(item, "type") or to_s,
            "to_s": to_s,
            "url": _string_field(item, "url"),
            "cve": (),
            "references": _coerce_references(item.get("references")),
            "fixed_in": None,
            "version": None,
        }


def _iter_core_version_vulns(
    payload: dict[str, Any],
) -> Iterable[dict[str, Any]]:
    """Yield records for ``version.vulnerabilities[*]`` (WordPress core)."""
    version_block = payload.get("version")
    if not isinstance(version_block, dict):
        return
    component_version = _string_field(version_block, "number")
    yield from _iter_vulnerabilities(
        version_block.get("vulnerabilities"),
        component="wordpress",
        slug=None,
        component_version=component_version,
    )


def _iter_main_theme_vulns(
    payload: dict[str, Any],
) -> Iterable[dict[str, Any]]:
    """Yield records for ``main_theme.vulnerabilities[*]``."""
    theme_block = payload.get("main_theme")
    if not isinstance(theme_block, dict):
        return
    slug = _string_field(theme_block, "slug")
    component_version = _extract_component_version(theme_block)
    yield from _iter_vulnerabilities(
        theme_block.get("vulnerabilities"),
        component="main_theme",
        slug=slug,
        component_version=component_version,
    )


def _iter_themes_vulns(payload: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Yield records across every entry of ``themes[slug].vulnerabilities[*]``."""
    yield from _iter_keyed_component_vulns(payload, key="themes", component="theme")


def _iter_plugins_vulns(payload: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Yield records across every entry of ``plugins[slug].vulnerabilities[*]``."""
    yield from _iter_keyed_component_vulns(payload, key="plugins", component="plugin")


def _iter_keyed_component_vulns(
    payload: dict[str, Any],
    *,
    key: str,
    component: str,
) -> Iterable[dict[str, Any]]:
    """Yield vulnerability records from ``payload[key][slug].vulnerabilities``.

    Used for both ``themes`` and ``plugins`` — WPScan packages them under a
    top-level dict keyed by the component slug.
    """
    block = payload.get(key)
    if not isinstance(block, dict):
        return
    for slug, entry in block.items():
        if not isinstance(entry, dict) or not isinstance(slug, str):
            continue
        component_version = _extract_component_version(entry)
        yield from _iter_vulnerabilities(
            entry.get("vulnerabilities"),
            component=component,
            slug=slug,
            component_version=component_version,
        )


def _iter_vulnerabilities(
    vulnerabilities: Any,
    *,
    component: str,
    slug: str | None,
    component_version: str | None,
) -> Iterable[dict[str, Any]]:
    """Yield per-vulnerability records under a component."""
    if not isinstance(vulnerabilities, list):
        return
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        title = _string_field(vuln, "title")
        if title is None:
            continue
        references = _coerce_references(vuln.get("references"))
        cve_tuple = _extract_cve_list(references, vuln.get("cve"))
        yield {
            "kind": "vuln",
            "component": component,
            "slug": slug,
            "title": title,
            "to_s": title,
            "url": _string_field(vuln, "url"),
            "cve": cve_tuple,
            "references": references,
            "fixed_in": _string_field(vuln, "fixed_in"),
            "version": component_version,
        }


def _iter_users(payload: dict[str, Any]) -> Iterable[dict[str, Any]]:
    """Yield records for enumerated WordPress users (CWE-200)."""
    users = payload.get("users")
    if not isinstance(users, dict):
        # WPScan uses dict-keyed-by-username; tolerate the legacy list shape too.
        if not isinstance(users, list):
            return
        for user in users:
            yield from _emit_user(user)
        return
    for username, user in users.items():
        if not isinstance(username, str):
            continue
        if not isinstance(user, dict):
            user = {"username": username}
        elif "username" not in user:
            user = {**user, "username": username}
        yield from _emit_user(user)


def _emit_user(user: Any) -> Iterable[dict[str, Any]]:
    """Yield a single user-enumeration record (or nothing for malformed input)."""
    if not isinstance(user, dict):
        return
    username = _string_field(user, "username") or _string_field(user, "name")
    if username is None:
        return
    yield {
        "kind": "user",
        "component": "user",
        "slug": username,
        "title": username,
        "to_s": username,
        "url": _string_field(user, "url"),
        "cve": (),
        "references": {},
        "fixed_in": None,
        "version": None,
    }


# ---------------------------------------------------------------------------
# Droopescan record extraction — lightweight info-only adapter
# ---------------------------------------------------------------------------


def _iter_droopescan_records(
    payload: dict[str, Any],
) -> Iterable[dict[str, Any]]:
    """Yield normalised records from droopescan ``-o json`` output."""
    yield from _iter_droopescan_versions(payload)
    yield from _iter_droopescan_components(payload, key="themes", component="theme")
    yield from _iter_droopescan_components(payload, key="plugins", component="plugin")
    yield from _iter_droopescan_components(payload, key="modules", component="plugin")
    yield from _iter_droopescan_users(payload)


def _iter_droopescan_versions(
    payload: dict[str, Any],
) -> Iterable[dict[str, Any]]:
    """Yield candidate-version records from droopescan."""
    block = payload.get("version") or payload.get("cms")
    candidates: list[dict[str, Any]] = []
    if isinstance(block, list):
        candidates = [c for c in block if isinstance(c, dict)]
    elif isinstance(block, dict):
        items = block.get("finds") or block.get("versions")
        if isinstance(items, list):
            candidates = [c for c in items if isinstance(c, dict)]
    for cand in candidates:
        version = _string_field(cand, "version") or _string_field(cand, "number")
        if version is None:
            continue
        yield {
            "kind": "interesting",
            "component": "cms_version",
            "slug": version,
            "title": f"CMS version: {version}",
            "to_s": version,
            "url": _string_field(cand, "url"),
            "cve": (),
            "references": {},
            "fixed_in": None,
            "version": version,
        }


def _iter_droopescan_components(
    payload: dict[str, Any],
    *,
    key: str,
    component: str,
) -> Iterable[dict[str, Any]]:
    """Yield component-discovery records from droopescan ``themes`` / ``plugins`` / ``modules``."""
    block = payload.get(key)
    items: list[dict[str, Any]] = []
    if isinstance(block, dict):
        # Droopescan packages discoveries under ``finds`` (plural).
        finds = block.get("finds") or block.get("entries")
        if isinstance(finds, list):
            items = [c for c in finds if isinstance(c, dict)]
    elif isinstance(block, list):
        items = [c for c in block if isinstance(c, dict)]
    for item in items:
        slug = _string_field(item, "name") or _string_field(item, "id")
        if slug is None:
            continue
        version = _string_field(item, "version")
        title = f"{component.capitalize()} discovered: {slug}"
        if version is not None:
            title = f"{title} ({version})"
        yield {
            "kind": "interesting",
            "component": component,
            "slug": slug,
            "title": title,
            "to_s": slug,
            "url": _string_field(item, "url"),
            "cve": (),
            "references": {},
            "fixed_in": None,
            "version": version,
        }


def _iter_droopescan_users(
    payload: dict[str, Any],
) -> Iterable[dict[str, Any]]:
    """Yield user-enumeration records from droopescan."""
    block = payload.get("users")
    items: list[dict[str, Any]] = []
    if isinstance(block, dict):
        finds = block.get("finds") or block.get("entries")
        if isinstance(finds, list):
            items = [c for c in finds if isinstance(c, dict)]
    elif isinstance(block, list):
        items = [c for c in block if isinstance(c, dict)]
    for item in items:
        yield from _emit_user(item)


# ---------------------------------------------------------------------------
# Helpers — payload loading
# ---------------------------------------------------------------------------


def _load_primary_payload(
    *,
    stdout: bytes,
    artifacts_dir: Path,
    canonical_name: str,
    tool_id: str,
) -> dict[str, Any] | None:
    """Resolve and parse the canonical JSON file or fall back to stdout.

    Returns ``None`` for empty / missing / malformed payloads (after a
    structured WARNING) so the caller can short-circuit to ``[]``.
    """
    canonical = _safe_join(artifacts_dir, canonical_name)
    if canonical is not None and canonical.is_file():
        try:
            raw = canonical.read_bytes()
        except OSError as exc:
            _logger.warning(
                "wpscan_parser.canonical_read_failed",
                extra={
                    "event": "wpscan_parser_canonical_read_failed",
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
                    "wpscan_parser.canonical_not_object",
                    extra={
                        "event": "wpscan_parser_canonical_not_object",
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
                "wpscan_parser.stdout_not_object",
                extra={
                    "event": "wpscan_parser_stdout_not_object",
                    "tool_id": tool_id,
                },
            )
    return None


def _safe_join(base: Path, name: str) -> Path | None:
    """Defensive ``base / name`` that refuses path-traversal segments.

    The dispatch layer always feeds a sandbox-allocated ``artifacts_dir``
    so traversal is impossible by construction; the guard exists to keep
    the parser side-effect-safe under direct test invocation with an
    arbitrary ``Path``.
    """
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
            "wpscan_parser.evidence_sidecar_write_failed",
            extra={
                "event": "wpscan_parser_evidence_sidecar_write_failed",
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
        "component": record.get("component"),
        "slug": record.get("slug"),
        "title": record.get("title"),
        "url": record.get("url"),
        "cve": list(record.get("cve") or ()),
        "fixed_in": record.get("fixed_in"),
        "version": record.get("version"),
        "references": record.get("references") or {},
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value in (None, "", [], {}):
            continue
        cleaned[key] = value
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Helpers — field accessors / normalisation
# ---------------------------------------------------------------------------


def _string_field(record: dict[str, Any], key: str) -> str | None:
    """Return ``record[key]`` if it is a non-empty string, else ``None``."""
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _coerce_references(raw: Any) -> dict[str, list[str]]:
    """Normalise WPScan's references blob into ``{key: [str, ...]}``.

    WPScan emits a dict keyed by reference type (``cve``, ``url``,
    ``exploitdb``, ``secunia``, ``wpvulndb``, …). The values can be either
    a list of strings or — rarely — a list of mixed types; we coerce
    everything to a list of strings and drop empty / non-string entries.
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, list[str]] = {}
    for key, value in raw.items():
        if not isinstance(key, str):
            continue
        if isinstance(value, list):
            cleaned = [v.strip() for v in value if isinstance(v, str) and v.strip()]
            if cleaned:
                out[key] = sorted(dict.fromkeys(cleaned))
        elif isinstance(value, str) and value.strip():
            out[key] = [value.strip()]
    return out


def _extract_cve_list(
    references: dict[str, list[str]],
    inline: Any,
) -> tuple[str, ...]:
    """Extract a sorted, deduplicated tuple of CVE ids.

    WPScan stores CVEs both inside ``references.cve`` (canonical) and —
    for legacy plugin records — in a top-level ``cve`` field on the
    vulnerability. Both are merged here.
    """
    collected: list[str] = []
    cve_ref = references.get("cve")
    if cve_ref:
        collected.extend(cve_ref)
    if isinstance(inline, list):
        collected.extend(v for v in inline if isinstance(v, str))
    elif isinstance(inline, str):
        collected.append(inline)
    normalised = {_normalise_cve(c) for c in collected if c}
    return tuple(sorted(c for c in normalised if c))


def _normalise_cve(raw: str) -> str:
    """Coerce a CVE token into ``CVE-YYYY-NNNNN`` form (best effort).

    WPScan sometimes ships the bare numeric pair (``2024-12345``) without
    the ``CVE-`` prefix — re-add it so downstream lookups stay consistent.
    Returns an empty string for inputs that do not look like a CVE id.
    """
    candidate = raw.strip().upper()
    if not candidate:
        return ""
    if candidate.startswith("CVE-"):
        return candidate
    if candidate[:4].isdigit() and "-" in candidate[4:]:
        return f"CVE-{candidate}"
    return ""


def _extract_component_version(block: Any) -> str | None:
    """Read a component's installed version from a WPScan theme/plugin block.

    WPScan packages the version under ``version.number`` (preferred) or
    sometimes under ``version`` directly when no confidence metadata is
    present. Unknown shapes degrade to ``None``.
    """
    if not isinstance(block, dict):
        return None
    version = block.get("version")
    if isinstance(version, dict):
        return _string_field(version, "number")
    if isinstance(version, str) and version.strip():
        return version.strip()
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_droopescan_json",
    "parse_wpscan_json",
]
