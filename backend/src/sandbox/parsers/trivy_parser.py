"""Parser for Trivy JSON output (Backlog/dev1_md §4.15 — ARG-018).

§4.15 ships twelve Cloud / IaC / container scanners; this module covers the
two flagship Trivy invocations that emit the canonical Aqua Security
``trivy ... -f json`` envelope on disk:

* **trivy_image** (``trivy image -f json -o /out/trivy.json {image}``) —
  scans a container image's package layers for known CVEs (OS packages
  + language ecosystems), config issues (Dockerfile lint), and embedded
  secrets. Canonical artifact filename: ``trivy.json``.
* **trivy_fs**    (``trivy fs -f json -o /out/trivy_fs.json {path}``)   —
  same scanner family pointed at a local filesystem / repo bundle for
  IaC / dependency / secret findings without container layer fetch.
  Canonical artifact filename: ``trivy_fs.json`` (distinct from the
  image scanner's filename so both Trivy YAMLs can write into the same
  ``/out`` mount without collision when chained inside one job).

Both invocations share the exact same envelope shape (Trivy v0.50+):

.. code-block:: json

    {
      "ArtifactName": "registry.example/foo:1.2.3",
      "ArtifactType": "container_image",
      "Results": [
        {
          "Target":  "registry.example/foo:1.2.3 (debian 12.5)",
          "Class":   "os-pkgs",
          "Type":    "debian",
          "Vulnerabilities": [
            {
              "VulnerabilityID":   "CVE-2024-12345",
              "PkgName":           "openssl",
              "InstalledVersion":  "3.0.11-1~deb12u1",
              "FixedVersion":      "3.0.11-1~deb12u2",
              "Severity":          "HIGH",
              "Title":             "openssl: padding oracle in PKCS1 v1.5",
              "Description":       "...",
              "PrimaryURL":        "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
              "References":        ["https://...", "https://..."],
              "CweIDs":            ["CWE-310", "CWE-327"],
              "CVSS": {
                "nvd":    {"V3Vector": "CVSS:3.1/AV:N/...", "V3Score": 7.5},
                "redhat": {"V3Vector": "CVSS:3.1/AV:N/...", "V3Score": 6.5}
              }
            }
          ],
          "Misconfigurations": [
            {
              "Type":          "Dockerfile",
              "ID":            "DS002",
              "AVDID":         "AVD-DS-0002",
              "Title":         "Image user should not be 'root'",
              "Description":   "...",
              "Message":       "Specify at least 1 USER command in Dockerfile",
              "Namespace":     "builtin.dockerfile.DS002",
              "Resolution":    "Add 'USER non-root' before any sensitive ops",
              "Severity":      "HIGH",
              "PrimaryURL":    "https://avd.aquasec.com/misconfig/ds002",
              "References":    ["https://..."],
              "Status":        "FAIL",
              "CauseMetadata": {"StartLine": 5, "EndLine": 5}
            }
          ],
          "Secrets": [
            {
              "RuleID":      "github-pat",
              "Category":    "GitHub",
              "Title":       "GitHub Personal Access Token",
              "Severity":    "CRITICAL",
              "StartLine":   42,
              "EndLine":     42,
              "Match":       "ghp_*****REDACTED*****",
              "Code": {
                "Lines": [{"Number": 42, "Content": "...", "IsCause": true}]
              }
            }
          ]
        }
      ]
    }

Translation rules
-----------------

Common (all three result kinds):

* **Severity → confidence** — Trivy severity is high-precision (it comes
  from NVD / vendor advisories or, for misconfig, Aqua's own checks).
  Mapping:

  - ``CRITICAL`` / ``HIGH`` → ``LIKELY`` (NVD-confirmed CVE or signed
    advisory); secrets at ``CRITICAL`` escalate to ``CONFIRMED``
    because Trivy actually matched a high-entropy regex.
  - ``MEDIUM`` → ``LIKELY`` if a CVE id is present, ``SUSPECTED``
    otherwise (config-only).
  - ``LOW`` / ``UNKNOWN`` → ``SUSPECTED``.

* **Severity → CVSS score** — preferred source:

  1. ``Vulnerabilities[*].CVSS["nvd"].V3Score`` (NVD authoritative).
  2. Any other ``CVSS["<vendor>"].V3Score`` (first match in priority order).
  3. Severity-bucket sentinel from :data:`_SEVERITY_TO_CVSS`.

* **CVSS vector** — same priority as score; reject anything not matching
  the FindingDTO regex (``CVSS:[34].[0-9]/...``).

* **CWE list** — pulled from ``Vulnerabilities[*].CweIDs`` or the
  per-category default in :data:`_CATEGORY_DEFAULT_CWE` (Pydantic
  requires non-empty CWE).

* **OWASP-WSTG** — category-driven via :data:`_OWASP_BY_CATEGORY`;
  supply-chain CVEs land on ``WSTG-INFO-08`` (component identification),
  IaC misconfigs on ``WSTG-CONF-04``, secrets on ``WSTG-ATHN-06``.

Per result-kind specifics:

* **Vulnerabilities** (``Class=os-pkgs/lang-pkgs``) →
  :class:`FindingCategory.SUPPLY_CHAIN`. Evidence carries package
  name + installed version + fix version + CVE id(s) + primary URL.
* **Misconfigurations** (``Class=config``) → :class:`FindingCategory.MISCONFIG`.
  Records with ``Status="PASS"`` are dropped (Trivy emits passes for
  audit completeness; not findings). Evidence carries policy id +
  message + start/end line.
* **Secrets** (``Class=secret``) → :class:`FindingCategory.SECRET_LEAK`.
  Evidence carries rule id + category + truncated match (first 200
  bytes) + line number.

Dedup
-----

Stable key per kind:

* Vulnerabilities: ``("vuln", target, pkg_name, installed_version, vuln_id)``
* Misconfigurations: ``("misconfig", target, check_id, start_line)``
* Secrets:           ``("secret", target, rule_id, start_line, match_hash)``

A 12-char SHA-256 prefix of the secret match is folded into the dedup
key so two distinct secrets at the same line do not collapse, but the
secret value itself is never written into the dedup tuple (defence
against accidental log leaks).

Sorting is deterministic on a (severity desc → kind → key) tuple so two
runs against the same fixture produce byte-identical sidecars.

Cap
---

Hard-limited to :data:`_MAX_FINDINGS = 10_000` so a runaway scan over a
multi-thousand-package image (or a full mono-repo IaC tree) cannot
exhaust worker memory.

Sidecar
-------

Every emitted record is mirrored into
``artifacts_dir / "trivy_findings.jsonl"``. Each record carries its
source ``tool_id`` (``trivy_image`` or ``trivy_fs``) so the sidecar
stays demultiplexable.

Failure model
-------------

Fail-soft by contract:

* Missing canonical artifact (``trivy.json`` for ``trivy_image``,
  ``trivy_fs.json`` for ``trivy_fs``) falls back to stdout parsing.
* Malformed JSON returns ``[]`` after a structured warning.
* Unknown result class is logged and skipped.
* OS errors writing the sidecar are logged and swallowed.
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
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants — surfaced for tests + downstream evidence pipeline.
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "trivy_findings.jsonl"


# Hard cap on emitted findings. A trivy image scan over a 5k-package
# Debian base + a npm node_modules tree easily emits 8–9k records;
# 10k keeps the worker bounded against a misconfigured ignore-list.
_MAX_FINDINGS: Final[int] = 10_000


# Hard cap on the bytes we keep from a single ``Description`` /
# ``Message`` / ``Match`` blob in the evidence sidecar. Large enough
# to retain the human-readable summary without ballooning if the
# upstream record carries a multi-KB advisory text.
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


# Cap on the leading bytes of a leaked secret string carried into the
# dedup hash. We never write the raw match into the dedup key — only
# its 12-char SHA-256 prefix — so capping the input keeps the hash
# bounded against multi-MB false-positive matches.
_DEDUP_MATCH_PREFIX: Final[int] = 256


# CVSS regex prefixes — mirrors the FindingDTO contract
# (``CVSS:[34]\.[0-9]/...``). CVSS:2.0 vectors degrade to the sentinel
# (the FindingDTO would reject them anyway).
_CVSS_VECTOR_PREFIXES: Final[tuple[str, ...]] = ("CVSS:3.", "CVSS:4.")


# Trivy uses upper-case severities; normalise to lower for routing.
_NORMALISED_SEVERITY: Final[dict[str, str]] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
    "none": "info",
    "negligible": "low",
}


# Severity → CVSS v3.1 base score sentinel (used when the CVSS block is
# absent; Trivy does occasionally surface CVEs without a vector for
# language-ecosystem databases that did not land an NVD score yet).
# Values are anchored on Backlog/dev1_md §11 priority weighting.
_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.5,
    "low": 3.7,
    "info": 0.0,
}


# CVSS vendor priority — NVD wins over vendor-specific scoring because
# the FindingDTO's downstream Normaliser already speaks the NVD API for
# reconciliation. RHEL / Ghsa scores act as fallbacks.
_CVSS_VENDOR_PRIORITY: Final[tuple[str, ...]] = (
    "nvd",
    "ghsa",
    "redhat",
    "ubuntu",
    "vendor",
)


# Severity → ConfidenceLevel mapping. Vuln rows climb to ``LIKELY``
# above ``MEDIUM`` (NVD-confirmed); secrets at ``CRITICAL`` are bumped
# to ``CONFIRMED`` in the per-record builder.
_SEVERITY_CONFIDENCE: Final[dict[str, ConfidenceLevel]] = {
    "critical": ConfidenceLevel.LIKELY,
    "high": ConfidenceLevel.LIKELY,
    "medium": ConfidenceLevel.SUSPECTED,
    "low": ConfidenceLevel.SUSPECTED,
    "info": ConfidenceLevel.SUSPECTED,
}


# Per-category CWE backstop when Trivy did not surface a CWE id.
# Aligned with the §4.15 backlog hints + CWE Top-25 / Cloud-25 mapping.
_CATEGORY_DEFAULT_CWE: Final[dict[FindingCategory, tuple[int, ...]]] = {
    FindingCategory.SUPPLY_CHAIN: (1395,),  # vulnerable third-party component.
    FindingCategory.MISCONFIG: (16, 1032),  # security misconfiguration.
    FindingCategory.SECRET_LEAK: (798,),  # hard-coded credentials.
    FindingCategory.INFO: (200,),
}


# Per-category OWASP-WSTG hint tuples.
_OWASP_BY_CATEGORY: Final[dict[FindingCategory, tuple[str, ...]]] = {
    FindingCategory.SUPPLY_CHAIN: ("WSTG-INFO-08",),
    FindingCategory.MISCONFIG: ("WSTG-CONF-04",),
    FindingCategory.SECRET_LEAK: ("WSTG-ATHN-06", "WSTG-INFO-08"),
    FindingCategory.INFO: ("WSTG-INFO-08",),
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


# Per-tool canonical artifact filename. Both Trivy callers emit the
# same v2 envelope shape but write to distinct files so they can share
# a single ``/out`` mount when chained inside one job (Backlog §4.15;
# ``trivy_image.yaml`` writes ``-o /out/trivy.json`` and
# ``trivy_fs.yaml`` writes ``-o /out/trivy_fs.json``). Unknown tool_ids
# fall back to ``trivy.json`` for backwards-compat with any future
# caller registered without a dedicated filename mapping.
_CANONICAL_FILENAME_BY_TOOL: Final[dict[str, str]] = {
    "trivy_image": "trivy.json",
    "trivy_fs": "trivy_fs.json",
}
_DEFAULT_CANONICAL_FILENAME: Final[str] = "trivy.json"


# ---------------------------------------------------------------------------
# Public entry point — signature mandated by the dispatch layer:
# ``(stdout, stderr, artifacts_dir, tool_id) -> list[FindingDTO]``.
# ---------------------------------------------------------------------------


def parse_trivy_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate Trivy ``-f json`` output into FindingDTOs.

    Resolution order for the JSON blob:

    1. ``artifacts_dir / <canonical_filename>`` where
       ``<canonical_filename>`` is resolved from
       :data:`_CANONICAL_FILENAME_BY_TOOL` keyed on ``tool_id``:

       * ``trivy_image`` → ``trivy.json``
       * ``trivy_fs``    → ``trivy_fs.json``
       * unknown / future caller → falls back to ``trivy.json``

       Each Trivy YAML writes to its dedicated filename via
       ``-o /out/<filename>`` so two callers chained in one job never
       overwrite each other's evidence.
    2. ``stdout`` fallback — Trivy without ``-o`` streams the JSON to
       stdout instead.

    ``stderr`` is accepted for parser dispatch signature symmetry but
    intentionally not consumed (Trivy uses stderr for its progress bar /
    DB-update banner only). The ``tool_id`` is stamped on every emitted
    sidecar record so a single sidecar shared across ``trivy_image`` /
    ``trivy_fs`` stays demultiplexable.
    """
    del stderr
    payload = _load_payload(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        tool_id=tool_id,
    )
    if payload is None:
        return []
    records = list(_iter_normalised(payload, tool_id=tool_id))
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
    keyed: list[tuple[tuple[int, str, str], DedupKey, FindingDTO, str]] = []

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
                "trivy_parser.cap_reached",
                extra={
                    "event": "trivy_parser_cap_reached",
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
    """Stable dedup key for a normalised Trivy record."""
    kind = str(record.get("kind") or "vuln")
    target = str(record.get("target") or "")
    if kind == "vuln":
        return (
            kind,
            target,
            str(record.get("pkg_name") or ""),
            str(record.get("installed_version") or ""),
            str(record.get("vuln_id") or ""),
        )
    if kind == "misconfig":
        return (
            kind,
            target,
            str(record.get("check_id") or ""),
            str(record.get("start_line") or ""),
        )
    if kind == "secret":
        return (
            kind,
            target,
            str(record.get("rule_id") or ""),
            str(record.get("start_line") or ""),
            str(record.get("match_hash") or ""),
        )
    return (kind, target, str(record.get("name") or ""))


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str]:
    """Deterministic sort key (severity desc → kind → target)."""
    severity = str(record.get("severity", "info"))
    rank = _SEVERITY_RANK.get(severity, 0)
    return (
        -rank,
        str(record.get("kind") or ""),
        str(record.get("target") or ""),
    )


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    """Map a normalised Trivy record onto a :class:`FindingDTO`."""
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


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    """Build a compact evidence JSON for downstream redaction + persistence."""
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": record.get("kind"),
        "target": record.get("target"),
        "class": record.get("class"),
        "type": record.get("type"),
        "name": record.get("name"),
        "severity": record.get("severity"),
        "vuln_id": record.get("vuln_id"),
        "pkg_name": record.get("pkg_name"),
        "installed_version": record.get("installed_version"),
        "fixed_version": record.get("fixed_version"),
        "primary_url": record.get("primary_url"),
        "references": list(record.get("references") or ()),
        "cve": list(record.get("cve") or ()),
        "cwe": list(record.get("cwe") or ()),
        "cvss_v3_score": record.get("cvss_v3_score"),
        "cvss_v3_vector": record.get("cvss_v3_vector"),
        "cvss_source": record.get("cvss_source"),
        "epss_score": record.get("epss_score"),
        "check_id": record.get("check_id"),
        "namespace": record.get("namespace"),
        "message": _truncate_text(record.get("message")),
        "resolution": _truncate_text(record.get("resolution")),
        "start_line": record.get("start_line"),
        "end_line": record.get("end_line"),
        "rule_id": record.get("rule_id"),
        "secret_category": record.get("secret_category"),
        "match_preview": _truncate_text(record.get("match_preview")),
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
            "trivy_parser.evidence_sidecar_write_failed",
            extra={
                "event": "trivy_parser_evidence_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


# ---------------------------------------------------------------------------
# Payload resolution
# ---------------------------------------------------------------------------


def _load_payload(
    *,
    stdout: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> Any:
    """Resolve the per-tool canonical Trivy blob or fall back to stdout.

    The canonical filename is resolved through
    :data:`_CANONICAL_FILENAME_BY_TOOL` so each Trivy YAML
    (``trivy_image`` → ``trivy.json``, ``trivy_fs`` → ``trivy_fs.json``)
    reads exactly the file its sandbox wrapper wrote. Unknown tool_ids
    fall back to :data:`_DEFAULT_CANONICAL_FILENAME` so a future caller
    is parsed best-effort instead of returning ``[]`` silently.
    """
    canonical_name = _CANONICAL_FILENAME_BY_TOOL.get(
        tool_id, _DEFAULT_CANONICAL_FILENAME
    )
    canonical = _safe_join(artifacts_dir, canonical_name)
    if canonical is not None and canonical.is_file():
        try:
            raw = canonical.read_bytes()
        except OSError as exc:
            _logger.warning(
                "trivy_parser.canonical_read_failed",
                extra={
                    "event": "trivy_parser_canonical_read_failed",
                    "tool_id": tool_id,
                    "path": canonical_name,
                    "error_type": type(exc).__name__,
                },
            )
            raw = b""
        if raw.strip():
            payload = safe_load_json(raw, tool_id=tool_id)
            if payload is not None:
                return payload
    if stdout and stdout.strip():
        return safe_load_json(stdout, tool_id=tool_id)
    return None


def _safe_join(base: Path, name: str) -> Path | None:
    """Defensive ``base / name`` that refuses path-traversal segments."""
    if "/" in name or "\\" in name or ".." in name:
        return None
    return base / name


# ---------------------------------------------------------------------------
# Record normalisation — Vulnerabilities + Misconfigurations + Secrets
# ---------------------------------------------------------------------------


def _iter_normalised(
    payload: Any,
    *,
    tool_id: str,
) -> Iterable[dict[str, Any]]:
    """Yield normalised records from a Trivy ``-f json`` envelope."""
    if not isinstance(payload, dict):
        _logger.warning(
            "trivy_parser.envelope_not_dict",
            extra={
                "event": "trivy_parser_envelope_not_dict",
                "tool_id": tool_id,
            },
        )
        return
    results = payload.get("Results")
    if not isinstance(results, list):
        return
    for result in results:
        if not isinstance(result, dict):
            continue
        target = _string_field(result, "Target") or ""
        result_class = _string_field(result, "Class") or ""
        result_type = _string_field(result, "Type") or ""

        for raw_vuln in _ensure_list(result.get("Vulnerabilities")):
            normalised = _normalise_vulnerability(
                raw_vuln,
                target=target,
                result_class=result_class,
                result_type=result_type,
            )
            if normalised is not None:
                yield normalised

        for raw_mis in _ensure_list(result.get("Misconfigurations")):
            normalised = _normalise_misconfig(
                raw_mis,
                target=target,
                result_class=result_class,
                result_type=result_type,
            )
            if normalised is not None:
                yield normalised

        for raw_secret in _ensure_list(result.get("Secrets")):
            normalised = _normalise_secret(
                raw_secret,
                target=target,
                result_class=result_class,
                result_type=result_type,
            )
            if normalised is not None:
                yield normalised


def _normalise_vulnerability(
    raw: Any,
    *,
    target: str,
    result_class: str,
    result_type: str,
) -> dict[str, Any] | None:
    """Translate a single ``Vulnerabilities[]`` entry into our schema."""
    if not isinstance(raw, dict):
        return None
    vuln_id = _string_field(raw, "VulnerabilityID")
    pkg_name = _string_field(raw, "PkgName")
    if vuln_id is None or pkg_name is None:
        return None
    severity = _normalise_severity(_string_field(raw, "Severity"))
    cve_list = _extract_cve_list(vuln_id, raw.get("References"))
    cwe_list = _extract_cwe_list(raw.get("CweIDs"))
    cvss_score, cvss_vector, cvss_source = _extract_cvss(raw.get("CVSS"), severity)
    confidence = _classify_confidence(severity=severity, has_cve=bool(cve_list))
    references = _extract_references(raw.get("References"))
    return {
        "kind": "vuln",
        "category": FindingCategory.SUPPLY_CHAIN,
        "target": target,
        "class": result_class,
        "type": result_type,
        "vuln_id": vuln_id,
        "name": _string_field(raw, "Title") or vuln_id,
        "severity": severity,
        "pkg_name": pkg_name,
        "installed_version": _string_field(raw, "InstalledVersion"),
        "fixed_version": _string_field(raw, "FixedVersion"),
        "primary_url": _string_field(raw, "PrimaryURL"),
        "references": references,
        "cve": cve_list,
        "cwe": cwe_list,
        "cvss_v3_score": cvss_score,
        "cvss_v3_vector": cvss_vector,
        "cvss_source": cvss_source,
        "epss_score": None,
        "confidence": confidence,
        "owasp_wstg": _OWASP_BY_CATEGORY[FindingCategory.SUPPLY_CHAIN],
        "message": _string_field(raw, "Description"),
    }


def _normalise_misconfig(
    raw: Any,
    *,
    target: str,
    result_class: str,
    result_type: str,
) -> dict[str, Any] | None:
    """Translate a single ``Misconfigurations[]`` entry into our schema."""
    if not isinstance(raw, dict):
        return None
    status = _string_field(raw, "Status")
    if status and status.upper() == "PASS":
        return None
    check_id = _string_field(raw, "ID") or _string_field(raw, "AVDID")
    if check_id is None:
        return None
    severity = _normalise_severity(_string_field(raw, "Severity"))
    raw_cause = raw.get("CauseMetadata")
    cause: dict[str, Any] = raw_cause if isinstance(raw_cause, dict) else {}
    references = _extract_references(raw.get("References"))
    confidence = _classify_confidence(severity=severity, has_cve=False)
    return {
        "kind": "misconfig",
        "category": FindingCategory.MISCONFIG,
        "target": target,
        "class": result_class,
        "type": result_type,
        "check_id": check_id,
        "namespace": _string_field(raw, "Namespace"),
        "name": _string_field(raw, "Title") or check_id,
        "severity": severity,
        "primary_url": _string_field(raw, "PrimaryURL"),
        "references": references,
        "cwe": [],
        "cvss_v3_score": _SEVERITY_TO_CVSS.get(severity, 0.0),
        "cvss_v3_vector": SENTINEL_CVSS_VECTOR,
        "cvss_source": "trivy.severity",
        "epss_score": None,
        "confidence": confidence,
        "owasp_wstg": _OWASP_BY_CATEGORY[FindingCategory.MISCONFIG],
        "message": _string_field(raw, "Message") or _string_field(raw, "Description"),
        "resolution": _string_field(raw, "Resolution"),
        "start_line": _coerce_int(cause.get("StartLine")),
        "end_line": _coerce_int(cause.get("EndLine")),
    }


def _normalise_secret(
    raw: Any,
    *,
    target: str,
    result_class: str,
    result_type: str,
) -> dict[str, Any] | None:
    """Translate a single ``Secrets[]`` entry into our schema.

    Secrets get special handling:

    * The raw match is hashed (12-char SHA-256 prefix) for the dedup
      key so two distinct secrets at the same line stay distinct, but
      the secret value never enters the dedup tuple.
    * A truncated copy of the match (first 64 chars) lands in the
      sidecar as ``match_preview`` for operator triage; downstream
      redaction passes can scrub it further before it reaches PDF.
    * ``CRITICAL`` secret findings escalate to ``CONFIRMED`` because
      Trivy actually matched a high-entropy regex (vs. severity
      coming from a centralised Aqua advisory list).
    """
    if not isinstance(raw, dict):
        return None
    rule_id = _string_field(raw, "RuleID")
    if rule_id is None:
        return None
    severity = _normalise_severity(_string_field(raw, "Severity"))
    match = _string_field(raw, "Match") or ""
    match_hash = _stable_hash(match[:_DEDUP_MATCH_PREFIX]) if match else ""
    confidence = _classify_confidence(severity=severity, has_cve=False)
    if severity == "critical":
        confidence = ConfidenceLevel.CONFIRMED
    return {
        "kind": "secret",
        "category": FindingCategory.SECRET_LEAK,
        "target": target,
        "class": result_class,
        "type": result_type,
        "rule_id": rule_id,
        "secret_category": _string_field(raw, "Category"),
        "name": _string_field(raw, "Title") or rule_id,
        "severity": severity,
        "primary_url": None,
        "references": (),
        "cwe": [],
        "cvss_v3_score": _SEVERITY_TO_CVSS.get(severity, 0.0),
        "cvss_v3_vector": SENTINEL_CVSS_VECTOR,
        "cvss_source": "trivy.severity",
        "epss_score": None,
        "confidence": confidence,
        "owasp_wstg": _OWASP_BY_CATEGORY[FindingCategory.SECRET_LEAK],
        "match_preview": _redact_secret(match),
        "match_hash": match_hash,
        "start_line": _coerce_int(raw.get("StartLine")),
        "end_line": _coerce_int(raw.get("EndLine")),
    }


# ---------------------------------------------------------------------------
# Helpers — field accessors / classifiers / coercers
# ---------------------------------------------------------------------------


def _ensure_list(value: Any) -> list[Any]:
    """Return ``value`` if it's a list, else an empty list."""
    return value if isinstance(value, list) else []


def _string_field(record: dict[str, Any], key: str) -> str | None:
    """Return ``record[key]`` if it is a non-empty string, else ``None``."""
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _normalise_severity(raw: str | None) -> str:
    """Coerce a Trivy severity string into the canonical bucket."""
    if raw is None:
        return "info"
    return _NORMALISED_SEVERITY.get(raw.strip().lower(), "info")


def _classify_confidence(*, severity: str, has_cve: bool) -> ConfidenceLevel:
    """Pick the :class:`ConfidenceLevel` for a record."""
    base = _SEVERITY_CONFIDENCE.get(severity, ConfidenceLevel.SUSPECTED)
    if severity == "medium" and has_cve:
        return ConfidenceLevel.LIKELY
    return base


def _extract_cve_list(vuln_id: str, references: Any) -> tuple[str, ...]:
    """Return a sorted, deduplicated tuple of CVE ids.

    Trivy stores the canonical CVE in ``VulnerabilityID``; some advisories
    list additional CVE aliases in ``References`` (e.g. RHSA-2024-1234
    referencing CVE-2024-12345). Both surface in the tuple.
    """
    candidates: list[str] = []
    candidates.append(vuln_id)
    if isinstance(references, list):
        for ref in references:
            if isinstance(ref, str) and "CVE-" in ref.upper():
                candidates.append(ref)
    normalised = {_normalise_cve(c) for c in candidates if c}
    return tuple(sorted(c for c in normalised if c))


def _normalise_cve(raw: str) -> str:
    """Coerce a CVE token into the canonical ``CVE-YYYY-NNNN+`` form.

    Returns ``""`` for invalid tokens (rejected upstream by the dedup
    + sidecar layer). Identical contract to the Nuclei parser so the
    Normaliser sees uniform CVE shapes.
    """
    candidate = raw.strip().upper()
    if not candidate:
        return ""
    if "CVE-" not in candidate:
        return ""
    idx = candidate.find("CVE-")
    body = candidate[idx + 4 :]
    parts = body.split("-", 1)
    if len(parts) != 2:
        return ""
    year_part = parts[0]
    seq_part = parts[1]
    seq_digits: list[str] = []
    for ch in seq_part:
        if ch.isdigit():
            seq_digits.append(ch)
        else:
            break
    if not (year_part.isdigit() and len(year_part) == 4 and int(year_part) >= 1999):
        return ""
    if len(seq_digits) < 4:
        return ""
    return f"CVE-{year_part}-{''.join(seq_digits)}"


def _extract_cwe_list(raw: Any) -> list[int]:
    """Return a sorted, deduplicated list of CWE ids (positive integers)."""
    collected: list[int] = []
    if isinstance(raw, list):
        for item in raw:
            cwe_id = _coerce_cwe(item)
            if cwe_id is not None:
                collected.append(cwe_id)
    elif isinstance(raw, str | int):
        cwe_id = _coerce_cwe(raw)
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


def _extract_cvss(
    raw: Any,
    severity: str,
) -> tuple[float, str, str | None]:
    """Return ``(score, vector, source)`` from a Trivy ``CVSS`` block.

    Walks vendors in :data:`_CVSS_VENDOR_PRIORITY` order; the first
    vendor with a valid ``V3Score`` and ``V3Vector`` wins. If no
    vendor surfaces a usable score, we fall back to the severity-bucket
    sentinel from :data:`_SEVERITY_TO_CVSS` so the FindingDTO never
    lands at a zeroed-out vector for a HIGH-severity record.
    """
    if isinstance(raw, dict):
        for vendor in _CVSS_VENDOR_PRIORITY:
            block = raw.get(vendor)
            if not isinstance(block, dict):
                continue
            score = _coerce_float(block.get("V3Score"))
            vector_raw = block.get("V3Vector")
            if score is None or not (0.0 <= score <= 10.0):
                continue
            vector = (
                vector_raw.strip()
                if isinstance(vector_raw, str) and vector_raw.strip()
                else SENTINEL_CVSS_VECTOR
            )
            if not any(vector.startswith(prefix) for prefix in _CVSS_VECTOR_PREFIXES):
                vector = SENTINEL_CVSS_VECTOR
            return score, vector, vendor
        for vendor, block in raw.items():
            if not isinstance(block, dict):
                continue
            score = _coerce_float(block.get("V3Score"))
            vector_raw = block.get("V3Vector")
            if score is None or not (0.0 <= score <= 10.0):
                continue
            vector = (
                vector_raw.strip()
                if isinstance(vector_raw, str) and vector_raw.strip()
                else SENTINEL_CVSS_VECTOR
            )
            if not any(vector.startswith(prefix) for prefix in _CVSS_VECTOR_PREFIXES):
                vector = SENTINEL_CVSS_VECTOR
            return score, vector, str(vendor)
    return (
        _SEVERITY_TO_CVSS.get(severity, SENTINEL_CVSS_SCORE),
        SENTINEL_CVSS_VECTOR,
        "trivy.severity",
    )


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


def _coerce_int(value: Any) -> int | None:
    """Coerce ``value`` into a positive int (or ``None``)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.strip().isdigit():
        candidate = int(value.strip())
        return candidate if candidate >= 0 else None
    return None


def _truncate_text(text: str | None) -> str | None:
    """Cap a single string at :data:`_MAX_EVIDENCE_BYTES` UTF-8 bytes."""
    if text is None or text == "":
        return None
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_EVIDENCE_BYTES:
        return text
    truncated = encoded[:_MAX_EVIDENCE_BYTES].decode("utf-8", errors="replace")
    return truncated + "...[truncated]"


def _redact_secret(match: str) -> str | None:
    """Return a redacted preview of a secret match.

    Keeps the leading 8 chars (typically the token type prefix, e.g.
    ``ghp_``, ``AKIA``, ``sk_live_``) and replaces the rest with a
    masked marker. This gives operators enough signal for triage while
    keeping the raw secret out of the sidecar.
    """
    if not match:
        return None
    prefix_len = min(8, max(0, len(match) - 4))
    if prefix_len <= 0:
        return "***REDACTED***"
    return match[:prefix_len] + "***REDACTED***"


def _stable_hash(text: str) -> str:
    """Return a cross-process deterministic 12-char hex digest of ``text``.

    Mirrors the contract used by ``nuclei_parser._stable_hash`` /
    ``dalfox_parser._stable_hash``: SHA-256 truncated to 12 hex chars
    so dedup keys stay byte-identical across CI workers regardless of
    PYTHONHASHSEED.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_trivy_json",
]
