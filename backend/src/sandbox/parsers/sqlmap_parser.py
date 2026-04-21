"""Parser for sqlmap text-log output (Backlog/dev1_md §4.9 — ARG-016).

§4.9 ships six SQL-injection scanners; this module covers the two that
share the canonical sqlmap CLI shape:

* **sqlmap_safe** (``--technique=BT --level 2 --risk 1 --safe-url=...
  --output-dir=/out/sqlmap``) — passive boolean / time-based detection.
* **sqlmap_confirm** (``--technique=E --dbs --count
  --output-dir=/out/sqlmap_confirm``) — error-based exploitation pass
  (gated behind ``requires_approval=true``).

Both wrappers materialise the same on-disk artifact tree under
``--output-dir`` (note the ``=`` is required; sqlmap rejects whitespace
between the flag and value):

* ``<output-dir>/<host_or_ip>/log`` — the line-based attack log
  (canonical source for the parser).
* ``<output-dir>/<host_or_ip>/session.sqlite`` — internal state DB.
* ``<output-dir>/<host_or_ip>/target.txt`` — target summary.

The remaining four §4.9 tools (``ghauri``, ``jsql``, ``tplmap``,
``nosqlmap``) ship without parsers in Cycle 2: their YAMLs declare
``parse_strategy=text_lines`` (or ``json_object`` for jsql), and the
dispatch layer emits ``parsers.dispatch.unmapped_tool`` for now.

Output shape per parsed record
------------------------------
For each ``Parameter: <name> ...`` block in the sqlmap log/stdout the
parser collapses every reported injection technique into a single
finding family per ``(target_url, parameter_name, parameter_location)``:
sqlmap may report 4-5 sub-techniques on the same parameter (boolean
blind, error-based, UNION, time-based) and they are the same
underlying SQLi — keeping one per ``(url, param, location)`` keeps
the operator inbox flat while preserving every technique in the
evidence sidecar.

* ``severity`` is implicit through the CVSS sentinel; downstream
  Normalizer / SSVC raise it via the CWE-89 + CVE lookup path.
* ``category`` → :class:`FindingCategory.SQLI` for SQL injection,
  :class:`FindingCategory.NOSQLI` only when the log explicitly mentions
  a NoSQL DBMS (this parser also tolerates the wider §4.9 family,
  but ``sqlmap_*`` itself is SQLi-only).
* ``confidence`` → :attr:`ConfidenceLevel.CONFIRMED` because sqlmap
  only flags an injection point after a positive payload round-trip.
* ``cwe`` → ``[89]`` (CWE-89: Improper Neutralization of Special
  Elements used in an SQL Command).
* ``owasp_wstg`` → ``["WSTG-INPV-05"]`` (Testing for SQL Injection).

Dedup
-----
Records collapse on a stable key:

* ``(target_url, parameter_name, parameter_location)``

Sorting is deterministic on that triple so two runs against the same
fixture produce byte-identical sidecars.

Hard cap at :data:`_MAX_FINDINGS` defends the worker against a
runaway sqlmap run that surfaces every known DBMS / technique
permutation against an enumeration-heavy target.

Sidecar
-------
Every emitted record is mirrored into
``artifacts_dir / "sqlmap_findings.jsonl"`` for the downstream
evidence pipeline. Each record carries its source ``tool_id``
(``sqlmap_safe`` or ``sqlmap_confirm``).

Failure model
-------------
Fail-soft by contract:

* Missing ``<output-dir>/.../log`` files fall back to stdout parsing.
* Unreadable log files are logged via
  ``sqlmap_parser.canonical_read_failed`` and the parser carries on
  with stdout only.
* Empty / oversized inputs return ``[]`` after a structured warning.
* OS errors writing the sidecar are logged via
  ``sqlmap_parser.evidence_sidecar_write_failed`` and swallowed.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import (
    MAX_STDOUT_BYTES,
    make_finding_dto,
    safe_decode,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants — surfaced for tests + downstream evidence pipeline.
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "sqlmap_findings.jsonl"


# Hard cap on emitted findings. A wildcard target with ``--crawl`` set
# legitimately surfaces hundreds of injectable parameters; capping
# defends the worker against a runaway scan.
_MAX_FINDINGS: Final[int] = 5_000


# Hard cap on individual evidence fields kept verbatim. Keeps the
# sidecar bounded even when sqlmap echoes a 50 KiB payload chain.
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


# Hard cap on the per-host log file size we will read. Mirrors the
# stdout cap; sqlmap can produce a 100+ MiB log on long-running scans
# and we do not want a single host log to dominate worker memory.
_MAX_LOG_BYTES: Final[int] = MAX_STDOUT_BYTES


# Compiled line patterns. The ``[XX:YY:ZZ]`` timestamp prefix is sqlmap's
# default and always present on the log lines; we keep the regex
# tolerant (timestamp is optional) so stdout-only runs still parse.
# A leading ``\s*`` accepts the 4-space indentation sqlmap applies to
# ``Type:`` / ``Title:`` / ``Payload:`` lines inside a Parameter block.
_LEADING = r"^\s*"
_TS_PREFIX = r"(?:\[[0-9:]{8}\]\s*)?"

# ``[INFO|WARNING|CRITICAL|ERROR|DEBUG] heading: ...`` style markers.
_LEVEL_PREFIX = r"(?:\[[A-Z]+\]\s*)?"


_PARAM_RE: Final[re.Pattern[str]] = re.compile(
    rf"{_LEADING}{_TS_PREFIX}{_LEVEL_PREFIX}Parameter:\s+(?P<param>[^\s(]+)\s*"
    r"\((?P<location>[A-Za-z][A-Za-z0-9_-]*)\)\s*$",
)

_TYPE_RE: Final[re.Pattern[str]] = re.compile(
    rf"{_LEADING}{_TS_PREFIX}{_LEVEL_PREFIX}Type:\s+(?P<type>.+?)\s*$",
)

_TITLE_RE: Final[re.Pattern[str]] = re.compile(
    rf"{_LEADING}{_TS_PREFIX}{_LEVEL_PREFIX}Title:\s+(?P<title>.+?)\s*$",
)

_PAYLOAD_RE: Final[re.Pattern[str]] = re.compile(
    rf"{_LEADING}{_TS_PREFIX}{_LEVEL_PREFIX}Payload:\s+(?P<payload>.+?)\s*$",
)

# ``[INFO] testing connection to the target URL`` precedes the URL line
# in stdout; we capture the explicit ``URL: ...`` and ``GET parameter`` /
# ``POST parameter`` headings too.
_TARGET_URL_RE: Final[re.Pattern[str]] = re.compile(
    rf"{_LEADING}{_TS_PREFIX}{_LEVEL_PREFIX}URL:\s+(?P<url>https?://\S+)\s*$",
)

_TESTING_TARGET_RE: Final[re.Pattern[str]] = re.compile(
    rf"{_LEADING}{_TS_PREFIX}{_LEVEL_PREFIX}testing connection to the target URL:?\s+"
    r"(?P<url>https?://\S+)\s*$",
    re.IGNORECASE,
)

# ``the back-end DBMS is MySQL`` (post-detection) and
# ``[CRITICAL] back-end DBMS is MySQL`` variants.
_DBMS_RE: Final[re.Pattern[str]] = re.compile(
    rf"{_LEADING}{_TS_PREFIX}{_LEVEL_PREFIX}(?:the\s+)?"
    r"back-end DBMS is\s+(?P<dbms>.+?)\s*$",
    re.IGNORECASE,
)


# Stable dedup key shape: (target_url, param_name, param_location). Exposed
# as a module-level alias so the dedup loop and ``_dedup_key`` share a
# single canonical type instead of repeating ``tuple[str, str, str]``
# inline in three places.
DedupKey: TypeAlias = tuple[str, str, str]


# Technique → CVSS v3.1 base score map (ARG-016/017 reviewer H1).
#
# Sqlmap only lists a parameter once it has confirmed a working injection,
# so every record this parser emits is a ``CONFIRMED`` SQLi by definition.
# The score is therefore lifted above the parser-layer sentinel
# ``cvss_v3_score=0.0`` so the downstream :class:`Prioritizer` does not
# flatten verified injections to :attr:`PriorityTier.P4_INFO`.
#
# The technique-specific anchors reflect the realistic blast radius
# documented in Backlog/dev1_md §11 priority weighting:
#
# * ``stacked queries`` (9.5)        — write primitive, often gives
#   arbitrary INSERT / UPDATE on the target schema.
# * ``UNION query`` (9.1)            — full data exfiltration possible
#   in a single round-trip.
# * ``error-based`` (8.8)            — fast, reliable exfiltration via
#   crafted error messages.
# * ``boolean-based blind`` (8.5)    — slow but reliable exfiltration.
# * ``time-based blind`` (8.5)       — slow but reliable exfiltration
#   when error / UNION channels are blocked.
# * ``inline queries`` (8.5)         — sub-select primitive.
#
# The keys are matched case-insensitively against the lower-cased
# ``Type:`` strings sqlmap emits ("UNION query", "boolean-based blind",
# …). Unknown techniques default to :data:`_SQLMAP_DEFAULT_CVSS` (8.5)
# which is the conservative confirmed-SQLi baseline.
_SQLMAP_TYPE_TO_CVSS: Final[dict[str, float]] = {
    "stacked queries": 9.5,
    "union query": 9.1,
    "error-based": 8.8,
    "boolean-based blind": 8.5,
    "time-based blind": 8.5,
    "inline queries": 8.5,
}
_SQLMAP_DEFAULT_CVSS: Final[float] = 8.5


# ---------------------------------------------------------------------------
# Public entry point — signature mandated by the dispatch layer:
# ``(stdout, stderr, artifacts_dir, tool_id) -> list[FindingDTO]``.
# ---------------------------------------------------------------------------


def parse_sqlmap_output(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate sqlmap line-log output into FindingDTOs.

    Resolution order for the line-log payload:

    1. ``artifacts_dir/sqlmap*/<host>/log`` (canonical: sqlmap writes
       per-host log files there when invoked with
       ``--output-dir=/out/sqlmap[_confirm]``). Multiple host
       directories are concatenated in lexicographic order so two
       runs against the same target are byte-identical.
    2. ``stdout`` fallback (some operators run sqlmap without
       ``--output-dir`` so the report lands on stdout instead).

    ``stderr`` is accepted for parser dispatch signature symmetry but
    intentionally not consumed — sqlmap reserves stderr for its own
    banners and the operator-facing progress bar; nothing finding-
    relevant lands there.
    """
    del stderr
    text = _resolve_log_text(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        tool_id=tool_id,
    )
    if not text:
        return []
    records = list(_iter_sqlmap_records(text))
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
    """Common pipeline: dedup → cap → sort → build FindingDTO + sidecar.

    Mirrors the ``_emit`` helpers in ``wpscan_parser`` / ``nuclei_parser``
    so the §4.9 sqlmap parser shares the same dedup / cap / sort
    semantics as the rest of the parsers package.
    """

    seen: dict[DedupKey, dict[str, Any]] = {}
    order: list[DedupKey] = []

    for record in records:
        key = _dedup_key(record)
        existing = seen.get(key)
        if existing is None:
            seen[key] = _clone_record(record)
            order.append(key)
            if len(seen) >= _MAX_FINDINGS:
                _logger.warning(
                    "sqlmap_parser.cap_reached",
                    extra={
                        "event": "sqlmap_parser_cap_reached",
                        "tool_id": tool_id,
                        "cap": _MAX_FINDINGS,
                    },
                )
                break
            continue
        _merge_record(existing, record)

    order.sort()

    keyed: list[tuple[DedupKey, FindingDTO, str]] = []
    for key in order:
        record = seen[key]
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        keyed.append((key, finding, evidence_blob))

    if keyed:
        _persist_evidence_sidecar(
            artifacts_dir,
            tool_id=tool_id,
            evidence_records=[blob for _, _, blob in keyed],
        )
    return [finding for _, finding, _ in keyed]


def _dedup_key(record: dict[str, Any]) -> DedupKey:
    """Build a stable dedup key for a normalised record.

    ``(target_url, param_name, param_location)`` collapses every
    sub-technique sqlmap reports against the same injectable parameter
    onto a single finding while preserving every technique inside the
    evidence sidecar.
    """
    url = str(record.get("target_url", ""))
    param = str(record.get("param", ""))
    location = str(record.get("location", ""))
    return (url, param, location)


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    """Map a normalised record to a CONFIRMED SQLi FindingDTO.

    Lifts ``cvss_v3_score`` from :data:`_SQLMAP_TYPE_TO_CVSS` so the
    downstream :class:`Prioritizer` can place the verified injection
    above :attr:`PriorityTier.P4_INFO` (ARG-016/017 reviewer H1).

    When sqlmap reports several techniques against the same parameter
    (the dedup loop folds them onto a single record), the highest
    matching technique CVSS wins — sqlmap-confirmed escalation paths
    like ``stacked queries`` should not be diluted by a co-detected
    boolean-based blind technique.
    """
    return make_finding_dto(
        category=FindingCategory.SQLI,
        cwe=[89],
        cvss_v3_score=_max_cvss_for_techniques(record.get("techniques") or []),
        owasp_wstg=["WSTG-INPV-05"],
        confidence=ConfidenceLevel.CONFIRMED,
    )


def _max_cvss_for_techniques(techniques: Iterable[Any]) -> float:
    """Return the highest CVSS score across ``techniques``.

    Falls back to :data:`_SQLMAP_DEFAULT_CVSS` when no technique is
    recognised — the parser still treats it as a confirmed SQLi.
    """
    best = _SQLMAP_DEFAULT_CVSS
    matched = False
    for raw in techniques:
        if not isinstance(raw, str):
            continue
        score = _SQLMAP_TYPE_TO_CVSS.get(raw.strip().lower())
        if score is None:
            continue
        matched = True
        if score > best:
            best = score
    return best if matched else _SQLMAP_DEFAULT_CVSS


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    """Build a compact evidence JSON for downstream redaction + persistence."""
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "sqlmap_injection",
        "target_url": record.get("target_url"),
        "parameter": record.get("param"),
        "location": record.get("location"),
        "techniques": _sorted_unique(record.get("techniques") or []),
        "titles": _sorted_unique(record.get("titles") or []),
        "payloads": _truncate_list(record.get("payloads") or []),
        "dbms": record.get("dbms"),
        "log_excerpt": _truncate_text(record.get("log_excerpt") or ""),
        "synthetic_id": _stable_hash(
            f"{record.get('target_url', '')}::"
            f"{record.get('param', '')}::"
            f"{record.get('location', '')}"
        ),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None:
            continue
        if isinstance(value, list | tuple) and not value:
            continue
        if value == "":
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
            "sqlmap_parser.evidence_sidecar_write_failed",
            extra={
                "event": "sqlmap_parser_evidence_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


# ---------------------------------------------------------------------------
# Record extraction
# ---------------------------------------------------------------------------


def _iter_sqlmap_records(text: str) -> Iterable[dict[str, Any]]:
    """Yield normalised records by streaming the sqlmap log line-by-line.

    State machine:

    * ``Parameter: <name> (GET|POST|COOKIE|HEADER|...)`` opens a new
      block. Any unfinished block is flushed first.
    * Subsequent ``Type:``, ``Title:``, ``Payload:`` lines fold into
      the open block.
    * ``URL: ...`` / ``testing connection to the target URL: ...`` /
      ``the back-end DBMS is ...`` carry over to every subsequent
      block (they are scan-scoped, not parameter-scoped).
    * A blank line is *not* a delimiter: sqlmap interleaves status
      banners between blocks. We close a block when the next
      ``Parameter:`` arrives.
    """
    target_url: str | None = None
    dbms: str | None = None
    current: dict[str, Any] | None = None
    log_excerpt_lines: list[str] = []

    def _flush() -> dict[str, Any] | None:
        nonlocal current, log_excerpt_lines
        if current is None:
            return None
        # Snapshot the excerpt and reset for the next block.
        current["log_excerpt"] = "\n".join(log_excerpt_lines)
        log_excerpt_lines = []
        snap = current
        current = None
        return snap

    for line in text.splitlines():
        stripped = line.rstrip()
        if not stripped:
            if current is not None:
                log_excerpt_lines.append(stripped)
            continue

        # Carry-over scan-scoped fields.
        url_match = _TARGET_URL_RE.match(stripped) or _TESTING_TARGET_RE.match(stripped)
        if url_match:
            target_url = url_match.group("url")
            if current is not None:
                log_excerpt_lines.append(stripped)
            continue

        dbms_match = _DBMS_RE.match(stripped)
        if dbms_match:
            dbms_value = dbms_match.group("dbms").strip()
            # Trim trailing "is" / "(version ...)" noise to a single token
            # for the dedup-friendly evidence summary.
            dbms = dbms_value.split("(")[0].strip() or dbms_value
            if current is not None:
                current.setdefault("dbms", dbms)
                log_excerpt_lines.append(stripped)
            continue

        param_match = _PARAM_RE.match(stripped)
        if param_match:
            done = _flush()
            if done is not None:
                yield done
            current = {
                "target_url": target_url or "",
                "param": param_match.group("param"),
                "location": param_match.group("location"),
                "techniques": [],
                "titles": [],
                "payloads": [],
                "dbms": dbms,
            }
            log_excerpt_lines = [stripped]
            continue

        if current is None:
            # Skip status banners before the first Parameter: block.
            continue

        type_match = _TYPE_RE.match(stripped)
        if type_match:
            current["techniques"].append(type_match.group("type").strip())
            log_excerpt_lines.append(stripped)
            continue

        title_match = _TITLE_RE.match(stripped)
        if title_match:
            current["titles"].append(title_match.group("title").strip())
            log_excerpt_lines.append(stripped)
            continue

        payload_match = _PAYLOAD_RE.match(stripped)
        if payload_match:
            current["payloads"].append(payload_match.group("payload").strip())
            log_excerpt_lines.append(stripped)
            continue

        log_excerpt_lines.append(stripped)

    done = _flush()
    if done is not None:
        yield done


# ---------------------------------------------------------------------------
# Helpers — log file resolution
# ---------------------------------------------------------------------------


def _resolve_log_text(
    *,
    stdout: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> str:
    """Resolve the canonical sqlmap log payload or fall back to stdout.

    Walks ``artifacts_dir/sqlmap*/<host>/log`` recursively (sqlmap
    writes one log file per scanned host beneath the user-supplied
    ``--output-dir``). Files are concatenated in lexicographic order
    for determinism. Stdout is the fallback when no log files are
    discoverable / readable.
    """
    log_text = _read_log_files(artifacts_dir, tool_id=tool_id)
    if log_text:
        return log_text
    return safe_decode(stdout, limit=MAX_STDOUT_BYTES)


def _read_log_files(artifacts_dir: Path, *, tool_id: str) -> str:
    """Read every ``sqlmap*/<host>/log`` under ``artifacts_dir`` deterministically.

    Returns the concatenation of every log file found (lexicographic
    order). Skips path-traversal-tainted directory names defensively.
    Unreadable individual files are logged and skipped — one corrupt
    host directory does not poison the rest of the run.
    """
    if not isinstance(artifacts_dir, Path):
        return ""
    if not artifacts_dir.is_dir():
        return ""

    chunks: list[str] = []
    total = 0
    try:
        # Match both ``sqlmap`` (sqlmap_safe) and ``sqlmap_confirm``
        # output dir names; the wildcard is bounded to the first level
        # of nesting beneath ``artifacts_dir``.
        roots = sorted(p for p in artifacts_dir.glob("sqlmap*") if p.is_dir())
    except OSError as exc:
        _logger.warning(
            "sqlmap_parser.canonical_glob_failed",
            extra={
                "event": "sqlmap_parser_canonical_glob_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )
        return ""

    for root in roots:
        try:
            host_dirs = sorted(p for p in root.iterdir() if p.is_dir())
        except OSError:
            continue
        for host_dir in host_dirs:
            if _is_unsafe_segment(host_dir.name):
                continue
            log_path = host_dir / "log"
            if not log_path.is_file():
                continue
            try:
                size = log_path.stat().st_size
            except OSError:
                continue
            if size <= 0:
                continue
            if total + size > _MAX_LOG_BYTES:
                _logger.warning(
                    "sqlmap_parser.log_size_cap_reached",
                    extra={
                        "event": "sqlmap_parser_log_size_cap_reached",
                        "tool_id": tool_id,
                        "path": str(log_path),
                        "cap": _MAX_LOG_BYTES,
                    },
                )
                break
            try:
                raw = log_path.read_bytes()
            except OSError as exc:
                _logger.warning(
                    "sqlmap_parser.canonical_read_failed",
                    extra={
                        "event": "sqlmap_parser_canonical_read_failed",
                        "tool_id": tool_id,
                        "path": str(log_path),
                        "error_type": type(exc).__name__,
                    },
                )
                continue
            chunks.append(safe_decode(raw, limit=_MAX_LOG_BYTES))
            total += size
        else:
            continue
        break
    return "\n".join(c for c in chunks if c)


def _is_unsafe_segment(name: str) -> bool:
    """Refuse ``..`` / path separators as a directory segment name."""
    return ".." in name or "/" in name or "\\" in name


# ---------------------------------------------------------------------------
# Helpers — record merging / cleanup
# ---------------------------------------------------------------------------


def _clone_record(record: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy with deduplicated list fields."""
    return {
        "target_url": record.get("target_url", ""),
        "param": record.get("param", ""),
        "location": record.get("location", ""),
        "techniques": list(record.get("techniques") or []),
        "titles": list(record.get("titles") or []),
        "payloads": list(record.get("payloads") or []),
        "dbms": record.get("dbms"),
        "log_excerpt": record.get("log_excerpt") or "",
    }


def _merge_record(existing: dict[str, Any], incoming: dict[str, Any]) -> None:
    """Fold ``incoming`` into ``existing`` (same dedup key).

    Sqlmap typically emits the same ``Parameter: <name>`` block once per
    detected technique. We collect every technique / title / payload
    into the existing record so the evidence sidecar carries the full
    technique chain, while ``_emit`` still only produces one
    FindingDTO per ``(url, param, location)``.
    """
    existing["techniques"].extend(incoming.get("techniques") or [])
    existing["titles"].extend(incoming.get("titles") or [])
    existing["payloads"].extend(incoming.get("payloads") or [])
    if not existing.get("dbms") and incoming.get("dbms"):
        existing["dbms"] = incoming["dbms"]
    incoming_excerpt = incoming.get("log_excerpt") or ""
    if incoming_excerpt and incoming_excerpt not in (existing.get("log_excerpt") or ""):
        existing["log_excerpt"] = (
            (existing.get("log_excerpt") or "") + "\n" + incoming_excerpt
        ).strip()


def _sorted_unique(values: Iterable[str]) -> list[str]:
    """Return the de-duplicated, sorted list of non-empty trimmed strings."""
    seen: set[str] = set()
    out: list[str] = []
    for raw in values:
        if not isinstance(raw, str):
            continue
        token = raw.strip()
        if not token or token in seen:
            continue
        seen.add(token)
        out.append(token)
    out.sort()
    return out


def _truncate_list(values: Iterable[str]) -> list[str]:
    """Return a deduplicated, length-capped projection of ``values``."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in values:
        if not isinstance(raw, str):
            continue
        text = _truncate_text(raw)
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    out.sort()
    return out


def _truncate_text(text: str) -> str:
    """Cap a single string at :data:`_MAX_EVIDENCE_BYTES` UTF-8 bytes."""
    if not text:
        return ""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_EVIDENCE_BYTES:
        return text
    truncated = encoded[:_MAX_EVIDENCE_BYTES]
    return truncated.decode("utf-8", errors="replace") + "...[truncated]"


def _stable_hash(text: str) -> str:
    """Return a cross-process deterministic 12-char hex digest of ``text``.

    Mirrors ``nuclei_parser._stable_hash``: ``hash()`` is randomised
    per-interpreter (PYTHONHASHSEED) and would make sidecar bytes
    non-reproducible across CI workers. SHA-256 truncated to 12 hex
    chars (48 bits) is collision-safe for the realistic upper bound of
    sqlmap findings per scan and stays constant across processes /
    operating systems.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_sqlmap_output",
]
