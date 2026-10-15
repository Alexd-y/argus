"""Per-artifact accounting ledger (Wave 4 / Stage 1 — R-6.1.1 / R-6.1.2 / R-7.2).

The wave's core invariant: *every artifact a scan produced is accounted for in the
report exactly once*. This module reconciles the artifacts a scan actually stored
(Evidence rows, tool-run outputs) against what the report references, and assigns
each one exactly one of three states:

* ``presented`` — its reference (evidence id or storage key) reaches the report;
* ``excluded`` — deliberately left out, with a **closed-enum** reason (never free
  text): duplicate / size-limit / tenant-policy / service-output / empty-artifact;
* ``unprocessed`` — neither presented nor excluded. An ``unprocessed`` artifact is
  a *release blocker* (R-6.1.2): the scan collected something the report silently
  dropped, which is exactly the completeness failure this wave closes.

Pure + deterministic: no DB, no I/O. The pipeline builds the input records from the
DB, computes the referenced sets from the canonical snapshot, calls
:func:`build_artifact_ledger`, persists the result, and feeds
:func:`ledger_release_blockers` into the fail-closed release gate.

Client-safety note: a :class:`LedgerEntry` deliberately carries the opaque
``evidence_id`` for display and keeps the internal ``object_key`` only for
persistence / de-duplication — the rendered appendix must never print the storage
key (it is an internal path; the content-parity C-29 gate blocks such a leak).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from enum import StrEnum


class LedgerState(StrEnum):
    """The three — and only three — accounting states (R-6.1.2)."""

    UNPROCESSED = "unprocessed"
    PRESENTED = "presented"
    EXCLUDED = "excluded"


class ExclusionReason(StrEnum):
    """Closed vocabulary of why an artifact is legitimately left out (R-6.1.1).

    Adding a reason is a deliberate contract change; free-text reasons are forbidden
    so "excluded" can never become a silent catch-all.
    """

    DUPLICATE = "duplicate"
    SIZE_LIMIT = "size_limit"
    TENANT_POLICY = "tenant_policy"
    SERVICE_OUTPUT = "service_output"
    EMPTY_ARTIFACT = "empty_artifact"


@dataclass(frozen=True)
class ArtifactRecord:
    """One artifact a scan produced, as reconciled against the report.

    ``source`` is the origin table (``evidence`` | ``tool_run``). ``object_key`` is
    the internal storage key (used for presence + de-dup; never rendered to clients).
    """

    scan_id: str
    evidence_id: str | None
    object_key: str | None
    kind: str | None
    size_bytes: int | None
    source: str
    tool_run_id: str | None = None


@dataclass(frozen=True)
class LedgerEntry:
    artifact: ArtifactRecord
    state: LedgerState
    exclusion_reason: ExclusionReason | None = None
    #: Report section id the artifact surfaces in (best-effort; None when excluded).
    section_ref: str | None = None
    note: str = ""


def _dedup_key(art: ArtifactRecord) -> str | None:
    """The identity used for duplicate detection: the storage key when present,
    else the evidence id. ``None`` disables de-dup for that record (nothing to key on)."""
    return art.object_key or art.evidence_id


def build_artifact_ledger(
    artifacts: list[ArtifactRecord],
    *,
    referenced_keys: set[str],
    referenced_evidence_ids: set[str],
    referenced_tool_run_ids: frozenset[str] = frozenset(),
    size_limit_bytes: int | None = None,
    tenant_excluded_kinds: frozenset[str] = frozenset(),
    service_output_kinds: frozenset[str] = frozenset(),
    section_for: dict[str, str] | None = None,
) -> list[LedgerEntry]:
    """Reconcile ``artifacts`` against the report, assigning each exactly one state.

    Precedence (first match wins):

    1. **excluded / duplicate** — a *prior* artifact already claimed this dedup key
       (storage key, else evidence id). Only the first occurrence of a key is counted;
       every later copy is a duplicate, so a content-addressed artifact stored twice is
       presented once and the rest accounted as duplicates rather than double-counted.
    2. **presented** — ``object_key`` ∈ ``referenced_keys``, ``evidence_id`` ∈
       ``referenced_evidence_ids``, or ``tool_run_id`` ∈ ``referenced_tool_run_ids``
       (a tool-run output is presented when its run is in the execution log).
       Presentation wins over the remaining exclusion rules: a referenced artifact is
       in the report regardless of its size/kind.
    3. **excluded / empty_artifact** — ``size_bytes == 0``.
    4. **excluded / size_limit** — ``size_limit_bytes`` set and ``size_bytes`` exceeds it.
    5. **excluded / tenant_policy** — ``kind`` ∈ ``tenant_excluded_kinds``.
    6. **excluded / service_output** — ``kind`` ∈ ``service_output_kinds``.
    7. **unprocessed** — none of the above → a release blocker.

    ``section_for`` optionally maps a presented artifact's evidence id (or key) to the
    report section it appears in, purely for the ledger's ``section_ref`` display.
    """
    section_for = section_for or {}
    entries: list[LedgerEntry] = []
    seen_dedup: set[str] = set()

    for art in artifacts:
        key = _dedup_key(art)

        # (1) A repeat of an already-seen key is a duplicate, whatever its reference
        # state — we present/account the first copy only.
        if key is not None and key in seen_dedup:
            entries.append(
                LedgerEntry(
                    artifact=art,
                    state=LedgerState.EXCLUDED,
                    exclusion_reason=ExclusionReason.DUPLICATE,
                )
            )
            continue
        if key is not None:
            seen_dedup.add(key)

        is_referenced = (
            (art.object_key is not None and art.object_key in referenced_keys)
            or (art.evidence_id is not None and art.evidence_id in referenced_evidence_ids)
            or (art.tool_run_id is not None and art.tool_run_id in referenced_tool_run_ids)
        )

        # (2) presented — reference wins over size/kind exclusions.
        if is_referenced:
            section_ref = section_for.get(art.evidence_id or "") or section_for.get(
                art.object_key or ""
            )
            entries.append(
                LedgerEntry(artifact=art, state=LedgerState.PRESENTED, section_ref=section_ref)
            )
            continue

        # (3–6) Unreferenced → closed-enum exclusion rules, else (7) unprocessed.
        reason: ExclusionReason | None = None
        if art.size_bytes == 0:
            reason = ExclusionReason.EMPTY_ARTIFACT
        elif (
            size_limit_bytes is not None
            and art.size_bytes is not None
            and art.size_bytes > size_limit_bytes
        ):
            reason = ExclusionReason.SIZE_LIMIT
        elif art.kind is not None and art.kind in tenant_excluded_kinds:
            reason = ExclusionReason.TENANT_POLICY
        elif art.kind is not None and art.kind in service_output_kinds:
            reason = ExclusionReason.SERVICE_OUTPUT

        if reason is not None:
            entries.append(
                LedgerEntry(artifact=art, state=LedgerState.EXCLUDED, exclusion_reason=reason)
            )
        else:
            entries.append(LedgerEntry(artifact=art, state=LedgerState.UNPROCESSED))

    return entries


def ledger_release_blockers(entries: list[LedgerEntry]) -> list[str]:
    """R-6.1.2 — any ``unprocessed`` artifact blocks the release.

    Returns one human-readable blocker summarising the unprocessed artifacts (empty
    when the ledger is fully reconciled). Kept as a single aggregate line so the gate
    log stays legible even when many artifacts are unaccounted.
    """
    unprocessed = [e for e in entries if e.state == LedgerState.UNPROCESSED]
    if not unprocessed:
        return []
    ids = sorted(
        (e.artifact.evidence_id or e.artifact.object_key or "?") for e in unprocessed
    )
    shown = ", ".join(ids[:5])
    more = f" (+{len(ids) - 5} more)" if len(ids) > 5 else ""
    return [
        f"LEDGER: {len(unprocessed)} unprocessed artifact(s) not presented or excluded: "
        f"{shown}{more}"
    ]


def ledger_summary(entries: list[LedgerEntry]) -> dict[str, object]:
    """Counts by state + a breakdown of exclusion reasons (for logs / the appendix)."""
    by_state: Counter[str] = Counter(e.state.value for e in entries)
    by_reason: Counter[str] = Counter(
        e.exclusion_reason.value for e in entries if e.exclusion_reason is not None
    )
    return {
        "total": len(entries),
        "presented": by_state.get(LedgerState.PRESENTED.value, 0),
        "excluded": by_state.get(LedgerState.EXCLUDED.value, 0),
        "unprocessed": by_state.get(LedgerState.UNPROCESSED.value, 0),
        "by_reason": dict(by_reason),
    }


__all__ = [
    "ArtifactRecord",
    "ExclusionReason",
    "LedgerEntry",
    "LedgerState",
    "build_artifact_ledger",
    "ledger_release_blockers",
    "ledger_summary",
]
