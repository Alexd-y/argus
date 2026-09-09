"""Producers that turn real run facts into WSTG test executions + evidence.

This is the IO-adjacent layer that feeds the pure gate. It integrates one
end-to-end path today: **confirmed findings → executions**.

A confirmed finding that (a) maps to a WSTG test and (b) carries validated
evidence is a *completed* execution of that test with a ``fail`` outcome — the
finding is the control-failure evidence. Findings without evidence produce a
``partial`` diagnostic execution that never counts.

The :class:`ReportDataEvidenceResolver` validates ``FINDING:<id>`` refs against
the already-materialised report data (no network, so ``compute_wstg_coverage``
stays pure). It only marks a finding "resolved" when the finding exists for this
scan and actually carries evidence — a bare ``FINDING:123`` string never
validates on its own.
"""

from __future__ import annotations

from typing import Any

from src.reports.wstg_evidence import ArtifactKind, ResolvedArtifact
from src.reports.wstg_execution import TestExecution
from src.reports.wstg_model import ExecutionStatus, Outcome

_FINDING_REF_PREFIX = "FINDING:"

# Evidence-store artifact ``kind`` string → the typed :class:`ArtifactKind` the
# validator reasons about. Unknown kinds resolve to ``UNKNOWN`` (still a real
# artifact, but the validator can reject it if a specific type is required).
_KIND_MAP: dict[str, ArtifactKind] = {
    "tool_output": ArtifactKind.TOOL_OUTPUT,
    "stdout": ArtifactKind.TOOL_OUTPUT,
    "raw": ArtifactKind.TOOL_OUTPUT,
    "poc": ArtifactKind.POC_FILE,
    "proof_of_concept": ArtifactKind.POC_FILE,
    "http": ArtifactKind.HTTP_EXCHANGE,
    "http_exchange": ArtifactKind.HTTP_EXCHANGE,
    "request_response": ArtifactKind.HTTP_EXCHANGE,
    "screenshot": ArtifactKind.SCREENSHOT,
    "finding": ArtifactKind.FINDING,
}


def _artifact_kind(raw: Any) -> ArtifactKind:
    return _KIND_MAP.get(str(raw or "").strip().lower(), ArtifactKind.UNKNOWN)


def findings_to_executions(
    findings: list[dict[str, Any]],
    *,
    scan_id: str,
    target: str | None,
    wstg_ids_for_finding,
) -> list[TestExecution]:
    """Project evidenced findings into completed/fail WSTG test executions.

    ``wstg_ids_for_finding`` is injected (from ``wstg_coverage``) to keep this
    module free of that import cycle.
    """
    executions: list[TestExecution] = []
    for f in findings:
        fid = str(f.get("id") or "").strip()
        if not fid:
            continue
        wids = wstg_ids_for_finding(f)
        if not wids:
            continue
        has_evidence = bool(f.get("_has_evidence"))
        ref = f"{_FINDING_REF_PREFIX}{fid}"
        for wid in wids:
            if has_evidence:
                executions.append(
                    TestExecution(
                        execution_id=f"finding:{fid}:{wid}",
                        scan_id=scan_id,
                        test_id=wid,
                        scenario_id=f"finding:{fid}",
                        executor="finding_producer",
                        target_ref=target,
                        execution_status=ExecutionStatus.COMPLETED,
                        outcome=Outcome.FAIL,
                        evidence_refs=(ref,),
                        completion_criteria_results={
                            "finding_confirmed": True,
                            "evidence_present": True,
                        },
                    )
                )
            else:
                executions.append(
                    TestExecution(
                        execution_id=f"finding:{fid}:{wid}",
                        scan_id=scan_id,
                        test_id=wid,
                        scenario_id=f"finding:{fid}",
                        executor="finding_producer",
                        target_ref=target,
                        execution_status=ExecutionStatus.PARTIAL,
                        outcome=Outcome.INCONCLUSIVE,
                        evidence_refs=(),
                        completion_criteria_results={"evidence_present": False},
                        limitations=("finding carries no validated evidence",),
                    )
                )
    return executions


class ReportDataEvidenceResolver:
    """Resolve ``FINDING:<id>`` refs against the materialised report + evidence store.

    Network-free: it uses the findings and the persisted-evidence index already
    materialised by the report pipeline, so it can run in the snapshot build
    without an N+1 database/MinIO fan-out.

    When ``evidence_entries`` is supplied, a finding ref only validates if the
    store actually holds ≥1 artifact (a non-empty ``object_key``) for that
    finding — a bare ``_has_evidence`` flag is *not* sufficient. This is the
    store-backed check required by ARGUS-WSTG-COV-1 §Evidence. When it is omitted
    the resolver falls back to the ``_has_evidence`` flag for back-compat with
    lightweight callers/tests.
    """

    def __init__(
        self,
        findings: list[dict[str, Any]],
        *,
        scan_id: str,
        target: str | None,
        evidence_entries: list[dict[str, Any]] | None = None,
    ) -> None:
        self._scan_id = scan_id
        self._target = target
        self._by_id: dict[str, dict[str, Any]] = {}
        for f in findings:
            fid = str(f.get("id") or "").strip()
            if fid:
                self._by_id[fid] = f
        # Store-backed index: finding_id → best real artifact (object_key + kind).
        self._store_backed = evidence_entries is not None
        self._artifact_by_finding: dict[str, tuple[str, ArtifactKind]] = {}
        for entry in evidence_entries or []:
            fid = str(entry.get("finding_id") or "").strip()
            object_key = str(entry.get("object_key") or "").strip()
            if fid and object_key:
                self._artifact_by_finding.setdefault(
                    fid, (object_key, _artifact_kind(entry.get("kind")))
                )

    def resolve(self, refs: list[str]) -> dict[str, ResolvedArtifact]:
        out: dict[str, ResolvedArtifact] = {}
        for ref in refs:
            out[ref] = self._resolve_one(ref)
        return out

    def _resolve_one(self, ref: str) -> ResolvedArtifact:
        if not ref.startswith(_FINDING_REF_PREFIX):
            return ResolvedArtifact(
                ref, exists=False, unresolved_reason="unsupported evidence ref scheme"
            )
        fid = ref[len(_FINDING_REF_PREFIX) :]
        finding = self._by_id.get(fid)
        if finding is None:
            return ResolvedArtifact(
                ref, exists=False, unresolved_reason="finding not present in report data"
            )

        if self._store_backed:
            artifact = self._artifact_by_finding.get(fid)
            if artifact is None:
                # The finding exists but the store holds no artifact for it — a
                # bare flag never validates on its own (spec §Evidence).
                return ResolvedArtifact(
                    ref,
                    exists=True,
                    kind=ArtifactKind.FINDING,
                    scan_id=self._scan_id,
                    target_ref=self._target,
                    content_present=False,
                    finding_resolved=False,
                    unresolved_reason="no stored artifact for finding",
                )
            _object_key, _kind = artifact
            return ResolvedArtifact(
                ref=ref,
                exists=True,
                kind=ArtifactKind.FINDING,
                scan_id=self._scan_id,
                target_ref=self._target,
                content_present=True,
                finding_resolved=True,
            )

        # Back-compat path: no evidence store index supplied.
        has_evidence = bool(finding.get("_has_evidence"))
        return ResolvedArtifact(
            ref=ref,
            exists=True,
            kind=ArtifactKind.FINDING,
            scan_id=self._scan_id,
            target_ref=self._target,
            content_present=has_evidence,
            finding_resolved=has_evidence,
        )


__all__ = ["ReportDataEvidenceResolver", "findings_to_executions"]
