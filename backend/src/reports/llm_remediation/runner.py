"""Orchestration for the mandatory Valhalla per-finding LLM analysis phase.

Responsibilities (prompt §5, §9):

* Build a redacted context package per finding and compute the deterministic
  permitted closure status.
* Call the LLM per finding (remediation plan + closure conclusion) via an
  injectable callable (real facade in production, mock in tests).
* Parse, schema-validate and bounded-repair the response.
* Reject invented references (evidence/retest IDs not present in the inputs)
  and never let the model *strengthen* the computed closure status.
* Attach short verifiable provenance and cache accepted outputs by input hash
  so re-render never re-invokes the LLM (L10/L23).
* On unrecoverable failure, mark the finding ``failed``/``incomplete`` with an
  honest reason instead of emitting a false ``fixed_verified`` (L09).
* Synthesize a report-wide summary from accepted analyses with exact counts.

The runner is synchronous to mirror the existing report pipeline
(``call_llm_sync``) and to keep tests deterministic.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import ValidationError

from src.reports.ai_text_generation import canonical_payload_hash
from src.reports.llm_remediation.closure_status import (
    ClosureComputationInput,
    RetestExecution,
    RetestOutcome,
    compute_permitted_closure_status,
)
from src.reports.llm_remediation.context import (
    REDACTION_VERSION,
    build_finding_context,
)
from src.reports.llm_remediation.prompts import (
    CLOSURE_SCHEMA_ID,
    REMEDIATION_PROMPT_VERSION,
    REMEDIATION_SCHEMA_ID,
    SCHEMA_VERSION,
    SUMMARY_PROMPT_VERSION,
    SUMMARY_SCHEMA_ID,
    get_closure_prompt,
    get_remediation_prompt,
)
from src.reports.llm_remediation.schemas import (
    AnalysisStatus,
    FindingClosureConclusion,
    FindingRemediationAnalysis,
    LlmProvenance,
    PermittedClosureStatus,
    ReportClosureSummary,
    closure_rank,
)

logger = logging.getLogger(__name__)

# One of "remediation" | "closure" | "summary".
LlmKind = str

# (system_prompt, user_prompt, kind) -> raw JSON string.
LlmCallable = Callable[[str, str, LlmKind], str]

_DEFAULT_PROVIDER = "unknown"
_DEFAULT_MODEL = "unknown"


class LlmTransientError(RuntimeError):
    """Raised by an ``LlmCallable`` to request a bounded retry with backoff."""


class LlmNotInvokedError(RuntimeError):
    """Raised by an ``LlmCallable`` when no provider could be invoked at all.

    Typical causes: no configured provider for the report alias, cloud disabled
    for report tasks, or the budget ledger denying a paid call. Distinct from a
    call that was made and failed (prompt §28.2).
    """


class LlmFailureKind(StrEnum):
    """Distinguishable reasons an LLM analysis did not produce an accepted result."""

    NOT_INVOKED = "llm_not_invoked"
    CALL_FAILED = "llm_call_failed"
    SCHEMA_INVALID = "llm_schema_invalid"
    VALIDATION_REJECTED = "llm_validation_rejected"


class LlmCallError(RuntimeError):
    """A classified, non-retryable LLM call failure carrying diagnostic detail."""

    def __init__(self, failure_kind: LlmFailureKind, detail: str) -> None:
        super().__init__(detail)
        self.failure_kind = failure_kind
        self.detail = detail


#: Exception type-name fragments that mean "the provider was never reached".
_NOT_INVOKED_MARKERS: tuple[str, ...] = (
    "budget",
    "notconfigured",
    "not_configured",
    "noprovider",
    "no_provider",
    "unavailable",
    "disabled",
)

_MAX_ERROR_MESSAGE = 300


def _http_status(exc: BaseException) -> str:
    code = getattr(exc, "status_code", None)
    if code is None:
        response = getattr(exc, "response", None)
        code = getattr(response, "status_code", None)
    return str(code) if code is not None else "-"


def _classify_exception(exc: BaseException) -> LlmFailureKind:
    if isinstance(exc, LlmNotInvokedError):
        return LlmFailureKind.NOT_INVOKED
    haystack = f"{type(exc).__name__} {exc}".lower().replace(" ", "")
    if any(marker in haystack for marker in _NOT_INVOKED_MARKERS):
        return LlmFailureKind.NOT_INVOKED
    return LlmFailureKind.CALL_FAILED


def format_llm_error(
    failure_kind: LlmFailureKind | str,
    *,
    stage: str,
    exc: BaseException | None = None,
    message: str = "",
    attempt: int | None = None,
    provider: str = _DEFAULT_PROVIDER,
    model: str = _DEFAULT_MODEL,
) -> str:
    """Render one structured, log-safe diagnostic line for a failed LLM step."""
    kind = failure_kind.value if isinstance(failure_kind, LlmFailureKind) else str(failure_kind)
    text = message or (str(exc) if exc is not None else "")
    text = " ".join(text.split())[:_MAX_ERROR_MESSAGE]
    exc_type = type(exc).__name__ if exc is not None else "-"
    http = _http_status(exc) if exc is not None else "-"
    return (
        f"{kind}: stage={stage} type={exc_type} http={http} "
        f"attempt={attempt if attempt is not None else '-'} "
        f"provider={provider} model={model} msg={text}"
    )


def classify_failure(errors: Sequence[str]) -> str | None:
    """Return the dominant :class:`LlmFailureKind` value recorded in ``errors``."""
    for kind in (
        LlmFailureKind.NOT_INVOKED,
        LlmFailureKind.CALL_FAILED,
        LlmFailureKind.SCHEMA_INVALID,
        LlmFailureKind.VALIDATION_REJECTED,
    ):
        if any(e.startswith(kind.value) for e in errors):
            return kind.value
    if any(e.startswith(("invented_", "clamped_")) for e in errors):
        return LlmFailureKind.VALIDATION_REJECTED.value
    return None


#: Provenance for the deterministic, application-computed report summary.
SUMMARY_PROVIDER = "argus_app"
SUMMARY_MODEL = "deterministic_aggregation"
SUMMARY_VALIDATION_STATUS = "app_computed_no_llm_call"

PROBE_SYSTEM_PROMPT = 'You are a health probe. Reply with the single JSON object {"ok": true}.'
PROBE_USER_PROMPT = 'Health check for the Valhalla report LLM phase. Return {"ok": true}.'


@dataclass
class FindingAnalysisResult:
    """Outcome of analysing a single finding."""

    finding_id: str
    llm_analysis_status: str
    remediation: FindingRemediationAnalysis | None = None
    closure: FindingClosureConclusion | None = None
    permitted_status: PermittedClosureStatus = PermittedClosureStatus.NOT_RETESTED
    context_hash: str = ""
    errors: list[str] = field(default_factory=list)
    from_cache: bool = False
    failure_kind: str | None = None


@dataclass
class RemediationRunResult:
    """Outcome of a full per-finding analysis pass over a report."""

    results: list[FindingAnalysisResult] = field(default_factory=list)
    summary: ReportClosureSummary | None = None
    completeness: str = "incomplete"
    #: Set when the pre-flight health probe failed and no per-finding call was made.
    probe_error: str | None = None

    @property
    def errors(self) -> list[str]:
        """Every per-finding diagnostic, prefixed with its finding id (for the manifest)."""
        out: list[str] = []
        if self.probe_error:
            out.append(f"probe: {self.probe_error}")
        for res in self.results:
            for err in res.errors:
                out.append(f"finding:{res.finding_id}: {err}")
        return out

    @property
    def all_complete(self) -> bool:
        return bool(self.results) and all(
            r.llm_analysis_status == AnalysisStatus.GENERATED_VALIDATED.value for r in self.results
        )


def _strip_json_fence(text: str) -> str:
    """Remove an optional ```json ... ``` markdown wrapper."""

    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[-1] if "\n" in stripped else stripped
        if stripped.endswith("```"):
            stripped = stripped[:-3]
        # Drop a leading language tag left on the first line.
        if stripped.lstrip().startswith("json"):
            stripped = stripped.lstrip()[4:]
    return stripped.strip()


def _parse_json(text: str) -> dict[str, Any]:
    return json.loads(_strip_json_fence(text))


def _make_provenance(
    *,
    prompt_version: str,
    schema_id: str,
    input_hash: str,
    validation_status: str,
    provider: str,
    model: str,
) -> LlmProvenance:
    return LlmProvenance(
        analysis_id=str(uuid.uuid4()),
        provider=provider,
        model=model,
        prompt_version=prompt_version,
        schema_version=f"{schema_id}:{SCHEMA_VERSION}",
        input_hash=input_hash,
        generated_at=datetime.now(UTC),
        validation_status=validation_status,
    )


def _cache_key(context_hash: str, prompt_version: str, schema_id: str, model: str) -> str:
    return f"{context_hash}:{prompt_version}:{schema_id}:{model}:{REDACTION_VERSION}"


def _call_with_retry(
    llm_callable: LlmCallable,
    system: str,
    user: str,
    kind: LlmKind,
    *,
    max_attempts: int,
    sleeper: Callable[[float], None],
    provider: str = _DEFAULT_PROVIDER,
    model: str = _DEFAULT_MODEL,
) -> str:
    """Call the LLM with bounded retry; raise :class:`LlmCallError` on failure.

    Only :class:`LlmTransientError` is retried. Any other exception is classified
    (``llm_not_invoked`` vs ``llm_call_failed``) and surfaced with its type, HTTP
    code, attempt, provider and model so the cause is never lost (prompt §28.1).
    An empty response is a failed call, not an empty analysis.
    """
    last: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            raw = llm_callable(system, user, kind)
        except LlmTransientError as exc:  # bounded retry with backoff
            last = exc
            logger.warning(
                "llm_remediation_transient_error",
                extra={
                    "event": "llm_remediation_transient_error",
                    "stage": kind,
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                },
            )
            if attempt < max_attempts:
                sleeper(min(2.0 ** (attempt - 1), 8.0))
            continue
        except Exception as exc:  # noqa: BLE001 — classified, never swallowed
            failure_kind = _classify_exception(exc)
            raise LlmCallError(
                failure_kind,
                format_llm_error(
                    failure_kind,
                    stage=kind,
                    exc=exc,
                    attempt=attempt,
                    provider=provider,
                    model=model,
                ),
            ) from exc
        if not (raw or "").strip():
            raise LlmCallError(
                LlmFailureKind.CALL_FAILED,
                format_llm_error(
                    LlmFailureKind.CALL_FAILED,
                    stage=kind,
                    message="empty_response",
                    attempt=attempt,
                    provider=provider,
                    model=model,
                ),
            )
        return raw
    raise LlmCallError(
        LlmFailureKind.CALL_FAILED,
        format_llm_error(
            LlmFailureKind.CALL_FAILED,
            stage=kind,
            exc=last,
            message=f"transient_failure exhausted after {max_attempts} attempts: {last}",
            attempt=max_attempts,
            provider=provider,
            model=model,
        ),
    )


class RemediationRunner:
    """Runs the per-finding remediation + closure LLM analysis for a report."""

    def __init__(
        self,
        llm_callable: LlmCallable,
        *,
        provider: str = _DEFAULT_PROVIDER,
        model: str = _DEFAULT_MODEL,
        cache: dict[str, Any] | None = None,
        max_transient_attempts: int = 3,
        max_repair_attempts: int = 1,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self._llm = llm_callable
        self._provider = provider
        self._model = model
        self._cache = cache if cache is not None else {}
        self._max_transient_attempts = max(1, max_transient_attempts)
        self._max_repair_attempts = max(0, max_repair_attempts)
        self._sleeper = sleeper

    # -- remediation ------------------------------------------------------

    def _generate_remediation(
        self,
        context_json: dict[str, Any],
        *,
        context_hash: str,
        known_evidence_ids: set[str],
        known_reference_ids: set[str],
    ) -> tuple[FindingRemediationAnalysis | None, list[str]]:
        system, user, version = get_remediation_prompt(context_json)
        errors: list[str] = []
        attempts = self._max_repair_attempts + 1
        repair_note = ""

        for attempt in range(1, attempts + 1):
            try:
                raw = _call_with_retry(
                    self._llm,
                    system,
                    user + repair_note,
                    "remediation",
                    max_attempts=self._max_transient_attempts,
                    sleeper=self._sleeper,
                    provider=self._provider,
                    model=self._model,
                )
            except LlmCallError as exc:
                return None, [exc.detail]

            try:
                data = _parse_json(raw)
                model_obj = FindingRemediationAnalysis.model_validate(
                    {
                        **data,
                        "source_context_hash": data.get("source_context_hash") or context_hash,
                        "llm_provenance": data.get("llm_provenance")
                        or _make_provenance(
                            prompt_version=version,
                            schema_id=REMEDIATION_SCHEMA_ID,
                            input_hash=context_hash,
                            validation_status="validated",
                            provider=self._provider,
                            model=self._model,
                        ),
                    }
                )
            except (json.JSONDecodeError, ValidationError) as exc:
                errors = [
                    format_llm_error(
                        LlmFailureKind.SCHEMA_INVALID,
                        stage="remediation",
                        exc=exc,
                        attempt=attempt,
                        provider=self._provider,
                        model=self._model,
                    )
                ]
                repair_note = (
                    "\n\nПредыдущий ответ не прошёл валидацию схемы: "
                    f"{exc}. Верни строго валидный JSON по схеме."
                )
                continue

            # Preserve finding_id and reject invented references (L07).
            ref_errors = self._validate_remediation_refs(
                model_obj, known_evidence_ids, known_reference_ids
            )
            if ref_errors:
                return _downgrade_remediation(model_obj, ref_errors), ref_errors
            return model_obj, []

        return None, errors or [
            format_llm_error(
                LlmFailureKind.SCHEMA_INVALID,
                stage="remediation",
                message="exhausted repair attempts",
                provider=self._provider,
                model=self._model,
            )
        ]

    @staticmethod
    def _validate_remediation_refs(
        analysis: FindingRemediationAnalysis,
        known_evidence_ids: set[str],
        known_reference_ids: set[str],
    ) -> list[str]:
        problems: list[str] = []
        for eid in analysis.root_cause.evidence_ids:
            if known_evidence_ids and eid not in known_evidence_ids:
                problems.append(f"invented_evidence_id: {eid}")
        for step in analysis.permanent_fix_steps:
            for rid in step.source_reference_ids:
                if known_reference_ids and rid not in known_reference_ids:
                    problems.append(f"invented_reference_id: {rid}")
        return problems

    # -- closure ----------------------------------------------------------

    def _generate_closure(
        self,
        context_json: dict[str, Any],
        *,
        context_hash: str,
        permitted: PermittedClosureStatus,
        known_evidence_ids: set[str],
        known_retest_ids: set[str],
    ) -> tuple[FindingClosureConclusion | None, list[str]]:
        system, user, version = get_closure_prompt(context_json)
        errors: list[str] = []
        attempts = self._max_repair_attempts + 1
        repair_note = ""

        for attempt in range(1, attempts + 1):
            try:
                raw = _call_with_retry(
                    self._llm,
                    system,
                    user + repair_note,
                    "closure",
                    max_attempts=self._max_transient_attempts,
                    sleeper=self._sleeper,
                    provider=self._provider,
                    model=self._model,
                )
            except LlmCallError as exc:
                return None, [exc.detail]

            try:
                data = _parse_json(raw)
                # Clamp status BEFORE validation so the model can never publish
                # a stronger claim than the evidence permits (prompt §7, L08).
                clamp_notes = _clamp_closure_status(data, permitted)
                model_obj = FindingClosureConclusion.model_validate(
                    {
                        **data,
                        "source_context_hash": data.get("source_context_hash") or context_hash,
                        "llm_provenance": data.get("llm_provenance")
                        or _make_provenance(
                            prompt_version=version,
                            schema_id=CLOSURE_SCHEMA_ID,
                            input_hash=context_hash,
                            validation_status="validated",
                            provider=self._provider,
                            model=self._model,
                        ),
                    }
                )
            except (json.JSONDecodeError, ValidationError) as exc:
                errors = [
                    format_llm_error(
                        LlmFailureKind.SCHEMA_INVALID,
                        stage="closure",
                        exc=exc,
                        attempt=attempt,
                        provider=self._provider,
                        model=self._model,
                    )
                ]
                repair_note = (
                    "\n\nПредыдущий ответ не прошёл валидацию схемы: "
                    f"{exc}. Верни строго валидный JSON по схеме."
                )
                continue

            ref_errors = self._validate_closure_refs(
                model_obj, known_evidence_ids, known_retest_ids
            )
            problems = clamp_notes + ref_errors
            return model_obj, problems

        return None, errors or [
            format_llm_error(
                LlmFailureKind.SCHEMA_INVALID,
                stage="closure",
                message="exhausted repair attempts",
                provider=self._provider,
                model=self._model,
            )
        ]

    @staticmethod
    def _validate_closure_refs(
        closure: FindingClosureConclusion,
        known_evidence_ids: set[str],
        known_retest_ids: set[str],
    ) -> list[str]:
        problems: list[str] = []
        for eid in closure.supporting_evidence_ids:
            if known_evidence_ids and eid not in known_evidence_ids:
                problems.append(f"invented_evidence_id: {eid}")
        for tid in closure.supporting_retest_ids:
            if known_retest_ids and tid not in known_retest_ids:
                problems.append(f"invented_retest_id: {tid}")
        return problems

    # -- per finding ------------------------------------------------------

    def analyze_finding(
        self,
        finding: dict[str, Any],
        *,
        report_meta: dict[str, Any],
        closure_input: ClosureComputationInput,
        allowed_evidence_ids: list[str] | None = None,
        evidence_fragments: dict[str, str] | None = None,
        locale: str = "ru",
    ) -> FindingAnalysisResult:
        permitted = compute_permitted_closure_status(closure_input)
        ctx = build_finding_context(
            finding,
            report_meta=report_meta,
            permitted=permitted,
            allowed_evidence_ids=allowed_evidence_ids,
            evidence_fragments=evidence_fragments,
            locale=locale,
        )
        finding_id = ctx.finding_id or closure_input.finding_id

        known_evidence = set(allowed_evidence_ids or []) | set(permitted.supporting_evidence_ids)
        known_retests = {r.test_id for r in closure_input.retests}
        known_refs = set(finding.get("approved_reference_ids") or [])

        cache_key = _cache_key(
            ctx.context_hash, REMEDIATION_PROMPT_VERSION, REMEDIATION_SCHEMA_ID, self._model
        )
        cached = self._cache.get(cache_key)
        if cached is not None:
            return FindingAnalysisResult(
                finding_id=finding_id,
                llm_analysis_status=cached["status"],
                remediation=cached["remediation"],
                closure=cached["closure"],
                permitted_status=permitted.permitted_status,
                context_hash=ctx.context_hash,
                from_cache=True,
            )

        errors: list[str] = []
        remediation, rem_errors = self._generate_remediation(
            ctx.payload,
            context_hash=ctx.context_hash,
            known_evidence_ids=known_evidence,
            known_reference_ids=known_refs,
        )
        errors.extend(rem_errors)

        closure: FindingClosureConclusion | None = None
        if classify_failure(rem_errors) == LlmFailureKind.NOT_INVOKED.value:
            # The provider was never reached — a second (closure) call would fail
            # for the same reason and only duplicate the diagnostic.
            pass
        else:
            closure, clo_errors = self._generate_closure(
                ctx.payload,
                context_hash=ctx.context_hash,
                permitted=permitted.permitted_status,
                known_evidence_ids=known_evidence,
                known_retest_ids=known_retests,
            )
            errors.extend(clo_errors)

        status = self._derive_status(remediation, closure, errors)

        result = FindingAnalysisResult(
            finding_id=finding_id,
            llm_analysis_status=status,
            remediation=remediation,
            closure=closure,
            permitted_status=permitted.permitted_status,
            context_hash=ctx.context_hash,
            errors=errors,
            failure_kind=(
                None
                if status == AnalysisStatus.GENERATED_VALIDATED.value
                else classify_failure(errors)
            ),
        )

        if status == AnalysisStatus.GENERATED_VALIDATED.value:
            self._cache[cache_key] = {
                "status": status,
                "remediation": remediation,
                "closure": closure,
            }
        return result

    @staticmethod
    def _derive_status(
        remediation: FindingRemediationAnalysis | None,
        closure: FindingClosureConclusion | None,
        errors: list[str],
    ) -> str:
        if remediation is None or closure is None:
            return "failed"
        if any(e.startswith(("invented_", "clamped_")) for e in errors):
            return AnalysisStatus.NEEDS_REVIEW.value
        if remediation.analysis_status != AnalysisStatus.GENERATED_VALIDATED:
            return remediation.analysis_status.value
        return AnalysisStatus.GENERATED_VALIDATED.value

    # -- health probe -----------------------------------------------------

    def probe(self) -> str | None:
        """One cheap pre-flight call; return a diagnostic string on failure, else None.

        Run before the per-finding pass so an unreachable/unconfigured provider is
        reported once as ``llm_not_invoked`` / ``llm_call_failed`` with its real
        cause, instead of N identical opaque ``failed`` findings (prompt §28.6).
        """
        try:
            _call_with_retry(
                self._llm,
                PROBE_SYSTEM_PROMPT,
                PROBE_USER_PROMPT,
                "probe",
                max_attempts=1,
                sleeper=self._sleeper,
                provider=self._provider,
                model=self._model,
            )
        except LlmCallError as exc:
            return exc.detail
        return None

    # -- report pass ------------------------------------------------------

    def run(
        self,
        findings: Sequence[dict[str, Any]],
        *,
        report_meta: dict[str, Any],
        closure_inputs: dict[str, ClosureComputationInput],
        allowed_evidence_ids: dict[str, list[str]] | None = None,
        evidence_fragments: dict[str, dict[str, str]] | None = None,
        locale: str = "ru",
        build_summary: bool = True,
        health_probe: bool = False,
    ) -> RemediationRunResult:
        """Analyse every finding (no hidden top-N; last items included, L28)."""

        allowed_evidence_ids = allowed_evidence_ids or {}
        evidence_fragments = evidence_fragments or {}
        results: list[FindingAnalysisResult] = []

        if health_probe and findings:
            probe_error = self.probe()
            if probe_error is not None:
                kind = classify_failure([probe_error]) or LlmFailureKind.CALL_FAILED.value
                for finding in findings:
                    fid = str(finding.get("finding_id") or finding.get("id") or "")
                    results.append(
                        FindingAnalysisResult(
                            finding_id=fid,
                            llm_analysis_status="failed",
                            errors=[f"{kind}: stage=probe skipped per-finding call"],
                            failure_kind=kind,
                        )
                    )
                run_result = RemediationRunResult(
                    results=results, completeness="failed", probe_error=probe_error
                )
                if build_summary:
                    run_result.summary = self._synthesize_summary(results, report_meta)
                return run_result

        for finding in findings:
            fid = str(finding.get("finding_id") or finding.get("id") or "")
            closure_input = closure_inputs.get(
                fid, ClosureComputationInput(finding_id=fid, acceptance_criteria_ids=())
            )
            results.append(
                self.analyze_finding(
                    finding,
                    report_meta=report_meta,
                    closure_input=closure_input,
                    allowed_evidence_ids=allowed_evidence_ids.get(fid),
                    evidence_fragments=evidence_fragments.get(fid),
                    locale=locale,
                )
            )

        run_result = RemediationRunResult(results=results)
        run_result.completeness = "complete" if run_result.all_complete else "incomplete"

        if build_summary:
            run_result.summary = self._synthesize_summary(results, report_meta)
        return run_result

    def _synthesize_summary(
        self,
        results: list[FindingAnalysisResult],
        report_meta: dict[str, Any],
    ) -> ReportClosureSummary | None:
        # Exact counts computed by the application, never total-minus-open.
        counts: Counter[str] = Counter()
        verified: list[str] = []
        not_verified: list[str] = []
        accepted: list[str] = []
        source_ids: list[str] = []

        for res in results:
            counts[res.llm_analysis_status] += 1
            if res.closure is not None:
                counts[f"closure:{res.closure.permitted_closure_status.value}"] += 1
                status = res.closure.permitted_closure_status
                if status == PermittedClosureStatus.FIXED_VERIFIED:
                    verified.append(res.finding_id)
                elif status == PermittedClosureStatus.RISK_ACCEPTED:
                    accepted.append(res.finding_id)
                else:
                    not_verified.append(res.finding_id)
                source_ids.append(res.closure.llm_provenance.analysis_id)

        overall = (
            f"Обработано находок: {len(results)}. "
            f"Подтверждённо закрыто: {len(verified)}; "
            f"не подтверждено: {len(not_verified)}; принятый риск: {len(accepted)}."
        )
        summary_hash = canonical_payload_hash(
            {
                "report_version": report_meta.get("report_version"),
                "counts": dict(counts),
                "verified": verified,
                "not_verified": not_verified,
                "accepted": accepted,
            }
        )
        # The report-wide summary is computed deterministically by the application
        # from accepted per-finding analyses — no model call is made. Record that
        # unambiguously instead of an alias-looking "facade/report_writer" pair
        # (prompt §28.2, R-02).
        provenance = _make_provenance(
            prompt_version=SUMMARY_PROMPT_VERSION,
            schema_id=SUMMARY_SCHEMA_ID,
            input_hash=summary_hash,
            validation_status=SUMMARY_VALIDATION_STATUS,
            provider=SUMMARY_PROVIDER,
            model=SUMMARY_MODEL,
        )
        try:
            return ReportClosureSummary(
                report_version=str(report_meta.get("report_version") or "unknown"),
                exact_counts_by_verification_and_remediation_status=dict(counts),
                overall_conclusion=overall,
                verified_closed_finding_ids=verified,
                not_verified_closed_finding_ids=not_verified,
                accepted_risk_finding_ids=accepted,
                source_analysis_ids=source_ids,
                llm_provenance=provenance,
            )
        except ValidationError:
            logger.exception("Failed to synthesize ReportClosureSummary")
            return None


def _clamp_closure_status(data: dict[str, Any], permitted: PermittedClosureStatus) -> list[str]:
    """Force the model's closure status down to the permitted status.

    Mutates ``data`` in place. Returns a note if a clamp was applied so the
    finding can be routed to ``needs_review`` (the model attempted to overstate
    closure, prompt §7 / L08).
    """

    raw = data.get("permitted_closure_status")
    try:
        claimed = PermittedClosureStatus(raw)
    except ValueError:
        data["permitted_closure_status"] = permitted.value
        return [f"clamped_invalid_status: {raw!r} -> {permitted.value}"]

    if closure_rank(claimed) > closure_rank(permitted):
        data["permitted_closure_status"] = permitted.value
        # Strengthening implies unproven criteria: drop any claimed supporting
        # retests to keep the record consistent with the weaker status.
        if permitted in {PermittedClosureStatus.NOT_RETESTED, PermittedClosureStatus.INCONCLUSIVE}:
            data["supporting_retest_ids"] = []
            data["satisfied_criteria_ids"] = []
        return [f"clamped_status: {claimed.value} -> {permitted.value}"]
    return []


def _downgrade_remediation(
    analysis: FindingRemediationAnalysis, problems: list[str]
) -> FindingRemediationAnalysis:
    """Return a copy of the analysis marked needs_review with recorded gaps."""

    missing = list(dict.fromkeys([*analysis.missing_information, *problems]))
    return analysis.model_copy(
        update={
            "analysis_status": AnalysisStatus.NEEDS_REVIEW,
            "missing_information": missing,
        }
    )


def make_retest_execution(
    test_id: str,
    outcome: RetestOutcome,
    *,
    criteria_ids: Sequence[str] = (),
    evidence_ids: Sequence[str] = (),
) -> RetestExecution:
    """Convenience factory kept next to the runner for callers/tests."""

    return RetestExecution(
        test_id=test_id,
        outcome=outcome,
        criteria_ids=tuple(criteria_ids),
        evidence_ids=tuple(evidence_ids),
    )


__all__ = [
    "SUMMARY_MODEL",
    "SUMMARY_PROVIDER",
    "SUMMARY_VALIDATION_STATUS",
    "FindingAnalysisResult",
    "LlmCallError",
    "LlmCallable",
    "LlmFailureKind",
    "LlmNotInvokedError",
    "LlmTransientError",
    "RemediationRunResult",
    "RemediationRunner",
    "classify_failure",
    "format_llm_error",
    "make_retest_execution",
]
