"""Single source of truth for the Valhalla report provability partition (VHL-PROVABLE-001).

The Valhalla report must be assembled from raw, confirmed data and be 100% provable
from that raw data. A finding is therefore included in the main report ONLY if it is
*provable from raw evidence* — i.e. backed by at least one concrete raw artifact
(raw HTTP request/response, raw tool output, an out-of-band/OAST callback, a
screenshot/browser proof, command output, or a header/TLS observation that is itself
demonstrated by the raw response).

Findings that are not provable from raw evidence (threat-model hypotheses, scanner
"candidate" hits without demonstrated impact, inconclusive parser output) are NOT
silently dropped. They are routed to a clearly-labelled "Unconfirmed — requires manual
verification" section together with the reason they could not be confirmed.

This module is the ONE place that decides "provable vs unconfirmed". Every output
format (HTML, PDF, JSON, CSV/Markdown) calls into it so the partition is identical
across formats.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from src.reports.report_quality_gate import classify_evidence

#: ``evidence_classification`` values considered provable from raw data.
#:
#: - ``validated``: full PoC chain (raw request + response, payload, observed impact,
#:   reproduction steps, manual/browser/server-side validation).
#: - ``observed``: technical observation demonstrated by the raw response itself
#:   (missing security header, server banner, HTTP 429 rate-limit signal).
#:
#: ``candidate`` (scanner hit without demonstrated impact) and ``inconclusive``
#: (insufficient/failed evidence) are NOT provable from raw data.
PROVABLE_CLASSIFICATIONS: frozenset[str] = frozenset({"validated", "observed"})

_VALID_CLASSIFICATIONS: frozenset[str] = frozenset(
    {"validated", "observed", "candidate", "inconclusive"}
)

#: ``evidence_type`` that is, by definition, an inference rather than a raw observation.
INFERENCE_EVIDENCE_TYPE = "threat_model_inference"


def _attr(finding: Any, name: str, default: Any = None) -> Any:
    if isinstance(finding, dict):
        return finding.get(name, default)
    return getattr(finding, name, default)


def _set_attr(finding: Any, name: str, value: Any) -> None:
    if isinstance(finding, dict):
        finding[name] = value
        return
    try:
        setattr(finding, name, value)
    except (AttributeError, ValueError, TypeError):
        # Frozen/extra-forbid models without the field — downstream recomputes instead.
        pass


def _evidence_type(finding: Any) -> str:
    return str(_attr(finding, "evidence_type", "") or "").strip().lower()


def _classification(finding: Any) -> str:
    """Resolve the evidence classification, recomputing it when not pre-tagged."""
    existing = str(_attr(finding, "evidence_classification", "") or "").strip().lower()
    if existing in _VALID_CLASSIFICATIONS:
        return existing
    return str(classify_evidence(finding) or "inconclusive").strip().lower()


def is_provable_from_raw(finding: Any) -> bool:
    """Return True when the finding is provable from raw evidence (belongs in main report).

    Reuses the existing ``classify_evidence`` taxonomy (the single classifier for
    evidence strength) and additionally excludes pure inferences such as
    ``threat_model_inference`` that, by definition, carry no captured raw artifact.
    """
    if _evidence_type(finding) == INFERENCE_EVIDENCE_TYPE:
        return False
    return _classification(finding) in PROVABLE_CLASSIFICATIONS


def unconfirmed_reason(finding: Any) -> str | None:
    """Human-readable reason the finding is NOT provable, or ``None`` when it is.

    The text is intentionally English to match the rendered report body and is safe to
    show to customers (no secrets, tokens, or stack traces).
    """
    if is_provable_from_raw(finding):
        return None
    if _evidence_type(finding) == INFERENCE_EVIDENCE_TYPE:
        return (
            "Threat-model hypothesis — no raw request/response, tool output or "
            "out-of-band proof was captured. Requires manual verification."
        )
    classification = _classification(finding)
    if classification == "candidate":
        return (
            "Scanner/heuristic candidate — impact not demonstrated and no raw "
            "request/response, tool output, OAST callback or screenshot was captured. "
            "Requires manual verification."
        )
    if classification == "inconclusive":
        return (
            "Inconclusive — the tool or parser produced no usable raw artifact for this "
            "finding. Requires manual verification."
        )
    return "Not provable from captured raw evidence. Requires manual verification."


def partition_findings(
    findings: Iterable[Any], *, tag: bool = True
) -> tuple[list[Any], list[Any]]:
    """Split findings into ``(confirmed_provable, unconfirmed)``.

    When ``tag`` is True (default) each finding is annotated in place with
    ``is_provable`` (bool) and ``unconfirmed_reason`` (str | None) so downstream
    serializers and templates render the partition without recomputing it.
    Order within each bucket is preserved.
    """
    confirmed: list[Any] = []
    unconfirmed: list[Any] = []
    for finding in findings:
        provable = is_provable_from_raw(finding)
        reason = None if provable else unconfirmed_reason(finding)
        if tag:
            _set_attr(finding, "is_provable", provable)
            _set_attr(finding, "unconfirmed_reason", reason)
        (confirmed if provable else unconfirmed).append(finding)
    return confirmed, unconfirmed
