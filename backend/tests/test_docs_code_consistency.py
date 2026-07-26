"""Doc-to-code consistency guard (audit hardening).

The operator-facing docs (`README.md`, `CLAUDE.md`) make several load-bearing
architectural claims that silently rot when code changes:

* the pentest pipeline has **N phases** in a specific order,
* Celery routes tasks across **M queues**,
* WhiteRabbitNeo is the sole engine for pentest *analysis* tasks — cloud
  providers are only a *report/OSINT* supplement.

Each of these was found drifting during the audit (the docs claimed "10 queues
total" while the code defined 9). This module pins the invariants against the
executable source of truth so any future drift — in **either** the code or the
docs — fails CI instead of misleading an operator.

Two layers of assertions:

1. **Code invariants** — self-consistency of the code itself (phase tables agree,
   the cloud-routing frozensets never leak a pentest-analysis task to a cloud
   provider). These are the security/cost-critical guards.
2. **Doc-to-code** — the canonical Markdown docs quote the numbers/contract the
   code actually implements.

The test resolves the repo root from this file's location
(``backend/tests/<this>`` → ``parents[2]``) and reads the docs as UTF-8.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from src.celery_app import app as celery_app
from src.llm.facade import _CLOUD_FALLBACK_TASKS, _CLOUD_PREFERRED_TASKS
from src.llm.task_router import LLMTask
from src.orchestration.phases import PHASE_ORDER, PHASE_PROGRESS, ScanPhase

# --------------------------------------------------------------------------- #
# Repo layout / doc discovery
# --------------------------------------------------------------------------- #

_REPO_ROOT = Path(__file__).resolve().parents[2]
_README = _REPO_ROOT / "README.md"
_CLAUDE = _REPO_ROOT / "CLAUDE.md"


def _read_doc(path: Path) -> str:
    """Read a canonical doc as UTF-8, failing loudly if it moved/vanished."""
    if not path.exists():
        pytest.fail(
            f"canonical doc missing: {path.relative_to(_REPO_ROOT)} "
            "(doc-to-code consistency test cannot run)"
        )
    return path.read_text(encoding="utf-8")


def _collapse_ws(text: str) -> str:
    """Collapse all whitespace runs (incl. newlines) to single spaces.

    Lets the phase-chain assertion match docs that wrap the arrow chain across
    multiple lines.
    """
    return re.sub(r"\s+", " ", text)


# --------------------------------------------------------------------------- #
# Canonical values derived from executable code (single source of truth)
# --------------------------------------------------------------------------- #


def _distinct_celery_queues() -> set[str]:
    """The exact set of Celery queues the app can dispatch to.

    Mirrors how a worker/operator enumerates queues: every explicit
    ``task_routes`` target plus the default queue.
    """
    queues = {route["queue"] for route in celery_app.conf.task_routes.values()}
    queues.add(celery_app.conf.task_default_queue)
    return queues


# Pentest *analysis* tasks: WhiteRabbitNeo-only, MUST NOT ever fall back to a
# cloud provider (data-exfil + cost regression risk). This mirrors the docs'
# "PRIMARY for all pentest analysis tasks … NO cloud fallback".
_CORE_ANALYSIS_TASKS: frozenset[LLMTask] = frozenset(
    {
        LLMTask.ORCHESTRATION,
        LLMTask.THREAT_MODELING,
        LLMTask.VULN_ANALYSIS,
        LLMTask.VALIDATION_ONESHOT,
        LLMTask.ZERO_DAY_ANALYSIS,
        LLMTask.DEDUP_ANALYSIS,
    }
)


# --------------------------------------------------------------------------- #
# Layer 1 — code self-consistency (phase tables)
# --------------------------------------------------------------------------- #


def test_phase_tables_are_internally_consistent() -> None:
    """``ScanPhase`` / ``PHASE_ORDER`` / ``PHASE_PROGRESS`` describe one pipeline."""
    n = len(ScanPhase)
    assert len(PHASE_ORDER) == n, "PHASE_ORDER length diverged from ScanPhase"
    assert len(PHASE_PROGRESS) == n, "PHASE_PROGRESS length diverged from ScanPhase"

    # PHASE_ORDER is a permutation of every enum member (no dupes, no gaps).
    assert set(PHASE_ORDER) == set(ScanPhase)
    assert len(set(PHASE_ORDER)) == n

    # Every phase value has a progress entry, and progress increases
    # monotonically in pipeline order and terminates at 100.
    progresses = [PHASE_PROGRESS[p.value] for p in PHASE_ORDER]
    assert progresses == sorted(progresses), "PHASE_PROGRESS not monotonic in PHASE_ORDER"
    assert progresses[-1] == 100, "final phase must report 100% progress"


# --------------------------------------------------------------------------- #
# Layer 1 — code self-consistency (LLM cloud-routing frozensets)
# --------------------------------------------------------------------------- #


def test_cloud_fallback_set_is_exactly_report_and_osint() -> None:
    """Only report-supplement + OSINT tasks may fall back to a cloud provider."""
    assert _CLOUD_FALLBACK_TASKS == frozenset(
        {
            LLMTask.REPORT_SECTION,
            LLMTask.EXECUTIVE_SUMMARY,
            LLMTask.COST_SUMMARY,
            LLMTask.PERPLEXITY_OSINT,
        }
    )


def test_cloud_preferred_set_is_exactly_exploit_and_poc() -> None:
    """Cloud-preferred routing is the documented exploit/PoC-JSON exception only."""
    assert _CLOUD_PREFERRED_TASKS == frozenset(
        {LLMTask.EXPLOIT_GENERATION, LLMTask.POC_GENERATION}
    )


def test_core_analysis_tasks_never_route_to_cloud() -> None:
    """Security/cost invariant: pentest analysis stays on WhiteRabbitNeo.

    A pentest-analysis task appearing in either cloud set would let sensitive
    target analysis leave the local WRB engine for a third-party API — exactly
    the regression this guard exists to catch.
    """
    leaked_fallback = _CORE_ANALYSIS_TASKS & _CLOUD_FALLBACK_TASKS
    leaked_preferred = _CORE_ANALYSIS_TASKS & _CLOUD_PREFERRED_TASKS
    assert not leaked_fallback, f"analysis tasks leaked to cloud fallback: {leaked_fallback}"
    assert not leaked_preferred, f"analysis tasks leaked to cloud preferred: {leaked_preferred}"


def test_cloud_sets_are_disjoint() -> None:
    """A task cannot be both 'prefer cloud' and 'WRB-first, cloud fallback'."""
    assert not (_CLOUD_FALLBACK_TASKS & _CLOUD_PREFERRED_TASKS)


# --------------------------------------------------------------------------- #
# Layer 2 — doc-to-code: phase count + ordered pipeline
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("doc_path", [_README, _CLAUDE], ids=["README", "CLAUDE"])
def test_docs_quote_correct_phase_count(doc_path: Path) -> None:
    """Canonical docs must state the same phase count the code defines."""
    n = len(ScanPhase)
    doc = _read_doc(doc_path)
    pattern = re.compile(rf"scan pipeline \({n} phases\)", re.IGNORECASE)
    assert pattern.search(doc), (
        f"{doc_path.name} does not state 'Scan pipeline ({n} phases)'; "
        "phase count drifted from code"
    )


@pytest.mark.parametrize("doc_path", [_README, _CLAUDE], ids=["README", "CLAUDE"])
def test_docs_contain_canonical_phase_chain(doc_path: Path) -> None:
    """Docs must show the exact ordered phase chain from ``PHASE_ORDER``."""
    chain = " → ".join(p.value for p in PHASE_ORDER)
    doc = _collapse_ws(_read_doc(doc_path))
    assert chain in doc, (
        f"{doc_path.name} is missing the canonical phase chain:\n  {chain}"
    )


# --------------------------------------------------------------------------- #
# Layer 2 — doc-to-code: Celery queue count
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("doc_path", [_README, _CLAUDE], ids=["README", "CLAUDE"])
def test_docs_quote_correct_queue_count(doc_path: Path) -> None:
    """Canonical docs must state the same queue total the code routes to."""
    n = len(_distinct_celery_queues())
    doc = _read_doc(doc_path)
    pattern = re.compile(rf"{n} queues total", re.IGNORECASE)
    assert pattern.search(doc), (
        f"{doc_path.name} does not state '{n} queues total'; "
        f"queue count drifted from code (code defines {n} distinct queues)"
    )


# --------------------------------------------------------------------------- #
# Layer 2 — doc-to-code: LLM routing contract
# --------------------------------------------------------------------------- #


def test_claude_documents_no_cloud_fallback_contract() -> None:
    """CLAUDE.md must still assert the WRB-only contract for analysis tasks.

    Pairs with :func:`test_core_analysis_tasks_never_route_to_cloud`: the code
    enforces it, the doc must keep promising it.
    """
    doc = _read_doc(_CLAUDE)
    assert "WhiteRabbitNeo" in doc, "CLAUDE.md no longer names the WRB engine"
    assert re.search(r"no cloud fallback", doc, re.IGNORECASE), (
        "CLAUDE.md dropped the 'NO cloud fallback' contract for pentest analysis"
    )
