"""ARGUS declarative playbook subsystem (P2-PLAYBOOKS-002).

Public surface:

* :mod:`~src.playbooks.schema` — the signed, non-executable playbook contract.
* :mod:`~src.playbooks.registry` — the fail-closed signed :class:`PlaybookRegistry`.
* :mod:`~src.playbooks.lifecycle` — the scenario status state machine.
* :mod:`~src.playbooks.planner` — applicability selection (P2 skeleton).
* :mod:`~src.playbooks.actions` — declarative step interpreter (no shell strings).
* :mod:`~src.playbooks.oracles` — deterministic outcome oracles.
* :mod:`~src.playbooks.evidence` — redacted evidence bundles.
"""

from __future__ import annotations

from src.playbooks.actions import (
    Action,
    ActionContext,
    ActionError,
    ActionResult,
    BrowserActionNotSupported,
    HttpClient,
    HttpExchange,
    HttpRequestSpec,
    HttpResponse,
    execute_step,
    get_action,
)
from src.playbooks.evidence import (
    EvidenceBundle,
    NormalizedDiff,
    build_evidence_bundle,
    redact,
)
from src.playbooks.lifecycle import (
    InvalidTransitionError,
    ScenarioState,
    ScenarioStatus,
    can_transition,
    validate_transition,
)
from src.playbooks.oracles import (
    Oracle,
    OracleNotImplemented,
    OracleResult,
    OracleVerdict,
    get_oracle,
)
from src.playbooks.planner import (
    ApplicabilityContext,
    PlannedScenario,
    PlaybookPlanner,
)
from src.playbooks.registry import (
    PlaybookNotFoundError,
    PlaybookRegistry,
    PlaybookRegistrySummary,
    PlaybookSignatureError,
    RegistryLoadError,
)
from src.playbooks.schema import (
    ActionType,
    AppliesWhen,
    OracleSpec,
    OracleType,
    Playbook,
    PlaybookCategory,
    PlaybookRiskLevel,
    PlaybookStep,
    is_valid_playbook_id,
)

__all__ = [
    "Action",
    "ActionContext",
    "ActionError",
    "ActionResult",
    "ActionType",
    "ApplicabilityContext",
    "AppliesWhen",
    "BrowserActionNotSupported",
    "EvidenceBundle",
    "HttpClient",
    "HttpExchange",
    "HttpRequestSpec",
    "HttpResponse",
    "InvalidTransitionError",
    "NormalizedDiff",
    "Oracle",
    "OracleNotImplemented",
    "OracleResult",
    "OracleSpec",
    "OracleType",
    "OracleVerdict",
    "Playbook",
    "PlaybookCategory",
    "PlaybookNotFoundError",
    "PlaybookPlanner",
    "PlaybookRegistry",
    "PlaybookRegistrySummary",
    "PlaybookRiskLevel",
    "PlaybookSignatureError",
    "PlaybookStep",
    "PlannedScenario",
    "RegistryLoadError",
    "ScenarioState",
    "ScenarioStatus",
    "build_evidence_bundle",
    "can_transition",
    "execute_step",
    "get_action",
    "get_oracle",
    "is_valid_playbook_id",
    "redact",
    "validate_transition",
]
