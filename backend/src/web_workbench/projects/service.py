"""Project scope + EAP evaluation services (WB-P1-FOUNDATION).

Pure, side-effect-free domain logic that ties a workbench project's persisted
scope rules and signed EAP to the *shared* policy primitives:

* scope matching goes through :class:`src.policy.scope.ScopeEngine` — the same
  engine used by :class:`src.policy.preflight.PreflightChecker`;
* EAP verification goes through
  :class:`src.policy.engagement_authorization.EngagementAuthorizationService` —
  fail-closed, exactly as the preflight EAP gate.

No bespoke scope parsing and no bespoke signature checking live here; this
module only orchestrates the existing, audited abstractions so the workbench
cannot drift from platform policy (ADR-WB-4).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from pydantic import ValidationError

from src.pipeline.contracts.tool_job import TargetSpec
from src.policy.engagement_authorization import (
    EAP_FAILURE_REASONS,
    EngagementAuthorizationError,
    EngagementAuthorizationProfile,
    EngagementAuthorizationService,
)
from src.policy.scope import ScopeDecision, ScopeEngine, ScopeRule

#: EAP display statuses re-derived fail-closed from the signed blob.
EAP_STATUS_VERIFIED: Final[str] = "verified"
EAP_STATUS_INVALID: Final[str] = "invalid"
EAP_STATUS_EXPIRED: Final[str] = "expired"

_REASON_EXPIRED: Final[str] = "eap_expired"


def scope_engine_for_rules(rules: Sequence[ScopeRule]) -> ScopeEngine:
    """Build the shared :class:`ScopeEngine` for a project's scope rules.

    The engine is default-deny: with an empty rule list every target is
    rejected. Deny rules always shadow allow rules (enforced by the engine).
    """
    return ScopeEngine(tuple(rules))


class ProjectScopeService:
    """Evaluate targets against a project's persisted scope rules.

    Construct once per project (the rule set is closed over at construction),
    then call :meth:`check` for each candidate target — this is the mandatory
    gate before *any* active operation (SI-WB-1).
    """

    def __init__(self, rules: Sequence[ScopeRule]) -> None:
        self._engine = scope_engine_for_rules(rules)

    @property
    def engine(self) -> ScopeEngine:
        return self._engine

    def check(self, target: TargetSpec, *, port: int | None = None) -> ScopeDecision:
        """Return the shared engine's decision for ``target`` (and ``port``)."""
        return self._engine.check(target, port=port)

    def is_in_scope(self, target: TargetSpec, *, port: int | None = None) -> bool:
        return self._engine.check(target, port=port).allowed


@dataclass(frozen=True)
class WorkbenchEapEvaluation:
    """Fail-closed result of evaluating a signed EAP blob for persistence.

    ``profile`` is only present when the blob parsed into a valid model (it may
    still be ``status != verified`` when the signature is bad or it expired).
    """

    status: str
    profile: EngagementAuthorizationProfile | None
    engagement_id: str | None
    signer_key_id: str | None
    expires: datetime | None
    failure_reason: str | None


def evaluate_eap(
    signed_profile: Mapping[str, object],
    *,
    eap_service: EngagementAuthorizationService,
) -> WorkbenchEapEvaluation:
    """Parse and verify a signed EAP blob, deriving a persistence projection.

    Fail-closed:

    * a blob that does not parse into an
      :class:`EngagementAuthorizationProfile` → ``status=invalid`` with no
      profile;
    * a profile that fails signature verification → ``status=invalid``;
    * a profile whose signature is valid but which has expired →
      ``status=expired``;
    * only a fully valid, unexpired, correctly-signed profile →
      ``status=verified``.

    The ``expires`` / ``engagement_id`` / ``signer_key_id`` projections are
    taken from the parsed model (never from unauthenticated caller-supplied
    scalar fields).
    """
    try:
        profile = EngagementAuthorizationProfile.model_validate(dict(signed_profile))
    except ValidationError:
        return WorkbenchEapEvaluation(
            status=EAP_STATUS_INVALID,
            profile=None,
            engagement_id=None,
            signer_key_id=None,
            expires=None,
            failure_reason="eap_unparseable",
        )

    try:
        eap_service.verify(profile)
    except EngagementAuthorizationError as exc:
        reason = exc.summary if exc.summary in EAP_FAILURE_REASONS else "eap_invalid"
        status = EAP_STATUS_EXPIRED if reason == _REASON_EXPIRED else EAP_STATUS_INVALID
        return WorkbenchEapEvaluation(
            status=status,
            profile=profile,
            engagement_id=profile.engagement_id,
            signer_key_id=profile.signer_key_id,
            expires=profile.expires,
            failure_reason=reason,
        )

    return WorkbenchEapEvaluation(
        status=EAP_STATUS_VERIFIED,
        profile=profile,
        engagement_id=profile.engagement_id,
        signer_key_id=profile.signer_key_id,
        expires=profile.expires,
        failure_reason=None,
    )
