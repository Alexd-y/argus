"""Engagement Authorization Profile — pre-authorized action classes (P4-SCENARIO-004).

An **Engagement Authorization Profile (EAP)** is a signed, time-bounded
contract in which the customer pre-authorizes specific *classes* of action
against a specific *allow-list of targets* for one engagement. It is the
source of *automatic approval* for those pre-agreed actions.

Security model (SI-1 — the EAP never *disables* approval):

* The EAP does not weaken :class:`~src.policy.preflight.PreflightChecker`.
  Scope / ownership / policy guardrails always run first and unchanged.
* When (and only when) the policy layer demands an approval, the approval
  layer MAY ask the EAP: "is this action class pre-authorized for this
  target?". If yes, the approval requirement is *satisfied pre-authorized* —
  a fresh ``approval_id`` is minted and an immutable audit record is written
  attributing it to ``engagement_id`` / ``authorized_by`` (who pre-authorized,
  when). If no (class not listed, or target outside the EAP allow-list), the
  EAP grants nothing and the action stays ``WAITING_APPROVAL`` / denied.
* The EAP ``targets`` list is an *allow-list*; third-party / out-of-scope
  targets are additionally blocked by the existing
  :class:`~src.policy.scope.ScopeEngine` (SI-2).

The profile is cryptographically signed with an Ed25519 key registered in the
:class:`~src.sandbox.signing.KeyManager`, mirroring
:class:`~src.policy.approval_service.ApprovalService` and the signed catalog
registries. Verification is fail-closed: a missing / invalid signature or an
expired profile authorizes nothing.
"""

from __future__ import annotations

import ipaddress
import json
import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Final, Self
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from src.pipeline.contracts.tool_job import TargetSpec
from src.policy.audit import AuditEventType, AuditLogger
from src.policy.scope import ScopeEngine, ScopeKind, ScopeRule
from src.sandbox.signing import (
    KeyManager,
    KeyNotFoundError,
    public_key_id,
    sign_blob,
    verify_blob,
)

_logger = logging.getLogger(__name__)

_KEY_ID_LEN: Final[int] = 16


# ---------------------------------------------------------------------------
# Closed taxonomy of failure summaries
# ---------------------------------------------------------------------------


_REASON_NOT_SIGNED: Final[str] = "eap_not_signed"
_REASON_UNKNOWN_KEY: Final[str] = "eap_unknown_key"
_REASON_SIG_INVALID: Final[str] = "eap_signature_invalid"
_REASON_EXPIRED: Final[str] = "eap_expired"
_REASON_CLASS_NOT_PREAUTHORIZED: Final[str] = "eap_action_class_not_preauthorized"
_REASON_TARGET_NOT_IN_ALLOWLIST: Final[str] = "eap_target_not_in_allowlist"

EAP_FAILURE_REASONS: Final[frozenset[str]] = frozenset(
    {
        _REASON_NOT_SIGNED,
        _REASON_UNKNOWN_KEY,
        _REASON_SIG_INVALID,
        _REASON_EXPIRED,
        _REASON_CLASS_NOT_PREAUTHORIZED,
        _REASON_TARGET_NOT_IN_ALLOWLIST,
    }
)


class EngagementAuthorizationError(Exception):
    """Raised when an EAP fails verification. ``summary`` is a closed reason."""

    def __init__(self, summary: str) -> None:
        super().__init__(summary)
        self.summary = summary


# ---------------------------------------------------------------------------
# Action classes
# ---------------------------------------------------------------------------


class ActionClass(StrEnum):
    """Closed set of action classes a customer may pre-authorize.

    These are coarser than tool ids or oracle types on purpose: a customer
    signs off on *what kind of thing* an engagement may do, not on each
    individual request.
    """

    RECON = "recon"
    INJECTION_SAFE = "injection_safe"
    RCE = "rce"
    DESTRUCTIVE_UPLOAD = "destructive_upload"
    ACCOUNT_MUTATION = "account_mutation"
    PAYMENT = "payment"
    DATA_DELETION = "data_deletion"
    RACE = "race"
    DOS_LIKE = "dos_like"
    MASS_MAIL = "mass_mail"
    THIRD_PARTY = "third_party"


def _utcnow() -> datetime:
    return datetime.now(tz=timezone.utc)


# ---------------------------------------------------------------------------
# Profile model
# ---------------------------------------------------------------------------


class EngagementAuthorizationProfile(BaseModel):
    """Signed, time-bounded pre-authorization for an engagement.

    The signature binds every operator-meaningful field (see
    :meth:`canonical_bytes`) but NOT the ``signer_key_id`` / ``signature``
    fields themselves, so the profile can be built unsigned and then signed.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    engagement_id: StrictStr = Field(min_length=1, max_length=128)
    authorized_by: StrictStr = Field(min_length=1, max_length=256)
    targets: tuple[StrictStr, ...] = Field(min_length=1, max_length=256)
    allow_action_classes: frozenset[ActionClass] = Field(default_factory=frozenset)
    max_request_budget: StrictInt = Field(ge=0, le=100_000_000)
    expires: datetime
    signer_key_id: StrictStr | None = Field(default=None, min_length=16, max_length=16)
    signature: StrictStr | None = Field(default=None, min_length=86, max_length=128)

    @field_validator("targets")
    @classmethod
    def _check_targets(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for target in value:
            if not target.strip() or "\n" in target or "\r" in target:
                raise ValueError("EAP targets must be non-empty single-line patterns")
        return value

    @model_validator(mode="after")
    def _validate(self) -> Self:
        if self.expires.tzinfo is None:
            raise ValueError("EAP expires must be timezone-aware")
        return self

    def canonical_bytes(self) -> bytes:
        """Return the stable JSON payload the signature endorses.

        Excludes ``signer_key_id`` / ``signature`` (identity of the endorsement
        is not itself endorsed) so the same bytes can be produced before and
        after signing.
        """
        payload: Mapping[str, object] = {
            "engagement_id": self.engagement_id,
            "authorized_by": self.authorized_by,
            "targets": sorted(self.targets),
            "allow_action_classes": sorted(c.value for c in self.allow_action_classes),
            "max_request_budget": self.max_request_budget,
            "expires": self.expires.astimezone(timezone.utc).isoformat(),
        }
        return json.dumps(
            payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")

    def is_expired(self, *, now: datetime | None = None) -> bool:
        return (now or _utcnow()) >= self.expires


# ---------------------------------------------------------------------------
# Decision value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EngagementAuthorizationDecision:
    """Outcome of asking the EAP to satisfy an approval.

    ``authorized=True`` carries a freshly-minted ``approval_id`` that the
    approval layer treats as a valid, audited approval token. ``authorized=
    False`` carries a closed-taxonomy ``reason`` and no token.
    """

    authorized: bool
    engagement_id: str
    action_class: ActionClass
    approval_id: UUID | None = None
    reason: str | None = None


# ---------------------------------------------------------------------------
# Target classification (EAP targets -> ScopeRule allow-list)
# ---------------------------------------------------------------------------


def _classify_target(pattern: str) -> ScopeRule:
    """Turn one EAP target string into a :class:`ScopeRule` allow entry.

    Reuses the existing scope semantics so the EAP allow-list is enforced with
    the same, audited matching logic (no bespoke SSRF-prone parsing).
    """
    text = pattern.strip()
    lowered = text.lower()
    if lowered.startswith(("http://", "https://")):
        return ScopeRule(kind=ScopeKind.URL, pattern=text)
    if "/" in text:
        try:
            ipaddress.ip_network(text, strict=False)
            return ScopeRule(kind=ScopeKind.CIDR, pattern=text)
        except ValueError:
            pass
    try:
        ipaddress.ip_address(text)
        return ScopeRule(kind=ScopeKind.IP, pattern=text)
    except ValueError:
        pass
    return ScopeRule(kind=ScopeKind.DOMAIN, pattern=text)


def _scope_engine_for(profile: EngagementAuthorizationProfile) -> ScopeEngine:
    return ScopeEngine([_classify_target(t) for t in profile.targets])


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------


class EngagementAuthorizationService:
    """Verify EAPs and use them as an audited source of auto-approval.

    Stateless apart from references to the key manager and audit logger; the
    caller owns EAP persistence.
    """

    def __init__(
        self,
        *,
        key_manager: KeyManager,
        audit_logger: AuditLogger,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._key_manager = key_manager
        self._audit_logger = audit_logger
        self._clock: Callable[[], datetime] = clock or _utcnow

    # -- signing (test / tooling convenience) --------------------------------

    @staticmethod
    def sign_profile(
        profile: EngagementAuthorizationProfile, *, private_key: Ed25519PrivateKey
    ) -> EngagementAuthorizationProfile:
        """Return a signed copy of ``profile`` (dev/test helper)."""
        kid = public_key_id(private_key.public_key())
        signature = sign_blob(private_key, profile.canonical_bytes())
        return profile.model_copy(update={"signer_key_id": kid, "signature": signature})

    # -- verification --------------------------------------------------------

    def verify(self, profile: EngagementAuthorizationProfile) -> None:
        """Validate the profile's signature and expiry. Raise on failure.

        Order: signed → key known → signature valid → not expired.
        """
        if profile.signer_key_id is None or profile.signature is None:
            raise EngagementAuthorizationError(_REASON_NOT_SIGNED)
        try:
            public_key = self._key_manager.get(profile.signer_key_id)
        except KeyNotFoundError as exc:
            _logger.warning(
                "policy.eap.unknown_key",
                extra={
                    "engagement_id": profile.engagement_id,
                    "signer_key_id": profile.signer_key_id,
                    "error_class": type(exc).__name__,
                },
            )
            raise EngagementAuthorizationError(_REASON_UNKNOWN_KEY) from exc
        if not verify_blob(public_key, profile.canonical_bytes(), profile.signature):
            raise EngagementAuthorizationError(_REASON_SIG_INVALID)
        if profile.is_expired(now=self._clock()):
            raise EngagementAuthorizationError(_REASON_EXPIRED)

    def is_verified(self, profile: EngagementAuthorizationProfile) -> bool:
        """Non-raising variant of :meth:`verify`."""
        try:
            self.verify(profile)
        except EngagementAuthorizationError:
            return False
        return True

    # -- pre-authorization check --------------------------------------------

    def is_preauthorized(
        self,
        profile: EngagementAuthorizationProfile,
        action_class: ActionClass,
        target: TargetSpec,
    ) -> bool:
        """Return ``True`` iff ``action_class`` is allowed AND ``target`` is in
        the profile's target allow-list.

        Pure: does not verify the signature (call :meth:`verify` first, or use
        :meth:`authorize` which verifies then checks). Never widens scope — the
        allow-list is evaluated with the shared :class:`ScopeEngine`.
        """
        if action_class not in profile.allow_action_classes:
            return False
        decision = _scope_engine_for(profile).check(target, port=None)
        return decision.allowed

    # -- audited auto-approval ----------------------------------------------

    def authorize(
        self,
        profile: EngagementAuthorizationProfile,
        action_class: ActionClass,
        target: TargetSpec,
        *,
        tenant_id: UUID,
        scan_id: UUID | None = None,
        actor_id: UUID | None = None,
    ) -> EngagementAuthorizationDecision:
        """Satisfy an approval pre-authorized by ``profile``, with an audit trail.

        Returns an ``authorized=True`` decision carrying a fresh ``approval_id``
        only when the profile verifies AND the action class + target are
        pre-authorized. Otherwise returns ``authorized=False`` with a closed
        reason and emits a deny audit event. In no case is a pending approval
        silently bypassed (SI-1).
        """
        try:
            self.verify(profile)
        except EngagementAuthorizationError as exc:
            self._emit(
                event_type=AuditEventType.APPROVAL_DENIED,
                profile=profile,
                action_class=action_class,
                target=target,
                tenant_id=tenant_id,
                scan_id=scan_id,
                actor_id=actor_id,
                allowed=False,
                summary=exc.summary,
                approval_id=None,
            )
            return EngagementAuthorizationDecision(
                authorized=False,
                engagement_id=profile.engagement_id,
                action_class=action_class,
                reason=exc.summary,
            )

        if action_class not in profile.allow_action_classes:
            reason = _REASON_CLASS_NOT_PREAUTHORIZED
        elif not _scope_engine_for(profile).check(target, port=None).allowed:
            reason = _REASON_TARGET_NOT_IN_ALLOWLIST
        else:
            reason = None

        if reason is not None:
            self._emit(
                event_type=AuditEventType.APPROVAL_DENIED,
                profile=profile,
                action_class=action_class,
                target=target,
                tenant_id=tenant_id,
                scan_id=scan_id,
                actor_id=actor_id,
                allowed=False,
                summary=reason,
                approval_id=None,
            )
            return EngagementAuthorizationDecision(
                authorized=False,
                engagement_id=profile.engagement_id,
                action_class=action_class,
                reason=reason,
            )

        approval_id = uuid4()
        self._emit(
            event_type=AuditEventType.APPROVAL_GRANTED,
            profile=profile,
            action_class=action_class,
            target=target,
            tenant_id=tenant_id,
            scan_id=scan_id,
            actor_id=actor_id,
            allowed=True,
            summary=None,
            approval_id=approval_id,
        )
        return EngagementAuthorizationDecision(
            authorized=True,
            engagement_id=profile.engagement_id,
            action_class=action_class,
            approval_id=approval_id,
        )

    # -- internals -----------------------------------------------------------

    def _emit(
        self,
        *,
        event_type: AuditEventType,
        profile: EngagementAuthorizationProfile,
        action_class: ActionClass,
        target: TargetSpec,
        tenant_id: UUID,
        scan_id: UUID | None,
        actor_id: UUID | None,
        allowed: bool,
        summary: str | None,
        approval_id: UUID | None,
    ) -> None:
        payload: dict[str, object] = {
            "engagement_id": profile.engagement_id,
            "authorized_by": profile.authorized_by,
            "action_class": action_class.value,
            "target": target.value,
            "preauthorized": allowed,
        }
        if approval_id is not None:
            payload["approval_id"] = approval_id
        self._audit_logger.emit(
            event_type=event_type,
            tenant_id=tenant_id,
            scan_id=scan_id,
            actor_id=actor_id,
            decision_allowed=allowed,
            failure_summary=summary,
            payload=payload,
        )
        _logger.info(
            "policy.eap.decision",
            extra={
                "engagement_id": profile.engagement_id,
                "action_class": action_class.value,
                "allowed": allowed,
                "failure_summary": summary,
            },
        )


def default_action_class(*, category: str, risk_level: str) -> ActionClass:
    """Best-effort map a playbook category/risk to an :class:`ActionClass`.

    Used by callers (e.g. the scenario executor's approval gate) that need to
    ask the EAP about a playbook without threading an explicit action class
    through every layer. Callers may override the mapping.
    """
    by_category: Mapping[str, ActionClass] = {
        "authentication": ActionClass.INJECTION_SAFE,
        "authorization": ActionClass.INJECTION_SAFE,
        "account_lifecycle": ActionClass.ACCOUNT_MUTATION,
        "session_management": ActionClass.INJECTION_SAFE,
        "business_logic": ActionClass.PAYMENT,
        "rate_limit": ActionClass.DOS_LIKE,
        "race_conditions": ActionClass.RACE,
        "file_upload": ActionClass.DESTRUCTIVE_UPLOAD,
        "technology_exposure": ActionClass.RECON,
    }
    mapped = by_category.get(category)
    if mapped is not None:
        return mapped
    if risk_level == "destructive":
        return ActionClass.DATA_DELETION
    return ActionClass.INJECTION_SAFE


def preauthorized_classes(
    profile: EngagementAuthorizationProfile,
) -> Sequence[ActionClass]:
    """Return the sorted action classes the profile pre-authorizes (helper)."""
    return sorted(profile.allow_action_classes, key=lambda c: c.value)


__all__ = [
    "EAP_FAILURE_REASONS",
    "ActionClass",
    "EngagementAuthorizationDecision",
    "EngagementAuthorizationError",
    "EngagementAuthorizationProfile",
    "EngagementAuthorizationService",
    "default_action_class",
    "preauthorized_classes",
]
