"""Composition helpers tying the OAST plane to PayloadBuilder + PolicyEngine.

The validator loop never instantiates a provisioner / correlator / canary
generator directly. Instead it asks :class:`OASTPlane` for an
:class:`EvidencePreparation` matching the current
:class:`PayloadFamily` and :class:`PolicyContext`. The preparation
bundles three things:

* an :class:`EvidenceStrategy` discriminator (``oast`` or ``canary``) so
  the verifier can pick the right confirmation path;
* a populated :class:`~src.payloads.builder.PayloadBuildRequest` with
  ``oast_host`` / ``canary`` placeholders pre-filled (so the existing
  registry templates render unchanged);
* the back-references the verifier needs to confirm evidence — a
  :class:`OASTToken` in OAST mode, a :class:`Canary` in canary mode.

The plane exposes a deliberately tiny API:

* :meth:`OASTPlane.prepare` — pick a strategy and return everything the
  validator needs.
* :meth:`OASTPlane.is_oast_required_for_family` — pure check used by the
  policy preflight to surface ``oast_disabled_for_oast_required``
  failures early.

Every public surface is fully typed and side-effect-free apart from the
provisioner's bookkeeping (which is itself thread-safe).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from src.oast.canary import (
    Canary,
    CanaryGenerator,
    CanaryKind,
)
from src.oast.correlator import OASTCorrelator
from src.oast.listener_protocol import OASTListenerProtocol
from src.oast.provisioner import (
    OASTBackendKind,
    OASTProvisioner,
    OASTToken,
    OASTUnavailableError,
)
if TYPE_CHECKING:
    from src.payloads.registry import PayloadFamily
    from src.policy.policy_engine import PolicyContext


_logger = logging.getLogger(__name__)


_DEFAULT_TOKEN_TTL: Final[timedelta] = timedelta(minutes=10)
_OAST_DISABLED_REASON: Final[str] = "oast_disabled_for_oast_required"


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OASTIntegrationError(Exception):
    """Base class for integration-layer failures."""


class OASTRequiredButDisabledError(OASTIntegrationError):
    """Raised when the family requires OAST and the plane cannot provide it."""

    def __init__(self, family_id: str, *, reason: str) -> None:
        super().__init__(
            f"family_id={family_id!r} requires OAST but it is unavailable: {reason}"
        )
        self.family_id = family_id
        self.reason = reason


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class EvidenceStrategy(StrEnum):
    """How the validator will collect evidence for the upcoming payload run."""

    OAST = "oast"
    CANARY = "canary"


class EvidencePreparation(BaseModel):
    """Bundle returned by :meth:`OASTPlane.prepare`.

    ``payload_request`` is ready to be passed into
    :meth:`PayloadBuilder.build`. The verifier holds onto either
    :attr:`oast_token` or :attr:`canary` depending on the strategy and
    uses the matching confirmation path.

    Attributes
    ----------
    canary_token_for_finding
        Lowercase hex string fit for ``ValidationJob.canary_token`` /
        ``ReproducerSpecDTO.canary_token``. Always populated so the audit
        record carries a stable reference even when OAST is the primary
        strategy (in OAST mode this is derived from ``oast_token.id``).
    """

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    strategy: EvidenceStrategy
    payload_request: Any
    oast_token: OASTToken | None = None
    canary: Canary | None = None
    canary_token_for_finding: StrictStr = Field(
        min_length=16,
        max_length=128,
        description="Lowercase-hex value for ValidationJob.canary_token",
    )

    def model_post_init(self, _context: object) -> None:
        if self.strategy is EvidenceStrategy.OAST:
            if self.oast_token is None:
                raise ValueError(
                    "EvidencePreparation: OAST strategy requires an oast_token"
                )
            if self.canary is not None:
                raise ValueError(
                    "EvidencePreparation: OAST strategy must not carry a canary"
                )
        else:
            if self.canary is None:
                raise ValueError(
                    "EvidencePreparation: CANARY strategy requires a canary"
                )
            if self.oast_token is not None:
                raise ValueError(
                    "EvidencePreparation: CANARY strategy must not carry an oast_token"
                )


# ---------------------------------------------------------------------------
# Plane
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OASTPlaneConfig:
    """Tunables for :class:`OASTPlane`.

    ``token_ttl`` bounds the OAST token lifetime; the validator typically
    completes well within that window so the default keeps the lookup
    table small.
    """

    token_ttl: timedelta = _DEFAULT_TOKEN_TTL
    canary_kind_for_unknown_family: CanaryKind = CanaryKind.DOM_MARKER


class OASTPlane:
    """Composition root for the OAST plane (provisioner + correlator + canary).

    The plane knows nothing about the validator runtime — it accepts a
    :class:`PayloadFamily` and a :class:`PolicyContext`, decides whether
    OAST is available, and returns an :class:`EvidencePreparation` the
    validator can immediately feed into the :class:`PayloadBuilder`.

    Parameters
    ----------
    provisioner
        The active token provisioner. May be a
        :class:`DisabledOASTProvisioner` when the tenant policy turns
        OAST off; in that case the plane downgrades to canaries and
        raises :class:`OASTRequiredButDisabledError` for families that
        cannot live without OAST.
    correlator
        Used to register issued tokens; the plane does not call
        :meth:`OASTCorrelator.wait_for_interaction` itself, that is the
        verifier's job.
    canary_generator
        Source of fallback canaries.
    listener
        Optional hook for keeping the listener's lookup tables in sync
        with newly issued tokens. May be ``None`` for unit tests that
        only exercise the integration helpers.
    config
        Tunables; defaults are appropriate for unit tests and the in-cluster
        sandbox.
    """

    def __init__(
        self,
        provisioner: OASTProvisioner,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
        *,
        listener: OASTListenerProtocol | None = None,
        config: OASTPlaneConfig | None = None,
    ) -> None:
        self._provisioner = provisioner
        self._correlator = correlator
        self._canary_generator = canary_generator
        self._listener = listener
        self._config = config or OASTPlaneConfig()

    # -- public API ----------------------------------------------------------

    @property
    def is_oast_active(self) -> bool:
        """Return ``True`` when the plane can issue OAST tokens."""
        return self._provisioner.backend is not OASTBackendKind.DISABLED

    @staticmethod
    def is_oast_required_for_family(family: PayloadFamily) -> bool:
        return family.oast_required

    def policy_failure_reason_oast_disabled(self) -> str:
        """Stable string the policy preflight uses when denying OAST families."""
        return _OAST_DISABLED_REASON

    def prepare(
        self,
        *,
        family: PayloadFamily,
        policy_context: "PolicyContext",
        correlation_key: str,
        encoding_pipeline: str | None = None,
        approval_id: str | None = None,
        max_payloads: int = 64,
        validation_job_id: UUID | None = None,
        extra_parameters: dict[str, str] | None = None,
        canary_kind_override: CanaryKind | None = None,
        canary_header_name: str | None = None,
        canary_cookie_name: str | None = None,
    ) -> EvidencePreparation:
        """Pick a strategy and build the matching :class:`PayloadBuildRequest`.

        The plane prefers OAST when both the family and the plane allow
        it; otherwise it falls back to canary mode. Families with
        :attr:`PayloadFamily.oast_required` set may NOT silently downgrade —
        the method raises :class:`OASTRequiredButDisabledError` so the
        caller surfaces ``oast_disabled_for_oast_required`` to the
        policy log instead of generating a misleading payload bundle.
        """
        merged_extra = dict(extra_parameters or {})
        for reserved in ("oast_host", "canary"):
            if reserved in merged_extra:
                raise OASTIntegrationError(
                    f"extra_parameters must not provide reserved key {reserved!r}"
                )

        if self.is_oast_active:
            try:
                return self._prepare_oast(
                    family=family,
                    policy_context=policy_context,
                    correlation_key=correlation_key,
                    encoding_pipeline=encoding_pipeline,
                    approval_id=approval_id,
                    max_payloads=max_payloads,
                    validation_job_id=validation_job_id,
                    extra_parameters=merged_extra,
                )
            except OASTUnavailableError as exc:
                if family.oast_required:
                    raise OASTRequiredButDisabledError(
                        family.family_id, reason=str(exc) or _OAST_DISABLED_REASON
                    ) from exc
                _logger.info(
                    "oast.integration.fallback_to_canary",
                    extra={
                        "family_id": family.family_id,
                        "reason": str(exc) or _OAST_DISABLED_REASON,
                    },
                )
                # Fall through to canary mode below.

        if family.oast_required:
            raise OASTRequiredButDisabledError(
                family.family_id, reason=_OAST_DISABLED_REASON
            )

        return self._prepare_canary(
            family=family,
            correlation_key=correlation_key,
            encoding_pipeline=encoding_pipeline,
            approval_id=approval_id,
            max_payloads=max_payloads,
            extra_parameters=merged_extra,
            canary_kind=canary_kind_override
            or self._config.canary_kind_for_unknown_family,
            canary_header_name=canary_header_name,
            canary_cookie_name=canary_cookie_name,
        )

    # -- internal helpers ----------------------------------------------------

    def _prepare_oast(
        self,
        *,
        family: PayloadFamily,
        policy_context: "PolicyContext",
        correlation_key: str,
        encoding_pipeline: str | None,
        approval_id: str | None,
        max_payloads: int,
        validation_job_id: UUID | None,
        extra_parameters: dict[str, str],
    ) -> EvidencePreparation:
        token = self._provisioner.issue(
            tenant_id=policy_context.tenant_id,
            scan_id=policy_context.scan_id or _zero_uuid(),
            validation_job_id=validation_job_id,
            family=family.family_id,
            ttl=self._config.token_ttl,
        )
        if self._listener is not None:
            self._listener.register(token)

        parameters: dict[str, str] = dict(extra_parameters)
        parameters["oast_host"] = token.subdomain
        parameters["canary"] = token.path_token.lower()

        from src.payloads.builder import PayloadBuildRequest

        request = PayloadBuildRequest(
            family_id=family.family_id,
            correlation_key=correlation_key,
            encoding_pipeline=encoding_pipeline,
            approval_id=approval_id,
            parameters=parameters,
            max_payloads=max_payloads,
        )
        canary_token = _canary_token_from_uuid(token.id)
        _logger.debug(
            "oast.integration.prepared",
            extra={
                "strategy": EvidenceStrategy.OAST.value,
                "family_id": family.family_id,
                "tenant_id": str(policy_context.tenant_id),
            },
        )
        return EvidencePreparation(
            strategy=EvidenceStrategy.OAST,
            payload_request=request,
            oast_token=token,
            canary=None,
            canary_token_for_finding=canary_token,
        )

    def _prepare_canary(
        self,
        *,
        family: PayloadFamily,
        correlation_key: str,
        encoding_pipeline: str | None,
        approval_id: str | None,
        max_payloads: int,
        extra_parameters: dict[str, str],
        canary_kind: CanaryKind,
        canary_header_name: str | None,
        canary_cookie_name: str | None,
    ) -> EvidencePreparation:
        # Canary mode cannot serve OAST-only templates; the caller should
        # have caught this via ``family.oast_required`` already.
        if family.oast_required:
            raise OASTRequiredButDisabledError(
                family.family_id, reason=_OAST_DISABLED_REASON
            )

        canary = self._canary_generator.generate(
            canary_kind,
            target_hint=family.family_id,
            header_name=canary_header_name,
            cookie_name=canary_cookie_name,
        )
        parameters: dict[str, str] = dict(extra_parameters)
        # The marker the templates expect is ``{canary}``; ``{oast_host}``
        # is ONLY embedded into OAST-required families, so we deliberately
        # leave it absent to surface a missing-parameter error if the
        # caller paired a canary with an OAST template.
        parameters["canary"] = canary.secret_value

        from src.payloads.builder import PayloadBuildRequest as _PayloadBuildRequest

        request = _PayloadBuildRequest(
            family_id=family.family_id,
            correlation_key=correlation_key,
            encoding_pipeline=encoding_pipeline,
            approval_id=approval_id,
            parameters=parameters,
            max_payloads=max_payloads,
        )
        canary_token_value = _canary_token_from_uuid(canary.id)
        _logger.debug(
            "oast.integration.prepared",
            extra={
                "strategy": EvidenceStrategy.CANARY.value,
                "family_id": family.family_id,
                "canary_kind": canary_kind.value,
            },
        )
        return EvidencePreparation(
            strategy=EvidenceStrategy.CANARY,
            payload_request=request,
            oast_token=None,
            canary=canary,
            canary_token_for_finding=canary_token_value,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _zero_uuid() -> UUID:
    """Return the all-zero UUID for the rare case ``scan_id`` is missing.

    The provisioner contract requires a non-null ``scan_id`` because every
    real-world callsite supplies it. Using the all-zero UUID for the
    optional ``PolicyContext.scan_id == None`` path keeps the call shape
    stable while making it trivial to spot in logs ("token issued without
    scan_id").
    """
    return UUID(int=0)


def _canary_token_from_uuid(value: UUID) -> str:
    """Project a UUID into the canary-token regex shape (lowercase 32-char hex)."""
    return value.hex


__all__ = [
    "EvidencePreparation",
    "EvidenceStrategy",
    "OASTIntegrationError",
    "OASTPlane",
    "OASTPlaneConfig",
    "OASTRequiredButDisabledError",
]
