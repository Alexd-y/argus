"""Unit tests for :mod:`src.oast.integration` (ARG-007).

Verifies the strategy-selection logic, parameter merging, and
OAST-required hard-fail path.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from uuid import UUID

import pytest

from src.oast.canary import CanaryGenerator, CanaryKind
from src.oast.correlator import OASTCorrelator
from src.oast.integration import (
    EvidencePreparation,
    EvidenceStrategy,
    OASTIntegrationError,
    OASTPlane,
    OASTPlaneConfig,
    OASTRequiredButDisabledError,
)
from src.oast.listener_protocol import FakeOASTListener
from src.oast.provisioner import (
    DisabledOASTProvisioner,
    InternalOASTProvisioner,
)
from src.payloads.registry import (
    EncodingPipeline,
    PayloadEntry,
    PayloadFamily,
)
from src.pipeline.contracts.finding_dto import ConfidenceLevel
from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel
from src.policy.policy_engine import PolicyContext


_TENANT = UUID("11111111-1111-1111-1111-111111111111")
_SCAN = UUID("22222222-2222-2222-2222-222222222222")
_CANARY_TOKEN_RE_HEX_LEN = 32  # uuid.hex


def _policy_context(
    *,
    tool_id: str = "argus.validator",
    family_id: str | None = "ssrf",
    risk_level: RiskLevel = RiskLevel.MEDIUM,
) -> PolicyContext:
    return PolicyContext(
        tenant_id=_TENANT,
        scan_id=_SCAN,
        phase=ScanPhase.VULN_ANALYSIS,
        risk_level=risk_level,
        tool_id=tool_id,
        family_id=family_id,
        target="https://target.example.com/api",
    )


def _payload_family(
    *,
    family_id: str = "ssrf",
    oast_required: bool = False,
    template: str = "http://{oast_host}/{canary}",
    requires_approval: bool = False,
) -> PayloadFamily:
    return PayloadFamily(
        family_id=family_id,
        description="Test payload family used by ARG-007 integration suite.",
        cwe_ids=[918],
        owasp_top10=["A10:2021"],
        risk_level=RiskLevel.MEDIUM,
        requires_approval=requires_approval,
        oast_required=oast_required,
        payloads=[
            PayloadEntry(
                id="seed_one",
                template=template,
                confidence=ConfidenceLevel.LIKELY,
                notes="Probe template that uses the OAST host placeholder.",
            ),
        ],
        mutations=[],
        encodings=[
            EncodingPipeline(name="identity", stages=[], description="No-op."),
        ],
    )


# ---------------------------------------------------------------------------
# OASTPlane — happy paths
# ---------------------------------------------------------------------------


class TestOASTPlaneOAST:
    def test_prepare_in_oast_mode_populates_parameters_and_token(
        self,
        internal_provisioner: InternalOASTProvisioner,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
        listener: FakeOASTListener,
    ) -> None:
        plane = OASTPlane(
            internal_provisioner,
            correlator,
            canary_generator,
            listener=listener,
        )
        family = _payload_family(oast_required=True)
        prep = plane.prepare(
            family=family,
            policy_context=_policy_context(),
            correlation_key="scan-1|hyp-1",
        )
        assert prep.strategy is EvidenceStrategy.OAST
        assert prep.oast_token is not None
        assert prep.canary is None
        assert prep.payload_request.family_id == family.family_id
        assert prep.payload_request.parameters["oast_host"] == prep.oast_token.subdomain
        assert (
            prep.payload_request.parameters["canary"]
            == prep.oast_token.path_token.lower()
        )
        assert len(prep.canary_token_for_finding) == _CANARY_TOKEN_RE_HEX_LEN
        # Listener should have been notified about the issued token.
        assert listener.is_registered(prep.oast_token.id)

    def test_prepare_attaches_extra_parameters(
        self,
        internal_provisioner: InternalOASTProvisioner,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
    ) -> None:
        plane = OASTPlane(internal_provisioner, correlator, canary_generator)
        family = _payload_family(template="http://{oast_host}/{canary}?p={param}")
        prep = plane.prepare(
            family=family,
            policy_context=_policy_context(),
            correlation_key="scan-1|hyp-2",
            extra_parameters={"param": "id"},
        )
        assert prep.payload_request.parameters["param"] == "id"
        assert "oast_host" in prep.payload_request.parameters
        assert "canary" in prep.payload_request.parameters

    def test_prepare_rejects_overriding_reserved_parameters(
        self,
        internal_provisioner: InternalOASTProvisioner,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
    ) -> None:
        plane = OASTPlane(internal_provisioner, correlator, canary_generator)
        with pytest.raises(OASTIntegrationError):
            plane.prepare(
                family=_payload_family(),
                policy_context=_policy_context(),
                correlation_key="scan-1",
                extra_parameters={"oast_host": "evil.example.com"},
            )
        with pytest.raises(OASTIntegrationError):
            plane.prepare(
                family=_payload_family(),
                policy_context=_policy_context(),
                correlation_key="scan-1",
                extra_parameters={"canary": "deadbeef"},
            )

    def test_is_oast_active_true_for_internal_provisioner(
        self,
        internal_provisioner: InternalOASTProvisioner,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
    ) -> None:
        plane = OASTPlane(internal_provisioner, correlator, canary_generator)
        assert plane.is_oast_active is True

    def test_is_oast_required_for_family_check(self) -> None:
        family_required = _payload_family(oast_required=True)
        family_optional = _payload_family(oast_required=False)
        assert OASTPlane.is_oast_required_for_family(family_required) is True
        assert OASTPlane.is_oast_required_for_family(family_optional) is False


# ---------------------------------------------------------------------------
# OASTPlane — canary fallback paths
# ---------------------------------------------------------------------------


class TestOASTPlaneCanary:
    def test_disabled_provisioner_falls_back_to_canary(
        self,
        disabled_provisioner: DisabledOASTProvisioner,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
    ) -> None:
        plane = OASTPlane(
            disabled_provisioner,
            correlator,
            canary_generator,
        )
        family = _payload_family(oast_required=False, template="<m>{canary}</m>")
        prep = plane.prepare(
            family=family,
            policy_context=_policy_context(),
            correlation_key="scan-1|hyp-3",
            canary_kind_override=CanaryKind.DOM_MARKER,
        )
        assert prep.strategy is EvidenceStrategy.CANARY
        assert prep.oast_token is None
        assert prep.canary is not None
        assert prep.payload_request.parameters["canary"] == prep.canary.secret_value
        # OAST host MUST NOT leak into canary mode (templates that use it
        # should fail the missing-parameter check inside the builder).
        assert "oast_host" not in prep.payload_request.parameters

    def test_disabled_provisioner_with_oast_required_family_raises(
        self,
        disabled_provisioner: DisabledOASTProvisioner,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
    ) -> None:
        plane = OASTPlane(
            disabled_provisioner,
            correlator,
            canary_generator,
        )
        family = _payload_family(oast_required=True)
        with pytest.raises(OASTRequiredButDisabledError) as exc_info:
            plane.prepare(
                family=family,
                policy_context=_policy_context(),
                correlation_key="scan-1|hyp-4",
            )
        assert exc_info.value.family_id == family.family_id
        assert exc_info.value.reason
        assert (
            plane.policy_failure_reason_oast_disabled()
            == "oast_disabled_for_oast_required"
        )

    def test_canary_mode_requires_header_name_for_header_marker(
        self,
        disabled_provisioner: DisabledOASTProvisioner,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
    ) -> None:
        plane = OASTPlane(disabled_provisioner, correlator, canary_generator)
        family = _payload_family(oast_required=False, template="<m>{canary}</m>")
        # Generator raises if no header name is supplied for HEADER_MARKER.
        with pytest.raises(Exception):
            plane.prepare(
                family=family,
                policy_context=_policy_context(),
                correlation_key="scan-1",
                canary_kind_override=CanaryKind.HEADER_MARKER,
            )

    def test_canary_kind_override_is_respected(
        self,
        disabled_provisioner: DisabledOASTProvisioner,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
    ) -> None:
        plane = OASTPlane(disabled_provisioner, correlator, canary_generator)
        family = _payload_family(oast_required=False, template="<m>{canary}</m>")
        prep = plane.prepare(
            family=family,
            policy_context=_policy_context(),
            correlation_key="scan-1",
            canary_kind_override=CanaryKind.HEADER_MARKER,
            canary_header_name="X-Argus-Marker",
        )
        assert prep.canary is not None
        assert prep.canary.kind is CanaryKind.HEADER_MARKER
        assert prep.canary.header_name == "X-Argus-Marker"

    def test_default_canary_kind_uses_dom_marker(
        self,
        disabled_provisioner: DisabledOASTProvisioner,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
    ) -> None:
        plane = OASTPlane(
            disabled_provisioner,
            correlator,
            canary_generator,
            config=OASTPlaneConfig(
                canary_kind_for_unknown_family=CanaryKind.DOM_MARKER
            ),
        )
        family = _payload_family(oast_required=False, template="<m>{canary}</m>")
        prep = plane.prepare(
            family=family,
            policy_context=_policy_context(),
            correlation_key="scan-1",
        )
        assert prep.canary is not None
        assert prep.canary.kind is CanaryKind.DOM_MARKER


# ---------------------------------------------------------------------------
# EvidencePreparation invariants
# ---------------------------------------------------------------------------


class TestEvidencePreparationInvariants:
    def test_oast_strategy_requires_token(
        self,
        internal_provisioner: InternalOASTProvisioner,
    ) -> None:
        from src.payloads.builder import PayloadBuildRequest

        with pytest.raises(ValueError):
            EvidencePreparation(
                strategy=EvidenceStrategy.OAST,
                payload_request=PayloadBuildRequest(
                    family_id="ssrf",
                    correlation_key="x",
                    parameters={"oast_host": "h", "canary": "c"},
                ),
                oast_token=None,
                canary=None,
                canary_token_for_finding="0" * 32,
            )

    def test_canary_strategy_requires_canary(self) -> None:
        from src.payloads.builder import PayloadBuildRequest

        with pytest.raises(ValueError):
            EvidencePreparation(
                strategy=EvidenceStrategy.CANARY,
                payload_request=PayloadBuildRequest(
                    family_id="ssrf",
                    correlation_key="x",
                    parameters={"canary": "c"},
                ),
                oast_token=None,
                canary=None,
                canary_token_for_finding="0" * 32,
            )

    def test_oast_strategy_rejects_canary_payload(
        self,
        internal_provisioner: InternalOASTProvisioner,
        canary_generator: CanaryGenerator,
        fixed_clock: Callable[[], datetime],
    ) -> None:

        from src.payloads.builder import PayloadBuildRequest

        token = internal_provisioner.issue(tenant_id=_TENANT, scan_id=_SCAN)
        canary = canary_generator.generate(CanaryKind.DOM_MARKER)
        with pytest.raises(ValueError):
            EvidencePreparation(
                strategy=EvidenceStrategy.OAST,
                payload_request=PayloadBuildRequest(
                    family_id="ssrf",
                    correlation_key="x",
                    parameters={"oast_host": "h", "canary": "c"},
                ),
                oast_token=token,
                canary=canary,
                canary_token_for_finding="0" * 32,
            )
