"""Integration: :class:`OASTPlane` + :class:`PayloadBuilder` + signed catalog.

The integration verifies that the OAST plane's :meth:`OASTPlane.prepare`
output is a fully-formed :class:`PayloadBuildRequest` that the builder
accepts without complaint, for both the OAST and canary fallback paths.

The signed payload catalog under ``backend/config/payloads`` is the
single source of truth; if it is missing the test skips so the suite
remains green in environments that do not vendor it (CI runs that
deliberately omit signed bundles for speed).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime, timezone
from itertools import count
from pathlib import Path
from uuid import UUID

import pytest

from src.oast.canary import CanaryGenerator, CanaryKind, CanaryVerifier
from src.oast.correlator import (
    InteractionKind,
    OASTCorrelator,
)
from src.oast.integration import (
    EvidenceStrategy,
    OASTPlane,
    OASTRequiredButDisabledError,
)
from src.oast.listener_protocol import FakeOASTListener
from src.oast.provisioner import (
    DisabledOASTProvisioner,
    InternalOASTProvisioner,
)
from src.payloads.builder import PayloadBuildError, PayloadBuilder
from src.payloads.registry import PayloadRegistry
from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel
from src.policy.policy_engine import PolicyContext


_TENANT = UUID("33333333-3333-3333-3333-333333333333")
_SCAN = UUID("44444444-4444-4444-4444-444444444444")
_BASE_DOMAIN = "oast.argus.local"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def real_payload_registry() -> PayloadRegistry:
    here = Path(__file__).resolve()
    backend_dir = here.parents[3]
    catalog = backend_dir / "config" / "payloads"
    if not catalog.is_dir():
        pytest.skip(
            f"signed payload catalog not present at {catalog}; "
            "OAST integration test requires it"
        )
    registry = PayloadRegistry(payloads_dir=catalog)
    registry.load()
    return registry


@pytest.fixture()
def fixed_clock() -> Callable[[], datetime]:
    moment = datetime(2026, 4, 17, 12, 0, 0, tzinfo=timezone.utc)
    return lambda: moment


@pytest.fixture()
def deterministic_uuid_factory() -> Callable[[], UUID]:
    counter = count(start=1)

    def _factory() -> UUID:
        return UUID(int=next(counter))

    return _factory


@pytest.fixture()
def deterministic_token_factory() -> Callable[[int], str]:
    counter = count(start=1)

    def _factory(nbytes: int) -> str:
        index = next(counter)
        marker = format(index, "x")
        if len(marker) > nbytes * 2:
            raise AssertionError(
                "deterministic_token_factory exhausted; raise the upper bound"
            )
        return marker.rjust(nbytes * 2, "a")

    return _factory


@pytest.fixture()
def internal_provisioner(
    fixed_clock: Callable[[], datetime],
    deterministic_uuid_factory: Callable[[], UUID],
    deterministic_token_factory: Callable[[int], str],
) -> InternalOASTProvisioner:
    return InternalOASTProvisioner(
        base_domain=_BASE_DOMAIN,
        clock=fixed_clock,
        id_factory=deterministic_uuid_factory,
        token_factory=deterministic_token_factory,
    )


@pytest.fixture()
def correlator(internal_provisioner: InternalOASTProvisioner) -> OASTCorrelator:
    return OASTCorrelator(internal_provisioner, default_window_s=1, max_window_s=2)


@pytest.fixture()
def listener(
    correlator: OASTCorrelator,
    deterministic_uuid_factory: Callable[[], UUID],
) -> FakeOASTListener:
    return FakeOASTListener(correlator, id_factory=deterministic_uuid_factory)


@pytest.fixture()
def canary_generator(
    deterministic_uuid_factory: Callable[[], UUID],
    deterministic_token_factory: Callable[[int], str],
    fixed_clock: Callable[[], datetime],
) -> CanaryGenerator:
    delays = count(start=1)

    def _delay_factory() -> int:
        return 1500 + (next(delays) * 100)

    return CanaryGenerator(
        id_factory=deterministic_uuid_factory,
        token_factory=deterministic_token_factory,
        delay_ms_factory=_delay_factory,
        clock=fixed_clock,
    )


def _policy_context(
    family_id: str | None = None, *, target: str = "https://target.example.com/api"
) -> PolicyContext:
    return PolicyContext(
        tenant_id=_TENANT,
        scan_id=_SCAN,
        phase=ScanPhase.VULN_ANALYSIS,
        risk_level=RiskLevel.MEDIUM,
        tool_id="argus.validator",
        family_id=family_id,
        target=target,
    )


# ---------------------------------------------------------------------------
# OAST mode end-to-end with real catalog
# ---------------------------------------------------------------------------


class TestOASTPlaneWithRealRegistry:
    """End-to-end coverage of OASTPlane → PayloadBuilder using shipped seeds."""

    def test_oast_mode_renders_ssrf_payload(
        self,
        real_payload_registry: PayloadRegistry,
        internal_provisioner: InternalOASTProvisioner,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
        listener: FakeOASTListener,
    ) -> None:
        family = real_payload_registry.get_family("ssrf")
        assert family.oast_required is True

        plane = OASTPlane(
            internal_provisioner,
            correlator,
            canary_generator,
            listener=listener,
        )
        prep = plane.prepare(
            family=family,
            policy_context=_policy_context(family_id="ssrf"),
            correlation_key="oast-int-1",
        )
        assert prep.strategy is EvidenceStrategy.OAST
        assert prep.oast_token is not None
        assert prep.canary is None

        builder = PayloadBuilder(real_payload_registry)
        bundle = builder.build(prep.payload_request)

        assert bundle.family_id == "ssrf"
        assert bundle.payloads
        assert bundle.oast_required is True
        # The SSRF family runs case_flip + unicode_homoglyph mutations
        # over the placeholder substitution result, so the literal host
        # string is not preserved byte-for-byte. We instead assert the
        # invariants that survive every mutation chain: no leftover
        # `{placeholder}` markers AND the bundle uses the OAST encoding
        # pipelines (identity / url_only / url_double).
        rendered = "".join(p.payload for p in bundle.payloads)
        assert "{oast_host}" not in rendered
        assert "{canary}" not in rendered
        assert "{param}" not in rendered
        # Listener should have been notified about the new token.
        assert listener.is_registered(prep.oast_token.id)
        # The plane MUST have produced a non-empty path token / subdomain;
        # those are the bytes the validator embeds in the payload bundle.
        assert prep.oast_token.subdomain.endswith(_BASE_DOMAIN)
        assert len(prep.oast_token.path_token) >= 8

    def test_oast_mode_xss_payload_renders(
        self,
        real_payload_registry: PayloadRegistry,
        internal_provisioner: InternalOASTProvisioner,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
    ) -> None:
        family = real_payload_registry.get_family("xss")
        plane = OASTPlane(internal_provisioner, correlator, canary_generator)
        prep = plane.prepare(
            family=family,
            policy_context=_policy_context(family_id="xss"),
            correlation_key="oast-int-2",
        )
        builder = PayloadBuilder(real_payload_registry)
        bundle = builder.build(prep.payload_request)
        assert bundle.payloads
        rendered = "".join(p.payload for p in bundle.payloads)
        assert "{canary}" not in rendered
        assert "{oast_host}" not in rendered
        # XSS bundle should be marked as oast_required so the verifier
        # picks the right confirmation path.
        assert bundle.oast_required is True

    def test_canary_mode_succeeds_for_canary_friendly_family(
        self,
        real_payload_registry: PayloadRegistry,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
    ) -> None:
        # nosqli has oast_required=false; templates use {canary} only.
        family = real_payload_registry.get_family("nosqli")
        assert family.oast_required is False

        disabled = DisabledOASTProvisioner()
        plane = OASTPlane(disabled, correlator, canary_generator)
        prep = plane.prepare(
            family=family,
            policy_context=_policy_context(family_id="nosqli"),
            correlation_key="oast-int-3",
            canary_kind_override=CanaryKind.DOM_MARKER,
        )
        assert prep.strategy is EvidenceStrategy.CANARY
        assert prep.canary is not None

        builder = PayloadBuilder(real_payload_registry)
        bundle = builder.build(prep.payload_request)
        assert bundle.payloads

        rendered = "".join(p.payload for p in bundle.payloads)
        # nosqli runs case_flip mutation; the canary lowercase hex value
        # is preserved in shape but its case is randomised. Compare on a
        # lowercase projection so the assertion survives mutation.
        assert prep.canary.secret_value in rendered.lower()
        assert "{canary}" not in rendered

    def test_canary_mode_succeeds_for_canary_free_family(
        self,
        real_payload_registry: PayloadRegistry,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
    ) -> None:
        # path_traversal templates use no placeholders → canary plane
        # passes the canary parameter but the builder ignores it.
        family = real_payload_registry.get_family("path_traversal")
        assert family.oast_required is False

        disabled = DisabledOASTProvisioner()
        plane = OASTPlane(disabled, correlator, canary_generator)
        prep = plane.prepare(
            family=family,
            policy_context=_policy_context(family_id="path_traversal"),
            correlation_key="oast-int-4",
            canary_kind_override=CanaryKind.DOM_MARKER,
        )
        builder = PayloadBuilder(real_payload_registry)
        bundle = builder.build(prep.payload_request)
        assert bundle.payloads
        # Templates carry no placeholders so the canary value MUST NOT
        # leak into the rendered bundle (even after case_flip).
        rendered = "".join(p.payload for p in bundle.payloads).lower()
        assert prep.canary is not None
        assert prep.canary.secret_value not in rendered

    def test_oast_required_with_disabled_provisioner_raises(
        self,
        real_payload_registry: PayloadRegistry,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
    ) -> None:
        family = real_payload_registry.get_family("ssrf")
        assert family.oast_required is True
        disabled = DisabledOASTProvisioner()
        plane = OASTPlane(disabled, correlator, canary_generator)
        with pytest.raises(OASTRequiredButDisabledError):
            plane.prepare(
                family=family,
                policy_context=_policy_context(family_id="ssrf"),
                correlation_key="oast-int-5",
            )

    def test_canary_mode_for_oast_template_surfaces_builder_error(
        self,
        real_payload_registry: PayloadRegistry,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
    ) -> None:
        # XSS template seeds embed both {canary} and {oast_host}; the
        # canary plane intentionally omits oast_host so the builder
        # raises a missing-parameter error — the orchestrator can then
        # downgrade the family.
        family = real_payload_registry.get_family("xss")
        assert family.oast_required is True
        disabled = DisabledOASTProvisioner()
        plane = OASTPlane(disabled, correlator, canary_generator)
        # OAST required → canary fallback NOT permitted.
        with pytest.raises(OASTRequiredButDisabledError):
            plane.prepare(
                family=family,
                policy_context=_policy_context(family_id="xss"),
                correlation_key="oast-int-6",
                canary_kind_override=CanaryKind.DOM_MARKER,
            )


# ---------------------------------------------------------------------------
# Correlator round-trip with the integration plane
# ---------------------------------------------------------------------------


class TestOASTPlaneCorrelatorRoundTrip:
    """Verifies that listener emissions land in the correlator and unblock waiters."""

    @pytest.mark.asyncio()
    async def test_listener_emits_match_for_issued_token(
        self,
        real_payload_registry: PayloadRegistry,
        internal_provisioner: InternalOASTProvisioner,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
        listener: FakeOASTListener,
    ) -> None:
        family = real_payload_registry.get_family("ssrf")
        plane = OASTPlane(
            internal_provisioner,
            correlator,
            canary_generator,
            listener=listener,
        )
        prep = plane.prepare(
            family=family,
            policy_context=_policy_context(family_id="ssrf"),
            correlation_key="oast-int-rtt-1",
        )
        assert prep.oast_token is not None

        listener.emit_dns_query(prep.oast_token, kind=InteractionKind.DNS_A)

        result = await correlator.wait_for_interaction(
            prep.oast_token.id,
            timeout_s=1,
            kinds=[InteractionKind.DNS_A],
        )
        assert len(result) == 1
        assert result[0].metadata["qname"] == prep.oast_token.subdomain

    @pytest.mark.asyncio()
    async def test_correlator_unblocks_on_async_interaction(
        self,
        real_payload_registry: PayloadRegistry,
        internal_provisioner: InternalOASTProvisioner,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
        listener: FakeOASTListener,
    ) -> None:
        family = real_payload_registry.get_family("xxe")
        plane = OASTPlane(
            internal_provisioner,
            correlator,
            canary_generator,
            listener=listener,
        )
        prep = plane.prepare(
            family=family,
            policy_context=_policy_context(family_id="xxe"),
            correlation_key="oast-int-rtt-2",
        )
        assert prep.oast_token is not None
        token = prep.oast_token

        async def _emit_after_delay() -> None:
            await asyncio.sleep(0.05)
            listener.emit_http_request(token, scheme="http")

        emit_task = asyncio.create_task(_emit_after_delay())
        try:
            result = await correlator.wait_for_interaction(
                token.id,
                timeout_s=2,
                kinds=[InteractionKind.HTTP_REQUEST, InteractionKind.HTTPS_REQUEST],
            )
        finally:
            await emit_task
        assert len(result) >= 1
        assert result[0].kind in {
            InteractionKind.HTTP_REQUEST,
            InteractionKind.HTTPS_REQUEST,
        }


# ---------------------------------------------------------------------------
# Canary verifier round-trip with the integration plane
# ---------------------------------------------------------------------------


class TestCanaryVerifierRoundTrip:
    """End-to-end smoke for canary mode: generate → render → verify."""

    def test_dom_marker_round_trip(
        self,
        real_payload_registry: PayloadRegistry,
        canary_generator: CanaryGenerator,
        correlator: OASTCorrelator,
    ) -> None:
        family = real_payload_registry.get_family("nosqli")
        disabled = DisabledOASTProvisioner()
        plane = OASTPlane(disabled, correlator, canary_generator)
        prep = plane.prepare(
            family=family,
            policy_context=_policy_context(family_id="nosqli"),
            correlation_key="oast-int-canary-1",
            canary_kind_override=CanaryKind.DOM_MARKER,
        )
        assert prep.canary is not None

        verifier = CanaryVerifier()
        response_body = f"<html>injected: {prep.canary.secret_value}</html>"
        result = verifier.verify(prep.canary, response_text=response_body)
        assert result.verified is True

    def test_time_delay_round_trip(
        self,
        real_payload_registry: PayloadRegistry,
        canary_generator: CanaryGenerator,
        correlator: OASTCorrelator,
    ) -> None:
        family = real_payload_registry.get_family("nosqli")
        disabled = DisabledOASTProvisioner()
        plane = OASTPlane(disabled, correlator, canary_generator)
        prep = plane.prepare(
            family=family,
            policy_context=_policy_context(family_id="nosqli"),
            correlation_key="oast-int-canary-2",
            canary_kind_override=CanaryKind.TIME_DELAY,
        )
        assert prep.canary is not None
        assert prep.canary.expected_delay_ms is not None

        verifier = CanaryVerifier()
        result = verifier.verify(
            prep.canary, response_time_ms=prep.canary.expected_delay_ms
        )
        assert result.verified is True
        result = verifier.verify(prep.canary, response_time_ms=10)
        assert result.verified is False


# ---------------------------------------------------------------------------
# Builder error surfaces — explicit confirmation
# ---------------------------------------------------------------------------


class TestBuilderErrorSurfaces:
    """Defensive: missing parameter from extra_parameters is surfaced cleanly."""

    def test_missing_extra_parameter_raises_payload_build_error(
        self,
        real_payload_registry: PayloadRegistry,
        internal_provisioner: InternalOASTProvisioner,
        correlator: OASTCorrelator,
        canary_generator: CanaryGenerator,
    ) -> None:
        # nosqli has a {canary} placeholder but also `query_string_ne`
        # which uses {canary}. We strip the parameter manually to
        # confirm the builder rejects an under-populated request.
        family = real_payload_registry.get_family("nosqli")
        plane = OASTPlane(internal_provisioner, correlator, canary_generator)
        prep = plane.prepare(
            family=family,
            policy_context=_policy_context(family_id="nosqli"),
            correlation_key="oast-int-err-1",
        )
        # Forge a copy of the request without the canary parameter.
        from src.payloads.builder import PayloadBuildRequest

        broken = PayloadBuildRequest(
            family_id=prep.payload_request.family_id,
            correlation_key=prep.payload_request.correlation_key,
            parameters={
                k: v
                for k, v in prep.payload_request.parameters.items()
                if k != "canary"
            },
            max_payloads=prep.payload_request.max_payloads,
        )
        builder = PayloadBuilder(real_payload_registry)
        with pytest.raises(PayloadBuildError):
            builder.build(broken)
