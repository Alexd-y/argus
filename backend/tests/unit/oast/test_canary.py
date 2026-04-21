"""Unit tests for :mod:`src.oast.canary` (ARG-007).

Coverage focus:

* Canary generation enforces the per-kind contract: time delays must be
  numeric, marker canaries must come from a CSPRNG, header / cookie
  canaries must carry their target name.
* Verification correctly reports ``verified=True`` only when the
  observed response satisfies the canary's expectations.
* Failure paths use the closed :class:`CanaryFailureReason` taxonomy and
  surface a ``SUSPECTED`` confidence; success paths cap at ``LIKELY``
  per Backlog §12 ("canary evidence is at most medium").
* Verifier is robust against missing inputs, oversize bodies, and
  case-insensitive header / cookie matching.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from src.oast.canary import (
    Canary,
    CanaryFailureReason,
    CanaryGenerationError,
    CanaryGenerator,
    CanaryKind,
    CanaryVerificationInputError,
    CanaryVerifier,
)
from src.pipeline.contracts.finding_dto import ConfidenceLevel


# ---------------------------------------------------------------------------
# Canary model
# ---------------------------------------------------------------------------


class TestCanaryModel:
    def test_time_delay_canary_validates_numeric_secret(
        self, fixed_clock: Callable[[], datetime]
    ) -> None:
        canary = Canary(
            id=uuid4(),
            kind=CanaryKind.TIME_DELAY,
            secret_value="1500",
            created_at=fixed_clock(),
        )
        assert canary.expected_delay_ms == 1500

    def test_time_delay_canary_rejects_text_secret(
        self, fixed_clock: Callable[[], datetime]
    ) -> None:
        with pytest.raises(ValidationError):
            Canary(
                id=uuid4(),
                kind=CanaryKind.TIME_DELAY,
                secret_value="abcdef0123",
                created_at=fixed_clock(),
            )

    def test_time_delay_canary_rejects_out_of_range(
        self, fixed_clock: Callable[[], datetime]
    ) -> None:
        with pytest.raises(ValidationError):
            Canary(
                id=uuid4(),
                kind=CanaryKind.TIME_DELAY,
                secret_value="100",
                created_at=fixed_clock(),
            )
        with pytest.raises(ValidationError):
            Canary(
                id=uuid4(),
                kind=CanaryKind.TIME_DELAY,
                secret_value="99999",
                created_at=fixed_clock(),
            )

    def test_dom_marker_requires_url_safe_value(
        self, fixed_clock: Callable[[], datetime]
    ) -> None:
        with pytest.raises(ValidationError):
            Canary(
                id=uuid4(),
                kind=CanaryKind.DOM_MARKER,
                secret_value="bad value!",
                created_at=fixed_clock(),
            )

    def test_header_marker_requires_header_name(
        self, fixed_clock: Callable[[], datetime]
    ) -> None:
        with pytest.raises(ValidationError):
            Canary(
                id=uuid4(),
                kind=CanaryKind.HEADER_MARKER,
                secret_value="abcdef0123456789",
                created_at=fixed_clock(),
            )

    def test_cookie_marker_requires_cookie_name(
        self, fixed_clock: Callable[[], datetime]
    ) -> None:
        with pytest.raises(ValidationError):
            Canary(
                id=uuid4(),
                kind=CanaryKind.COOKIE_MARKER,
                secret_value="abcdef0123456789",
                created_at=fixed_clock(),
            )

    def test_time_delay_canary_rejects_header_name(
        self, fixed_clock: Callable[[], datetime]
    ) -> None:
        with pytest.raises(ValidationError):
            Canary(
                id=uuid4(),
                kind=CanaryKind.TIME_DELAY,
                secret_value="2000",
                header_name="X-Foo",
                created_at=fixed_clock(),
            )

    def test_canary_is_frozen(self, fixed_clock: Callable[[], datetime]) -> None:
        canary = Canary(
            id=uuid4(),
            kind=CanaryKind.DOM_MARKER,
            secret_value="abcdef0123456789",
            created_at=fixed_clock(),
        )
        with pytest.raises(ValidationError):
            canary.secret_value = "other"


# ---------------------------------------------------------------------------
# CanaryGenerator
# ---------------------------------------------------------------------------


class TestCanaryGenerator:
    def test_generate_time_delay(self, canary_generator: CanaryGenerator) -> None:
        canary = canary_generator.generate(CanaryKind.TIME_DELAY)
        assert canary.kind is CanaryKind.TIME_DELAY
        assert canary.expected_delay_ms is not None
        assert 250 <= canary.expected_delay_ms <= 30_000

    def test_generate_dom_marker(self, canary_generator: CanaryGenerator) -> None:
        canary = canary_generator.generate(CanaryKind.DOM_MARKER)
        assert canary.kind is CanaryKind.DOM_MARKER
        assert canary.header_name is None
        assert canary.cookie_name is None

    def test_generate_header_marker_requires_name(
        self, canary_generator: CanaryGenerator
    ) -> None:
        with pytest.raises(CanaryGenerationError):
            canary_generator.generate(CanaryKind.HEADER_MARKER)
        canary = canary_generator.generate(
            CanaryKind.HEADER_MARKER, header_name="X-Test-Marker"
        )
        assert canary.header_name == "X-Test-Marker"

    def test_generate_cookie_marker_requires_name(
        self, canary_generator: CanaryGenerator
    ) -> None:
        with pytest.raises(CanaryGenerationError):
            canary_generator.generate(CanaryKind.COOKIE_MARKER)
        canary = canary_generator.generate(
            CanaryKind.COOKIE_MARKER, cookie_name="argus_canary"
        )
        assert canary.cookie_name == "argus_canary"

    def test_time_delay_rejects_header_name(
        self, canary_generator: CanaryGenerator
    ) -> None:
        with pytest.raises(CanaryGenerationError):
            canary_generator.generate(CanaryKind.TIME_DELAY, header_name="X-Hi")

    def test_default_factory_uses_secrets_random(self) -> None:
        gen = CanaryGenerator()
        a = gen.generate(CanaryKind.DOM_MARKER)
        b = gen.generate(CanaryKind.DOM_MARKER)
        assert a.secret_value != b.secret_value
        assert len(a.secret_value) >= 16


# ---------------------------------------------------------------------------
# CanaryVerifier
# ---------------------------------------------------------------------------


@pytest.fixture()
def verifier() -> CanaryVerifier:
    return CanaryVerifier()


class TestCanaryVerifier:
    # -- Time-delay paths ----------------------------------------------------

    def test_time_delay_verified_when_response_within_tolerance(
        self,
        canary_generator: CanaryGenerator,
        verifier: CanaryVerifier,
    ) -> None:
        canary = canary_generator.generate(CanaryKind.TIME_DELAY)
        assert canary.expected_delay_ms is not None
        result = verifier.verify(canary, response_time_ms=canary.expected_delay_ms)
        assert result.verified is True
        assert result.confidence is ConfidenceLevel.LIKELY
        assert result.failure_reason is None
        assert result.observed_response_time_ms == canary.expected_delay_ms

    def test_time_delay_fails_when_response_too_fast(
        self,
        canary_generator: CanaryGenerator,
        verifier: CanaryVerifier,
    ) -> None:
        canary = canary_generator.generate(CanaryKind.TIME_DELAY)
        result = verifier.verify(canary, response_time_ms=50)
        assert result.verified is False
        assert result.failure_reason is CanaryFailureReason.UNDER_TOLERANCE
        assert result.confidence is ConfidenceLevel.SUSPECTED

    def test_time_delay_fails_without_response(
        self,
        canary_generator: CanaryGenerator,
        verifier: CanaryVerifier,
    ) -> None:
        canary = canary_generator.generate(CanaryKind.TIME_DELAY)
        result = verifier.verify(canary, response_time_ms=None)
        assert result.verified is False
        assert result.failure_reason is CanaryFailureReason.NO_RESPONSE

    def test_time_delay_negative_response_raises(
        self,
        canary_generator: CanaryGenerator,
        verifier: CanaryVerifier,
    ) -> None:
        canary = canary_generator.generate(CanaryKind.TIME_DELAY)
        with pytest.raises(CanaryVerificationInputError):
            verifier.verify(canary, response_time_ms=-5)

    # -- DOM marker paths ----------------------------------------------------

    def test_dom_marker_verified_when_present(
        self,
        canary_generator: CanaryGenerator,
        verifier: CanaryVerifier,
    ) -> None:
        canary = canary_generator.generate(CanaryKind.DOM_MARKER)
        body = f"<html><body>Hello {canary.secret_value} world</body></html>"
        result = verifier.verify(canary, response_text=body)
        assert result.verified is True
        assert result.evidence["matched_marker"] == canary.secret_value

    def test_dom_marker_fails_when_absent(
        self,
        canary_generator: CanaryGenerator,
        verifier: CanaryVerifier,
    ) -> None:
        canary = canary_generator.generate(CanaryKind.DOM_MARKER)
        result = verifier.verify(canary, response_text="<html></html>")
        assert result.verified is False
        assert result.failure_reason is CanaryFailureReason.NO_MATCH

    def test_dom_marker_fails_when_no_response_text(
        self,
        canary_generator: CanaryGenerator,
        verifier: CanaryVerifier,
    ) -> None:
        canary = canary_generator.generate(CanaryKind.DOM_MARKER)
        result = verifier.verify(canary, response_text=None)
        assert result.verified is False
        assert result.failure_reason is CanaryFailureReason.NO_RESPONSE

    def test_dom_marker_refuses_oversize_body(
        self,
        canary_generator: CanaryGenerator,
        verifier: CanaryVerifier,
    ) -> None:
        canary = canary_generator.generate(CanaryKind.DOM_MARKER)
        oversize = "x" * (8 * 1024 * 1024 + 1)
        result = verifier.verify(canary, response_text=oversize)
        assert result.verified is False
        assert result.failure_reason is CanaryFailureReason.NO_MATCH
        assert result.evidence["reason"] == "response_too_large"

    # -- Header marker paths -------------------------------------------------

    def test_header_marker_match_is_case_insensitive(
        self,
        canary_generator: CanaryGenerator,
        verifier: CanaryVerifier,
    ) -> None:
        canary = canary_generator.generate(
            CanaryKind.HEADER_MARKER, header_name="X-Argus-Marker"
        )
        result = verifier.verify(
            canary,
            response_headers={"x-argus-marker": canary.secret_value},
        )
        assert result.verified is True
        assert result.evidence["header"] == "X-Argus-Marker"

    def test_header_marker_missing_header_fails(
        self,
        canary_generator: CanaryGenerator,
        verifier: CanaryVerifier,
    ) -> None:
        canary = canary_generator.generate(
            CanaryKind.HEADER_MARKER, header_name="X-Argus-Marker"
        )
        result = verifier.verify(canary, response_headers={"X-Other": "anything"})
        assert result.verified is False
        assert result.failure_reason is CanaryFailureReason.MISSING_HEADER

    def test_header_marker_missing_response_fails(
        self,
        canary_generator: CanaryGenerator,
        verifier: CanaryVerifier,
    ) -> None:
        canary = canary_generator.generate(
            CanaryKind.HEADER_MARKER, header_name="X-Argus-Marker"
        )
        result = verifier.verify(canary, response_headers=None)
        assert result.verified is False
        assert result.failure_reason is CanaryFailureReason.NO_RESPONSE

    # -- Cookie marker paths -------------------------------------------------

    def test_cookie_marker_verified(
        self,
        canary_generator: CanaryGenerator,
        verifier: CanaryVerifier,
    ) -> None:
        canary = canary_generator.generate(
            CanaryKind.COOKIE_MARKER, cookie_name="argus_canary"
        )
        result = verifier.verify(
            canary,
            response_cookies={"ARGUS_CANARY": canary.secret_value},
        )
        assert result.verified is True

    def test_cookie_marker_missing_cookie_fails(
        self,
        canary_generator: CanaryGenerator,
        verifier: CanaryVerifier,
    ) -> None:
        canary = canary_generator.generate(
            CanaryKind.COOKIE_MARKER, cookie_name="argus_canary"
        )
        result = verifier.verify(canary, response_cookies={"other": "x"})
        assert result.verified is False
        assert result.failure_reason is CanaryFailureReason.MISSING_COOKIE

    def test_cookie_marker_missing_response_fails(
        self,
        canary_generator: CanaryGenerator,
        verifier: CanaryVerifier,
    ) -> None:
        canary = canary_generator.generate(
            CanaryKind.COOKIE_MARKER, cookie_name="argus_canary"
        )
        result = verifier.verify(canary, response_cookies=None)
        assert result.verified is False
        assert result.failure_reason is CanaryFailureReason.NO_RESPONSE

    # -- Constructor validation ---------------------------------------------

    def test_constructor_rejects_bad_tolerance(self) -> None:
        with pytest.raises(ValueError):
            CanaryVerifier(time_delay_tolerance_ratio=0.0)
        with pytest.raises(ValueError):
            CanaryVerifier(time_delay_tolerance_ratio=1.0)
        with pytest.raises(ValueError):
            CanaryVerifier(time_delay_tolerance_absolute_ms=-1)
