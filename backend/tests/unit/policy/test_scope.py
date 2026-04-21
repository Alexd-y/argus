"""Unit tests for :mod:`src.policy.scope`.

Covers rule validation (positive + negative), the deny-overrides-allow
contract, port-range narrowing, host / domain / URL / IP / CIDR matching,
and the closed-taxonomy failure summaries.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.pipeline.contracts.tool_job import TargetKind, TargetSpec
from src.policy.scope import (
    SCOPE_FAILURE_REASONS,
    PortRange,
    ScopeDecision,
    ScopeEngine,
    ScopeKind,
    ScopeRule,
    ScopeViolation,
)


# ---------------------------------------------------------------------------
# PortRange
# ---------------------------------------------------------------------------


class TestPortRange:
    def test_single_port(self) -> None:
        rng = PortRange(low=80, high=80)
        assert rng.contains(80) is True
        assert rng.contains(81) is False

    def test_inclusive_bounds(self) -> None:
        rng = PortRange(low=80, high=443)
        assert rng.contains(80) is True
        assert rng.contains(443) is True
        assert rng.contains(442) is True
        assert rng.contains(444) is False

    def test_high_below_low_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PortRange(low=443, high=80)

    @pytest.mark.parametrize("port", [0, -1, 65_536])
    def test_out_of_range_rejected(self, port: int) -> None:
        with pytest.raises(ValidationError):
            PortRange(low=port, high=port if port > 0 else 80)

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            PortRange.model_validate({"low": 80, "high": 80, "name": "http"})


# ---------------------------------------------------------------------------
# ScopeRule validation
# ---------------------------------------------------------------------------


class TestScopeRuleValidation:
    def test_url_rule_valid(self) -> None:
        rule = ScopeRule(kind=ScopeKind.URL, pattern="https://example.com/api")
        assert rule.pattern == "https://example.com/api"
        assert rule.deny is False

    @pytest.mark.parametrize(
        "pattern", ["ftp://example.com", "ws://example.com", "://example.com", ""]
    )
    def test_url_rule_rejects_bad_scheme(self, pattern: str) -> None:
        with pytest.raises(ValidationError):
            ScopeRule(kind=ScopeKind.URL, pattern=pattern)

    def test_url_rule_requires_host(self) -> None:
        with pytest.raises(ValidationError):
            ScopeRule(kind=ScopeKind.URL, pattern="https://")

    def test_domain_rule_lowercases_and_strips_dot(self) -> None:
        rule = ScopeRule(kind=ScopeKind.DOMAIN, pattern="  .Example.COM  ")
        assert rule.pattern == "example.com"

    @pytest.mark.parametrize(
        "pattern",
        ["evil example.com", "example.com/path", "example.com?x=1", "ex#ample.com"],
    )
    def test_domain_rule_rejects_forbidden_chars(self, pattern: str) -> None:
        with pytest.raises(ValidationError):
            ScopeRule(kind=ScopeKind.DOMAIN, pattern=pattern)

    def test_ip_rule_validates_ipv4_and_ipv6(self) -> None:
        ScopeRule(kind=ScopeKind.IP, pattern="10.1.2.3")
        ScopeRule(kind=ScopeKind.IP, pattern="2001:db8::1")

    def test_ip_rule_rejects_garbage(self) -> None:
        with pytest.raises(ValidationError):
            ScopeRule(kind=ScopeKind.IP, pattern="not.an.ip")

    def test_cidr_rule_accepts_v4_and_v6(self) -> None:
        ScopeRule(kind=ScopeKind.CIDR, pattern="10.0.0.0/8")
        ScopeRule(kind=ScopeKind.CIDR, pattern="2001:db8::/32")

    def test_cidr_rule_rejects_garbage(self) -> None:
        with pytest.raises(ValidationError):
            ScopeRule(kind=ScopeKind.CIDR, pattern="not-a-cidr")

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            ScopeRule.model_validate(
                {"kind": "domain", "pattern": "example.com", "extra": "nope"}
            )

    def test_frozen(self) -> None:
        rule = ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com")
        with pytest.raises(ValidationError):
            rule.pattern = "other.com"


# ---------------------------------------------------------------------------
# ScopeRule.covers_port
# ---------------------------------------------------------------------------


class TestCoversPort:
    def test_no_ports_means_any_port_allowed(self) -> None:
        rule = ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com")
        assert rule.covers_port(80) is True
        assert rule.covers_port(None) is True

    def test_explicit_ports_match(self) -> None:
        rule = ScopeRule(
            kind=ScopeKind.DOMAIN,
            pattern="example.com",
            ports=(PortRange(low=80, high=80), PortRange(low=8000, high=8443)),
        )
        assert rule.covers_port(80) is True
        assert rule.covers_port(8200) is True
        assert rule.covers_port(443) is False

    def test_explicit_ports_reject_none_port(self) -> None:
        rule = ScopeRule(
            kind=ScopeKind.DOMAIN,
            pattern="example.com",
            ports=(PortRange(low=443, high=443),),
        )
        assert rule.covers_port(None) is False


# ---------------------------------------------------------------------------
# ScopeEngine — empty / default-deny
# ---------------------------------------------------------------------------


class TestEmptyEngine:
    def test_empty_rules_default_deny(self) -> None:
        engine = ScopeEngine([])
        decision = engine.check(TargetSpec(kind=TargetKind.HOST, host="example.com"))
        assert decision.allowed is False
        assert decision.failure_summary == "target_not_in_scope"
        assert decision.matched_rule_index is None

    def test_assert_allowed_raises(self) -> None:
        engine = ScopeEngine([])
        with pytest.raises(ScopeViolation) as exc_info:
            engine.assert_allowed(TargetSpec(kind=TargetKind.HOST, host="example.com"))
        assert exc_info.value.summary == "target_not_in_scope"
        assert exc_info.value.target == "example.com"


# ---------------------------------------------------------------------------
# ScopeEngine — allow / deny / port semantics
# ---------------------------------------------------------------------------


class TestEngineMatching:
    def test_domain_suffix_match(self) -> None:
        engine = ScopeEngine([ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com")])
        for host in ["example.com", "api.example.com", "deep.api.example.com"]:
            decision = engine.check(TargetSpec(kind=TargetKind.HOST, host=host))
            assert decision.allowed is True, host

    def test_domain_suffix_does_not_falsely_match_substring(self) -> None:
        engine = ScopeEngine([ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com")])
        decision = engine.check(TargetSpec(kind=TargetKind.HOST, host="notexample.com"))
        assert decision.allowed is False

    def test_url_prefix_match(self) -> None:
        engine = ScopeEngine(
            [ScopeRule(kind=ScopeKind.URL, pattern="https://example.com/api")]
        )
        decision = engine.check(
            TargetSpec(kind=TargetKind.URL, url="https://example.com/api/v1/users")
        )
        assert decision.allowed is True

    def test_url_scheme_mismatch_rejected(self) -> None:
        engine = ScopeEngine(
            [ScopeRule(kind=ScopeKind.URL, pattern="https://example.com")]
        )
        decision = engine.check(
            TargetSpec(kind=TargetKind.URL, url="http://example.com")
        )
        assert decision.allowed is False

    def test_cidr_membership(self) -> None:
        engine = ScopeEngine([ScopeRule(kind=ScopeKind.CIDR, pattern="10.0.0.0/8")])
        decision = engine.check(TargetSpec(kind=TargetKind.IP, ip="10.5.6.7"))
        assert decision.allowed is True

    def test_cidr_excludes_outside_range(self) -> None:
        engine = ScopeEngine([ScopeRule(kind=ScopeKind.CIDR, pattern="10.0.0.0/8")])
        decision = engine.check(TargetSpec(kind=TargetKind.IP, ip="192.168.1.1"))
        assert decision.allowed is False

    def test_cidr_supernet_of_target_cidr(self) -> None:
        engine = ScopeEngine([ScopeRule(kind=ScopeKind.CIDR, pattern="10.0.0.0/8")])
        decision = engine.check(TargetSpec(kind=TargetKind.CIDR, cidr="10.1.0.0/16"))
        assert decision.allowed is True

    def test_cidr_does_not_match_supernet_target(self) -> None:
        engine = ScopeEngine([ScopeRule(kind=ScopeKind.CIDR, pattern="10.1.0.0/16")])
        decision = engine.check(TargetSpec(kind=TargetKind.CIDR, cidr="10.0.0.0/8"))
        assert decision.allowed is False

    def test_ip_exact_match(self) -> None:
        engine = ScopeEngine([ScopeRule(kind=ScopeKind.IP, pattern="10.1.2.3")])
        decision = engine.check(TargetSpec(kind=TargetKind.IP, ip="10.1.2.3"))
        assert decision.allowed is True

    def test_host_exact_lowercase(self) -> None:
        engine = ScopeEngine(
            [ScopeRule(kind=ScopeKind.HOST, pattern="api.example.com")]
        )
        decision = engine.check(
            TargetSpec(kind=TargetKind.HOST, host="API.example.com")
        )
        assert decision.allowed is True


class TestDenyOverridesAllow:
    def test_deny_wins_over_allow(self) -> None:
        engine = ScopeEngine(
            [
                ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com"),
                ScopeRule(
                    kind=ScopeKind.HOST, pattern="staging.example.com", deny=True
                ),
            ]
        )
        decision = engine.check(
            TargetSpec(kind=TargetKind.HOST, host="staging.example.com")
        )
        assert decision.allowed is False
        assert decision.failure_summary == "target_explicitly_denied"
        assert decision.matched_rule_index == 1

    def test_deny_in_first_position(self) -> None:
        engine = ScopeEngine(
            [
                ScopeRule(
                    kind=ScopeKind.HOST, pattern="staging.example.com", deny=True
                ),
                ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com"),
            ]
        )
        decision = engine.check(
            TargetSpec(kind=TargetKind.HOST, host="staging.example.com")
        )
        assert decision.allowed is False


class TestPortMatching:
    def test_allowed_port_passes(self) -> None:
        engine = ScopeEngine(
            [
                ScopeRule(
                    kind=ScopeKind.DOMAIN,
                    pattern="example.com",
                    ports=(PortRange(low=443, high=443),),
                )
            ]
        )
        decision = engine.check(
            TargetSpec(kind=TargetKind.HOST, host="api.example.com"), port=443
        )
        assert decision.allowed is True

    def test_disallowed_port_rejected_with_port_summary(self) -> None:
        engine = ScopeEngine(
            [
                ScopeRule(
                    kind=ScopeKind.DOMAIN,
                    pattern="example.com",
                    ports=(PortRange(low=443, high=443),),
                )
            ]
        )
        decision = engine.check(
            TargetSpec(kind=TargetKind.HOST, host="api.example.com"), port=80
        )
        assert decision.allowed is False
        assert decision.failure_summary == "target_port_not_allowed"

    def test_no_matching_rule_returns_not_in_scope_not_port_miss(self) -> None:
        engine = ScopeEngine([ScopeRule(kind=ScopeKind.DOMAIN, pattern="other.com")])
        decision = engine.check(
            TargetSpec(kind=TargetKind.HOST, host="api.example.com"), port=80
        )
        assert decision.failure_summary == "target_not_in_scope"


class TestFailureSummariesAreClosedTaxonomy:
    def test_every_summary_is_in_closed_set(
        self,
    ) -> None:
        # Each branch uses an isolated rule set so the first-matching-allow
        # contract does not shadow the more-specific port rule.
        not_in_scope_engine = ScopeEngine(
            [ScopeRule(kind=ScopeKind.DOMAIN, pattern="other.com")]
        )
        denied_engine = ScopeEngine(
            [
                ScopeRule(
                    kind=ScopeKind.HOST,
                    pattern="block.example.com",
                    deny=True,
                ),
                ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com"),
            ]
        )
        ports_only_engine = ScopeEngine(
            [
                ScopeRule(
                    kind=ScopeKind.DOMAIN,
                    pattern="example.com",
                    ports=(PortRange(low=443, high=443),),
                ),
            ]
        )
        decisions: list[ScopeDecision] = [
            not_in_scope_engine.check(
                TargetSpec(kind=TargetKind.HOST, host="api.example.com")
            ),
            denied_engine.check(
                TargetSpec(kind=TargetKind.HOST, host="block.example.com")
            ),
            ports_only_engine.check(
                TargetSpec(kind=TargetKind.HOST, host="api.example.com"),
                port=80,
            ),
        ]
        for decision in decisions:
            assert decision.allowed is False
            assert decision.failure_summary in SCOPE_FAILURE_REASONS


# ---------------------------------------------------------------------------
# assert_allowed contract
# ---------------------------------------------------------------------------


class TestScopeAssertAllowed:
    def test_returns_decision_when_allowed(self) -> None:
        engine = ScopeEngine([ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com")])
        decision = engine.assert_allowed(
            TargetSpec(kind=TargetKind.HOST, host="example.com")
        )
        assert decision.allowed is True

    def test_raises_violation_with_summary(self) -> None:
        engine = ScopeEngine(
            [
                ScopeRule(kind=ScopeKind.HOST, pattern="x.example.com", deny=True),
                ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com"),
            ]
        )
        with pytest.raises(ScopeViolation) as exc_info:
            engine.assert_allowed(
                TargetSpec(kind=TargetKind.HOST, host="x.example.com")
            )
        assert exc_info.value.summary == "target_explicitly_denied"
