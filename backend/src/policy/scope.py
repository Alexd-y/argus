"""Scope enforcement for ARGUS pre-flight (Backlog/dev1_md §8).

Every pre-engagement contract pins a customer to a finite, explicit set of
*authorised targets* — a hostname, a URL prefix, an IPv4/IPv6 address or
CIDR block, plus optional port ranges. The :class:`ScopeEngine` answers a
single question:

    ``check(target, port=...) → ScopeDecision(allowed=bool, …)``

Hard rules:

* Default deny — empty rule list yields ``allowed=False``.
* Deny rules ALWAYS override allow rules. A target that matches both an
  allow and a deny is rejected.
* No DNS resolution: hostnames are matched as suffixes against the allow
  list. The :class:`OwnershipVerifier` (see :mod:`src.policy.ownership`) is
  responsible for proving the customer controls the host before the rule
  ever lands here.
* No external I/O. The engine is pure — safe to call inside hot loops.

Failure summaries returned to callers are drawn from a closed taxonomy
(``"target_not_in_scope"``, ``"target_explicitly_denied"``, etc.) so a
user-facing message can never echo internal rule indexes, regex patterns,
or the customer's full target list.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from enum import StrEnum
from typing import Final, Self
from urllib.parse import urlparse

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

from src.pipeline.contracts.tool_job import TargetKind, TargetSpec


# ---------------------------------------------------------------------------
# Closed-taxonomy failure summaries
# ---------------------------------------------------------------------------


_REASON_NOT_IN_SCOPE: Final[str] = "target_not_in_scope"
_REASON_EXPLICITLY_DENIED: Final[str] = "target_explicitly_denied"
_REASON_PORT_NOT_ALLOWED: Final[str] = "target_port_not_allowed"
_REASON_MALFORMED_RULE: Final[str] = "scope_rule_malformed"

SCOPE_FAILURE_REASONS: Final[frozenset[str]] = frozenset(
    {
        _REASON_NOT_IN_SCOPE,
        _REASON_EXPLICITLY_DENIED,
        _REASON_PORT_NOT_ALLOWED,
        _REASON_MALFORMED_RULE,
    }
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ScopeViolation(Exception):
    """Raised when a caller demands strict enforcement and the check fails."""

    def __init__(self, summary: str, *, target: str) -> None:
        super().__init__(summary)
        self.summary = summary
        self.target = target


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class ScopeKind(StrEnum):
    """Discriminator for :class:`ScopeRule`.

    Each rule matches exactly one of these target shapes. URL rules match a
    URL *prefix*; CIDR rules match IP / nested-CIDR membership; DOMAIN rules
    match a hostname suffix (``example.com`` matches ``api.example.com`` but
    not ``notexample.com``).
    """

    URL = "url"
    DOMAIN = "domain"
    HOST = "host"
    IP = "ip"
    CIDR = "cidr"


_MAX_PORT: Final[int] = 65_535


class PortRange(BaseModel):
    """Inclusive [low, high] port range.

    Single-port rules use ``low == high``. The validator enforces strict
    bounds and ordering so an attacker cannot smuggle a wildcard via
    ``low=0, high=65535`` unless that exact range is what the operator
    explicitly typed.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    low: StrictInt = Field(ge=1, le=_MAX_PORT)
    high: StrictInt = Field(ge=1, le=_MAX_PORT)

    @model_validator(mode="after")
    def _validate_order(self) -> Self:
        if self.high < self.low:
            raise ValueError(
                f"PortRange requires low<=high, got [{self.low}, {self.high}]"
            )
        return self

    def contains(self, port: int) -> bool:
        return self.low <= port <= self.high


class ScopeRule(BaseModel):
    """One row of the customer's authorised-target list.

    Notes
    -----
    * Pattern semantics depend on :attr:`kind`:
        * ``URL``    → exact-prefix match, including scheme and path.
        * ``DOMAIN`` → suffix match (``example.com`` ≠ ``notexample.com``).
        * ``HOST``   → exact lowercase hostname.
        * ``IP``     → exact IPv4/IPv6 address.
        * ``CIDR``   → IPv4/IPv6 network membership.
    * ``deny=True`` rules always shadow allow rules with the same target.
    * ``ports`` is *optional*. When omitted, the rule accepts any port. When
      set, all listed ranges must individually pass validation.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: ScopeKind
    pattern: StrictStr = Field(min_length=1, max_length=2_048)
    deny: StrictBool = False
    ports: tuple[PortRange, ...] = Field(default_factory=tuple, max_length=64)
    note: StrictStr = Field(default="", max_length=256)

    @model_validator(mode="before")
    @classmethod
    def _normalise(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        kind_value = data.get("kind")
        pattern_value = data.get("pattern")
        if not isinstance(pattern_value, str):
            return data
        normalised = pattern_value.strip()
        kind_enum: ScopeKind | None
        if isinstance(kind_value, ScopeKind):
            kind_enum = kind_value
        elif isinstance(kind_value, str):
            try:
                kind_enum = ScopeKind(kind_value)
            except ValueError:
                kind_enum = None
        else:
            kind_enum = None
        if kind_enum in {ScopeKind.DOMAIN, ScopeKind.HOST}:
            normalised = normalised.lower().lstrip(".")
        return {**data, "pattern": normalised}

    @model_validator(mode="after")
    def _validate_pattern(self) -> Self:
        if not self.pattern:
            raise ValueError("ScopeRule.pattern must not be empty")
        if self.kind is ScopeKind.URL:
            parsed = urlparse(self.pattern)
            if parsed.scheme not in {"http", "https"}:
                raise ValueError(
                    f"URL scope rule must use http/https scheme, got {parsed.scheme!r}"
                )
            if not parsed.netloc:
                raise ValueError("URL scope rule requires a non-empty host component")
        elif self.kind in {ScopeKind.DOMAIN, ScopeKind.HOST}:
            if any(ch in self.pattern for ch in (" ", "/", "\\", "?", "#")):
                raise ValueError(
                    f"{self.kind.value} pattern contains forbidden characters"
                )
        elif self.kind is ScopeKind.IP:
            try:
                ipaddress.ip_address(self.pattern)
            except ValueError as exc:
                raise ValueError(f"invalid IP address {self.pattern!r}: {exc}") from exc
        elif self.kind is ScopeKind.CIDR:
            try:
                ipaddress.ip_network(self.pattern, strict=False)
            except ValueError as exc:
                raise ValueError(f"invalid CIDR {self.pattern!r}: {exc}") from exc
        return self

    def covers_port(self, port: int | None) -> bool:
        """Return ``True`` if this rule's port set admits ``port``.

        Rules without an explicit ``ports`` list cover every port. Rules
        with a ``ports`` list match only if at least one range contains the
        requested port — when ``port is None`` the rule is rejected (the
        caller forgot to specify a port for a port-restricted rule).
        """
        if not self.ports:
            return True
        if port is None:
            return False
        return any(rng.contains(port) for rng in self.ports)


class ScopeDecision(BaseModel):
    """Pure output of :meth:`ScopeEngine.check`.

    The decision carries the matched rule index for audit only; user-facing
    messaging MUST consume :attr:`failure_summary` instead so internal
    structure is never echoed back.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    allowed: StrictBool
    target: StrictStr = Field(min_length=1, max_length=2_048)
    matched_rule_index: StrictInt | None = Field(default=None, ge=0)
    failure_summary: StrictStr | None = Field(default=None, max_length=64)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ScopeEngine:
    """Stateless evaluator of :class:`ScopeRule` collections.

    Hold a single instance per tenant; the rule set is closed over at
    construction time so concurrent ``check`` calls cannot observe a
    half-mutated allow-list.
    """

    def __init__(self, rules: Sequence[ScopeRule]) -> None:
        self._rules: tuple[ScopeRule, ...] = tuple(rules)

    @property
    def rules(self) -> tuple[ScopeRule, ...]:
        return self._rules

    def check(self, target: TargetSpec, *, port: int | None = None) -> ScopeDecision:
        """Evaluate ``target`` (and optional ``port``) against the rule set.

        Decision algorithm:

        1. Iterate the rule list and collect every rule that matches the
           target's value.
        2. If any matching rule has ``deny=True``, return a deny decision.
        3. If no matching rule has ``allowed`` semantics + the requested
           port, return ``allowed=False``.
        4. Otherwise the first matching allow rule wins.
        """
        if not self._rules:
            return ScopeDecision(
                allowed=False,
                target=target.value,
                failure_summary=_REASON_NOT_IN_SCOPE,
            )

        target_value = target.value
        first_allow_index: int | None = None
        first_allow_port_miss: int | None = None
        for index, rule in enumerate(self._rules):
            if not _rule_matches_target(rule, target):
                continue
            if rule.deny:
                return ScopeDecision(
                    allowed=False,
                    target=target_value,
                    matched_rule_index=index,
                    failure_summary=_REASON_EXPLICITLY_DENIED,
                )
            if rule.covers_port(port):
                if first_allow_index is None:
                    first_allow_index = index
            elif first_allow_port_miss is None:
                first_allow_port_miss = index

        if first_allow_index is not None:
            return ScopeDecision(
                allowed=True,
                target=target_value,
                matched_rule_index=first_allow_index,
                failure_summary=None,
            )
        if first_allow_port_miss is not None:
            return ScopeDecision(
                allowed=False,
                target=target_value,
                matched_rule_index=first_allow_port_miss,
                failure_summary=_REASON_PORT_NOT_ALLOWED,
            )
        return ScopeDecision(
            allowed=False,
            target=target_value,
            failure_summary=_REASON_NOT_IN_SCOPE,
        )

    def assert_allowed(
        self, target: TargetSpec, *, port: int | None = None
    ) -> ScopeDecision:
        """Like :meth:`check`, but raise :class:`ScopeViolation` on deny."""
        decision = self.check(target, port=port)
        if not decision.allowed:
            assert decision.failure_summary is not None
            raise ScopeViolation(decision.failure_summary, target=decision.target)
        return decision


# ---------------------------------------------------------------------------
# Internal matchers
# ---------------------------------------------------------------------------


def _rule_matches_target(rule: ScopeRule, target: TargetSpec) -> bool:
    """Return ``True`` iff ``rule`` covers ``target.value`` ignoring port.

    Type compatibility matrix:

    * ``ScopeKind.URL``    matches ``TargetKind.URL`` only (prefix match).
    * ``ScopeKind.DOMAIN`` matches ``TargetKind.URL``, ``HOST``, ``DOMAIN``.
    * ``ScopeKind.HOST``   matches ``TargetKind.HOST``, ``URL`` (host part).
    * ``ScopeKind.IP``     matches ``TargetKind.IP``.
    * ``ScopeKind.CIDR``   matches ``TargetKind.IP`` and ``TargetKind.CIDR``.

    All other combinations short-circuit to ``False`` so a CIDR rule cannot
    accidentally allow a hostname (the operator would have written a DOMAIN
    rule for that).
    """
    if rule.kind is ScopeKind.URL:
        return target.kind is TargetKind.URL and _url_matches(
            rule.pattern, target.value
        )
    if rule.kind is ScopeKind.DOMAIN:
        host = _extract_host(target)
        return host is not None and _domain_matches(rule.pattern, host)
    if rule.kind is ScopeKind.HOST:
        host = _extract_host(target)
        return host is not None and host == rule.pattern
    if rule.kind is ScopeKind.IP:
        if target.kind is not TargetKind.IP:
            return False
        return _ip_equals(rule.pattern, target.value)
    if rule.kind is ScopeKind.CIDR:
        return _cidr_contains(rule.pattern, target)
    return False


def _extract_host(target: TargetSpec) -> str | None:
    """Return the lowercase hostname embedded in a target spec, if any."""
    if target.kind is TargetKind.HOST:
        return target.value.lower()
    if target.kind is TargetKind.DOMAIN:
        return target.value.lower()
    if target.kind is TargetKind.URL:
        parsed = urlparse(target.value)
        if not parsed.hostname:
            return None
        return parsed.hostname.lower()
    return None


def _url_matches(pattern: str, candidate: str) -> bool:
    """URL prefix match honouring scheme, host (case-insensitive), and path."""
    pat = urlparse(pattern)
    can = urlparse(candidate)
    if pat.scheme.lower() != can.scheme.lower():
        return False
    if (pat.hostname or "").lower() != (can.hostname or "").lower():
        return False
    if pat.port not in (None, can.port):
        return False
    pat_path = pat.path or "/"
    can_path = can.path or "/"
    if not can_path.startswith(pat_path):
        return False
    return True


def _domain_matches(pattern: str, host: str) -> bool:
    """Suffix match — ``example.com`` matches ``api.example.com``."""
    pattern = pattern.lower().lstrip(".")
    host = host.lower()
    if host == pattern:
        return True
    return host.endswith(f".{pattern}")


def _ip_equals(rule_ip: str, candidate: str) -> bool:
    try:
        return ipaddress.ip_address(rule_ip) == ipaddress.ip_address(candidate)
    except ValueError:
        return False


def _cidr_contains(rule_cidr: str, target: TargetSpec) -> bool:
    try:
        network = ipaddress.ip_network(rule_cidr, strict=False)
    except ValueError:
        return False
    if target.kind is TargetKind.IP:
        try:
            return ipaddress.ip_address(target.value) in network
        except ValueError:
            return False
    if target.kind is TargetKind.CIDR:
        try:
            other = ipaddress.ip_network(target.value, strict=False)
        except ValueError:
            return False
        if network.version != other.version:
            return False
        # ``supernet_of`` requires the same address family on both
        # sides; mypy cannot narrow the union after the version check
        # alone, so we cast explicitly.
        if isinstance(network, ipaddress.IPv4Network) and isinstance(
            other, ipaddress.IPv4Network
        ):
            return network.supernet_of(other)
        if isinstance(network, ipaddress.IPv6Network) and isinstance(
            other, ipaddress.IPv6Network
        ):
            return network.supernet_of(other)
        return False
    return False


__all__ = [
    "PortRange",
    "SCOPE_FAILURE_REASONS",
    "ScopeDecision",
    "ScopeEngine",
    "ScopeKind",
    "ScopeRule",
    "ScopeViolation",
]
