"""Deterministic oracles that judge scenario outcomes (P2-PLAYBOOKS-002).

An *oracle* compares a baseline exchange (legitimate / control) with a mutated
exchange (the attack) and returns a verdict. Oracles are **pure functions**:
same inputs → same verdict, no I/O, no randomness. This makes findings
reproducible and auditable.

Design rules enforced here:

* A bare ``HTTP 200`` is never proof of a vulnerability (a common false
  positive). The authz oracle only confirms when the attacker actually
  received the victim's private data.
* Absence of a negative signal is not a positive: the rate-limit oracle never
  reports a finding merely because it did not observe a ``429`` on a single
  request — that is :attr:`OracleVerdict.INCONCLUSIVE`.

Implemented and tested here (all deterministic, pure): ``authz``, ``authn``,
``rate_limit`` (P2) plus ``race`` / ``file_upload`` / ``business_logic`` (P4).
Every oracle is a same-inputs → same-verdict comparison with no I/O.

:class:`OracleNotImplemented` is retained as a legacy, exported symbol for
backward compatibility only — no oracle raises it anymore.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from collections.abc import Mapping
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from src.pipeline.contracts.finding_dto import ConfidenceLevel
from src.playbooks.actions import HttpExchange
from src.playbooks.schema import OracleType

# Fields whose values legitimately change between two otherwise-identical
# responses (server clocks, request ids). A difference confined to these is
# treated conservatively as "not proof of cross-user access".
_DEFAULT_VOLATILE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "timestamp",
        "time",
        "date",
        "datetime",
        "now",
        "server_time",
        "request_id",
        "trace_id",
        "last_seen",
        "updated_at",
        "created_at",
        "expires_at",
        "iat",
        "exp",
        "nonce",
    }
)

_DEFAULT_DENIED_STATUSES: Final[tuple[int, ...]] = (401, 403, 404)


# ---------------------------------------------------------------------------
# Errors / result types
# ---------------------------------------------------------------------------


class OracleNotImplemented(NotImplementedError):
    """Raised when an oracle whose logic is deferred to P4 is invoked."""

    def __init__(self, oracle_type: OracleType) -> None:
        super().__init__(
            f"oracle {oracle_type.value!r} is defined but its evaluation logic "
            "lands in P4; no verdict backend is wired yet"
        )
        self.oracle_type = oracle_type


class OracleVerdict(StrEnum):
    """Outcome of an oracle evaluation."""

    FINDING = "finding"
    NO_FINDING = "no_finding"
    INCONCLUSIVE = "inconclusive"


class OracleResult(BaseModel):
    """Immutable verdict produced by an oracle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    oracle_type: OracleType
    verdict: OracleVerdict
    confidence: ConfidenceLevel
    reason: StrictStr = Field(min_length=1, max_length=2000)
    differing_fields: list[StrictStr] = Field(default_factory=list, max_length=256)

    @property
    def is_finding(self) -> bool:
        return self.verdict is OracleVerdict.FINDING


# ---------------------------------------------------------------------------
# Per-oracle typed params
# ---------------------------------------------------------------------------


class AuthzOracleParams(BaseModel):
    """Params for the authorization (IDOR / BOLA) oracle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sensitive_fields: list[StrictStr] = Field(default_factory=list, max_length=64)
    volatile_fields: list[StrictStr] = Field(default_factory=list, max_length=64)
    denied_statuses: list[StrictInt] = Field(
        default_factory=lambda: list(_DEFAULT_DENIED_STATUSES), max_length=16
    )

    def volatile(self) -> frozenset[str]:
        return _DEFAULT_VOLATILE_FIELDS | frozenset(self.volatile_fields)


class AuthnOracleParams(BaseModel):
    """Params for the authentication-bypass oracle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    denied_statuses: list[StrictInt] = Field(default_factory=lambda: [401, 403], max_length=16)
    success_min: StrictInt = Field(default=200, ge=100, le=599)
    success_max: StrictInt = Field(default=299, ge=100, le=599)


class RateLimitOracleParams(BaseModel):
    """Params for the rate-limit oracle."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    threshold: StrictInt = Field(default=20, ge=2, le=100_000)
    # Optional full burst of observed status codes (evidence of a real
    # volume test). When absent, the oracle can only inspect the single
    # ``mutated`` response and will not auto-confirm a missing limit.
    observed_statuses: list[StrictInt] = Field(default_factory=list, max_length=100_000)
    throttle_status: StrictInt = Field(default=429, ge=100, le=599)
    honor_retry_after: StrictBool = True


class BusinessLogicRelation(StrEnum):
    """Declarative invariant relation for the business-logic oracle."""

    UNCHANGED = "unchanged"
    NON_DECREASING = "non_decreasing"
    NON_INCREASING = "non_increasing"
    EQUALS_EXPECTED = "equals_expected"


class RaceOracleParams(BaseModel):
    """Params for the race-condition / TOCTOU oracle.

    A race finding requires the server to have applied an operation *more
    times than its idempotency invariant allows* — proven by an actual
    change in server-side state (``state_field``), not merely by many 2xx
    responses (a server may accept duplicates then dedupe).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Dotted JSON path to a numeric server-side counter/balance read both in
    # the baseline (pre-race) and mutated (post-race) state exchanges.
    state_field: StrictStr | None = Field(default=None, max_length=512)
    # Idempotency invariant: how many times the operation may legitimately
    # take effect (usually 1 — e.g. a coupon may be redeemed once).
    expected_max_success: StrictInt = Field(default=1, ge=0, le=1_000_000)
    # Runtime-populated: number of concurrent operations the server accepted.
    success_count: StrictInt = Field(default=0, ge=0, le=1_000_000)
    # Runtime-populated: per-request status codes of the concurrent burst.
    observed_statuses: list[StrictInt] = Field(default_factory=list, max_length=100_000)
    success_statuses: list[StrictInt] = Field(default_factory=lambda: [200, 201], max_length=16)


class FileUploadOracleParams(BaseModel):
    """Params for the malicious-file-upload oracle.

    ``mutated`` MUST be the *fetch-after-upload* exchange (a GET of the stored
    file). A finding requires the safe marker content to be served back with a
    success status — i.e. the upload is actually reachable / processed. A bare
    upload-accepted 2xx is never proof on its own.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Unique, benign marker embedded in the uploaded file (never real malware).
    marker: StrictStr = Field(min_length=1, max_length=512)
    success_statuses: list[StrictInt] = Field(default_factory=lambda: [200], max_length=16)
    denied_statuses: list[StrictInt] = Field(default_factory=lambda: [401, 403, 404], max_length=16)


class BusinessLogicOracleParams(BaseModel):
    """Params for the business-logic invariant oracle.

    Compares a before-state (``baseline``) and after-state (``mutated``) value
    at ``field`` against a declared ``relation``. A finding is raised when the
    invariant is *violated* (e.g. a balance increased without a payment).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: StrictStr = Field(min_length=1, max_length=512)
    relation: BusinessLogicRelation = BusinessLogicRelation.UNCHANGED
    expected: StrictStr | None = Field(default=None, max_length=512)


_ORACLE_PARAM_MODELS: Final[dict[OracleType, type[BaseModel]]] = {
    OracleType.AUTHZ: AuthzOracleParams,
    OracleType.AUTHN: AuthnOracleParams,
    OracleType.RATE_LIMIT: RateLimitOracleParams,
    OracleType.RACE: RaceOracleParams,
    OracleType.FILE_UPLOAD: FileUploadOracleParams,
    OracleType.BUSINESS_LOGIC: BusinessLogicOracleParams,
}


def validate_params(oracle_type: OracleType, params: Mapping[str, object]) -> BaseModel:
    """Validate ``params`` for ``oracle_type`` (fail-closed at registry load).

    For oracle types whose logic is deferred to P4 there is no param model
    yet; an empty mapping is accepted and anything else is rejected so a
    playbook cannot smuggle unvalidated data through a not-yet-live oracle.
    """
    model_cls = _ORACLE_PARAM_MODELS.get(oracle_type)
    if model_cls is None:
        if params:
            raise ValueError(
                f"oracle {oracle_type.value!r} accepts no params until its P4 "
                "implementation lands"
            )
        return _EmptyParams()
    return model_cls.model_validate(dict(params))


class _EmptyParams(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# ---------------------------------------------------------------------------
# JSON helpers (pure)
# ---------------------------------------------------------------------------


def _parse_json(body: str) -> object | None:
    try:
        return json.loads(body)
    except (ValueError, TypeError):
        return None


def _leaf(path: str) -> str:
    return path.rsplit(".", 1)[-1]


def _diff_paths(left: object, right: object, prefix: str = "") -> set[str]:
    """Return the set of dotted leaf paths where ``left`` and ``right`` differ."""
    here = prefix.rstrip(".") or "<root>"
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        paths: set[str] = set()
        for key in set(left) | set(right):
            child = f"{prefix}{key}"
            if key not in left or key not in right:
                paths.add(child)
            else:
                paths |= _diff_paths(left[key], right[key], child + ".")
        return paths
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return {here}
        paths = set()
        for index, (lft, rgt) in enumerate(zip(left, right)):
            paths |= _diff_paths(lft, rgt, f"{prefix}{index}.")
        return paths
    return set() if left == right else {here}


def _read_path(obj: object, path: str) -> object:
    current = obj
    for segment in path.split("."):
        if isinstance(current, Mapping) and segment in current:
            current = current[segment]
        elif isinstance(current, list) and segment.isdigit() and int(segment) < len(current):
            current = current[int(segment)]
        else:
            return None
    return current


def _to_number(value: object) -> float | None:
    """Best-effort numeric coercion for deterministic state comparisons.

    Returns ``None`` for values that are not a real number (``bool`` is
    intentionally rejected — a boolean is not a counter/balance).
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


# ---------------------------------------------------------------------------
# Oracle interface + implementations
# ---------------------------------------------------------------------------


class Oracle(ABC):
    """Interface for a deterministic scenario oracle."""

    oracle_type: OracleType

    @abstractmethod
    def evaluate(
        self,
        baseline: HttpExchange,
        mutated: HttpExchange,
        params: Mapping[str, object],
    ) -> OracleResult:
        """Compare ``baseline`` and ``mutated`` and return an :class:`OracleResult`."""
        raise NotImplementedError


class AuthzOracle(Oracle):
    """IDOR / BOLA oracle.

    ``baseline`` is the victim's legitimate response (their private data);
    ``mutated`` is the attacker's response when requesting the victim's
    resource. A finding requires the attacker to have actually received the
    victim's data — never a bare 2xx.
    """

    oracle_type = OracleType.AUTHZ

    def evaluate(
        self,
        baseline: HttpExchange,
        mutated: HttpExchange,
        params: Mapping[str, object],
    ) -> OracleResult:
        cfg = AuthzOracleParams.model_validate(dict(params))
        status = mutated.response.status

        if status in set(cfg.denied_statuses):
            return self._result(
                OracleVerdict.NO_FINDING,
                ConfidenceLevel.CONFIRMED,
                f"attacker request properly denied with HTTP {status}",
            )
        if not 200 <= status <= 299:
            return self._result(
                OracleVerdict.INCONCLUSIVE,
                ConfidenceLevel.SUSPECTED,
                f"attacker response HTTP {status} is neither a clear grant nor deny",
            )

        owner = _parse_json(baseline.response.body)
        attacker = _parse_json(mutated.response.body)

        if owner is None or attacker is None:
            return self._compare_raw(baseline, mutated)

        if cfg.sensitive_fields:
            return self._compare_sensitive(owner, attacker, cfg)
        return self._compare_full(owner, attacker, cfg)

    def _compare_raw(self, baseline: HttpExchange, mutated: HttpExchange) -> OracleResult:
        owner_body = baseline.response.body
        attacker_body = mutated.response.body
        if owner_body and owner_body == attacker_body:
            return self._result(
                OracleVerdict.FINDING,
                ConfidenceLevel.CONFIRMED,
                "attacker received a byte-identical copy of the victim's response",
            )
        return self._result(
            OracleVerdict.NO_FINDING,
            ConfidenceLevel.LIKELY,
            "attacker response differs from the victim's; no cross-user read proven",
        )

    def _compare_sensitive(
        self, owner: object, attacker: object, cfg: AuthzOracleParams
    ) -> OracleResult:
        matched: list[str] = []
        for field_path in cfg.sensitive_fields:
            owner_value = _read_path(owner, field_path)
            attacker_value = _read_path(attacker, field_path)
            if owner_value in (None, "", [], {}):
                continue
            if owner_value == attacker_value:
                matched.append(field_path)
        if matched:
            return self._result(
                OracleVerdict.FINDING,
                ConfidenceLevel.CONFIRMED,
                "attacker read the victim's sensitive field(s): " + ", ".join(sorted(matched)),
                differing_fields=[],
            )
        return self._result(
            OracleVerdict.NO_FINDING,
            ConfidenceLevel.LIKELY,
            "attacker did not obtain any victim sensitive-field values",
        )

    def _compare_full(
        self, owner: object, attacker: object, cfg: AuthzOracleParams
    ) -> OracleResult:
        diffs = _diff_paths(owner, attacker)
        if not diffs:
            return self._result(
                OracleVerdict.FINDING,
                ConfidenceLevel.CONFIRMED,
                "attacker received data identical to the victim's private record",
            )
        volatile = cfg.volatile()
        non_volatile = sorted(d for d in diffs if _leaf(d) not in volatile)
        if not non_volatile:
            return self._result(
                OracleVerdict.NO_FINDING,
                ConfidenceLevel.LIKELY,
                "responses differ only in volatile field(s) "
                f"({', '.join(sorted(diffs))}); not proof of cross-user read",
                differing_fields=sorted(diffs),
            )
        return self._result(
            OracleVerdict.NO_FINDING,
            ConfidenceLevel.LIKELY,
            "attacker sees substantively different data; no cross-user read proven",
            differing_fields=non_volatile,
        )

    def _result(
        self,
        verdict: OracleVerdict,
        confidence: ConfidenceLevel,
        reason: str,
        *,
        differing_fields: list[str] | None = None,
    ) -> OracleResult:
        return OracleResult(
            oracle_type=self.oracle_type,
            verdict=verdict,
            confidence=confidence,
            reason=reason,
            differing_fields=differing_fields or [],
        )


class AuthnOracle(Oracle):
    """Authentication-bypass oracle.

    ``baseline`` is an authenticated request that legitimately succeeds;
    ``mutated`` is the same request without / with invalid credentials. A
    finding requires the unauthenticated request to succeed with substantive
    data — not merely a 2xx on a public endpoint.
    """

    oracle_type = OracleType.AUTHN

    def evaluate(
        self,
        baseline: HttpExchange,
        mutated: HttpExchange,
        params: Mapping[str, object],
    ) -> OracleResult:
        cfg = AuthnOracleParams.model_validate(dict(params))
        status = mutated.response.status

        if status in set(cfg.denied_statuses):
            return OracleResult(
                oracle_type=self.oracle_type,
                verdict=OracleVerdict.NO_FINDING,
                confidence=ConfidenceLevel.CONFIRMED,
                reason=f"unauthenticated request correctly denied with HTTP {status}",
            )
        if not cfg.success_min <= status <= cfg.success_max:
            return OracleResult(
                oracle_type=self.oracle_type,
                verdict=OracleVerdict.INCONCLUSIVE,
                confidence=ConfidenceLevel.SUSPECTED,
                reason=f"unauthenticated response HTTP {status} is ambiguous",
            )

        baseline_ok = 200 <= baseline.response.status <= 299
        same_shape = _parse_json(baseline.response.body) is not None and (
            _parse_json(mutated.response.body) is not None
        )
        if baseline_ok and same_shape and mutated.response.body.strip():
            return OracleResult(
                oracle_type=self.oracle_type,
                verdict=OracleVerdict.FINDING,
                confidence=ConfidenceLevel.CONFIRMED,
                reason=(
                    "unauthenticated request returned a successful, data-bearing "
                    f"response (HTTP {status}); authentication is not enforced"
                ),
            )
        return OracleResult(
            oracle_type=self.oracle_type,
            verdict=OracleVerdict.INCONCLUSIVE,
            confidence=ConfidenceLevel.SUSPECTED,
            reason="unauthenticated response succeeded but carried no clear data",
        )


class RateLimitOracle(Oracle):
    """Rate-limit oracle.

    Confirms a *missing* rate limit only with volume evidence: a burst of at
    least ``threshold`` requests where none was throttled. A single response
    without a ``429`` is :attr:`OracleVerdict.INCONCLUSIVE`, never a finding.
    """

    oracle_type = OracleType.RATE_LIMIT

    def evaluate(
        self,
        baseline: HttpExchange,
        mutated: HttpExchange,
        params: Mapping[str, object],
    ) -> OracleResult:
        cfg = RateLimitOracleParams.model_validate(dict(params))

        if self._is_throttled(mutated, cfg):
            return OracleResult(
                oracle_type=self.oracle_type,
                verdict=OracleVerdict.NO_FINDING,
                confidence=ConfidenceLevel.CONFIRMED,
                reason=(
                    f"throttling observed (HTTP {cfg.throttle_status} / Retry-After); "
                    "rate limiting is enforced"
                ),
            )

        observed = cfg.observed_statuses
        if not observed:
            return OracleResult(
                oracle_type=self.oracle_type,
                verdict=OracleVerdict.INCONCLUSIVE,
                confidence=ConfidenceLevel.SUSPECTED,
                reason=(
                    "no throttling on the single observed request; absence of a "
                    "429 is not proof of a missing rate limit"
                ),
            )

        throttled = sum(1 for status in observed if status == cfg.throttle_status)
        if throttled:
            return OracleResult(
                oracle_type=self.oracle_type,
                verdict=OracleVerdict.NO_FINDING,
                confidence=ConfidenceLevel.CONFIRMED,
                reason=f"{throttled}/{len(observed)} burst requests were throttled",
            )
        if len(observed) >= cfg.threshold:
            return OracleResult(
                oracle_type=self.oracle_type,
                verdict=OracleVerdict.FINDING,
                confidence=ConfidenceLevel.CONFIRMED,
                reason=(
                    f"{len(observed)} consecutive requests (>= threshold "
                    f"{cfg.threshold}) with no throttling; rate limiting is absent"
                ),
            )
        return OracleResult(
            oracle_type=self.oracle_type,
            verdict=OracleVerdict.INCONCLUSIVE,
            confidence=ConfidenceLevel.SUSPECTED,
            reason=(
                f"only {len(observed)} requests observed (< threshold "
                f"{cfg.threshold}); insufficient volume to confirm a missing limit"
            ),
        )

    @staticmethod
    def _is_throttled(exchange: HttpExchange, cfg: RateLimitOracleParams) -> bool:
        if exchange.response.status == cfg.throttle_status:
            return True
        if cfg.honor_retry_after and exchange.response.header("Retry-After"):
            return True
        return False


class RaceOracle(Oracle):
    """Race-condition / TOCTOU oracle.

    ``baseline`` is the server-side state *before* the concurrent burst;
    ``mutated`` is the state *after*. The oracle confirms a race only when the
    operation took effect more times than the idempotency invariant allows —
    demonstrated by an actual state delta, not by a pile of 2xx responses.
    """

    oracle_type = OracleType.RACE

    def evaluate(
        self,
        baseline: HttpExchange,
        mutated: HttpExchange,
        params: Mapping[str, object],
    ) -> OracleResult:
        cfg = RaceOracleParams.model_validate(dict(params))
        successes = self._count_successes(cfg)

        if cfg.state_field is not None:
            return self._evaluate_state_delta(baseline, mutated, cfg, successes)

        # No server-state field to inspect: fall back to accepted-operation
        # counting. Weaker, but still deterministic and never a bare-2xx proof.
        if successes > cfg.expected_max_success:
            return OracleResult(
                oracle_type=self.oracle_type,
                verdict=OracleVerdict.FINDING,
                confidence=ConfidenceLevel.LIKELY,
                reason=(
                    f"{successes} concurrent operations succeeded (idempotency "
                    f"invariant allows {cfg.expected_max_success}); probable race"
                ),
            )
        return OracleResult(
            oracle_type=self.oracle_type,
            verdict=OracleVerdict.NO_FINDING,
            confidence=ConfidenceLevel.LIKELY,
            reason=(
                f"{successes} successful operation(s) within the idempotency "
                f"invariant ({cfg.expected_max_success}); no race proven"
            ),
        )

    @staticmethod
    def _count_successes(cfg: RaceOracleParams) -> int:
        if cfg.success_count > 0:
            return cfg.success_count
        success = set(cfg.success_statuses)
        return sum(1 for status in cfg.observed_statuses if status in success)

    def _evaluate_state_delta(
        self,
        baseline: HttpExchange,
        mutated: HttpExchange,
        cfg: RaceOracleParams,
        successes: int,
    ) -> OracleResult:
        assert cfg.state_field is not None
        before = _to_number(_read_path(_parse_json(baseline.response.body), cfg.state_field))
        after = _to_number(_read_path(_parse_json(mutated.response.body), cfg.state_field))
        if before is None or after is None:
            return OracleResult(
                oracle_type=self.oracle_type,
                verdict=OracleVerdict.INCONCLUSIVE,
                confidence=ConfidenceLevel.SUSPECTED,
                reason=(
                    f"could not read numeric server state at {cfg.state_field!r} "
                    "in both exchanges; race unproven"
                ),
            )
        delta = abs(after - before)
        if delta > cfg.expected_max_success:
            return OracleResult(
                oracle_type=self.oracle_type,
                verdict=OracleVerdict.FINDING,
                confidence=ConfidenceLevel.CONFIRMED,
                reason=(
                    f"server-side state changed by {delta:g} (>{cfg.expected_max_success} "
                    f"allowed) across {successes} concurrent operations; race confirmed"
                ),
            )
        return OracleResult(
            oracle_type=self.oracle_type,
            verdict=OracleVerdict.NO_FINDING,
            confidence=ConfidenceLevel.CONFIRMED,
            reason=(
                f"server-side state changed by only {delta:g} despite {successes} "
                "concurrent operations; idempotency held server-side"
            ),
        )


class FileUploadOracle(Oracle):
    """Malicious-file-upload oracle.

    ``mutated`` MUST be the fetch-after-upload exchange. A finding requires the
    benign marker to be served back with a success status (the upload is
    reachable / processed). Denials and marker-absent responses are not
    findings.
    """

    oracle_type = OracleType.FILE_UPLOAD

    def evaluate(
        self,
        baseline: HttpExchange,
        mutated: HttpExchange,
        params: Mapping[str, object],
    ) -> OracleResult:
        cfg = FileUploadOracleParams.model_validate(dict(params))
        status = mutated.response.status

        if status in set(cfg.denied_statuses):
            return OracleResult(
                oracle_type=self.oracle_type,
                verdict=OracleVerdict.NO_FINDING,
                confidence=ConfidenceLevel.CONFIRMED,
                reason=f"uploaded file fetch was denied with HTTP {status}",
            )
        if status not in set(cfg.success_statuses):
            return OracleResult(
                oracle_type=self.oracle_type,
                verdict=OracleVerdict.INCONCLUSIVE,
                confidence=ConfidenceLevel.SUSPECTED,
                reason=f"uploaded file fetch returned ambiguous HTTP {status}",
            )
        if cfg.marker in mutated.response.body:
            return OracleResult(
                oracle_type=self.oracle_type,
                verdict=OracleVerdict.FINDING,
                confidence=ConfidenceLevel.CONFIRMED,
                reason=(
                    "uploaded file is served back with its marker content "
                    f"(HTTP {status}); upload is stored and reachable"
                ),
            )
        return OracleResult(
            oracle_type=self.oracle_type,
            verdict=OracleVerdict.NO_FINDING,
            confidence=ConfidenceLevel.LIKELY,
            reason=(
                "uploaded file marker not present in the fetch response; "
                "no reachable/processed upload proven"
            ),
        )


class BusinessLogicOracle(Oracle):
    """Business-logic invariant oracle.

    ``baseline`` is the before-state and ``mutated`` the after-state. The
    oracle reads ``field`` from both and raises a finding when the observed
    change violates the declared :class:`BusinessLogicRelation` invariant.
    """

    oracle_type = OracleType.BUSINESS_LOGIC

    def evaluate(
        self,
        baseline: HttpExchange,
        mutated: HttpExchange,
        params: Mapping[str, object],
    ) -> OracleResult:
        cfg = BusinessLogicOracleParams.model_validate(dict(params))
        before = _read_path(_parse_json(baseline.response.body), cfg.field)
        after = _read_path(_parse_json(mutated.response.body), cfg.field)
        if before is None or after is None:
            return OracleResult(
                oracle_type=self.oracle_type,
                verdict=OracleVerdict.INCONCLUSIVE,
                confidence=ConfidenceLevel.SUSPECTED,
                reason=(
                    f"could not read {cfg.field!r} in both the before and after "
                    "states; invariant unchecked"
                ),
            )
        violated, detail = self._is_violated(cfg, before, after)
        if violated:
            return OracleResult(
                oracle_type=self.oracle_type,
                verdict=OracleVerdict.FINDING,
                confidence=ConfidenceLevel.CONFIRMED,
                reason=f"business-logic invariant violated: {detail}",
                differing_fields=[cfg.field],
            )
        return OracleResult(
            oracle_type=self.oracle_type,
            verdict=OracleVerdict.NO_FINDING,
            confidence=ConfidenceLevel.CONFIRMED,
            reason=f"business-logic invariant held: {detail}",
        )

    @staticmethod
    def _is_violated(
        cfg: BusinessLogicOracleParams, before: object, after: object
    ) -> tuple[bool, str]:
        relation = cfg.relation
        if relation is BusinessLogicRelation.EQUALS_EXPECTED:
            expected = cfg.expected
            matches = str(after) == str(expected)
            return (not matches, f"after={after!r} expected={expected!r}")
        if relation is BusinessLogicRelation.UNCHANGED:
            changed = str(before) != str(after)
            return (changed, f"before={before!r} after={after!r} (must be unchanged)")

        before_num = _to_number(before)
        after_num = _to_number(after)
        if before_num is None or after_num is None:
            # Non-numeric values cannot satisfy an ordering invariant
            # deterministically; treat as unchecked (not a finding).
            return (False, f"non-numeric before/after ({before!r}/{after!r}); ordering unchecked")
        if relation is BusinessLogicRelation.NON_DECREASING:
            return (after_num < before_num, f"before={before_num:g} after={after_num:g}")
        # NON_INCREASING
        return (after_num > before_num, f"before={before_num:g} after={after_num:g}")


_ORACLES: Final[dict[OracleType, Oracle]] = {
    OracleType.AUTHZ: AuthzOracle(),
    OracleType.AUTHN: AuthnOracle(),
    OracleType.RATE_LIMIT: RateLimitOracle(),
    OracleType.RACE: RaceOracle(),
    OracleType.FILE_UPLOAD: FileUploadOracle(),
    OracleType.BUSINESS_LOGIC: BusinessLogicOracle(),
}


def get_oracle(oracle_type: OracleType) -> Oracle:
    """Return the oracle registered for ``oracle_type``."""
    return _ORACLES[oracle_type]


__all__ = [
    "AuthnOracle",
    "AuthnOracleParams",
    "AuthzOracle",
    "AuthzOracleParams",
    "BusinessLogicOracle",
    "BusinessLogicOracleParams",
    "BusinessLogicRelation",
    "FileUploadOracle",
    "FileUploadOracleParams",
    "Oracle",
    "OracleNotImplemented",
    "OracleResult",
    "OracleVerdict",
    "RaceOracle",
    "RaceOracleParams",
    "RateLimitOracle",
    "RateLimitOracleParams",
    "get_oracle",
    "validate_params",
]
