"""Unit tests for :mod:`src.payloads.mutations` (ARG-005, Backlog/dev1_md §7).

Mutation rules are pure and fully deterministic given ``(payload, seed)``;
the tests assert this contract end-to-end.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from src.payloads.mutations import (
    MUTATION_NAMES,
    MutationContext,
    MutationResult,
    UnknownMutationError,
    apply_mutations,
    get_mutation,
    mutate_case_flip,
    mutate_comment_injection,
    mutate_length_pad,
    mutate_unicode_homoglyph,
    mutate_whitespace_alt,
)


def _ctx(
    seed: int = 1, family_id: str = "demo", payload_index: int = 0
) -> MutationContext:
    return MutationContext(seed=seed, family_id=family_id, payload_index=payload_index)


@dataclass(frozen=True, slots=True)
class _Rule:
    """Minimal stand-in for :class:`src.payloads.registry.MutationRule`.

    Lets the tests exercise :func:`apply_mutations` without dragging in
    the full Pydantic registry model — both classes are structurally
    compatible via the :class:`MutationRuleSpec` Protocol.
    """

    name: str
    max_per_payload: int = 1


# ---------------------------------------------------------------------------
# Registry shape
# ---------------------------------------------------------------------------


def test_mutation_registry_contains_expected_rules() -> None:
    assert MUTATION_NAMES == frozenset(
        {
            "case_flip",
            "comment_injection",
            "whitespace_alt",
            "unicode_homoglyph",
            "length_pad",
        }
    )


def test_get_mutation_unknown_rule_raises_with_named_attr() -> None:
    with pytest.raises(UnknownMutationError) as exc_info:
        get_mutation("ghost")
    assert exc_info.value.name == "ghost"


# ---------------------------------------------------------------------------
# Determinism contract
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rule",
    [
        "case_flip",
        "comment_injection",
        "whitespace_alt",
        "unicode_homoglyph",
        "length_pad",
    ],
)
def test_mutation_is_deterministic_given_same_seed(rule: str) -> None:
    fn = get_mutation(rule)
    payload = "SELECT * FROM users WHERE id = 1"
    a = fn(payload, _ctx(seed=42))
    b = fn(payload, _ctx(seed=42))
    assert a == b


@pytest.mark.parametrize(
    "rule",
    ["case_flip", "whitespace_alt", "length_pad"],
)
def test_mutation_changes_with_different_seeds(rule: str) -> None:
    fn = get_mutation(rule)
    payload = "SELECT * FROM users WHERE id = 1"
    seen: set[str] = set()
    for seed in range(64):
        seen.add(fn(payload, _ctx(seed=seed)))
    # With 64 seeds we must observe more than one variant — otherwise the
    # mutation is a no-op or degenerate.
    assert len(seen) > 1


# ---------------------------------------------------------------------------
# Per-mutation behaviour
# ---------------------------------------------------------------------------


def test_case_flip_is_case_insensitive_to_input_under_lower() -> None:
    payload = "SELECT * FROM users"
    out = mutate_case_flip(payload, _ctx(seed=7))
    assert out.lower() == payload.lower()


def test_case_flip_preserves_non_alpha() -> None:
    payload = "id=1' OR 1=1--"
    out = mutate_case_flip(payload, _ctx(seed=0))
    # All non-letters survive verbatim.
    expected_non_alpha = "".join(ch for ch in payload if not ch.isalpha())
    actual_non_alpha = "".join(ch for ch in out if not ch.isalpha())
    assert actual_non_alpha == expected_non_alpha


def test_comment_injection_does_not_grow_more_than_factor_two() -> None:
    payload = "SELECT id FROM users WHERE 1=1"
    out = mutate_comment_injection(payload, _ctx(seed=3))
    assert len(out) <= len(payload) * 2


def test_comment_injection_only_replaces_whitespace_runs() -> None:
    payload = "SELECT id"
    out = mutate_comment_injection(payload, _ctx(seed=42))
    # Either unchanged or whitespace replaced by /**/.
    assert out in {"SELECT id", "SELECT/**/id"}


def test_comment_injection_returns_payload_when_no_whitespace() -> None:
    payload = "no_whitespace_here"
    assert mutate_comment_injection(payload, _ctx(seed=1)) == payload


def test_comment_injection_handles_empty_string() -> None:
    assert mutate_comment_injection("", _ctx(seed=1)) == ""


def test_whitespace_alt_only_swaps_runs_of_spaces() -> None:
    payload = "select  *  from"  # two spaces between words
    out = mutate_whitespace_alt(payload, _ctx(seed=12))
    # The non-space characters survive in order.
    assert (
        out.replace("\t", "").replace("+", "").replace(" ", "").lower() == "select*from"
    )


def test_whitespace_alt_handles_empty_string() -> None:
    assert mutate_whitespace_alt("", _ctx(seed=1)) == ""


def test_unicode_homoglyph_only_replaces_known_letters() -> None:
    payload = "select"  # has 'e', 'c'
    out = mutate_unicode_homoglyph(payload, _ctx(seed=99))
    assert len(out) == len(payload)
    # Result must be the ASCII payload OR contain at least one Cyrillic glyph.
    assert any(ord(ch) > 127 for ch in out) or out == payload


def test_unicode_homoglyph_preserves_case() -> None:
    payload = "Apex"  # 'A' upper + lower-case 'pex'
    out = mutate_unicode_homoglyph(payload, _ctx(seed=4))
    # 'A' is replaceable; if replaced, the output's first char is still uppercase.
    assert out[0].isupper()


def test_unicode_homoglyph_handles_empty_string() -> None:
    assert mutate_unicode_homoglyph("", _ctx(seed=1)) == ""


def test_length_pad_appends_marker_and_pad() -> None:
    payload = "select"
    out = mutate_length_pad(payload, _ctx(seed=1))
    assert out.startswith(payload)
    assert "-- " in out
    assert len(out) > len(payload)


# ---------------------------------------------------------------------------
# Pipeline composition
# ---------------------------------------------------------------------------


def test_apply_mutations_with_empty_list_is_pass_through() -> None:
    result = apply_mutations("anything", [], _ctx())
    assert isinstance(result, MutationResult)
    assert result.payload == "anything"
    assert result.transforms_applied == ()


def test_apply_mutations_chains_left_to_right_deterministically() -> None:
    payload = "SELECT id FROM users"
    rules = [_Rule("case_flip"), _Rule("whitespace_alt")]
    a = apply_mutations(payload, rules, _ctx(seed=7))
    b = apply_mutations(payload, rules, _ctx(seed=7))
    assert a.payload == b.payload
    assert a.transforms_applied == b.transforms_applied
    assert a.transforms_applied == ("case_flip[0]", "whitespace_alt[0]")


def test_apply_mutations_unknown_rule_raises_unknown_mutation_error() -> None:
    with pytest.raises(UnknownMutationError):
        apply_mutations("payload", [_Rule("case_flip"), _Rule("ghost")], _ctx())


# ---------------------------------------------------------------------------
# max_per_payload semantics — the rule's repeat-count is honoured by the
# pipeline (regression coverage for the original "dead metadata" defect).
# ---------------------------------------------------------------------------


def test_apply_mutations_default_max_per_payload_runs_once() -> None:
    result = apply_mutations(
        "select id from users",
        [_Rule("case_flip", max_per_payload=1)],
        _ctx(seed=11),
    )
    assert result.transforms_applied == ("case_flip[0]",)


def test_apply_mutations_max_per_payload_two_runs_twice() -> None:
    result = apply_mutations(
        "select id from users",
        [_Rule("case_flip", max_per_payload=2)],
        _ctx(seed=11),
    )
    assert result.transforms_applied == ("case_flip[0]", "case_flip[1]")


def test_apply_mutations_max_per_payload_three_runs_three_times() -> None:
    result = apply_mutations(
        "select id from users",
        [_Rule("case_flip", max_per_payload=3)],
        _ctx(seed=11),
    )
    assert result.transforms_applied == (
        "case_flip[0]",
        "case_flip[1]",
        "case_flip[2]",
    )


def test_apply_mutations_repetitions_use_distinct_seeds() -> None:
    """Each repetition XORs ``rep_index`` into the seed → distinct sub-mutations."""
    payload = "SELECT id FROM users WHERE 1=1"
    one = apply_mutations(
        payload,
        [_Rule("case_flip", max_per_payload=1)],
        _ctx(seed=42),
    )
    three = apply_mutations(
        payload,
        [_Rule("case_flip", max_per_payload=3)],
        _ctx(seed=42),
    )
    # 1 vs 3 reps must produce different final strings — otherwise the
    # extra reps were no-ops and max_per_payload would be dead metadata.
    assert one.payload != three.payload
    # The case_flip mutator only flips letter case, so the lowered form
    # is invariant across any number of repetitions.
    assert one.payload.lower() == three.payload.lower() == payload.lower()


def test_apply_mutations_repetitions_remain_deterministic() -> None:
    rules = [_Rule("case_flip", max_per_payload=3)]
    a = apply_mutations("Select id from users", rules, _ctx(seed=5))
    b = apply_mutations("Select id from users", rules, _ctx(seed=5))
    assert a == b


def test_apply_mutations_chains_repetitions_across_multiple_rules() -> None:
    rules = [
        _Rule("case_flip", max_per_payload=2),
        _Rule("whitespace_alt", max_per_payload=3),
    ]
    result = apply_mutations("select id from users where 1=1", rules, _ctx(seed=99))
    assert result.transforms_applied == (
        "case_flip[0]",
        "case_flip[1]",
        "whitespace_alt[0]",
        "whitespace_alt[1]",
        "whitespace_alt[2]",
    )


def test_apply_mutations_accepts_pydantic_mutation_rule() -> None:
    """The real :class:`MutationRule` model satisfies :class:`MutationRuleSpec`."""
    from src.payloads.registry import MutationRule

    rule = MutationRule(name="case_flip", max_per_payload=2, description="")
    result = apply_mutations("Hello World", [rule], _ctx(seed=1))
    assert result.transforms_applied == ("case_flip[0]", "case_flip[1]")
    assert result.payload.lower() == "hello world"
