"""Mutation rules for ARGUS payload bundles (Backlog/dev1_md §7).

Mutations rewrite the *content* of a seed payload before the encoder
pipeline runs. Every mutation is:

* **Pure** — no I/O, no module-level state, no clock reads.
* **Deterministic given (payload, seed)** — the
  :class:`~src.payloads.builder.PayloadBuilder` derives the seed from a
  stable correlation key so identical requests reproduce identical
  payload bundles. This is critical for the "evidence-by-hash" guarantee
  the orchestrator gives the validator step.
* **Conservative** — mutations must not increase risk class. They may
  rewrite case, insert SQL/HTML comments, swap whitespace runs, or
  substitute homoglyphs; they must never inject new commands, new shell
  metacharacters, or new payload bodies.

Rule names live in :data:`MUTATION_NAMES` and are referenced by the
``MutationRule.name`` field of every payload-family YAML. Unknown rule
names raise :class:`UnknownMutationError`; the registry rejects such
descriptors at startup so this should never fire in production.
"""

from __future__ import annotations

import random
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable


class UnknownMutationError(KeyError):
    """Raised when a payload-family YAML references a missing mutation rule."""

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


@dataclass(frozen=True, slots=True)
class MutationContext:
    """Per-payload mutation context passed to every rule.

    ``seed`` is consumed by :class:`random.Random` so callers can obtain a
    deterministic per-payload PRNG without relying on mutable global state.
    The :class:`~src.payloads.builder.PayloadBuilder` builds it from a
    stable correlation key (``scan_id`` + ``family_id`` + payload index).
    """

    seed: int
    family_id: str
    payload_index: int


@runtime_checkable
class MutationRuleSpec(Protocol):
    """Structural contract for entries accepted by :func:`apply_mutations`.

    Defined here (not in :mod:`src.payloads.registry`) so the mutations
    module stays free of cycle-creating imports. Anything exposing the
    two read-only attributes — most notably
    :class:`src.payloads.registry.MutationRule` — satisfies it.
    """

    @property
    def name(self) -> str: ...

    @property
    def max_per_payload(self) -> int: ...


@dataclass(frozen=True, slots=True)
class MutationResult:
    """Output of :func:`apply_mutations` — mutated payload + transcript.

    ``payload`` is the final string after every rule has run for its
    declared ``max_per_payload`` count. ``transforms_applied`` is the
    ordered list of ``"<rule_name>[<rep_index>]"`` strings, one entry
    per repetition, so callers (and tests) can assert that the
    declared mutation depth was actually exercised.
    """

    payload: str
    transforms_applied: tuple[str, ...]


_MutationFn = Callable[[str, MutationContext], str]


# ---------------------------------------------------------------------------
# Pure mutation functions
# ---------------------------------------------------------------------------


def mutate_case_flip(payload: str, ctx: MutationContext) -> str:
    """Randomly upper/lowercase ASCII letters using a per-payload PRNG.

    Useful against case-sensitive substring filters (``UNION`` vs ``UnIoN``).
    Non-ASCII characters are returned unchanged.
    """
    rng = random.Random(ctx.seed)
    out_chars: list[str] = []
    for ch in payload:
        if ch.isascii() and ch.isalpha():
            out_chars.append(ch.upper() if rng.random() < 0.5 else ch.lower())
        else:
            out_chars.append(ch)
    return "".join(out_chars)


def mutate_comment_injection(payload: str, ctx: MutationContext) -> str:
    """Insert SQL-style inline comments between a few neighbouring tokens.

    Splits on whitespace and, for each gap, deterministically chooses
    whether to leave the gap alone or replace it with ``/**/``. The total
    payload length stays bounded (no expansion above ``len(payload) * 2``).
    """
    if not payload:
        return payload
    rng = random.Random(ctx.seed ^ 0x9E37_79B9)
    tokens = re.split(r"(\s+)", payload)
    if len(tokens) <= 1:
        return payload
    out: list[str] = []
    for token in tokens:
        if token.strip():
            out.append(token)
        elif rng.random() < 0.5:
            out.append("/**/")
        else:
            out.append(token)
    rendered = "".join(out)
    return rendered if len(rendered) <= len(payload) * 2 else payload


def mutate_whitespace_alt(payload: str, ctx: MutationContext) -> str:
    """Replace runs of ASCII spaces with alternative whitespace tokens.

    The substitution alphabet is ``[\\t, +, %20]`` (the latter literal,
    since percent-encoding is the encoder layer's job). The PRNG picks one
    replacement per match deterministically.
    """
    if not payload:
        return payload
    rng = random.Random(ctx.seed ^ 0xDEADBEEF)
    alphabet = ("\t", "+", " ")

    def _swap(_match: re.Match[str]) -> str:
        return rng.choice(alphabet)

    return re.sub(r" +", _swap, payload)


_HOMOGLYPHS: Final[Mapping[str, str]] = {
    "a": "\u0430",  # CYRILLIC SMALL LETTER A
    "e": "\u0435",  # CYRILLIC SMALL LETTER IE
    "o": "\u043e",  # CYRILLIC SMALL LETTER O
    "p": "\u0440",  # CYRILLIC SMALL LETTER ER
    "c": "\u0441",  # CYRILLIC SMALL LETTER ES
    "x": "\u0445",  # CYRILLIC SMALL LETTER HA
}


def mutate_unicode_homoglyph(payload: str, ctx: MutationContext) -> str:
    """Substitute selected ASCII letters with visually-identical Cyrillic glyphs.

    Each candidate letter is independently swapped with probability 0.5 using
    the per-payload PRNG. Only a tiny mapping is used to avoid breaking the
    payload's semantic intent.
    """
    if not payload:
        return payload
    rng = random.Random(ctx.seed ^ 0xCAFEBABE)
    out_chars: list[str] = []
    for ch in payload:
        replacement = _HOMOGLYPHS.get(ch.lower())
        if replacement and rng.random() < 0.5:
            out_chars.append(replacement.upper() if ch.isupper() else replacement)
        else:
            out_chars.append(ch)
    return "".join(out_chars)


def mutate_length_pad(payload: str, ctx: MutationContext) -> str:
    """Append a deterministic, payload-neutral whitespace pad (``length_variation``).

    The pad is at most 32 spaces and is rendered after a SQL line-comment
    marker so even SQL targets ignore it. Encoder layers may strip it; the
    point is to vary the payload's serialised length to confuse hash-based
    blocklists.
    """
    rng = random.Random(ctx.seed ^ 0x12345678)
    pad_len = rng.randint(1, 32)
    return f"{payload}-- {' ' * pad_len}"


_MUTATIONS: Final[Mapping[str, _MutationFn]] = {
    "case_flip": mutate_case_flip,
    "comment_injection": mutate_comment_injection,
    "whitespace_alt": mutate_whitespace_alt,
    "unicode_homoglyph": mutate_unicode_homoglyph,
    "length_pad": mutate_length_pad,
}


MUTATION_NAMES: Final[frozenset[str]] = frozenset(_MUTATIONS.keys())
"""Public set of all mutation rule names that may appear in YAMLs."""


def get_mutation(name: str) -> _MutationFn:
    """Return the mutation function for ``name`` or raise :class:`UnknownMutationError`."""
    try:
        return _MUTATIONS[name]
    except KeyError as exc:
        raise UnknownMutationError(name) from exc


def apply_mutations(
    payload: str,
    rules: Sequence[MutationRuleSpec],
    ctx: MutationContext,
) -> MutationResult:
    """Chain mutation ``rules`` left-to-right, applying each ``max_per_payload`` times.

    For every rule, the mutator is invoked ``rule.max_per_payload`` times
    on the running payload. Each repetition uses a per-iteration seed
    derived as ``ctx.seed ^ rep_index`` so the output is deterministic
    given the input but distinct between repetitions of the same rule
    (the first repetition uses the original ``ctx.seed`` since
    ``seed ^ 0 == seed``, preserving backward-compatible behaviour for
    families that keep the default ``max_per_payload=1``).

    Empty ``rules`` returns ``payload`` unchanged with an empty transcript.

    The :attr:`MutationResult.transforms_applied` tuple records one entry
    per repetition formatted as ``"<rule_name>[<rep_index>]"``.
    """
    out = payload
    transforms: list[str] = []
    for rule in rules:
        mutator = get_mutation(rule.name)
        for rep in range(rule.max_per_payload):
            iter_ctx = MutationContext(
                seed=ctx.seed ^ rep,
                family_id=ctx.family_id,
                payload_index=ctx.payload_index,
            )
            out = mutator(out, iter_ctx)
            transforms.append(f"{rule.name}[{rep}]")
    return MutationResult(payload=out, transforms_applied=tuple(transforms))


__all__ = [
    "MUTATION_NAMES",
    "MutationContext",
    "MutationResult",
    "MutationRuleSpec",
    "UnknownMutationError",
    "apply_mutations",
    "get_mutation",
    "mutate_case_flip",
    "mutate_comment_injection",
    "mutate_length_pad",
    "mutate_unicode_homoglyph",
    "mutate_whitespace_alt",
]
