"""Intruder request generation — ties positions + strategy + processors (WB-P4a).

:func:`generate_requests` is the pure core of the Intruder: given a parsed
template, a strategy and payload set(s), it yields each concrete request byte
string (byte-exact outside insertion points) together with the payload
assignment used, so a runner can send them (gated + persisted in WB-P4b) and
correlate responses.

No I/O, no persistence, no payload sourcing here — payload sets are supplied by
the caller, which MUST materialise them through the signed PayloadRegistry /
:class:`~src.payloads.builder.PayloadBuilder` (SI-5). High-volume execution,
scope/EAP gating, pause/resume and evidence bridging are the stateful WB-P4b
concern layered on top of this deterministic generator.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass

from src.web_workbench.intruder.positions import ParsedTemplate
from src.web_workbench.intruder.processors import Processor, apply_processors
from src.web_workbench.intruder.strategies import (
    PayloadSet,
    Strategy,
    iter_assignments,
    total_requests,
)


@dataclass(frozen=True)
class IntruderRequest:
    """One generated attack request."""

    index: int
    assignment: tuple[bytes, ...]
    raw: bytes


def generate_requests(
    template: ParsedTemplate,
    strategy: Strategy,
    payload_sets: Sequence[PayloadSet],
    *,
    processors: Sequence[Processor] = (),
) -> Iterator[IntruderRequest]:
    """Yield each concrete request for the attack, in deterministic order.

    ``processors`` are applied to every injected payload (never to base values),
    preserving byte-fidelity of the non-fuzzed request bytes.
    """

    def _process(payload: bytes) -> bytes:
        return apply_processors(payload, processors)

    assignments = iter_assignments(
        strategy,
        template.position_count,
        template.base_values,
        payload_sets,
        process=_process,
    )
    for index, assignment in enumerate(assignments):
        yield IntruderRequest(
            index=index,
            assignment=assignment,
            raw=template.render(assignment),
        )


def planned_total(
    template: ParsedTemplate, strategy: Strategy, payload_sets: Sequence[PayloadSet]
) -> int:
    """Total request count the attack will generate (for budgeting / progress)."""
    return total_requests(strategy, template.position_count, payload_sets)


__all__ = [
    "IntruderRequest",
    "generate_requests",
    "planned_total",
]
