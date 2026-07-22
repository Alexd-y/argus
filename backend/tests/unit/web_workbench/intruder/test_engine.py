"""Unit tests for the Intruder request generator (positions + strategy + processors)."""

from __future__ import annotations

from src.web_workbench.intruder.engine import generate_requests, planned_total
from src.web_workbench.intruder.positions import parse_template
from src.web_workbench.intruder.processors import Processor
from src.web_workbench.intruder.strategies import Strategy


def test_generate_sniper_renders_byte_exact_requests() -> None:
    template = parse_template(b"GET /?a={{1}}&b={{2}} HTTP/1.1\r\n\r\n")
    reqs = list(generate_requests(template, Strategy.SNIPER, [[b"x", b"y"]]))
    assert [r.index for r in reqs] == [0, 1, 2, 3]
    # First request fuzzes position 0 → "x", position 1 keeps base "2".
    assert reqs[0].raw == b"GET /?a=x&b=2 HTTP/1.1\r\n\r\n"
    # Third request fuzzes position 1 → "x", position 0 keeps base "1".
    assert reqs[2].raw == b"GET /?a=1&b=x HTTP/1.1\r\n\r\n"


def test_generate_applies_processors_to_payloads_only() -> None:
    template = parse_template(b"a={{seed}}&b={{keep}}")
    reqs = list(
        generate_requests(
            template,
            Strategy.SNIPER,
            [[b"P"]],
            processors=[Processor("prefix", {"value": "!"})],
        )
    )
    # Injected payload prefixed; the base value of the other position untouched.
    assert reqs[0].raw == b"a=!P&b=keep"
    assert reqs[1].raw == b"a=seed&b=!P"


def test_generate_cluster_bomb_count_matches_planned() -> None:
    template = parse_template(b"a={{x}}&b={{y}}")
    sets = [[b"1", b"2", b"3"], [b"a", b"b"]]
    reqs = list(generate_requests(template, Strategy.CLUSTER_BOMB, sets))
    assert len(reqs) == planned_total(template, Strategy.CLUSTER_BOMB, sets) == 6
