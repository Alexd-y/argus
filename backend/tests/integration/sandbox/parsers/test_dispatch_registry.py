"""Integration test: parser dispatch registry routing (Backlog/dev1_md §4.4).

Exercises the real :mod:`src.sandbox.parsers` registry — no mocks for the
registry itself — and asserts the contractual behaviour documented in
``src.sandbox.parsers.__init__``:

* The default registry exposes ``ParseStrategy.JSON_LINES`` for ``httpx``.
* :func:`dispatch_parse` routes by ``ParseStrategy``, forwards the raw
  bytes / artifacts dir / tool_id, and returns the parser's findings.
* Unknown strategies fail-soft: structured WARNING log + ARG-020
  heartbeat finding so the orchestrator / UI can distinguish "tool ran
  but parser deferred" from "tool ran and found nothing".
* Unknown ``tool_id`` within a known strategy fail-soft the same way.
* :func:`register_parser` rejects double-registration unless ``override``
  is set, and the override is observable on the next dispatch.
* :func:`reset_registry` restores the default surface (test-only helper
  used for hermetic test ordering).

The :func:`reset_registry` autouse fixture isolates every test from
side-effects of preceding test cases.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path

import pytest

from src.pipeline.contracts.finding_dto import FindingCategory, FindingDTO
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import (
    HEARTBEAT_TAG_PREFIX,
    ParserHandler,
    dispatch_parse,
    get_registered_strategies,
    register_parser,
    reset_registry,
)
from src.sandbox.parsers._base import make_finding_dto
from src.sandbox.parsers.httpx_parser import EVIDENCE_SIDECAR_NAME


# ---------------------------------------------------------------------------
# Hermetic registry fixture
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_registry() -> Iterator[None]:
    """Snapshot + restore the registry around every test."""
    yield
    reset_registry()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _httpx_jsonl(*records: dict[str, object]) -> bytes:
    """Encode ``records`` as the kind of JSONL httpx emits."""
    return ("\n".join(json.dumps(r, sort_keys=True) for r in records)).encode("utf-8")


# ---------------------------------------------------------------------------
# Default registry surface
# ---------------------------------------------------------------------------


def test_default_registry_includes_json_lines() -> None:
    """JSON_LINES handler is registered out of the box (httpx routing)."""
    strategies = get_registered_strategies()
    assert ParseStrategy.JSON_LINES in strategies


def test_default_registry_does_not_register_unimplemented_strategies() -> None:
    """Strategies whose parsers have not landed yet must NOT be registered.

    Defence-in-depth: a stray default registration would silently swallow
    the structured ``parsers.dispatch.no_handler`` warning we rely on to
    track parser-coverage gaps between cycles.

    Note: ``NUCLEI_JSONL`` was added in ARG-015 (§4.8) and ``XML_NMAP``
    was added in ARG-019 (§4.2 back-port). The assertion list below
    tracks the strategies still pending implementation in later cycles.
    """
    strategies = get_registered_strategies()
    assert ParseStrategy.CSV not in strategies
    assert ParseStrategy.XML_GENERIC not in strategies


# ---------------------------------------------------------------------------
# Routing: happy path
# ---------------------------------------------------------------------------


def test_dispatch_routes_httpx_jsonl_to_httpx_parser(tmp_path: Path) -> None:
    """``dispatch_parse`` for httpx returns the same findings as the parser."""
    stdout = _httpx_jsonl(
        {"url": "https://a.example", "status_code": 200, "tech": ["Nginx"]},
        {"url": "https://b.example", "status_code": 301, "tech": ["Apache"]},
    )

    findings = dispatch_parse(
        ParseStrategy.JSON_LINES,
        stdout,
        b"",
        tmp_path,
        tool_id="httpx",
    )

    assert len(findings) == 2
    assert all(isinstance(f, FindingDTO) for f in findings)
    assert all(f.category is FindingCategory.INFO for f in findings)
    # Sidecar was written by the actual parser via dispatch.
    sidecar = tmp_path / EVIDENCE_SIDECAR_NAME
    assert sidecar.is_file()
    assert sidecar.read_text(encoding="utf-8").count("\n") == 2


# ---------------------------------------------------------------------------
# Fail-soft branches
# ---------------------------------------------------------------------------


def test_unknown_strategy_emits_heartbeat_with_structured_warning(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """An unregistered strategy must log + emit one heartbeat finding (ARG-020).

    Prior to ARG-020 this branch returned ``[]``; the cycle-2 capstone
    extends fail-soft to also yield a single :class:`FindingDTO` heartbeat
    so the orchestrator / UI can distinguish "tool ran, parser deferred"
    from "tool ran, found nothing".  The structured warning is unchanged.
    """
    # ``CSV`` is intentionally NOT registered yet — pinned by the prior
    # ``test_default_registry_does_not_register_unimplemented_strategies``.
    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = dispatch_parse(
            ParseStrategy.CSV,
            b"col1,col2\nfoo,bar\n",
            b"",
            tmp_path,
            tool_id="some_csv_tool",
        )

    assert len(findings) == 1
    heartbeat = findings[0]
    assert heartbeat.category is FindingCategory.INFO
    assert heartbeat.cvss_v3_score == 0.0
    assert HEARTBEAT_TAG_PREFIX in heartbeat.owasp_wstg
    assert "HEARTBEAT-some_csv_tool" in heartbeat.owasp_wstg
    assert "HEARTBEAT-STRATEGY-csv" in heartbeat.owasp_wstg
    assert any(
        "parsers.dispatch.no_handler" in record.getMessage()
        or getattr(record, "event", "") == "parsers_dispatch_no_handler"
        for record in caplog.records
    ), f"missing structured warning; got {[r.getMessage() for r in caplog.records]}"


def test_unknown_tool_within_known_strategy_emits_heartbeat(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """JSON_LINES handler routes ``httpx`` — others log + emit one heartbeat (ARG-020).

    The strategy is wired but the per-tool parser table doesn't know
    about ``some_future_jsonl_tool`` yet.  The fail-soft contract (since
    ARG-020) emits the existing ``parsers.dispatch.unmapped_tool`` warning
    AND a single heartbeat finding so operators see "tool ran but parser
    deferred" downstream.
    """
    stdout = _httpx_jsonl({"url": "https://x.example"})

    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = dispatch_parse(
            ParseStrategy.JSON_LINES,
            stdout,
            b"",
            tmp_path,
            tool_id="some_future_jsonl_tool",
        )

    assert len(findings) == 1
    heartbeat = findings[0]
    assert heartbeat.category is FindingCategory.INFO
    assert heartbeat.cvss_v3_score == 0.0
    assert HEARTBEAT_TAG_PREFIX in heartbeat.owasp_wstg
    assert "HEARTBEAT-some_future_jsonl_tool" in heartbeat.owasp_wstg
    assert "HEARTBEAT-STRATEGY-json_lines" in heartbeat.owasp_wstg
    assert any(
        "parsers.dispatch.unmapped_tool" in record.getMessage()
        or getattr(record, "event", "") == "parsers_dispatch_unmapped_tool"
        for record in caplog.records
    )


def test_handler_exception_is_swallowed_and_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """If a handler raises an unexpected error, dispatch returns ``[]``."""

    def _exploding_handler(
        stdout: bytes, stderr: bytes, artifacts_dir: Path, tool_id: str
    ) -> list[FindingDTO]:
        raise RuntimeError("synthetic explosion")

    register_parser(ParseStrategy.JSON_OBJECT, _exploding_handler, override=True)

    with caplog.at_level(logging.WARNING, logger="src.sandbox.parsers"):
        findings = dispatch_parse(
            ParseStrategy.JSON_OBJECT,
            b"{}",
            b"",
            tmp_path,
            tool_id="bogus",
        )

    assert findings == []
    # Either log key acceptable depending on rendering of `extra`.
    assert any(
        "parsers.dispatch.handler_unexpected_error" in record.getMessage()
        or getattr(record, "event", "") == "parsers_dispatch_handler_unexpected_error"
        for record in caplog.records
    )


# ---------------------------------------------------------------------------
# Override semantics
# ---------------------------------------------------------------------------


def test_double_registration_without_override_raises() -> None:
    """Re-registering an existing strategy must fail loudly by default."""

    def _noop_handler(
        stdout: bytes, stderr: bytes, artifacts_dir: Path, tool_id: str
    ) -> list[FindingDTO]:
        return []

    with pytest.raises(ValueError, match="already registered"):
        register_parser(ParseStrategy.JSON_LINES, _noop_handler)


def test_override_registration_replaces_handler(tmp_path: Path) -> None:
    """``override=True`` swaps the handler, observable on the next dispatch."""
    sentinel_finding = make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200],
        owasp_wstg=["WSTG-INFO-02"],
    )

    def _stub_handler(
        stdout: bytes, stderr: bytes, artifacts_dir: Path, tool_id: str
    ) -> list[FindingDTO]:
        return [sentinel_finding]

    register_parser(ParseStrategy.JSON_LINES, _stub_handler, override=True)

    findings = dispatch_parse(
        ParseStrategy.JSON_LINES,
        b'{"url": "ignored"}',
        b"",
        tmp_path,
        tool_id="httpx",
    )

    assert findings == [sentinel_finding]


def test_reset_registry_restores_default_handlers() -> None:
    """``reset_registry`` brings the registry back to the default surface.

    Default surface as of ARG-019:
    * ``JSON_LINES``   — routes httpx (and any future per-tool registration).
    * ``JSON_OBJECT``  — routes ffuf-family content-discovery scanners
      (ffuf_dir / ffuf_vhost / ffuf_param / feroxbuster / dirsearch),
      the §4.7 wpscan / droopescan parsers, and the §4.8 nikto / wapiti
      adapters.
    * ``NUCLEI_JSONL`` — routes the §4.7 + §4.8 nuclei callers
      (nuclei / nextjs_check / spring_boot_actuator / jenkins_enum)
      through ``parse_nuclei_jsonl``.
    * ``TEXT_LINES``   — sqlmap (ARG-016).
    * ``XML_NMAP``     — §4.2 nmap back-port (ARG-019): nmap_tcp_full /
      nmap_tcp_top / nmap_udp / nmap_version / nmap_vuln.

    The test registers a non-default strategy + overrides JSON_OBJECT, then
    calls :func:`reset_registry` and asserts the default surface is back
    in place exactly (no extras, no missing).
    """

    def _noop_handler(
        stdout: bytes, stderr: bytes, artifacts_dir: Path, tool_id: str
    ) -> list[FindingDTO]:
        return []

    # Override an existing default strategy + add a non-default one.
    register_parser(ParseStrategy.JSON_OBJECT, _noop_handler, override=True)
    register_parser(ParseStrategy.CSV, _noop_handler)
    assert ParseStrategy.CSV in get_registered_strategies()

    reset_registry()

    strategies = get_registered_strategies()
    assert strategies == frozenset(
        {
            ParseStrategy.JSON_LINES,
            ParseStrategy.JSON_OBJECT,
            ParseStrategy.NUCLEI_JSONL,
            ParseStrategy.TEXT_LINES,
            ParseStrategy.XML_NMAP,
        }
    )


# ---------------------------------------------------------------------------
# ARG-011 follow-up coverage — registry edge cases requested by the test plan.
# Appended (do not interleave with the worker's tests above so a future
# rebase / blame stays readable).
# ---------------------------------------------------------------------------


def test_double_override_keeps_last_writer_wins(tmp_path: Path) -> None:
    """Two consecutive ``override=True`` registrations: the last one wins.

    Defence-in-depth for the override semantics: a stale handler must not
    linger in the registry, and the most recent ``register_parser`` call
    is what the next ``dispatch_parse`` sees.
    """
    sentinel_first = make_finding_dto(
        category=FindingCategory.INFO, cwe=[200], owasp_wstg=["WSTG-INFO-02"]
    )
    sentinel_second = make_finding_dto(
        category=FindingCategory.INFO, cwe=[201], owasp_wstg=["WSTG-INFO-08"]
    )

    def _first(
        stdout: bytes, stderr: bytes, artifacts_dir: Path, tool_id: str
    ) -> list[FindingDTO]:
        return [sentinel_first]

    def _second(
        stdout: bytes, stderr: bytes, artifacts_dir: Path, tool_id: str
    ) -> list[FindingDTO]:
        return [sentinel_second]

    register_parser(ParseStrategy.XML_NMAP, _first, override=True)
    register_parser(ParseStrategy.XML_NMAP, _second, override=True)

    findings = dispatch_parse(
        ParseStrategy.XML_NMAP,
        b"",
        b"",
        tmp_path,
        tool_id="nmap_tcp_top",
    )
    assert findings == [sentinel_second]


def test_strategy_constructed_from_string_value_finds_handler(
    tmp_path: Path,
) -> None:
    """``ParseStrategy("json_lines")`` resolves to the same registered handler.

    YAML deserialisation goes through Pydantic, which constructs the enum
    via its value. The test pins the contract that round-tripping the
    enum through its string form does not break dispatch.
    """
    strategy_from_string = ParseStrategy("json_lines")
    assert strategy_from_string is ParseStrategy.JSON_LINES

    stdout = _httpx_jsonl({"url": "https://a.example", "status_code": 200})
    findings = dispatch_parse(
        strategy_from_string,
        stdout,
        b"",
        tmp_path,
        tool_id="httpx",
    )
    assert len(findings) == 1


def test_strategy_string_value_is_case_sensitive() -> None:
    """``ParseStrategy("JSON_LINES")`` must raise — values are lowercase only.

    Pins the case-sensitive contract so a future "be helpful, accept any
    case" patch cannot land silently. Mismatched casing in a YAML must be
    caught at descriptor parse-time, not at dispatch-time.
    """
    with pytest.raises(ValueError):
        ParseStrategy("JSON_LINES")


def test_concurrent_registration_smoke(tmp_path: Path) -> None:
    """Register every non-default strategy from worker threads in parallel.

    Worker design: ``_REGISTRY`` is a plain ``dict``. Single-key dict
    assignments are atomic under the CPython GIL, so concurrent
    ``register_parser`` calls on *distinct* strategies cannot corrupt the
    table. This is a smoke test, not a stress test — the goal is to catch
    any regression that adds a non-atomic read-modify-write to the
    registry path. Every registered handler tags its synthetic finding
    with the strategy value, so a key-level mix-up between threads would
    surface as a tag mismatch.
    """
    import threading

    targets = [s for s in ParseStrategy if s is not ParseStrategy.JSON_LINES]
    assert len(targets) >= 9, (
        f"expected at least 9 non-default strategies, got {len(targets)}"
    )

    def _make_handler(tag: str) -> ParserHandler:
        sentinel = make_finding_dto(
            category=FindingCategory.INFO,
            cwe=[200],
            owasp_wstg=[f"TAG-{tag[:24]}"],
        )

        def _handler(
            stdout: bytes, stderr: bytes, artifacts_dir: Path, tool_id: str
        ) -> list[FindingDTO]:
            del stdout, stderr, artifacts_dir, tool_id
            return [sentinel]

        return _handler

    barrier = threading.Barrier(len(targets))

    def _register(strategy: ParseStrategy) -> None:
        barrier.wait(timeout=5.0)
        register_parser(strategy, _make_handler(strategy.value), override=True)

    threads = [
        threading.Thread(target=_register, args=(s,), name=f"reg-{s.value}")
        for s in targets
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5.0)
        assert not thread.is_alive(), f"thread {thread.name} did not finish"

    registered = get_registered_strategies()
    for strategy in targets:
        assert strategy in registered, (
            f"{strategy.value} dropped from registry under concurrent registration"
        )
        findings = dispatch_parse(strategy, b"", b"", tmp_path, tool_id="probe")
        assert len(findings) == 1
        assert findings[0].owasp_wstg == [f"TAG-{strategy.value[:24]}"], (
            f"strategy {strategy.value!r} returned wrong tag — possible thread mix-up"
        )
