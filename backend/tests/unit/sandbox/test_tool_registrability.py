"""Tool registrability gate (R9)."""

from __future__ import annotations

from dataclasses import dataclass

from src.sandbox.tool_registrability import (
    REASON_DESCRIPTOR_MISSING,
    REASON_EXECUTABLE_MISSING,
    REASON_PARSER_UNAVAILABLE,
    REASON_PROFILE_CAPABILITY_DENIED,
    evaluate_tool_registrability,
    load_known_executables,
    registrable_tool_ids,
    should_register_mcp_tool,
)


@dataclass
class FakeDescriptor:
    tool_id: str
    command_template: list[str]
    risk_level: str = "low"
    requires_approval: bool = False


PARSERS = frozenset({"nuclei", "ffuf", "sqlmap"})
EXECUTABLES = frozenset({"nuclei", "ffuf", "sqlmap"})


def test_fully_wired_tool_is_registrable():
    d = FakeDescriptor("nuclei", ["nuclei", "-u", "{target}"])
    r = evaluate_tool_registrability(d, parser_tool_ids=PARSERS, known_executables=EXECUTABLES)
    assert r.registrable is True
    assert r.reasons == ()


def test_missing_descriptor():
    r = evaluate_tool_registrability(None, parser_tool_ids=PARSERS)
    assert not r.registrable
    assert r.reason == REASON_DESCRIPTOR_MISSING


def test_missing_parser_blocks_registration():
    d = FakeDescriptor("skipfish", ["skipfish"])
    r = evaluate_tool_registrability(d, parser_tool_ids=PARSERS, known_executables=frozenset({"skipfish"}))
    assert not r.registrable
    assert REASON_PARSER_UNAVAILABLE in r.reasons


def test_missing_executable_blocks_registration():
    d = FakeDescriptor("nuclei", ["nuclei"])
    r = evaluate_tool_registrability(d, parser_tool_ids=PARSERS, known_executables=frozenset())
    assert not r.registrable
    assert REASON_EXECUTABLE_MISSING in r.reasons


def test_empty_command_template_is_executable_missing():
    d = FakeDescriptor("weird", [])
    r = evaluate_tool_registrability(d, parser_tool_ids=frozenset({"weird"}), known_executables=None)
    assert not r.registrable
    assert REASON_EXECUTABLE_MISSING in r.reasons


def test_profile_risk_ceiling_denies_destructive_for_quick():
    d = FakeDescriptor("sqlmap", ["sqlmap"], risk_level="destructive")
    r = evaluate_tool_registrability(
        d, parser_tool_ids=PARSERS, known_executables=EXECUTABLES, payload_risk_ceiling="low"
    )
    assert not r.registrable
    assert REASON_PROFILE_CAPABILITY_DENIED in r.reasons


def test_profile_risk_ceiling_allows_destructive_for_deep():
    d = FakeDescriptor("sqlmap", ["sqlmap"], risk_level="destructive")
    r = evaluate_tool_registrability(
        d, parser_tool_ids=PARSERS, known_executables=EXECUTABLES, payload_risk_ceiling="high"
    )
    assert r.registrable is True


def test_registrable_tool_ids_filters():
    descriptors = [
        FakeDescriptor("nuclei", ["nuclei"], risk_level="low"),
        FakeDescriptor("skipfish", ["skipfish"], risk_level="low"),  # no parser
        FakeDescriptor("sqlmap", ["sqlmap"], risk_level="destructive"),  # denied for light
    ]
    allowed = registrable_tool_ids(
        descriptors,
        parser_tool_ids=PARSERS,
        known_executables=frozenset({"nuclei", "skipfish", "sqlmap"}),
        payload_risk_ceiling="medium",
    )
    assert allowed == frozenset({"nuclei"})


def test_should_register_mcp_tool_gate():
    good = FakeDescriptor("ffuf", ["ffuf"])
    bad = FakeDescriptor("skipfish", ["skipfish"])
    assert should_register_mcp_tool(good, parser_tool_ids=PARSERS, known_executables=EXECUTABLES)
    assert not should_register_mcp_tool(bad, parser_tool_ids=PARSERS, known_executables=EXECUTABLES)


def test_load_known_executables_reads_manifest():
    # Reads the real infra manifest; must be non-empty and contain common tools.
    execs = load_known_executables()
    assert isinstance(execs, frozenset)
    # The repo ships expected_executables.json with 88 executables.
    assert len(execs) > 0
