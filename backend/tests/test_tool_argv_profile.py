"""Aggressive argv merge from tool_configs.json."""

from __future__ import annotations

from src.recon.vulnerability_analysis.active_scan.tool_argv_profile import (
    resolve_tool_argv_profile,
)


def test_resolve_dalfox_aggressive_off_unchanged() -> None:
    base = ["dalfox", "url", "https://ex.test/a?x=1"]
    assert resolve_tool_argv_profile(
        "dalfox",
        base,
        False,
        target_url="https://ex.test/a?x=1",
        fuzz_url="",
        use_sandbox=False,
    ) == base


def test_resolve_dalfox_aggressive_appends_custom_payload() -> None:
    base = ["dalfox", "url", "https://ex.test/a?x=1"]
    out = resolve_tool_argv_profile(
        "dalfox",
        base,
        True,
        target_url="https://ex.test/a?x=1",
        fuzz_url="",
        use_sandbox=False,
    )
    assert out[:3] == base
    assert "--custom-payload" in out
    assert any("/app/data/payloads/xss_custom.txt" in x for x in out)


def test_resolve_ffuf_replaces_wordlist_when_aggressive() -> None:
    base = [
        "ffuf",
        "-u",
        "https://ex.test/?a=FUZZ",
        "-w",
        "/old/wordlist.txt",
        "-t",
        "2",
        "-rate",
        "5",
    ]
    out = resolve_tool_argv_profile(
        "ffuf",
        base,
        True,
        target_url="https://ex.test/?a=1",
        fuzz_url="https://ex.test/?a=FUZZ",
        use_sandbox=True,
    )
    assert "/opt/argus-payloads/xss_custom.txt" in out
    i = out.index("-t")
    assert out[i + 1] == "3"
