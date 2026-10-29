"""commix stdout parser must recognize commix's real verdict grammar.

Regression: _COMMIX_EVIDENCE_RE only matched colon "Parameter:/Payload:" summary
forms or "command injection" AFTER the parameter, so it extracted NOTHING from
the lines commix actually prints (parameter precedes the injectability clause),
and commix command-injection candidates were silently lost on every run.
"""

from __future__ import annotations

from src.recon.vulnerability_analysis.active_scan.commix_va_adapter import (
    normalize_commix_findings,
    parse_commix_stdout,
)

_TARGET = "http://lab.example/ping"


def test_real_commix_confirmations_parse_to_findings() -> None:
    stdout = (
        "[*] Setting up commix...\n"
        "[+] The (GET) 'addr' parameter is vulnerable to (results-based) command injection "
        "technique.\n"
        "[+] The ('user') POST parameter appears to be injectable via (time-based) command "
        "injection technique.\n"
    )
    rows = parse_commix_stdout(stdout)
    assert len(rows) == 2
    findings = normalize_commix_findings(rows, target_url=_TARGET)
    assert len(findings) == 2
    assert all(f["data"]["type"] == "COMMAND_INJECTION_CANDIDATE" for f in findings)


def test_short_injectable_verdict_parses() -> None:
    assert len(parse_commix_stdout("[+] Parameter id is injectable.\n")) == 1


def test_negative_commix_verdict_is_ignored() -> None:
    neg = (
        "[*] Testing...\n"
        "[-] The (GET) 'addr' parameter is not injectable.\n"
        "[x] does not appear to be injectable.\n"
    )
    assert parse_commix_stdout(neg) == []


def test_banner_lines_do_not_parse() -> None:
    banner = (
        "    Commix (@commixproject)\n"
        "    by Anastasios Stasinopoulos\n"
        "    https://commixproject.com\n"
    )
    assert parse_commix_stdout(banner) == []
