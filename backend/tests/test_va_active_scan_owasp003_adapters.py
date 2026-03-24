"""VA active-scan adapters OWASP2-003: nuclei, gobuster, wfuzz, commix argv + parse."""

from __future__ import annotations

from pathlib import Path

from src.recon.vulnerability_analysis.active_scan.commix_va_adapter import (
    build_commix_va_argv,
    normalize_commix_findings,
    parse_commix_stdout,
)
from src.recon.vulnerability_analysis.active_scan.gobuster_va_adapter import (
    build_gobuster_va_argv,
    normalize_gobuster_findings,
    parse_gobuster_stdout,
)
from src.recon.vulnerability_analysis.active_scan.nuclei_va_adapter import (
    build_nuclei_va_argv,
    normalize_nuclei_findings,
    parse_nuclei_stdout,
)
from src.recon.vulnerability_analysis.active_scan.wfuzz_va_adapter import (
    build_wfuzz_va_argv,
    normalize_wfuzz_findings,
    parse_wfuzz_stdout,
)


def test_build_nuclei_argv_valid() -> None:
    u = "https://example.com/page?x=1"
    argv = build_nuclei_va_argv(u)
    assert argv[:3] == ["nuclei", "-u", u]
    assert "-jsonl" in argv
    assert "-duc" in argv
    assert "-ni" in argv


def test_build_nuclei_argv_rejects_unsafe() -> None:
    assert build_nuclei_va_argv("") == []
    assert build_nuclei_va_argv("ftp://x/") == []


def test_nuclei_parse_normalize() -> None:
    line = (
        '{"template-id":"xss-reflected","info":{"name":"X","severity":"high"},'
        '"matched-at":"https://example.com/q?q=1"}'
    )
    raw = parse_nuclei_stdout(line + "\n")
    assert len(raw) == 1
    norm = normalize_nuclei_findings(raw)
    assert len(norm) == 1
    assert norm[0]["source_tool"] == "nuclei"
    assert norm[0]["data"]["template_id"] == "xss-reflected"


def test_build_gobuster_argv_requires_wordlist(tmp_path: Path) -> None:
    wl = tmp_path / "wl.txt"
    wl.write_text("a\n", encoding="utf-8")
    argv = build_gobuster_va_argv("https://example.com/", wordlist_path=str(wl))
    assert argv[:4] == ["gobuster", "dir", "-u", "https://example.com/"]
    assert "-w" in argv
    assert argv[argv.index("-w") + 1] == str(wl)


def test_gobuster_parse_text_and_normalize() -> None:
    raw_out = "/admin                (Status: 301) [Size: 0]\n"
    rows = parse_gobuster_stdout(raw_out)
    assert len(rows) == 1
    assert rows[0]["path"] == "/admin"
    assert rows[0]["status"] == 301
    merged = normalize_gobuster_findings(rows, base_url="https://example.com/")
    assert merged[0]["source_tool"] == "gobuster"
    assert merged[0]["data"]["path"] == "/admin"


def test_gobuster_parse_json_results_wrapper() -> None:
    blob = '{"results":[{"input":{"Destination":"/api"},"Status":200,"Length":10}]}'
    rows = parse_gobuster_stdout(blob)
    assert len(rows) == 1
    merged = normalize_gobuster_findings(rows, base_url="https://example.com/")
    assert merged and merged[0]["data"]["status_code"] == 200


def test_build_wfuzz_argv(tmp_path: Path) -> None:
    wl = tmp_path / "wl.txt"
    wl.write_text("x\n", encoding="utf-8")
    argv = build_wfuzz_va_argv("https://example.com/?a=1", wordlist_path=str(wl))
    assert argv[0] == "wfuzz"
    assert "-u" in argv
    u_val = argv[argv.index("-u") + 1]
    assert "FUZZ" in u_val


def test_wfuzz_parse_console_line() -> None:
    line = '000000001:  C=200      9 L       28 W      341 Ch    "admin"\n'
    rows = parse_wfuzz_stdout(line)
    assert rows and rows[0]["status"] == 200
    norm = normalize_wfuzz_findings(rows, target_url="https://example.com/FUZZ")
    assert norm[0]["source_tool"] == "wfuzz"


def test_commix_argv_and_parse() -> None:
    argv = build_commix_va_argv("https://example.com/c", None)
    assert argv[:2] == ["commix", "--url"]
    assert "https://example.com/c" in argv
    rows = parse_commix_stdout("[+] Parameter id is injectable.\n")
    assert rows
    norm = normalize_commix_findings(rows, target_url="https://example.com/c")
    assert norm[0]["data"]["type"] == "COMMAND_INJECTION_CANDIDATE"
