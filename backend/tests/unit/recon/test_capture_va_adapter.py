"""Wave 2a (etap 6, live) — the VA tcpdump argv is scoped, headers-only, fail-closed."""

from __future__ import annotations

from src.recon.vulnerability_analysis.active_scan.capture_va_adapter import build_tcpdump_va_argv

_OUT = "/home/argus/cap.pcap"
_BPF = "host 10.0.0.5 and (port 80 or port 443)"


def test_argv_is_scoped_and_headers_only() -> None:
    argv = build_tcpdump_va_argv(outfile=_OUT, bpf=_BPF)
    assert argv, "a scoped capture must build an argv"
    assert argv[0] == "tcpdump"
    # Headers-only snaplen → payloads excluded (no credential leak).
    assert "-s" in argv and "96" in argv
    # The scope filter is the trailing expression; a neighbour host is not in it.
    assert argv[-1] == _BPF
    assert "10.0.0.6" not in " ".join(argv)


def test_argv_fail_closed_without_scope() -> None:
    # No BPF → refuse to build (no broad, unscoped capture).
    assert build_tcpdump_va_argv(outfile=_OUT, bpf="") == []
    assert build_tcpdump_va_argv(outfile=_OUT) == []


def test_argv_rejects_out_of_tree_outfile() -> None:
    assert build_tcpdump_va_argv(outfile="/etc/evil.pcap", bpf=_BPF) == []
