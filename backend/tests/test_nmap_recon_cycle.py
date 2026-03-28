"""KAL-003 — nmap recon cycle parser and sandbox gating."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from src.core.config import settings
from src.recon.nmap_recon_cycle import (
    merge_open_ports,
    parse_nmap_xml_stdout,
    run_nmap_recon_for_recon,
    target_looks_like_cidr,
)

_SAMPLE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="closed"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_target_looks_like_cidr() -> None:
    assert target_looks_like_cidr("10.0.0.0/24") is True
    assert target_looks_like_cidr("example.com") is False


def test_parse_nmap_xml_stdout_extracts_open_ports() -> None:
    parsed = parse_nmap_xml_stdout(_SAMPLE_XML)
    assert len(parsed["hosts"]) == 1
    ports = parsed["hosts"][0]["ports"]
    assert len(ports) == 1
    assert ports[0]["portid"] == "80"
    tcp, udp = merge_open_ports(parsed)
    assert tcp == {"80"}
    assert not udp


@pytest.mark.asyncio
async def test_legacy_path_when_sandbox_disabled() -> None:
    called: list[tuple[str, bool]] = []

    def fake_exec(cmd: str, use_cache: bool = True, use_sandbox: bool = False, timeout_sec: int | None = None):
        called.append((cmd, use_sandbox))
        return {"success": True, "stdout": "ok", "stderr": "", "return_code": 0, "execution_time": 0.1}

    with patch.object(settings, "sandbox_enabled", False):
        out = await run_nmap_recon_for_recon(
            "example.com",
            ports_option="1-1000",
            scan_options={},
            raw_sink=None,
            execute_command=fake_exec,
        )
    assert out["structured"]["mode"] == "legacy"
    assert len(called) == 1
    assert called[0][1] is False
    assert "-sV" in called[0][0] and "-p" in called[0][0]


@pytest.mark.asyncio
async def test_sandbox_cycle_runs_tcp_and_nse() -> None:
    calls: list[str] = []

    def fake_exec(cmd: str, use_cache: bool = True, use_sandbox: bool = False, timeout_sec: int | None = None):
        calls.append(cmd)
        return {
            "success": True,
            "stdout": _SAMPLE_XML,
            "stderr": "",
            "return_code": 0,
            "execution_time": 0.5,
        }

    with (
        patch.object(settings, "sandbox_enabled", True),
        patch.object(settings, "nmap_recon_cycle", True),
        patch.object(settings, "nmap_recon_phase_timeout_sec", 120),
    ):
        out = await run_nmap_recon_for_recon(
            "example.com",
            ports_option="1-1000",
            scan_options={},
            raw_sink=None,
            execute_command=fake_exec,
        )
    assert out["structured"]["mode"] == "sandbox_cycle"
    assert any("-sS" in c and "--top-ports" in c for c in calls)
    assert any("default and safe" in c and "-p" in c for c in calls)
    assert all("docker" not in c for c in calls)
    assert out["structured"]["open_tcp_ports"] == ["80"]


@pytest.mark.asyncio
async def test_cidr_includes_sn_phase() -> None:
    calls: list[str] = []

    def fake_exec(cmd: str, use_cache: bool = True, use_sandbox: bool = False, timeout_sec: int | None = None):
        calls.append(cmd)
        return {"success": True, "stdout": _SAMPLE_XML, "stderr": "", "return_code": 0, "execution_time": 0.1}

    with (
        patch.object(settings, "sandbox_enabled", True),
        patch.object(settings, "nmap_recon_cycle", True),
    ):
        await run_nmap_recon_for_recon(
            "10.0.0.0/24",
            ports_option="1-1000",
            scan_options={},
            raw_sink=None,
            execute_command=fake_exec,
        )
    assert any("-sn" in c for c in calls)
