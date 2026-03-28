"""KAL-003 — Multi-phase nmap recon when sandbox is on and KAL network_scanning argv policy allows."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import shlex
import xml.etree.ElementTree as ET
from typing import Any, Callable

from src.core.config import settings
from src.orchestration.raw_phase_artifacts import RawPhaseSink
from src.recon.mcp.policy import evaluate_kal_mcp_policy

logger = logging.getLogger(__name__)

_KAL_NETWORK = "network_scanning"
_MAX_NSE_PORTS = 256


def _argv_to_cmd(argv: list[str]) -> str:
    return " ".join(shlex.quote(p) for p in argv)


def target_looks_like_cidr(target: str) -> bool:
    t = (target or "").strip()
    if "/" not in t:
        return False
    try:
        ipaddress.ip_network(t, strict=False)
        return True
    except ValueError:
        return False


def nmap_argv_policy_allowed(argv: list[str]) -> bool:
    d = evaluate_kal_mcp_policy(
        category=_KAL_NETWORK,
        argv=argv,
        password_audit_opt_in=False,
        server_password_audit_enabled=False,
    )
    return d.allowed


def parse_nmap_xml_stdout(xml_text: str) -> dict[str, Any]:
    """Parse nmap -oX - (XML on stdout) into a compact JSON-serializable structure."""
    raw = (xml_text or "").strip()
    if not raw:
        return {"hosts": [], "note": "empty_xml"}
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return {"hosts": [], "note": "invalid_xml"}

    hosts_out: list[dict[str, Any]] = []
    for host in root.findall("host"):
        status_el = host.find("status")
        if status_el is not None and status_el.get("state") == "down":
            continue

        addrs: list[dict[str, str]] = []
        for addr in host.findall("address"):
            addrs.append({
                "addr": addr.get("addr", "") or "",
                "addrtype": addr.get("addrtype", "") or "",
            })

        ports_out: list[dict[str, Any]] = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state_el = port.find("state")
                state = state_el.get("state", "") if state_el is not None else ""
                if state != "open":
                    continue
                svc_el = port.find("service")
                ports_out.append({
                    "protocol": port.get("protocol", "") or "",
                    "portid": port.get("portid", "") or "",
                    "state": state,
                    "service": (svc_el.get("name", "") if svc_el is not None else "") or "",
                    "product": (svc_el.get("product", "") if svc_el is not None else "") or "",
                    "version": (svc_el.get("version", "") if svc_el is not None else "") or "",
                })

        hostnames: list[str] = []
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            for hn in hostnames_el.findall("hostname"):
                n = hn.get("name", "") or ""
                if n:
                    hostnames.append(n)

        if addrs or ports_out or hostnames:
            hosts_out.append({"addresses": addrs, "hostnames": hostnames, "ports": ports_out})

    return {"hosts": hosts_out}


def merge_open_ports(parsed: dict[str, Any]) -> tuple[set[str], set[str]]:
    """Return (tcp_port_ids, udp_port_ids) as strings for -p."""
    tcp: set[str] = set()
    udp: set[str] = set()
    for h in parsed.get("hosts", []):
        for p in h.get("ports", []):
            pid = str(p.get("portid", "") or "").strip()
            if not pid:
                continue
            proto = str(p.get("protocol", "") or "").lower()
            if proto == "udp":
                udp.add(pid)
            else:
                tcp.add(pid)
    return tcp, udp


def _summarize_for_llm(structured: dict[str, Any], max_chars: int = 14_000) -> str:
    lines: list[str] = []
    lines.append(
        f"target={structured.get('target')} open_tcp={sorted(structured.get('open_tcp_ports', []))} "
        f"open_udp={sorted(structured.get('open_udp_ports', []))}"
    )
    for ph in structured.get("phases", []):
        name = ph.get("name", "")
        lines.append(
            f"phase={name} success={ph.get('success')} policy_denied={ph.get('policy_denied', False)} "
            f"rc={ph.get('return_code')}"
        )
        parsed = ph.get("parsed") or {}
        for h in parsed.get("hosts", [])[:20]:
            for a in h.get("addresses", [])[:2]:
                addr = a.get("addr", "")
                for pr in h.get("ports", [])[:30]:
                    lines.append(
                        f"  {addr} {pr.get('protocol')}/{pr.get('portid')} "
                        f"{pr.get('service')} {pr.get('product')} {pr.get('version')}".strip()
                    )
    lines.append("--- NMAP_STRUCTURED_JSON ---")
    lines.append(json.dumps(structured, ensure_ascii=False, default=str)[: max_chars // 2])
    text = "\n".join(lines)
    if len(text) > max_chars:
        return text[: max_chars - 20] + "\n... [truncated]"
    return text


async def _run_one_phase(
    phase: str,
    argv: list[str],
    *,
    execute_command: Callable[..., dict[str, Any]],
    use_sandbox: bool,
    timeout_sec: int,
    raw_sink: RawPhaseSink | None,
) -> dict[str, Any]:
    if not nmap_argv_policy_allowed(argv):
        logger.info(
            "nmap_recon_phase_policy_denied",
            extra={"event": "nmap_recon_phase_policy_denied", "phase": phase},
        )
        return {
            "phase": phase,
            "success": False,
            "stdout": "",
            "stderr": "policy_denied",
            "return_code": -2,
            "execution_time": 0.0,
            "policy_denied": True,
            "parsed": {"hosts": []},
        }

    cmd = _argv_to_cmd(argv)

    def _invoke() -> dict[str, Any]:
        return execute_command(
            cmd,
            use_cache=False,
            use_sandbox=use_sandbox,
            timeout_sec=timeout_sec,
        )

    result = await asyncio.to_thread(_invoke)
    stdout = str(result.get("stdout") or "")
    stderr = str(result.get("stderr") or "")
    parsed = parse_nmap_xml_stdout(stdout)

    if raw_sink is not None:
        try:
            await asyncio.to_thread(raw_sink.upload_text, f"nmap_{phase}_stdout", stdout, "xml")
        except Exception:
            logger.warning(
                "nmap_recon_phase_artifact_upload_failed",
                extra={"event": "nmap_recon_phase_artifact_upload_failed", "phase": phase},
            )
        if stderr.strip():
            try:
                await asyncio.to_thread(raw_sink.upload_text, f"nmap_{phase}_stderr", stderr)
            except Exception:
                pass

    out = {
        "phase": phase,
        "success": bool(result.get("success")),
        "stdout": stdout,
        "stderr": stderr,
        "return_code": result.get("return_code"),
        "execution_time": result.get("execution_time", 0.0),
        "policy_denied": False,
        "parsed": parsed,
    }
    _log_phase_done(phase, out)
    return out


def _log_phase_done(phase: str, out: dict[str, Any]) -> None:
    logger.info(
        "nmap_recon_phase_finished",
        extra={
            "event": "nmap_recon_phase_finished",
            "phase": phase,
            "return_code": out.get("return_code"),
            "success": out.get("success"),
            "policy_denied": out.get("policy_denied"),
        },
    )


async def _legacy_parallel_nmap(
    target: str,
    ports_option: str,
    execute_command: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    cmd = f"nmap -sV -sC -T4 --open -p {ports_option} {target}"

    def _invoke() -> dict[str, Any]:
        return execute_command(cmd, use_cache=False, use_sandbox=False)

    result = await asyncio.to_thread(_invoke)
    return result


def _wants_sandbox_cycle(scan_options: dict[str, Any]) -> bool:
    if scan_options.get("nmap_recon_cycle") is False:
        return False
    if not settings.nmap_recon_cycle:
        return False
    return bool(settings.sandbox_enabled)


async def run_nmap_recon_for_recon(
    target: str,
    *,
    ports_option: str,
    scan_options: dict[str, Any],
    raw_sink: RawPhaseSink | None,
    execute_command: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    """
    When sandbox + NMAP_RECON_CYCLE + KAL policy allow the baseline SYN top-1000 scan, run phased nmap
    (-sn for CIDR, -sS --top-ports 1000, optional full TCP / UDP, NSE default+safe on open TCP ports).
    Otherwise run the historical single nmap -sV -sC against *ports_option* locally (no sandbox).
    """
    if not _wants_sandbox_cycle(scan_options):
        result = await _legacy_parallel_nmap(target, ports_option, execute_command)
        result = dict(result)
        result["structured"] = {
            "mode": "legacy",
            "target": target,
            "phases": [],
            "open_tcp_ports": [],
            "open_udp_ports": [],
        }
        return result

    baseline_argv = ["nmap", "-sS", "--top-ports", "1000", "-T4", "--open", "-oX", "-", target]
    if not nmap_argv_policy_allowed(baseline_argv):
        logger.info(
            "nmap_recon_cycle_policy_fallback_legacy",
            extra={"event": "nmap_recon_cycle_policy_fallback_legacy"},
        )
        result = await _legacy_parallel_nmap(target, ports_option, execute_command)
        result = dict(result)
        result["structured"] = {
            "mode": "legacy_policy_fallback",
            "target": target,
            "phases": [],
            "note": "kal_network_scanning_denied_baseline_argv",
        }
        return result

    use_sb = True
    tmo = int(settings.nmap_recon_phase_timeout_sec or settings.recon_tools_timeout)
    full_tcp = bool(scan_options.get("nmap_full_tcp", settings.nmap_full_tcp))
    udp50 = bool(scan_options.get("nmap_udp_top50", settings.nmap_udp_top50))

    phases_out: list[dict[str, Any]] = []
    open_tcp: set[str] = set()
    open_udp: set[str] = set()

    if target_looks_like_cidr(target):
        ping_argv = ["nmap", "-sn", "-oX", "-", target]
        pr = await _run_one_phase(
            "discover_sn",
            ping_argv,
            execute_command=execute_command,
            use_sandbox=use_sb,
            timeout_sec=min(tmo, settings.recon_tools_timeout),
            raw_sink=raw_sink,
        )
        phases_out.append(pr)

    tcp_argv = ["nmap", "-sS", "--top-ports", "1000", "-T4", "--open", "-oX", "-", target]
    tr = await _run_one_phase(
        "tcp_top1000",
        tcp_argv,
        execute_command=execute_command,
        use_sandbox=use_sb,
        timeout_sec=tmo,
        raw_sink=raw_sink,
    )
    phases_out.append(tr)
    t_tcp, t_udp = merge_open_ports(tr.get("parsed") or {})
    open_tcp |= t_tcp
    open_udp |= t_udp

    if full_tcp:
        full_argv = ["nmap", "-p-", "-sV", "-O", "--open", "-T4", "-oX", "-", target]
        fr = await _run_one_phase(
            "tcp_full_sv_os",
            full_argv,
            execute_command=execute_command,
            use_sandbox=use_sb,
            timeout_sec=tmo,
            raw_sink=raw_sink,
        )
        phases_out.append(fr)
        if fr.get("success"):
            a, b = merge_open_ports(fr.get("parsed") or {})
            open_tcp |= a
            open_udp |= b

    if udp50:
        uargv = ["nmap", "-sU", "--top-ports", "50", "-T4", "--open", "-oX", "-", target]
        ur = await _run_one_phase(
            "udp_top50",
            uargv,
            execute_command=execute_command,
            use_sandbox=use_sb,
            timeout_sec=tmo,
            raw_sink=raw_sink,
        )
        phases_out.append(ur)
        if ur.get("success"):
            a, b = merge_open_ports(ur.get("parsed") or {})
            open_tcp |= a
            open_udp |= b

    port_list = sorted(open_tcp, key=lambda x: int(x) if x.isdigit() else 0)[:_MAX_NSE_PORTS]
    if port_list:
        port_arg = ",".join(port_list)
        nse_argv = [
            "nmap",
            "-sV",
            "--script",
            "default and safe",
            "-p",
            port_arg,
            "-T4",
            "--open",
            "-oX",
            "-",
            target,
        ]
        nr = await _run_one_phase(
            "nse_default_safe",
            nse_argv,
            execute_command=execute_command,
            use_sandbox=use_sb,
            timeout_sec=tmo,
            raw_sink=raw_sink,
        )
        phases_out.append(nr)
        if nr.get("success"):
            a, b = merge_open_ports(nr.get("parsed") or {})
            open_tcp |= a
            open_udp |= b

    structured: dict[str, Any] = {
        "mode": "sandbox_cycle",
        "target": target,
        "phases": [
            {
                "name": p.get("phase"),
                "success": p.get("success"),
                "policy_denied": p.get("policy_denied", False),
                "return_code": p.get("return_code"),
                "parsed": p.get("parsed"),
            }
            for p in phases_out
        ],
        "open_tcp_ports": sorted(open_tcp, key=lambda x: int(x) if x.isdigit() else 0),
        "open_udp_ports": sorted(open_udp, key=lambda x: int(x) if x.isdigit() else 0),
    }

    if raw_sink is not None:
        try:
            await asyncio.to_thread(raw_sink.upload_json, "nmap_recon_structured", structured)
        except Exception:
            logger.warning("nmap_recon_structured_upload_failed", extra={"event": "nmap_recon_structured_upload_failed"})

    any_tcp_ok = any(
        p.get("phase") in ("tcp_top1000", "tcp_full_sv_os") and p.get("success")
        for p in phases_out
    )
    success = any_tcp_ok or bool(open_tcp)
    combined_stderr = "\n".join(
        str(p.get("stderr") or "") for p in phases_out if str(p.get("stderr") or "").strip()
    )
    combined_time = sum(float(p.get("execution_time") or 0) for p in phases_out)
    llm_stdout = _summarize_for_llm(structured)

    return {
        "success": success,
        "stdout": llm_stdout,
        "stderr": combined_stderr[:50_000],
        "return_code": 0 if success else 1,
        "execution_time": combined_time,
        "structured": structured,
    }
