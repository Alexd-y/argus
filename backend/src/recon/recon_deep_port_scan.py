"""RECON-005 — optional naabu discovery + bounded nmap -sV (full mode + deep_port_scan flag)."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import shutil
from typing import TYPE_CHECKING, Any

from src.core.config import Settings, settings as default_settings
from src.recon.mcp.kal_executor import run_kal_mcp_tool
from src.recon.mcp.policy import evaluate_kal_mcp_policy
from src.recon.recon_runtime import ReconRuntimeConfig
from src.recon.recon_subdomain_inventory import _DOMAIN_RE_HOST

if TYPE_CHECKING:
    from src.orchestration.raw_phase_artifacts import RawPhaseSink

logger = logging.getLogger(__name__)

_NAABU_LINE_RE = re.compile(r"^([^\s:]+|\[[^\]]+\]):(\d+)\s*$")


def _artifact_slug(host: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in (host or ""))[:120] or "host"


def _tool_binary_visible(argv0: str, app_settings: Settings) -> bool:
    if app_settings.sandbox_enabled:
        return True
    return shutil.which(argv0) is not None


def parse_naabu_host_port_lines(text: str) -> dict[str, set[int]]:
    """Map hostname/IP key -> open ports from naabu -silent lines (host:port or [ipv6]:port)."""
    by_host: dict[str, set[int]] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _NAABU_LINE_RE.match(line)
        if not m:
            h, _, tail = line.rpartition(":")
            if not tail.isdigit() or not h:
                continue
            host_key = h.strip().lower().strip("[]")
            port = int(tail)
        else:
            host_key = m.group(1).strip().lower().strip("[]")
            port = int(m.group(2))
        if not (1 <= port <= 65535):
            continue
        by_host.setdefault(host_key, set()).add(port)
    return by_host


def parse_user_ports_csv(ports_option: str, *, cap: int) -> set[int]:
    """Limited parse of scan ``ports`` (comma + simple a-b ranges) for primary-host hints."""
    out: set[int] = set()
    cap = max(1, int(cap))
    for part in (ports_option or "").split(","):
        part = part.strip()
        if not part:
            continue
        if len(out) >= cap:
            break
        if "-" in part and part.count("-") == 1:
            a, b = part.split("-", 1)
            try:
                lo, hi = int(a.strip()), int(b.strip())
            except ValueError:
                continue
            if lo > hi:
                lo, hi = hi, lo
            for p in range(lo, min(hi, lo + cap) + 1):
                if len(out) >= cap:
                    break
                if 1 <= p <= 65535:
                    out.add(p)
            continue
        try:
            p = int(part)
        except ValueError:
            continue
        if 1 <= p <= 65535:
            out.add(p)
    return out


def _tcp_ports_from_nmap_tool_result(tool_results: dict[str, Any]) -> set[int]:
    block = tool_results.get("nmap")
    if not isinstance(block, dict):
        return set()
    st = block.get("structured")
    if not isinstance(st, dict):
        return set()
    raw = st.get("open_tcp_ports")
    if not isinstance(raw, list):
        return set()
    out: set[int] = set()
    for x in raw:
        try:
            p = int(str(x).strip())
        except (TypeError, ValueError):
            continue
        if 1 <= p <= 65535:
            out.add(p)
    return out


def _apex_is_valid(apex_l: str) -> bool:
    if not apex_l:
        return False
    if _DOMAIN_RE_HOST.match(apex_l):
        return True
    try:
        ipaddress.ip_address(apex_l)
        return True
    except ValueError:
        return False


def collect_hosts_for_deep_scan(
    apex: str,
    tool_results: dict[str, Any],
    *,
    max_hosts: int,
) -> list[str]:
    """Apex first, then merged subdomains scoped to apex, capped."""
    apex_l = (apex or "").strip().lower()
    if not _apex_is_valid(apex_l):
        return []
    is_domain_apex = bool(_DOMAIN_RE_HOST.match(apex_l))
    hosts: list[str] = [apex_l]
    seen: set[str] = {apex_l}
    if not is_domain_apex:
        return hosts[: max(1, int(max_hosts))]
    sm = tool_results.get("subdomains_merged")
    if isinstance(sm, dict):
        try:
            arr = json.loads(str(sm.get("stdout") or "[]"))
        except (json.JSONDecodeError, TypeError, ValueError):
            arr = []
        if isinstance(arr, list):
            for x in arr:
                if not isinstance(x, str):
                    continue
                h = x.strip().lower().lstrip("*. ")
                if not h or h in seen:
                    continue
                if not _DOMAIN_RE_HOST.match(h):
                    continue
                if h != apex_l and not h.endswith("." + apex_l):
                    continue
                hosts.append(h)
                seen.add(h)
                if len(hosts) >= max(1, int(max_hosts)):
                    break
    return hosts[: max(1, int(max_hosts))]


def build_naabu_argv(host: str, top_ports: int) -> list[str]:
    tp = max(1, min(65535, int(top_ports)))
    return ["naabu", "-host", host, "-top-ports", str(tp), "-silent", "-no-color"]


def build_deep_nmap_sv_argv(host: str, port_csv: str) -> list[str]:
    return ["nmap", "-sV", "-T4", "--open", "-oX", "-", "-p", port_csv, host]


def _kal_target_url(host: str) -> str:
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 6:
            return f"http://[{ip.compressed}]/"
        return f"http://{ip.compressed}/"
    except ValueError:
        return f"https://{host}/"


def merge_deep_ports_into_nmap_tool_result(
    tool_results: dict[str, Any],
    deep_structured: dict[str, Any],
) -> None:
    """Add ``deep_port_enrichment`` and union TCP ports into existing nmap structured (additive)."""
    agg = deep_structured.get("aggregate_tcp_ports")
    if not isinstance(agg, list):
        return
    extra_tcp = {int(x) for x in agg if isinstance(x, (int, float)) or (isinstance(x, str) and str(x).isdigit())}
    extra_tcp = {p for p in extra_tcp if 1 <= p <= 65535}
    if not extra_tcp:
        return
    n = tool_results.get("nmap")
    if not isinstance(n, dict):
        return
    st = n.get("structured")
    if not isinstance(st, dict):
        st = {}
    cur_raw = st.get("open_tcp_ports")
    cur: set[int] = set()
    if isinstance(cur_raw, list):
        for x in cur_raw:
            try:
                cur.add(int(str(x).strip()))
            except (TypeError, ValueError):
                continue
    cur |= extra_tcp
    st = {**st, "open_tcp_ports": sorted(str(p) for p in cur), "deep_port_enrichment": deep_structured}
    n["structured"] = st
    tool_results["nmap"] = n


async def run_recon_deep_port_scan_bundle(
    target: str,
    domain: str,
    ports_option: str,
    tool_results: dict[str, Any],
    cfg: ReconRuntimeConfig,
    *,
    raw_sink: RawPhaseSink | None,
    tenant_id: str | None,
    scan_id: str | None,
    app_settings: Settings | None = None,
) -> dict[str, Any]:
    """
    Run optional naabu per capped host, then nmap -sV on capped port sets; upload raw; merge into nmap structured.
    Preconditions: caller only when plan includes DEEP_PORT_SCAN (full + recon_deep_port_scan).
    """
    s = app_settings or default_settings
    if cfg.mode != "full" or not cfg.deep_port_scan:
        return {}

    from src.recon.nmap_recon_cycle import merge_open_ports, parse_nmap_xml_stdout

    apex = (domain or "").strip().lower().split(":")[0]
    hosts = collect_hosts_for_deep_scan(apex, tool_results, max_hosts=cfg.deep_max_hosts)
    if not hosts:
        logger.info(
            "recon_deep_port_scan_skipped",
            extra={"event": "recon_deep_port_scan_skipped", "reason": "no_hosts"},
        )
        return {}

    timeout_sec = float(
        max(30, int(cfg.deep_timeout_sec or getattr(s, "recon_tools_timeout", 300) or 300))
    )
    max_ports = max(1, min(256, int(cfg.deep_max_ports_per_host)))
    prior_tcp = _tcp_ports_from_nmap_tool_result(tool_results)
    user_tcp = parse_user_ports_csv(ports_option, cap=max_ports)

    host_ports: dict[str, set[int]] = {h: set() for h in hosts}
    for h in hosts:
        if h == apex:
            host_ports[h] |= prior_tcp | user_tcp

    exec_time = 0.0
    naabu_summaries: list[dict[str, Any]] = []

    if cfg.deep_naabu_enabled:
        for host in hosts:
            argv_nb = build_naabu_argv(host, cfg.deep_naabu_top_ports)
            if not _tool_binary_visible(argv_nb[0], s):
                continue
            pol = evaluate_kal_mcp_policy(
                category="network_scanning",
                argv=argv_nb,
                password_audit_opt_in=False,
                server_password_audit_enabled=bool(s.kal_allow_password_audit),
            )
            if not pol.allowed:
                naabu_summaries.append({"host": host, "naabu": "policy_denied", "reason": pol.reason})
                continue
            tgt = _kal_target_url(host)
            nb_r = await asyncio.to_thread(
                run_kal_mcp_tool,
                category="network_scanning",
                argv=argv_nb,
                target=tgt,
                tenant_id=tenant_id,
                scan_id=scan_id,
                password_audit_opt_in=False,
                timeout_sec=timeout_sec,
            )
            exec_time += float(nb_r.get("execution_time") or 0.0)
            stdout = str(nb_r.get("stdout") or "")
            if raw_sink is not None:
                try:
                    await asyncio.to_thread(
                        raw_sink.upload_text,
                        f"deep_naabu_{_artifact_slug(host)}_stdout",
                        stdout,
                    )
                except Exception:
                    logger.warning(
                        "recon_deep_naabu_upload_failed",
                        extra={"event": "recon_deep_naabu_upload_failed"},
                    )
                err = str(nb_r.get("stderr") or "")
                if len(err) > 0:
                    try:
                        await asyncio.to_thread(
                            raw_sink.upload_text,
                            f"deep_naabu_{_artifact_slug(host)}_stderr",
                            err,
                        )
                    except Exception:
                        pass
            parsed_nb = parse_naabu_host_port_lines(stdout)
            naabu_summaries.append({"host": host, "naabu_ok": bool(nb_r.get("success")), "lines": len(stdout.splitlines())})
            for _hk, ports in parsed_nb.items():
                host_ports.setdefault(host, set()).update(ports)

    nmap_phases: list[dict[str, Any]] = []
    any_ok = False

    for host in hosts:
        ports = host_ports.get(host) or set()
        if not ports and host == apex:
            ports = set(prior_tcp) | set(user_tcp)
        if not ports:
            nmap_phases.append({"host": host, "skipped": True, "reason": "no_ports"})
            continue
        sorted_p = sorted(ports)
        capped = sorted_p[:max_ports]
        port_csv = ",".join(str(p) for p in capped)
        argv_nm = build_deep_nmap_sv_argv(host, port_csv)
        if not _tool_binary_visible(argv_nm[0], s):
            nmap_phases.append({"host": host, "skipped": True, "reason": "binary_missing"})
            continue
        pol = evaluate_kal_mcp_policy(
            category="network_scanning",
            argv=argv_nm,
            password_audit_opt_in=False,
            server_password_audit_enabled=bool(s.kal_allow_password_audit),
        )
        if not pol.allowed:
            nmap_phases.append({"host": host, "policy_denied": True, "reason": pol.reason})
            continue
        tgt = _kal_target_url(host)
        nm_r = await asyncio.to_thread(
            run_kal_mcp_tool,
            category="network_scanning",
            argv=argv_nm,
            target=tgt,
            tenant_id=tenant_id,
            scan_id=scan_id,
            password_audit_opt_in=False,
            timeout_sec=timeout_sec,
        )
        exec_time += float(nm_r.get("execution_time") or 0.0)
        stdout = str(nm_r.get("stdout") or "")
        parsed = parse_nmap_xml_stdout(stdout)
        t_tcp, _t_udp = merge_open_ports(parsed)
        if nm_r.get("success"):
            any_ok = True
        nmap_phases.append({
            "host": host,
            "success": bool(nm_r.get("success")),
            "return_code": nm_r.get("return_code"),
            "parsed": parsed,
            "open_tcp": sorted(t_tcp, key=lambda x: int(x) if str(x).isdigit() else 0),
        })
        if raw_sink is not None:
            try:
                await asyncio.to_thread(
                    raw_sink.upload_text,
                    f"deep_nmap_sv_{_artifact_slug(host)}_stdout",
                    stdout,
                    "xml",
                )
            except Exception:
                logger.warning(
                    "recon_deep_nmap_upload_failed",
                    extra={"event": "recon_deep_nmap_upload_failed"},
                )
            err = str(nm_r.get("stderr") or "")
            if len(err) > 0:
                try:
                    await asyncio.to_thread(
                        raw_sink.upload_text,
                        f"deep_nmap_sv_{_artifact_slug(host)}_stderr",
                        err,
                    )
                except Exception:
                    pass

    aggregate_tcp: set[int] = set()
    by_host_out: dict[str, list[dict[str, Any]]] = {}
    for ph in nmap_phases:
        h = str(ph.get("host") or "")
        pr = ph.get("parsed") if isinstance(ph.get("parsed"), dict) else {}
        hosts_xml = pr.get("hosts") if isinstance(pr.get("hosts"), list) else []
        port_rows: list[dict[str, Any]] = []
        for hx in hosts_xml:
            if not isinstance(hx, dict):
                continue
            for prt in hx.get("ports") or []:
                if not isinstance(prt, dict):
                    continue
                pid = str(prt.get("portid") or "").strip()
                if pid.isdigit():
                    aggregate_tcp.add(int(pid))
                port_rows.append(prt)
        if h:
            by_host_out[h] = port_rows

    deep_structured: dict[str, Any] = {
        "apex": apex,
        "hosts_scanned": hosts,
        "naabu": naabu_summaries,
        "nmap_phases": nmap_phases,
        "open_ports_by_host": {k: sorted({int(p["portid"]) for p in v if str(p.get("portid", "")).isdigit()}) for k, v in by_host_out.items()},
        "aggregate_tcp_ports": sorted(aggregate_tcp),
    }

    merge_deep_ports_into_nmap_tool_result(tool_results, deep_structured)

    if raw_sink is not None:
        try:
            await asyncio.to_thread(raw_sink.upload_json, "deep_port_scan_structured", deep_structured)
        except Exception:
            logger.warning(
                "recon_deep_structured_upload_failed",
                extra={"event": "recon_deep_structured_upload_failed"},
            )

    merged_ports = sorted(aggregate_tcp | prior_tcp)
    out: dict[str, Any] = {
        "deep_port_scan": {
            "success": any_ok or bool(aggregate_tcp),
            "stdout": json.dumps(
                {
                    "summary": "deep_port_scan naabu+nmap -sV",
                    "aggregate_tcp_ports": merged_ports,
                    "hosts": hosts,
                },
                ensure_ascii=False,
            ),
            "stderr": "",
            "return_code": 0 if (any_ok or aggregate_tcp) else 1,
            "execution_time": exec_time,
            "structured": deep_structured,
        },
        "recon_open_ports_merged": {
            "success": True,
            "stdout": json.dumps({"tcp_ports": merged_ports}),
            "stderr": "",
            "return_code": 0,
            "execution_time": 0.0,
        },
    }
    logger.info(
        "recon_deep_port_scan_finished",
        extra={
            "event": "recon_deep_port_scan_finished",
            "hosts": len(hosts),
            "tcp_union": len(merged_ports),
        },
    )
    return out
