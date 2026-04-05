"""RECON-009 — versioned aggregate of pipeline tool_results for MinIO + reporting (additive)."""

from __future__ import annotations

import copy
import json
import re
from typing import Any

RECON_SUMMARY_SCHEMA_VERSION = 1

_EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]{1,256}@[a-zA-Z0-9.\-]{1,128}\.[a-zA-Z]{2,24}",
    re.IGNORECASE,
)
_PORT_RE = re.compile(r"\b(?:port|ports)\s*[|:]?\s*(\d{1,5})\b", re.IGNORECASE)


def mask_email(email: str) -> str:
    """Mask local-part; keep domain for context (no full PII in summary)."""
    e = (email or "").strip()
    if "@" not in e:
        return e[:120] if e else ""
    local, _, domain = e.partition("@")
    domain = domain.strip()[:200]
    if not local:
        return f"*@{domain}" if domain else ""
    if len(local) <= 1:
        return f"{local}***@{domain}"
    return f"{local[0]}***@{domain}"


def _parse_json_lines(blob: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for line in (blob or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except (json.JSONDecodeError, TypeError, ValueError):
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _security_header_keys() -> frozenset[str]:
    return frozenset({
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "x-xss-protection",
        "cross-origin-opener-policy",
        "cross-origin-embedder-policy",
    })


def _extract_security_headers_from_httpx_stdout(stdout: str) -> dict[str, dict[str, str]]:
    """Best-effort host/url → lowercased security header map from httpx -json lines."""
    merged: dict[str, dict[str, str]] = {}
    keys = _security_header_keys()
    for row in _parse_json_lines(stdout):
        host = str(row.get("host") or row.get("input") or row.get("url") or "").strip()[:512]
        if not host:
            continue
        inner: dict[str, str] = {}
        for k, v in row.items():
            if not isinstance(k, str):
                continue
            kl = k.lower().replace("_", "-")
            if kl in keys and v is not None:
                inner[kl] = str(v).strip()[:4096]
        headers_obj = row.get("header") or row.get("headers")
        if isinstance(headers_obj, dict):
            for k, v in headers_obj.items():
                if not isinstance(k, str):
                    continue
                kl = k.lower()
                if kl in keys and v is not None:
                    inner[kl] = str(v).strip()[:4096]
        if inner:
            cur = merged.get(host, {})
            merged[host] = {**cur, **inner}
    return merged


def _subdomains_from_tool_results(tr: dict[str, Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []

    def add(h: str) -> None:
        t = h.strip().lower().lstrip("*.")[:253]
        if t and t not in seen:
            seen.add(t)
            out.append(t)

    sm = tr.get("subdomains_merged")
    if isinstance(sm, dict):
        try:
            arr = json.loads(sm.get("stdout") or "[]")
            if isinstance(arr, list):
                for x in arr:
                    if isinstance(x, str):
                        add(x)
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    intel = tr.get("kal_dns_intel")
    if isinstance(intel, list):
        for row in intel:
            if not isinstance(row, dict):
                continue
            data = row.get("data")
            if isinstance(data, dict):
                h = data.get("hostname")
                if isinstance(h, str):
                    add(h)
    return out[:10_000]


def _dns_records_flat(tr: dict[str, Any]) -> list[dict[str, Any]]:
    depth = tr.get("dns_depth")
    if not isinstance(depth, dict):
        return []
    st = depth.get("structured")
    if not isinstance(st, dict):
        return []
    recs = st.get("records")
    if not isinstance(recs, list):
        return []
    flat: list[dict[str, Any]] = []
    for r in recs[:5000]:
        if isinstance(r, dict):
            flat.append({k: v for k, v in r.items() if isinstance(k, str)})
    return flat


def _live_hosts_from_probe(tr: dict[str, Any]) -> list[str]:
    merged = tr.get("http_probe_tech_stack")
    if isinstance(merged, dict):
        bh = merged.get("by_host")
        if isinstance(bh, dict) and bh:
            return sorted({str(k).strip() for k in bh.keys() if str(k).strip()})[:2000]
    hx = tr.get("httpx")
    if isinstance(hx, dict):
        hosts: set[str] = set()
        for row in _parse_json_lines(str(hx.get("stdout") or "")):
            u = str(row.get("url") or "").strip()
            h = str(row.get("host") or "").strip()
            if u:
                hosts.add(u[:2048])
            elif h:
                hosts.add(h[:512])
        if hosts:
            return sorted(hosts)[:2000]
    return []


def _collect_ports(tr: dict[str, Any]) -> list[int]:
    found: set[int] = set()

    def add_p(p: object) -> None:
        if isinstance(p, int) and 0 < p <= 65535:
            found.add(p)
        elif isinstance(p, float) and p == int(p):
            add_p(int(p))
        elif isinstance(p, str) and p.isdigit():
            add_p(int(p))

    nmap = tr.get("nmap")
    if isinstance(nmap, dict):
        st = nmap.get("structured")
        if isinstance(st, dict):
            for key in ("open_ports", "ports", "tcp_ports", "udp_ports"):
                arr = st.get(key)
                if isinstance(arr, list):
                    for x in arr:
                        add_p(x)
            hosts = st.get("hosts")
            if isinstance(hosts, list):
                for h in hosts:
                    if not isinstance(h, dict):
                        continue
                    for pr in h.get("ports") or h.get("open") or []:
                        if isinstance(pr, dict):
                            add_p(pr.get("port") or pr.get("portid"))
                        else:
                            add_p(pr)

    dps = tr.get("deep_port_scan")
    if isinstance(dps, dict):
        st = dps.get("structured")
        if isinstance(st, dict):
            for host_blob in st.get("hosts") or []:
                if not isinstance(host_blob, dict):
                    continue
                for pr in host_blob.get("ports") or []:
                    if isinstance(pr, dict):
                        add_p(pr.get("port"))

    rpm = tr.get("recon_open_ports_merged")
    if isinstance(rpm, dict):
        txt = str(rpm.get("stdout") or "")
        for m in _PORT_RE.finditer(txt):
            add_p(m.group(1))

    return sorted(found)[:4096]


def _urls_from_history(tr: dict[str, Any]) -> list[str]:
    bundle = tr.get("url_history_urls")
    if not isinstance(bundle, dict):
        return []
    raw = bundle.get("urls")
    if not isinstance(raw, list):
        return []
    return [str(u).strip()[:4096] for u in raw if isinstance(u, str) and str(u).strip()][:50_000]


def _js_files_from_js_analysis(tr: dict[str, Any]) -> list[str]:
    ja = tr.get("js_analysis")
    if not isinstance(ja, dict):
        return []
    js = ja.get("js_urls")
    if not isinstance(js, list):
        return []
    return [str(u).strip()[:4096] for u in js if isinstance(u, str) and str(u).strip()][:10_000]


def _parameters_from_tool_results(tr: dict[str, Any]) -> dict[str, Any]:
    ja = tr.get("js_analysis")
    if isinstance(ja, dict):
        qp = ja.get("query_params")
        if isinstance(qp, dict):
            names = qp.get("unique_names")
            if not isinstance(names, list):
                names = []
            return {
                "source": "js_analysis",
                "unique_param_names": [str(x).strip()[:256] for x in names if str(x).strip()][:2000],
                "urls_with_query": int(qp.get("urls_with_query") or 0),
            }
    hc = tr.get("http_crawl")
    if isinstance(hc, dict):
        try:
            blob = json.loads(hc.get("stdout") or "{}")
        except (json.JSONDecodeError, TypeError, ValueError):
            blob = {}
        if isinstance(blob, dict):
            inv = blob.get("params_inventory")
            if isinstance(inv, list):
                names: list[str] = []
                for row in inv[:5000]:
                    if isinstance(row, dict):
                        n = row.get("name") or row.get("param") or row.get("key")
                        if isinstance(n, str) and n.strip():
                            names.append(n.strip()[:256])
                return {"source": "http_crawl", "unique_param_names": sorted(frozenset(names))[:2000]}
    return {"source": "", "unique_param_names": [], "urls_with_query": 0}


def _masked_emails_from_theharvester(tr: dict[str, Any]) -> list[str]:
    block = tr.get("theharvester")
    if not isinstance(block, dict):
        return []
    text = str(block.get("stdout") or "")
    seen: set[str] = set()
    out: list[str] = []
    for m in _EMAIL_RE.finditer(text):
        masked = mask_email(m.group(0))
        if masked and masked not in seen:
            seen.add(masked)
            out.append(masked)
        if len(out) >= 256:
            break
    return out


def _screenshots_map(tr: dict[str, Any]) -> dict[str, str | None]:
    gw = tr.get("gowitness_screenshots")
    if not isinstance(gw, dict):
        return {}
    arts = gw.get("artifacts")
    if not isinstance(arts, list):
        return {}
    out: dict[str, str | None] = {}
    for a in arts:
        if not isinstance(a, dict):
            continue
        u = str(a.get("url") or "").strip()[:2048]
        if not u:
            continue
        k = a.get("minio_key")
        out[u] = str(k).strip() if isinstance(k, str) and k.strip() else None
    return out


def _technologies_combined(tr: dict[str, Any]) -> dict[str, Any]:
    m = tr.get("http_probe_tech_stack")
    if isinstance(m, dict):
        try:
            return copy.deepcopy(m)
        except Exception:
            return {}
    return {}


def build_recon_summary_document(
    tool_results: dict[str, Any],
    *,
    target: str = "",
) -> dict[str, Any]:
    """
    Build additive recon summary (JSON-serializable). Does not mutate ``tool_results``.
    """
    tr = dict(tool_results or {})
    hx = tr.get("httpx")
    hx_stdout = str(hx.get("stdout") or "") if isinstance(hx, dict) else ""

    doc: dict[str, Any] = {
        "_schema_version": RECON_SUMMARY_SCHEMA_VERSION,
        "target": (target or "").strip()[:2048],
        "subdomains": _subdomains_from_tool_results(tr),
        "dns_records": _dns_records_flat(tr),
        "live_hosts": _live_hosts_from_probe(tr),
        "ports": _collect_ports(tr),
        "urls": _urls_from_history(tr),
        "js_files": _js_files_from_js_analysis(tr),
        "parameters": _parameters_from_tool_results(tr),
        "emails_masked": _masked_emails_from_theharvester(tr),
        "asn": tr.get("asn_summary") if isinstance(tr.get("asn_summary"), dict) else {},
        "screenshots": _screenshots_map(tr),
        "technologies_combined": _technologies_combined(tr),
        "security_headers": _merge_security_headers(tr, hx_stdout),
        "ssl_info": [],
        "outdated_components": [],
    }
    return doc


def _merge_security_headers(
    tr: dict[str, Any],
    hx_stdout: str,
) -> dict[str, Any]:
    """Prefer ARGUS-002 dedicated collector; fall back to httpx extraction."""
    sh = tr.get("security_headers")
    if isinstance(sh, dict) and not sh.get("error"):
        return {
            "source": "recon_http_headers",
            "score": sh.get("score", 0),
            "findings_count": len(sh.get("findings") or []),
            "headers_found": sh.get("headers_found") or {},
            "server": sh.get("server"),
            "x_powered_by": sh.get("x_powered_by"),
        }
    httpx_map = _extract_security_headers_from_httpx_stdout(hx_stdout)
    if httpx_map:
        return {"source": "httpx", **httpx_map}
    return {}
