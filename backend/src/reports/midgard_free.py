"""Free-tier (Midgard) report projection — single source of truth for the five
export formats (PDF, HTML, JSON, XML, CSV).

Product invariant (keep as the content contract):

    "A free scan of the domain you own: severity counts, every finding title,
    and one complete writeup with evidence and a fix."

Everything in this module is **pure** (no I/O, no DB, no logging of payload
bodies). It consumes the already tier-projected :class:`ReportData` — i.e. the
output of ``classify_for_tier(data, ReportTier.MIDGARD)``, whose ``timeline``,
``phase_outputs``, ``evidence``, ``screenshots``, ``raw_artifacts`` and
``remediation`` are already emptied — plus the production Jinja
``template_context`` collected by the report pipeline. From those it derives the
free-tier payload that every format renders.

Security contract (mirrors ``docs/develop/PROMPT-midgard-free-report.md`` §6):

* No PoC / payload / exploit-chain / raw tool output / credential / pre-signed
  MinIO link / internal API path ever leaves this module. The inventory rows
  and the single teaser writeup read **only** inventory-level, non-intrusive
  fields (severity, title, CWE, CVSS, a safe observation and a deterministic
  config fix). ``proof_of_concept``, ``raw_request``, ``raw_response``,
  ``tool_command`` and ``verification_command`` are never read.
* Leaked-credential / dark-web monitoring is a PAID (Asgard/Valhalla) capability.
  ``hibp_pwned_password_summary`` and ``dark_web_monitoring`` are NEVER read in
  this module — the free tier carries no breach/leak/dark-web data. (Defence in
  depth: ``tier_classifier._project_midgard`` also forces both fields to ``None``
  before this module runs.)
* ``on_absent``: when a reconnaissance source did not run we surface the
  :data:`INTEL_NOT_COLLECTED` sentinel — we never invent a value.

Because all five formats build from ``build_free_payload`` the content parity
(same finding set, same ``midgard_intel``, same teaser, same severity counts)
is structural rather than asserted after the fact.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.api.schemas import Finding
    from src.reports.generators import ReportData

# ``on_absent`` sentinels — distinguish "source did not run" from "ran, found
# nothing" so the template can colour them differently (prompt §4.3).
INTEL_NOT_COLLECTED = "Not collected"
INTEL_NOT_ASSESSED = "Not assessed"

#: Static upsell block (never LLM-generated). Replaces the per-finding
#: "PoC details are available…" rows and the failed AI slot.
UPSELL_TEXT = (
    "Unlock the full assessment. This free Midgard scan lists what was found. "
    "Detailed explanations, reproducible proof-of-concept, step-by-step "
    "remediation and the prioritized roadmap are delivered in the paid "
    "reports — Asgard (full findings, remediation and sanitized reproducer "
    "recipes) and Valhalla (provable findings with raw evidence, exploit "
    "chains, hardening roadmap and the executive business-impact lens)."
)

# Severity rank for deterministic ordering — byte-for-byte identical to
# ``tier_classifier._SEVERITY_RANK`` / ``generators._SEVERITY_RANK``.
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}

_SEVERITY_BUCKETS = ("critical", "high", "medium", "low", "info")


def _sev_key(severity: str | None) -> str:
    s = (severity or "").lower().strip()
    if s in ("informational", "info"):
        return "info"
    return s if s in _SEVERITY_BUCKETS else "info"


def _cvss_of(f: Finding) -> float | None:
    cvss = getattr(f, "cvss", None)
    if cvss is None:
        cvss = getattr(f, "cvss_score", None)
    try:
        return float(cvss) if cvss is not None else None
    except (TypeError, ValueError):
        return None


def _priority_key(f: Finding) -> tuple[int, float, str, str]:
    """Most-urgent-first key: severity → CVSS → title → CWE (deterministic)."""
    sev_rank = _SEVERITY_RANK.get(_sev_key(getattr(f, "severity", None)), 99)
    cvss = _cvss_of(f)
    cvss_desc = -cvss if cvss is not None else 0.0
    title = (getattr(f, "title", None) or "").lower()
    cwe = getattr(f, "cwe", None) or ""
    return (sev_rank, cvss_desc, title, cwe)


def _finding_id(f: Finding) -> str:
    return str(getattr(f, "finding_id", None) or getattr(f, "id", None) or "")


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    """Severity rollup over every finding (critical/high/medium/low/info)."""
    counts = dict.fromkeys(_SEVERITY_BUCKETS, 0)
    for f in findings:
        counts[_sev_key(getattr(f, "severity", None))] += 1
    return counts


def finding_inventory(findings: list[Finding]) -> list[dict[str, Any]]:
    """Every finding as an inventory row: ``id/title/severity/cwe/cvss``.

    No description, no remediation, no PoC — this is the free "every finding
    title" layer. Rows are ordered most-urgent-first and the ordering is
    stable, so all five formats agree row-for-row.
    """
    rows: list[dict[str, Any]] = []
    for f in sorted(findings, key=_priority_key):
        rows.append(
            {
                "id": _finding_id(f),
                "title": (getattr(f, "title", None) or "").strip(),
                "severity": _sev_key(getattr(f, "severity", None)),
                "cwe": (getattr(f, "cwe", None) or "").strip(),
                "cvss": _cvss_of(f),
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Teaser — the single "complete writeup with evidence and a fix" (prompt §4.4)
# ---------------------------------------------------------------------------

# Deterministic, safe, configuration-level fixes keyed by a predicate over the
# finding's CWE + title. ``Finding`` carries no remediation field, so a teaser
# "Recommended fix" is only shown when the finding matches one of these
# non-exploit, config-hardening recipes. Order matters: first match wins.
_SAFE_FIX_RULES: tuple[tuple[tuple[str, ...], tuple[str, ...], str], ...] = (
    # (cwe substrings, title keyword substrings, fix text)
    (
        ("cwe-16", "cwe-358"),
        ("dmarc",),
        "Publish an aggregate-reporting address and tighten the policy once "
        "reports are clean, e.g. `v=DMARC1; p=none; rua=mailto:dmarc@<domain>; "
        "fo=1`. Review aggregate reports for 2–4 weeks, confirm every "
        "legitimate sender aligns on SPF/DKIM, then raise the policy to "
        "`p=quarantine` and ultimately `p=reject`.",
    ),
    (
        ("cwe-350", "cwe-349"),
        ("dnssec",),
        "Enable DNSSEC at the authoritative DNS provider and publish the "
        "resulting DS record at the registrar so resolvers can validate the "
        "zone. Verify the chain of trust afterwards (e.g. with a DNSSEC "
        "analyzer) before relying on it.",
    ),
    (
        ("cwe-693", "cwe-16", "cwe-1021"),
        ("spf",),
        "Publish a single SPF record that authorises exactly the hosts that "
        "send mail for the domain and terminate it with `~all` (soft-fail) or "
        "`-all` (hard-fail) once the sender list is confirmed.",
    ),
    (
        ("cwe-693", "cwe-16"),
        ("hsts", "strict-transport"),
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` "
        "to every HTTPS response; add `preload` only once every subdomain is "
        "HTTPS-ready and you intend to commit to the preload list.",
    ),
    (
        ("cwe-693", "cwe-1021", "cwe-16"),
        ("content-security-policy", "csp"),
        "Deploy a Content-Security-Policy that pins the allowed script/style "
        "origins; start in `Content-Security-Policy-Report-Only` mode, review "
        "the reports, then enforce.",
    ),
    (
        ("cwe-310", "cwe-326", "cwe-327"),
        ("tls", "ssl", "cipher", "protocol"),
        "Disable legacy TLS 1.0/1.1 and weak ciphers, serve only TLS 1.2+ with "
        "an ECDHE/AEAD cipher suite, and keep the certificate chain current.",
    ),
)


def _safe_fix_for(f: Finding) -> str | None:
    cwe = (getattr(f, "cwe", None) or "").lower()
    title = (getattr(f, "title", None) or "").lower()
    for cwes, keywords, fix in _SAFE_FIX_RULES:
        cwe_hit = any(c in cwe for c in cwes) if cwes else False
        kw_hit = any(k in title for k in keywords) if keywords else False
        # A keyword hit is the strong signal; CWE alone is too broad to claim a
        # specific config fix, so we require the title keyword to match.
        if kw_hit and (cwe_hit or not cwes):
            return fix
    return None


def _is_safe_teaser_candidate(f: Finding) -> bool:
    """A finding we can fully write up without any exploit detail.

    Candidates are configuration findings (DMARC/DNSSEC/SPF/TLS/headers) with a
    deterministic safe fix AND a non-exploit observation we can show as
    evidence. ``exploit_demonstrated`` findings are never candidates.
    """
    if getattr(f, "exploit_demonstrated", False):
        return False
    if _safe_fix_for(f) is None:
        return False
    return bool(_safe_evidence_for(f))


def _safe_evidence_for(f: Finding) -> str:
    """Return a non-intrusive observation suitable as teaser evidence.

    Only safe, descriptive fields are considered — never ``proof_of_concept``,
    ``raw_request``/``raw_response``, ``tool_command`` or
    ``verification_command``. The result is a plain observation (a DNS record,
    a response header, certificate parameters), not an attack.
    """
    for attr in ("observed_impact", "tool_output_excerpt", "description"):
        val = getattr(f, attr, None)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def select_teaser_finding(findings: list[Finding]) -> Finding | None:
    """Deterministically choose the single finding to write up in full.

    1. Prefer a safe configuration candidate (``_is_safe_teaser_candidate``).
    2. Among candidates, pick the most urgent via ``_priority_key``.
    3. If no safe candidate exists, fall back to the single most urgent finding
       overall (its writeup then omits the "Recommended fix").

    Pure and stable: a fixed finding set always yields the same id.
    """
    if not findings:
        return None
    candidates = [f for f in findings if _is_safe_teaser_candidate(f)]
    pool = candidates or list(findings)
    return sorted(pool, key=_priority_key)[0]


def build_teaser_writeup(f: Finding | None) -> dict[str, Any] | None:
    """Build the single full writeup: what / evidence / why / fix.

    Returns ``None`` when there are no findings. ``fix`` is ``""`` when the
    finding has no safe deterministic configuration fix.
    """
    if f is None:
        return None
    description = (getattr(f, "description", None) or "").strip()
    why = (getattr(f, "observed_impact", None) or "").strip()
    if not why:
        # Deterministic, non-exploit rationale fallback.
        why = (
            "This weakness reduces the security posture of the asset and should "
            "be remediated as part of routine hardening."
        )
    return {
        "id": _finding_id(f),
        "title": (getattr(f, "title", None) or "").strip(),
        "severity": _sev_key(getattr(f, "severity", None)),
        "cwe": (getattr(f, "cwe", None) or "").strip(),
        "cvss": _cvss_of(f),
        "asset": (
            getattr(f, "affected_asset", None) or getattr(f, "affected_endpoint", None) or ""
        ).strip(),
        "what": description or (getattr(f, "title", None) or "").strip(),
        "evidence": _safe_evidence_for(f),
        "why": why,
        "fix": _safe_fix_for(f) or "",
    }


# ---------------------------------------------------------------------------
# Target Intelligence — open, non-intrusive recon (prompt §4.3)
# ---------------------------------------------------------------------------


def _attr(obj: Any, key: str, default: Any = None) -> Any:
    """Read ``key`` from a dict or a pydantic/dataclass-like object."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _nonempty_str(val: Any) -> str | None:
    if isinstance(val, str) and val.strip():
        return val.strip()
    return None


def _list_of_str(val: Any) -> list[str]:
    if not isinstance(val, (list, tuple)):
        return []
    out: list[str] = []
    for item in val:
        s = _nonempty_str(item if isinstance(item, str) else str(item))
        if s:
            out.append(s)
    return out


def build_midgard_intel(
    jinja_context: dict[str, Any] | None,
    report_data: ReportData,
) -> dict[str, Any]:
    """Assemble the Target Intelligence block from existing recon collectors.

    Pulls from whatever structured recon is present in the production
    ``template_context`` (``valhalla_context`` structured fields, the
    ``recon_summary`` pipeline rollups) and from ``report_data.technologies``.
    Every block degrades to :data:`INTEL_NOT_COLLECTED` when its source did not
    run — values are never invented.
    """
    ctx = jinja_context or {}
    # Already-built intel (idempotent pass-through from the export path).
    existing = ctx.get("midgard_intel")
    if isinstance(existing, dict) and existing:
        return existing

    vc = ctx.get("valhalla_context") or {}
    recon = ctx.get("recon_summary") or {}

    # --- WHOIS / registration -------------------------------------------
    registrar = _nonempty_str(_attr(vc, "whois_registrar"))
    whois = {
        "registrar": registrar or INTEL_NOT_COLLECTED,
        "registrant_org": _nonempty_str(_attr(vc, "whois_org")) or INTEL_NOT_COLLECTED,
        "created": _nonempty_str(_attr(vc, "whois_creation_date")) or INTEL_NOT_COLLECTED,
        "expires": _nonempty_str(_attr(vc, "whois_expiry_date")) or INTEL_NOT_COLLECTED,
        "name_servers": _list_of_str(_attr(vc, "dns_ns_records")),
    }

    # --- DNS -------------------------------------------------------------
    ns = _list_of_str(_attr(vc, "dns_ns_records"))
    mx = _list_of_str(_attr(vc, "dns_mx_records"))
    dns = {
        "ns": ns,
        "mx": mx,
        "soa_primary_ns": _nonempty_str(_attr(vc, "dns_soa_primary_ns")) or INTEL_NOT_COLLECTED,
    }

    # --- Email authentication / DNSSEC ----------------------------------
    email_auth = {
        "dnssec": _nonempty_str(_attr(vc, "dnssec_status")) or INTEL_NOT_ASSESSED,
        "spf": _nonempty_str(_attr(vc, "spf_record")) or INTEL_NOT_ASSESSED,
        "dmarc": _nonempty_str(_attr(vc, "dmarc_record")) or INTEL_NOT_ASSESSED,
        "dkim": _nonempty_str(_attr(vc, "dkim_status")) or INTEL_NOT_ASSESSED,
    }

    # --- TLS / certificate ----------------------------------------------
    ssl_rows = _attr(vc, "ssl_tls_table_rows") or recon.get("ssl_tls_table_rows") or []
    tls = _tls_from_rows(ssl_rows)

    # --- Ports / services -----------------------------------------------
    ports = _ports_from_context(vc, recon)

    # --- Technology fingerprint -----------------------------------------
    technologies = _list_of_str(recon.get("technologies")) or _list_of_str(
        getattr(report_data, "technologies", None)
    )

    # --- Subdomains ------------------------------------------------------
    subdomains = _list_of_str(recon.get("pipeline_subdomains"))

    # --- ASN -------------------------------------------------------------
    asn = {
        "asn": _nonempty_str(_attr(vc, "ip_whois_asn")) or INTEL_NOT_COLLECTED,
        "org": _nonempty_str(_attr(vc, "ip_whois_org")) or INTEL_NOT_COLLECTED,
    }

    return {
        "whois": whois,
        "dns": dns,
        "email_auth": email_auth,
        "tls": tls,
        "ports": ports,
        "technologies": technologies,
        "subdomains": subdomains,
        "asn": asn,
    }


def _tls_from_rows(rows: Any) -> dict[str, Any]:
    """Collapse ssl/tls table rows into a single-cert summary (best effort)."""
    if not isinstance(rows, (list, tuple)) or not rows:
        return {
            "issuer": INTEL_NOT_COLLECTED,
            "subject": INTEL_NOT_COLLECTED,
            "sans": [],
            "not_before": INTEL_NOT_COLLECTED,
            "not_after": INTEL_NOT_COLLECTED,
            "protocols": [],
        }
    first = rows[0]
    protocols: list[str] = []
    for r in rows:
        proto = _nonempty_str(_attr(r, "protocol"))
        if proto and proto not in protocols:
            protocols.append(proto)
    return {
        "issuer": _nonempty_str(_attr(first, "issuer")) or INTEL_NOT_COLLECTED,
        "subject": _nonempty_str(_attr(first, "subject")) or INTEL_NOT_COLLECTED,
        "sans": _list_of_str(_attr(first, "sans")),
        "not_before": _nonempty_str(_attr(first, "not_before")) or INTEL_NOT_COLLECTED,
        "not_after": _nonempty_str(_attr(first, "not_after")) or INTEL_NOT_COLLECTED,
        "protocols": protocols,
    }


def _ports_from_context(vc: Any, recon: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalise port rows from valhalla port-exposure or pipeline_ports."""
    rows = _attr(vc, "port_exposure_table_rows") or recon.get("pipeline_ports") or []
    out: list[dict[str, Any]] = []
    if not isinstance(rows, (list, tuple)):
        return out
    for r in rows:
        if isinstance(r, dict):
            port = r.get("port") or r.get("number")
            proto = r.get("protocol") or r.get("proto") or "tcp"
            service = r.get("service") or r.get("service_name") or ""
        else:
            port = _attr(r, "port")
            proto = _attr(r, "protocol", "tcp")
            service = _attr(r, "service", "")
        if port is None:
            continue
        out.append(
            {
                "port": str(port),
                "proto": str(proto or "tcp"),
                "service": _nonempty_str(service) or "",
            }
        )
    return out


# ---------------------------------------------------------------------------
# Deterministic executive summary (NOT LLM remediation) — prompt §4.5
# ---------------------------------------------------------------------------


def build_executive_summary(
    report_data: ReportData,
    counts: dict[str, int],
    inventory: list[dict[str, Any]],
) -> str:
    """Deterministic exec summary from numbers + top titles (no recommendations).

    Prefers an existing non-LLM ``executive_summary`` when present and
    meaningful; otherwise synthesises a stable sentence from the severity
    distribution and the highest-severity finding titles.
    """
    existing = (getattr(report_data, "executive_summary", None) or "").strip()
    if existing and not _looks_like_skipped(existing):
        return existing

    target = (getattr(report_data, "target", None) or "the target").strip() or "the target"
    total = sum(counts.values())
    dist = (
        f"{counts['critical']} critical, {counts['high']} high, "
        f"{counts['medium']} medium, {counts['low']} low and {counts['info']} informational"
    )
    top_titles = [row["title"] for row in inventory[:3] if row.get("title")]
    highlight = ""
    if top_titles:
        highlight = " Highlights include " + "; ".join(top_titles) + "."
    noun = "finding" if total == 1 else "findings"
    return (
        f"The scan of {target} identified {total} {noun}. "
        f"The severity distribution is {dist}.{highlight}"
    ).strip()


def _looks_like_skipped(text: str) -> bool:
    low = text.lower()
    return "ai generation skipped" in low or "could not generate" in low or "skipped_no_llm" in low


# ---------------------------------------------------------------------------
# The one free-tier payload every format renders
# ---------------------------------------------------------------------------


def build_free_payload(
    report_data: ReportData,
    jinja_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble the single free-tier projection shared by all five formats.

    ``report_data`` MUST already be the Midgard-projected ``ReportData``
    (post ``classify_for_tier(..., MIDGARD)``). The returned dict carries only
    free-tier content: meta, severity counts, target intelligence, the finding
    inventory, exactly one teaser writeup, a deterministic executive summary
    and the static upsell. It never contains timeline / phase outputs /
    evidence / screenshots / remediation / PoC.
    """
    findings = list(getattr(report_data, "findings", None) or [])
    counts = severity_counts(findings)
    inventory = finding_inventory(findings)
    teaser = build_teaser_writeup(select_teaser_finding(findings))
    intel = build_midgard_intel(jinja_context, report_data)
    exec_summary = build_executive_summary(report_data, counts, inventory)

    watermark = ""
    if isinstance(jinja_context, dict):
        watermark = str(jinja_context.get("pdf_watermark") or "")

    return {
        "meta": {
            "target": getattr(report_data, "target", None) or "",
            "tier": "midgard",
            "free_scan": True,
            "scan_id": getattr(report_data, "scan_id", None) or "",
            "report_id": getattr(report_data, "report_id", None) or "",
            "generated_at": getattr(report_data, "created_at", None) or "",
            "watermark": watermark,
        },
        "severity_counts": counts,
        "target_intelligence": intel,
        "findings": inventory,
        "sample_finding": teaser,
        "executive_summary": exec_summary,
        "upsell": UPSELL_TEXT,
    }


__all__ = [
    "INTEL_NOT_ASSESSED",
    "INTEL_NOT_COLLECTED",
    "UPSELL_TEXT",
    "build_executive_summary",
    "build_free_payload",
    "build_midgard_intel",
    "build_teaser_writeup",
    "finding_inventory",
    "select_teaser_finding",
    "severity_counts",
]
