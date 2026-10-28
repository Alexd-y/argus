"""Paid-tier (Asgard) report projection — single source of truth for the five
export formats (PDF, HTML, JSON, XML, CSV).

Mirrors :mod:`src.reports.midgard_free` for the first **paid** tier. Product
contract (sold with exactly this description, which is the content contract):

    "Unlocks every critical and important finding with evidence and what to fix,
    adds TLS and header analysis, and watches the dark web for leaked
    credentials. Rescans this target four times a month."

``build_asgard_payload`` is **pure** (no I/O, no DB, no logging of payload
bodies). It consumes the already tier-projected :class:`ReportData` — i.e. the
output of ``classify_for_tier(data, ReportTier.ASGARD)`` — plus the production
Jinja ``template_context`` collected by the report pipeline, and derives the one
payload every format renders:

    meta, severity_counts, findings[], tls_analysis, header_analysis,
    dark_web, owasp_alignment, ai_conclusions

Asgard is **wider than Midgard** (full findings + remediation + roadmap + the
paid TLS/header/dark-web sections) but **narrower than Valhalla**: no raw
evidence dumps, no multi-step exploit chains, no raw tool output, no phase
artefacts, no object-key register, no PoC/exploit command strings. Those remain
Valhalla-only. Nothing here reads ``proof_of_concept``, ``raw_request``,
``raw_response``, ``tool_command``, ``verification_command`` or object keys.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from src.api.schemas import Finding
    from src.reports.generators import ReportData

# ``on_absent`` sentinels (midgard discipline): distinguish "did not run" from
# "ran, found nothing".
NOT_ASSESSED = "not assessed"

# Plan catalogue — drive price/blurb/cadence from config, not literals in the
# template, so Valhalla/other plans differ (prompt §3.4). Kept here as the Asgard
# plan record; a settings-backed catalogue can override it later.
ASGARD_PLAN: dict[str, str] = {
    "price": "CA$1,891/month",
    "blurb": (
        "Unlocks every critical and important finding with evidence and what to "
        "fix, adds TLS and header analysis, and watches the dark web for leaked "
        "credentials. Rescans this target four times a month."
    ),
    "rescan_cadence": "4 rescans / month",
    "tier_label": "Asgard",
    "tier_focus": (
        "Security-team brief — full findings, remediation, TLS & header "
        "analysis, leaked-credential watch"
    ),
}

# The six HTTP security headers Asgard reviews (prompt §3.2).
_REVIEWED_HEADERS: tuple[tuple[str, str], ...] = (
    (
        "Content-Security-Policy",
        "Pin allowed script/style origins; report-only first, then enforce.",
    ),
    ("Strict-Transport-Security", "max-age=31536000; includeSubDomains once HTTPS-ready."),
    ("Referrer-Policy", "strict-origin-when-cross-origin."),
    ("Permissions-Policy", "Deny unused browser features (geolocation, camera, etc.)."),
    ("X-Content-Type-Options", "nosniff — keep."),
    ("X-Frame-Options", "SAMEORIGIN — keep (or fold into CSP frame-ancestors)."),
)

_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}
_SEVERITY_BUCKETS = ("critical", "high", "medium", "low", "info")


# ---------------------------------------------------------------------------
# small pure helpers
# ---------------------------------------------------------------------------


def _sev(severity: str | None) -> str:
    s = (severity or "").lower().strip()
    if s in ("informational", "info"):
        return "info"
    return s if s in _SEVERITY_BUCKETS else "info"


def _cvss_of(f: Finding) -> float | None:
    v = getattr(f, "cvss", None)
    if v is None:
        v = getattr(f, "cvss_score", None)
    try:
        return float(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def _priority_key(f: Finding) -> tuple[int, float, str, str]:
    rank = _SEVERITY_RANK.get(_sev(getattr(f, "severity", None)), 99)
    cvss = _cvss_of(f)
    return (
        rank,
        -cvss if cvss is not None else 0.0,
        (getattr(f, "title", None) or "").lower(),
        getattr(f, "cwe", None) or "",
    )


def _finding_id(f: Finding) -> str:
    return str(getattr(f, "finding_id", None) or getattr(f, "id", None) or "")


def _nonempty(val: Any) -> str | None:
    if isinstance(val, str) and val.strip():
        return val.strip()
    return None


def _attr(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = dict.fromkeys(_SEVERITY_BUCKETS, 0)
    for f in findings:
        counts[_sev(getattr(f, "severity", None))] += 1
    return counts


def owasp_label(owasp_category: str | None) -> str:
    """Format a finding's OWASP category as the 2021 display label.

    Reuses the canonical internal→2021 remap (``generators._VALHALLA_OWASP_2021_DISPLAY``)
    so the label (e.g. ``A03:2021 — Injection``) matches the rest of the platform.
    """
    code = (owasp_category or "").strip().upper()
    if not code:
        return ""
    from src.reports.generators import _VALHALLA_OWASP_2021_DISPLAY

    mapped = _VALHALLA_OWASP_2021_DISPLAY.get(code)
    if mapped:
        display_code, title, _desc = mapped
        return f"{display_code} — {title}"
    return code


def _status_of(f: Finding) -> str:
    """confirmed | suspected | informational — from evidence/validation state."""
    if _sev(getattr(f, "severity", None)) == "info":
        return "informational"
    ec = (getattr(f, "evidence_classification", None) or "").lower().strip()
    if ec in ("validated", "observed"):
        return "confirmed"
    if ec in ("candidate", "inconclusive"):
        return "suspected"
    vs = (getattr(f, "validation_status", None) or "").lower().strip()
    if vs in ("validated", "partially_validated"):
        return "confirmed"
    return "suspected"


def _confidence_of(f: Finding) -> str:
    if _sev(getattr(f, "severity", None)) == "info":
        return "informational"
    c = (getattr(f, "confidence", None) or "").lower().strip()
    return {"confirmed": "high", "likely": "high", "possible": "medium", "advisory": "low"}.get(
        c, c or "medium"
    )


# Deterministic remediation recipes, keyed by CWE then title keyword. First match
# wins. Every Critical/High must end up with a non-empty list (gate A-G1), so a
# generic fallback is always provided.
_REMEDIATION_RULES: tuple[tuple[tuple[str, ...], tuple[str, ...], list[str]], ...] = (
    (
        ("cwe-89",),
        ("sql inject", "sqli"),
        [
            "Use parameterized queries / prepared statements (or the ORM's bound-parameter API) for every query that consumes request input — never string-concatenate request input into SQL.",
            "Validate and canonicalize the input server-side and reject non-conforming values before they reach the data layer.",
            "Run the application's database account with least privilege (no DDL, no access to unrelated schemas).",
        ],
    ),
    (
        ("cwe-79",),
        ("xss", "cross-site script"),
        [
            "Context-encode all untrusted output (HTML/attribute/JS/URL) and prefer framework auto-escaping.",
            "Deploy a Content-Security-Policy that pins allowed script origins as a second line of defense.",
        ],
    ),
    (
        ("cwe-693", "cwe-16"),
        ("security header", "missing header", "http security"),
        [
            "Deploy a Content-Security-Policy that pins allowed script/style origins; start in Content-Security-Policy-Report-Only, review reports, then enforce.",
            "Add Strict-Transport-Security: max-age=31536000; includeSubDomains once every endpoint is served over HTTPS.",
            "Set Referrer-Policy: strict-origin-when-cross-origin and a least-privilege Permissions-Policy.",
        ],
    ),
    (
        ("cwe-16", "cwe-358"),
        ("spf",),
        [
            "Publish a single SPF record authorizing exactly the hosts that send mail for the domain, terminated with ~all (soft-fail) and tightened to -all once the sender list is confirmed.",
        ],
    ),
    (
        ("cwe-16", "cwe-358"),
        ("dkim",),
        [
            "Enable DKIM signing at the mail provider and publish the public key at the advertised selector; then move DMARC toward p=quarantine / p=reject once SPF and DKIM align.",
        ],
    ),
    (
        ("cwe-16",),
        ("dmarc",),
        [
            "Publish a DMARC aggregate-reporting address; review reports for 2–4 weeks, then raise the policy to p=quarantine and ultimately p=reject.",
        ],
    ),
    (
        ("cwe-350", "cwe-349"),
        ("dnssec",),
        [
            "Enable DNSSEC at the authoritative DNS provider and publish the DS record at the registrar; verify the chain of trust before relying on it.",
        ],
    ),
    (
        ("cwe-295",),
        ("caa",),
        [
            "Publish a CAA record naming only the CA(s) authorized to issue for the domain, with an iodef mailbox for violation reports.",
        ],
    ),
    (
        ("cwe-310", "cwe-326", "cwe-327"),
        ("tls", "ssl", "cipher", "cleartext"),
        [
            "Terminate TLS in front of the service and serve only TLS 1.2+ with an ECDHE/AEAD cipher suite; redirect HTTP to HTTPS and add HSTS.",
        ],
    ),
    (
        ("cwe-307",),
        ("rate limit", "rate-limit", "brute", "lockout"),
        [
            "Enforce per-account and per-IP rate limiting with exponential backoff, plus temporary lockout and CAPTCHA/step-up after a threshold of failures.",
        ],
    ),
    (
        ("cwe-200",),
        ("fingerprint", "disclos", "banner", "version"),
        [
            "Suppress or genericize framework banners and X-Powered-By style headers at the reverse proxy.",
        ],
    ),
)


def _remediation_steps(f: Finding) -> list[str]:
    cwe = (getattr(f, "cwe", None) or "").lower()
    title = (getattr(f, "title", None) or "").lower()
    if _sev(getattr(f, "severity", None)) == "info":
        return ["No action required; informational."]
    for cwes, kws, steps in _REMEDIATION_RULES:
        cwe_hit = any(c in cwe for c in cwes) if cwes else False
        kw_hit = any(k in title for k in kws) if kws else False
        if cwe_hit or kw_hit:
            return list(steps)
    # Advisory notes on the finding, if any (never PoC).
    notes = _nonempty(getattr(f, "applicability_notes", None))
    if notes:
        return [notes]
    return [
        "Review the finding and apply the vendor-recommended fix or a compensating control, then re-test."
    ]


def _safe_evidence(f: Finding) -> str:
    """Non-intrusive evidence prose — safe fields only, never PoC/raw."""
    for attr in ("observed_impact", "tool_output_excerpt", "description"):
        val = _nonempty(getattr(f, attr, None))
        if val:
            return val
    return ""


def _finding_to_row(f: Finding) -> dict[str, Any]:
    description = _nonempty(getattr(f, "description", None)) or (getattr(f, "title", None) or "")
    why = _nonempty(getattr(f, "observed_impact", None)) or (
        "This weakness reduces the security posture of the asset and should be "
        "remediated to preserve defense-in-depth."
    )
    status = _status_of(f)
    return {
        "id": _finding_id(f),
        "title": (getattr(f, "title", None) or "").strip(),
        "severity": _sev(getattr(f, "severity", None)),
        "cwe": _nonempty(getattr(f, "cwe", None)) or "—",
        "owasp": owasp_label(getattr(f, "owasp_category", None)),
        "cvss": _cvss_of(f),
        "cvss_vector": _nonempty(getattr(f, "cvss_vector", None)),
        # Exploitation outcome (C2): executive-safe marker + one-line summary (no raw
        # PoC — Asgard stays the sanitized paid tier; verbatim PoC remains Valhalla).
        "exploit_demonstrated": bool(getattr(f, "exploit_demonstrated", False)),
        "exploit_summary": _nonempty(getattr(f, "exploit_summary", None)),
        "asset": (
            _nonempty(getattr(f, "affected_asset", None))
            or _nonempty(getattr(f, "affected_endpoint", None))
            or ""
        ),
        "status": status,
        "confidence": _confidence_of(f),
        "what": description,
        "why": why,
        "evidence": _safe_evidence(f),
        # Asgard has no dedicated negative-control field on Finding; kept in the
        # schema (Valhalla carries it) but null here unless a collector supplies it.
        "negative_control": None,
        "remediation": _remediation_steps(f),
        "validation": (
            "No action required; informational."
            if status == "informational"
            else "Re-test the finding after the fix and confirm the weakness no longer reproduces."
        ),
    }


# ---------------------------------------------------------------------------
# Paid sections
# ---------------------------------------------------------------------------


def build_tls_analysis(
    report_data: ReportData, jinja_context: dict[str, Any] | None
) -> dict[str, Any]:
    """TLS & Transport analysis (C2). Reads the existing TLS/SSL collector.

    When the endpoint is cleartext HTTP, state it plainly and mark rows ``fail``
    — never fabricate a certificate.
    """
    ctx = jinja_context or {}
    vc = ctx.get("valhalla_context") or {}
    target = (getattr(report_data, "target", None) or "").strip()
    is_cleartext = target.lower().startswith("http://")
    ssl_rows = _attr(vc, "ssl_tls_table_rows") or []

    if is_cleartext or not ssl_rows:
        summary = (
            "The in-scope service is published on cleartext HTTP with no TLS layer "
            "on the scanned endpoint. No certificate, protocol or cipher could be "
            "negotiated. Any credentials or session tokens sent to this service "
            "travel unencrypted and are exposed to on-path interception."
            if is_cleartext
            else "TLS posture could not be assessed for the scanned endpoint (no TLS data collected)."
        )
        status = "fail" if is_cleartext else NOT_ASSESSED
        rows = [
            {
                "check": "Transport",
                "result": "Cleartext HTTP" if is_cleartext else NOT_ASSESSED,
                "status": status,
                "detail": (
                    "Service answered over http://; no TLS on the scanned port."
                    if is_cleartext
                    else "No transport data collected."
                ),
            },
            {
                "check": "Negotiated protocol",
                "result": "None (no TLS)" if is_cleartext else NOT_ASSESSED,
                "status": status,
                "detail": (
                    "TLS 1.2 / 1.3 could not be negotiated — no listener."
                    if is_cleartext
                    else "No protocol negotiated."
                ),
            },
            {
                "check": "Certificate chain",
                "result": "Not presented" if is_cleartext else NOT_ASSESSED,
                "status": status,
                "detail": (
                    "No X.509 certificate served on the scanned endpoint."
                    if is_cleartext
                    else "No certificate observed."
                ),
            },
            {
                "check": "HSTS",
                "result": "Absent" if is_cleartext else NOT_ASSESSED,
                "status": status,
                "detail": "Strict-Transport-Security header not set (see headers section).",
            },
        ]
        return {
            "summary": summary,
            "rows": rows,
            "remediation": [
                "Terminate TLS in front of the service (reverse proxy or load balancer) and serve only TLS 1.2+ with an ECDHE/AEAD cipher suite.",
                "Redirect HTTP to HTTPS and add HSTS once every endpoint is HTTPS-ready.",
                "Automate certificate issuance and renewal; keep the chain current.",
            ],
        }

    rows: list[dict[str, Any]] = []
    for r in ssl_rows:
        check = _nonempty(_attr(r, "check")) or _nonempty(_attr(r, "label")) or "TLS"
        result = _nonempty(_attr(r, "result")) or _nonempty(_attr(r, "value")) or ""
        st = (_nonempty(_attr(r, "status")) or "pass").lower()
        rows.append(
            {
                "check": check,
                "result": result,
                "status": st,
                "detail": _nonempty(_attr(r, "detail")) or "",
            }
        )
    return {
        "summary": "Negotiated TLS parameters for the scanned endpoint.",
        "rows": rows,
        "remediation": [
            "Keep TLS 1.2+ only with ECDHE/AEAD cipher suites and a current certificate chain.",
            "Enforce HSTS with a long max-age once every endpoint is HTTPS-ready.",
        ],
    }


def build_header_analysis(
    report_data: ReportData, jinja_context: dict[str, Any] | None = None
) -> dict[str, Any]:
    """HTTP security-header analysis (C2). ``present`` derived from observed
    response headers — never guessed."""
    observed = _observed_header_names(report_data, jinja_context)
    rows: list[dict[str, Any]] = []
    present_count = 0
    for name, rec in _REVIEWED_HEADERS:
        present = name.lower() in observed if observed is not None else False
        if present:
            present_count += 1
        rows.append(
            {
                "header": name,
                "present": present,
                "recommended": (f"Present: {rec}" if present else rec),
            }
        )
    if observed is None:
        summary = "Security-relevant response headers were not captured for this target; review is pending."
    else:
        summary = (
            f"Security-relevant response headers reviewed. {present_count} of "
            f"{len(_REVIEWED_HEADERS)} reviewed headers are present; the remainder are missing."
        )
    return {"summary": summary, "rows": rows}


def _observed_header_names(
    report_data: ReportData, jinja_context: dict[str, Any] | None
) -> set[str] | None:
    """Lower-cased set of observed response-header names, or None if not collected."""
    names: set[str] = set()
    seen = False
    for f in getattr(report_data, "findings", None) or []:
        rh = getattr(f, "response_headers", None)
        if isinstance(rh, dict) and rh:
            seen = True
            names.update(k.lower() for k in rh)
    ctx = jinja_context or {}
    vc = ctx.get("valhalla_context") or {}
    hdr_rows = _attr(vc, "security_headers_table_rows") or []
    for r in hdr_rows:
        hname = _nonempty(_attr(r, "header")) or _nonempty(_attr(r, "name"))
        present = _attr(r, "present")
        if hname:
            seen = True
            if present in (True, "true", "yes", "present"):
                names.add(hname.lower())
    return names if seen else None


def build_dark_web_summary(
    report_data: ReportData, jinja_context: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Leaked-credential (dark-web) monitoring summary (C3). Counts + status
    only — never plaintext secrets in the document.

    ``jinja_context`` is accepted for signature parity with the other section
    builders. The summary is derived from ``report_data.dark_web_monitoring``
    (the collected Dark Web Monitoring observations) when present, and falls back
    to ``report_data.hibp_pwned_password_summary`` when a DWM sweep did not run.
    Masked counts + redacted summaries only — never raw records or plaintext.
    """
    _ = jinja_context
    target = (getattr(report_data, "target", None) or "").strip()
    domain = _domain_of(target)
    last_checked = getattr(report_data, "created_at", None) or ""

    # Preferred source: collected Dark Web Monitoring observations (C4 GAP A).
    dwm = getattr(report_data, "dark_web_monitoring", None)
    if (
        isinstance(dwm, dict)
        and dwm.get("status")
        and dwm.get("status")
        not in (
            "disabled",
            "not_entitled",
        )
    ):
        new_exposures = int(dwm.get("observation_count", 0) or 0)
        total_tracked = int(dwm.get("selectors_count", 0) or 0)
        last_checked = dwm.get("generated_at") or last_checked
        rows = []
        for o in (dwm.get("observations") or [])[:50]:
            if not isinstance(o, dict):
                continue
            rows.append(
                {
                    "exposure_type": str(o.get("exposure_type", "")),
                    "severity": str(o.get("severity", "")),
                    "source_network": str(o.get("source_network", "")),
                    "source_ref": o.get("source_ref") or None,
                    "confidence": o.get("confidence") or None,
                    "evidence_tier": int(o.get("evidence_tier", 1) or 1),
                    # masked/redacted only — never raw_object_key / plaintext
                    "summary": o.get("redacted_summary") or o.get("summary") or None,
                }
            )
        found = new_exposures > 0
        summary = (
            "Dark-web monitoring watches the target's selectors against breach, paste "
            "and dark-web corpora. "
            + (
                f"This run surfaced {new_exposures} exposure observation(s) for the monitored selectors. "
                if found
                else "This run found no dark-web exposures for the monitored selectors. "
            )
            + "Masked counts and redacted summaries are shown here; full records stay in "
            "the evidence locker, never in plaintext in this document."
        )
        return {
            "summary": summary,
            "monitored_domain": domain or NOT_ASSESSED,
            "sources_checked": "Tor/onion indexes, paste sites, breach & credential-dump feeds",
            "new_exposures": new_exposures,
            "total_tracked": total_tracked,
            "last_checked": last_checked,
            "status": str(dwm.get("status", "")),
            "counts_by_severity": dwm.get("counts_by_severity") or {},
            "counts_by_exposure": dwm.get("counts_by_exposure") or {},
            "rows": rows,
        }

    # Fallback: HIBP breach summary (legacy behaviour when no DWM sweep ran).
    summary_src = getattr(report_data, "hibp_pwned_password_summary", None)
    new_exposures = 0
    total_tracked = 0
    if isinstance(summary_src, dict):
        new_exposures = int(summary_src.get("new_exposures", summary_src.get("breaches", 0)) or 0)
        total_tracked = int(summary_src.get("total_tracked", summary_src.get("accounts", 0)) or 0)
        last_checked = summary_src.get("last_checked") or last_checked
    found = new_exposures > 0
    summary = (
        "Leaked-credential monitoring watches the target domain against breach and "
        "paste corpora and dark-web dumps. "
        + (
            f"This run surfaced {new_exposures} new exposure(s) for the monitored domain; "
            if found
            else "This run found no newly exposed credentials for the monitored domain. "
        )
        + "Monitoring continues between the four monthly rescans; counts only are shown "
        "here and full records are delivered to the security team through the evidence "
        "locker, never in plaintext in this document."
    )
    return {
        "summary": summary,
        "monitored_domain": domain or NOT_ASSESSED,
        "sources_checked": "Public breach corpora, paste sites, credential-dump feeds",
        "new_exposures": new_exposures,
        "total_tracked": total_tracked,
        "last_checked": last_checked,
        "rows": [],  # counts-only; any match stays in the evidence locker
    }


def _domain_of(target: str) -> str:
    t = target.strip()
    for scheme in ("http://", "https://"):
        if t.lower().startswith(scheme):
            t = t[len(scheme) :]
            break
    t = t.split("/", 1)[0]
    t = t.split(":", 1)[0]
    return t


def build_owasp_alignment(findings: list[Finding]) -> list[dict[str, Any]]:
    """Rows of OWASP-2021 categories that have at least one finding (label, count)."""
    counts: dict[str, int] = {}
    for f in findings:
        label = owasp_label(getattr(f, "owasp_category", None))
        if label:
            counts[label] = counts.get(label, 0) + 1
    return [{"category": k, "count": v} for k, v in sorted(counts.items())]


# ---------------------------------------------------------------------------
# AI Conclusions — gated prose with deterministic fallback (prompt §5)
# ---------------------------------------------------------------------------


def _deterministic_conclusions(
    report_data: ReportData, counts: dict[str, int], rows: list[dict[str, Any]]
) -> dict[str, Any]:
    target = (getattr(report_data, "target", None) or "the target").strip() or "the target"
    total = sum(counts.values())
    top = [r["title"] for r in rows[:3] if r.get("title")]
    highlight = (" The most urgent items are " + "; ".join(top) + ".") if top else ""
    noun = "finding" if total == 1 else "findings"
    desc = (
        f"The assessment of {target} surfaced {total} {noun}: "
        f"{counts['critical']} critical, {counts['high']} high, {counts['medium']} medium, "
        f"{counts['low']} low and {counts['info']} informational.{highlight} "
        "The findings and their remediation are detailed above."
    )
    risk = (
        "Prioritise the critical and high-severity findings: together they represent "
        "the shortest path to account or data compromise, and the configuration gaps "
        "remove the defense-in-depth that would otherwise contain their impact."
    )
    roadmap = [
        "Now — remediate every critical and high-severity finding.",
        "This sprint — close the medium-severity configuration and transport gaps (TLS, security headers, rate limiting).",
        "This quarter — publish the missing email-authentication and DNS-integrity records and move DMARC toward enforcement.",
    ]
    return {
        "vulnerability_description": desc,
        "business_risk": risk,
        "prioritized_roadmap": roadmap,
    }


def build_ai_conclusions(
    report_data: ReportData,
    counts: dict[str, int],
    rows: list[dict[str, Any]],
    jinja_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Gated AI conclusions. Uses LLM slot text only when it passes the prose
    gate; otherwise the deterministic fallback. Never publishes an empty string
    as 'ok' (the D3 fail-soft defect)."""
    deterministic = _deterministic_conclusions(report_data, counts, rows)
    ctx = jinja_context or {}
    ai_slots = ctx.get("ai_sections") or ctx.get("ai_slots") or {}
    if not isinstance(ai_slots, dict):
        return deterministic

    from src.reports.prose_gate import ProseSeverity, evaluate_prose

    def _accept(text: str | None, section: str) -> bool:
        # Never accept a skip/failure placeholder as 'ok' (D3 fail-soft defect).
        if not text or _looks_like_skipped(text):
            return False
        violations = evaluate_prose(text, section=section, require_references=False)
        return not any(v.severity == ProseSeverity.BLOCK for v in violations)

    out = dict(deterministic)
    desc = _nonempty(ai_slots.get("vulnerability_description"))
    risk = _nonempty(ai_slots.get("business_risk"))
    if _accept(desc, "vulnerability_description"):
        out["vulnerability_description"] = desc
    if _accept(risk, "business_risk"):
        out["business_risk"] = risk
    return out


def _looks_like_skipped(text: str) -> bool:
    low = (text or "").lower()
    return (
        "ai generation skipped" in low
        or "could not generate" in low
        or "skipped_no_llm" in low
        or "generation failed" in low
    )


# ---------------------------------------------------------------------------
# The one payload every format renders
# ---------------------------------------------------------------------------


def build_asgard_payload(
    report_data: ReportData,
    jinja_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Single Asgard projection shared by PDF, HTML, JSON, XML, CSV.

    ``report_data`` MUST already be tier-projected
    (``classify_for_tier(data, ReportTier.ASGARD)``). Pure.
    """
    from src.reports.valhalla_report_context import get_brand

    findings = sorted(getattr(report_data, "findings", None) or [], key=_priority_key)
    counts = severity_counts(findings)
    rows = [_finding_to_row(f) for f in findings]
    ctx = jinja_context or {}

    target = getattr(report_data, "target", None) or ""
    completed_at = getattr(report_data, "created_at", None) or ""
    meta = {
        "brand_name": get_brand().name,
        "tier": "asgard",
        "tier_label": ASGARD_PLAN["tier_label"],
        "tier_focus": ASGARD_PLAN["tier_focus"],
        "plan_price": ASGARD_PLAN["price"],
        "plan_blurb": ASGARD_PLAN["blurb"],
        "rescan_cadence": ASGARD_PLAN["rescan_cadence"],
        "target": target,
        "scan_id": getattr(report_data, "scan_id", None) or "",
        "report_id": getattr(report_data, "report_id", None) or "",
        "tenant_id": getattr(report_data, "tenant_id", None) or "",
        "scope": f"{target} (external, authorized)" if target else "",
        "generated_at": str(ctx.get("generated_at") or completed_at or ""),
        "completed_at": str(completed_at or ""),
        "engagement_window": str(ctx.get("engagement_window") or ""),
    }
    return {
        "meta": meta,
        "severity_counts": counts,
        "findings": rows,
        "tls_analysis": build_tls_analysis(report_data, ctx),
        "header_analysis": build_header_analysis(report_data, ctx),
        "dark_web": build_dark_web_summary(report_data, ctx),
        "owasp_alignment": build_owasp_alignment(findings),
        "ai_conclusions": build_ai_conclusions(report_data, counts, rows, ctx),
    }


__all__ = [
    "ASGARD_PLAN",
    "NOT_ASSESSED",
    "build_ai_conclusions",
    "build_asgard_payload",
    "build_dark_web_summary",
    "build_header_analysis",
    "build_owasp_alignment",
    "build_tls_analysis",
    "owasp_label",
    "severity_counts",
]
