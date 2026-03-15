"""Anomaly builder — produces anomalies.md and anomalies_structured.json for Stage 1 report.

Detects unusual routing behavior, mismatched host purpose vs observed behavior,
legacy/service subdomains returning shared platform pages. Generates hypotheses
for Threat Modeling and next manual validation. Supports LLM interpretation with
rule-based fallback.

Structured output (anomalies_structured.json) provides type/source taxonomy for
programmatic rendering (e.g. html_report_builder) with labels and citations.
"""

import csv
import json
import logging
from collections.abc import Callable
from pathlib import Path

from src.core.llm_config import get_llm_client, has_any_llm_key

logger = logging.getLogger(__name__)

# Artifact paths for source attribution
SOURCE_HTTP_PROBE = "04_live_hosts/http_probe.csv"
SOURCE_LIVE_HOSTS = "live_hosts_detailed.csv"
SOURCE_CLASSIFICATION = "subdomain_classification.csv"

# Platform signatures that indicate shared/hosting infra (often 404 for service subdomains)
PLATFORM_SIGNATURES = frozenset(
    {"vercel", "netlify", "cloudflare", "github.com", "amazons3", "fastly"}
)

# Subdomain roles that expect dedicated service, not generic 404
SERVICE_LIKE_ROLES = frozenset(
    {"mail", "hosting/admin", "auth/sso", "special-purpose", "dev/test/stage"}
)

# Subdomain prefix patterns for service-like hosts (fallback when classification missing)
SERVICE_LIKE_PREFIXES = frozenset(
    {
        "mail.", "smtp.", "imap.", "pop.", "webmail.", "autodiscover.",
        "cpanel.", "admin.", "portal.", "dashboard.", "whm.", "plesk.",
        "auth.", "login.", "sso.", "api.", "vpn.", "git.", "jenkins.",
        "dev.", "staging.", "test.", "stage.", "uat.",
    }
)

ANOMALY_PROMPT_TEMPLATE = """You are a security analyst reviewing recon anomalies for threat modeling.

## Context
The following anomalies were detected from Stage 1 recon (subdomain enumeration, live host probing, tech fingerprinting):

{anomalies_json}

## Task
1. Interpret each anomaly in terms of security/recon significance.
2. Generate 1-3 hypotheses per anomaly for manual validation and threat modeling.
3. Prioritize: misconfigurations that could expose sensitive services, subdomains that suggest forgotten infrastructure, routing that bypasses expected controls.

## Output Format (JSON)
Return valid JSON only:
{{
  "interpretations": [
    {{"anomaly_id": "...", "significance": "...", "hypotheses": ["...", "..."]}}
  ],
  "summary": "Brief overall assessment"
}}

If you cannot process, return: {{"error": "reason"}}
"""

COVERAGE_GAPS_TEMPLATE = """## Coverage Gaps

### What Stage 1 Covered
- Subdomain enumeration and DNS resolution
- Live host probing (HTTP/HTTPS)
- Technology fingerprinting (Server headers)
- Subdomain role classification
- CNAME mapping and redirect chains
- Basic endpoint inventory (robots.txt, security.txt, etc.)

### What Stage 1 Did Not Cover
- Deep URL crawling and path discovery
- JavaScript analysis (secrets, endpoints, API discovery)
- Parameter and form analysis
- Port scanning beyond 80/443
- TLS certificate chain analysis
- Content clustering and deduplication
- OSINT correlation
- Manual validation of hypotheses

### Deeper Recon Steps Skipped
- Stage 2: URL crawling, JS analysis, param discovery
- Stage 3: API surface mapping, auth flow analysis
- Stage 4: Content discovery, fuzzing
- Stage 5: OSINT, certificate transparency, historical data

### Recommended Next Steps
1. Run URL crawler on live hosts to discover paths and forms
2. Extract and analyze JavaScript for secrets and API endpoints
3. Validate mail/admin subdomains manually (MX records, SMTP probes)
4. Check CNAME targets for takeover opportunities
5. Run port scan on critical hosts (if in scope)
6. Perform TLS/certificate analysis for misconfigurations
"""


def _load_csv(path: Path) -> list[dict]:
    """Load CSV into list of dicts. Returns empty list if file missing."""
    if not path.exists():
        return []
    try:
        with path.open(encoding="utf-8", errors="replace", newline="") as f:
            return list(csv.DictReader(f))
    except (OSError, csv.Error) as e:
        logger.warning("Failed to load CSV", extra={"path": str(path), "error": str(e)})
        return []


def _is_service_like_subdomain(subdomain: str, role: str | None) -> bool:
    """Check if subdomain name/role suggests dedicated service (mail, admin, etc.)."""
    if role and role in SERVICE_LIKE_ROLES:
        return True
    sub_lower = subdomain.lower()
    return any(sub_lower.startswith(p) for p in SERVICE_LIKE_PREFIXES)


def _is_platform_server(server: str) -> bool:
    """Check if Server header indicates shared platform (Vercel, Netlify, etc.)."""
    if not server:
        return False
    s = server.lower()
    return any(plat in s for plat in PLATFORM_SIGNATURES)


def _detect_rule_based_anomalies(
    classification: list[dict],
    live_hosts: list[dict],
    _tech_profile: list[dict],
) -> list[dict]:
    """Detect anomalies using rule-based heuristics."""
    anomalies: list[dict] = []
    seen_keys: set[str] = set()

    host_to_role: dict[str, str] = {}
    for row in classification:
        host = (row.get("subdomain") or "").strip()
        role = (row.get("role") or "").strip()
        if host:
            host_to_role[host] = role

    host_to_live: dict[str, dict] = {}
    for row in live_hosts:
        host = (row.get("host") or "").strip()
        if host:
            host_to_live[host] = row

    for row in live_hosts:
        host = (row.get("host") or "").strip()
        status = (row.get("status") or "").strip()
        server = (row.get("server") or "").strip()
        notes = (row.get("notes") or "").strip()

        if not host:
            continue

        role = host_to_role.get(host, "")
        is_service = _is_service_like_subdomain(host, role if role else None)
        is_platform = _is_platform_server(server)
        is_404 = status == "404"

        anomaly_desc: str | None = None
        taxonomy_type: str = "observation"
        source: str = SOURCE_HTTP_PROBE

        if is_service and is_404 and is_platform:
            anomaly_desc = f"{host} (role: {role or 'service-like'}) returns 404 on {server}"
            taxonomy_type = "evidence"
        elif is_service and is_404:
            anomaly_desc = f"{host} (role: {role or 'service-like'}) returns 404"
            taxonomy_type = "observation"
        elif is_service and is_platform and "shared" in notes.lower():
            anomaly_desc = f"{host} returns shared platform page ({server}) instead of dedicated service"
            taxonomy_type = "observation"
        elif role == "mail" and is_404:
            anomaly_desc = f"mail subdomain {host} returns 404 (expected mail service)"
            taxonomy_type = "inference"
            source = SOURCE_CLASSIFICATION
        elif role == "hosting/admin" and is_404:
            anomaly_desc = f"admin/hosting subdomain {host} returns 404 (expected cPanel/admin)"
            taxonomy_type = "inference"
            source = SOURCE_CLASSIFICATION

        if anomaly_desc:
            key = f"{host}|{anomaly_desc}"
            if key not in seen_keys:
                seen_keys.add(key)
                anomalies.append({
                    "id": f"anom_{len(anomalies) + 1}",
                    "type": taxonomy_type,
                    "source": source,
                    "host": host,
                    "status": status,
                    "server": server,
                    "description": anomaly_desc,
                    "role": role or "unknown",
                    "evidence": f"status={status}, server={server}, notes={notes}",
                })

    return anomalies


def _call_llm_default(_prompt: str, _context: dict) -> str:
    """Default no-op LLM callable when none configured."""
    return ""


def _interpret_with_llm(
    anomalies: list[dict],
    call_llm: Callable[[str, dict], str],
) -> dict:
    """Call LLM for interpretation. Returns {interpretations, summary} or empty dict on failure."""
    if not anomalies:
        return {}
    try:
        prompt = ANOMALY_PROMPT_TEMPLATE.format(
            anomalies_json=json.dumps(anomalies, indent=2, default=str)
        )
        response = call_llm(prompt, {"anomaly_count": len(anomalies)})
        if not response or not response.strip():
            return {}
        text = response.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(
                ln for ln in lines
                if not ln.startswith("```") and ln != "```"
            )
        data = json.loads(text)
        if data.get("error"):
            return {}
        return {
            "interpretations": data.get("interpretations", []),
            "summary": data.get("summary", ""),
        }
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.debug("LLM interpretation failed", extra={"error": str(e)})
        return {}


def _build_hypotheses_rule_based(anomalies: list[dict]) -> list[dict]:
    """Generate hypotheses from anomalies using rules (no LLM)."""
    hypotheses: list[dict] = []
    for a in anomalies:
        host = a.get("host", "")
        desc = a.get("description", "")
        anomaly_id = a.get("id", "")
        hypotheses.append({
            "anomaly_id": anomaly_id,
            "hypothesis": f"Verify {host}: {desc} — may indicate misconfiguration or forgotten infra",
            "priority": "high" if "mail" in desc or "admin" in desc else "medium",
        })
        hypotheses.append({
            "anomaly_id": anomaly_id,
            "hypothesis": f"Check CNAME/takeover potential for {host}",
            "priority": "medium",
        })
    return hypotheses


def _to_structured_hypotheses(
    hypotheses: list[dict],
    anomaly_sources: dict[str, str],
) -> list[dict]:
    """Convert hypotheses to structured format: {id, type, source, text}.

    Uses anomaly_sources mapping (anomaly_id -> artifact path) for proper source citation.
    """
    structured: list[dict] = []
    for i, h in enumerate(hypotheses):
        anomaly_id = h.get("anomaly_id", "")
        source = anomaly_sources.get(anomaly_id, SOURCE_CLASSIFICATION)
        structured.append({
            "id": f"hyp_{i + 1}",
            "type": "hypothesis",
            "source": source,
            "text": h.get("hypothesis", ""),
        })
    return structured


def _to_structured_anomalies(anomalies: list[dict]) -> list[dict]:
    """Convert anomalies to structured format for JSON output."""
    return [
        {
            "id": a.get("id", ""),
            "type": a.get("type", "observation"),
            "source": a.get("source", SOURCE_HTTP_PROBE),
            "host": a.get("host"),
            "status": a.get("status"),
            "server": a.get("server"),
            "description": a.get("description", ""),
        }
        for a in anomalies
    ]


def _build_coverage_gaps_structured() -> dict:
    """Build structured coverage gaps for JSON output."""
    return {
        "type": "coverage_gap",
        "source": "stage1_report",
        "items": [
            "Subdomain enumeration and DNS resolution",
            "Live host probing (HTTP/HTTPS)",
            "Technology fingerprinting (Server headers)",
            "Subdomain role classification",
            "CNAME mapping and redirect chains",
            "Basic endpoint inventory (robots.txt, security.txt, etc.)",
            "---",
            "Deep URL crawling and path discovery",
            "JavaScript analysis (secrets, endpoints, API discovery)",
            "Parameter and form analysis",
            "Port scanning beyond 80/443",
            "TLS certificate chain analysis",
            "Content clustering and deduplication",
            "OSINT correlation",
            "Manual validation of hypotheses",
            "---",
            "Run URL crawler on live hosts to discover paths and forms",
            "Extract and analyze JavaScript for secrets and API endpoints",
            "Validate mail/admin subdomains manually (MX records, SMTP probes)",
            "Check CNAME targets for takeover opportunities",
            "Run port scan on critical hosts (if in scope)",
            "Perform TLS/certificate analysis for misconfigurations",
        ],
    }


def build_anomalies(
    recon_dir: str | Path,
    call_llm: Callable[[str, dict], str] | None = None,
) -> tuple[str, dict]:
    """Build anomalies.md and structured data from Stage 1 artifacts.

    Args:
        recon_dir: Path to recon directory (e.g. .../recon/svalbard-stage1/)
        call_llm: Optional callable(prompt, context) -> str for AI interpretation.
                 If None or returns empty, uses rule-based heuristics only.

    Returns:
        Tuple of (markdown content for anomalies.md, structured dict for anomalies_structured.json)
    """
    base = Path(recon_dir)
    classification = _load_csv(base / "subdomain_classification.csv")
    live_hosts = _load_csv(base / "live_hosts_detailed.csv")
    tech_profile = _load_csv(base / "tech_profile.csv")

    anomalies = _detect_rule_based_anomalies(classification, live_hosts, tech_profile)

    if call_llm is None and has_any_llm_key():
        try:
            call_llm = get_llm_client()
        except Exception:
            call_llm = None
    llm = call_llm or _call_llm_default
    llm_result = _interpret_with_llm(anomalies, llm)
    interpretations = llm_result.get("interpretations", [])
    llm_summary = llm_result.get("summary") or None

    if interpretations:
        hypotheses = []
        for i in interpretations:
            if isinstance(i, dict):
                for h in i.get("hypotheses", []):
                    hypotheses.append({
                        "anomaly_id": i.get("anomaly_id", ""),
                        "hypothesis": h,
                        "priority": "medium",
                    })
    else:
        hypotheses = _build_hypotheses_rule_based(anomalies)

    lines: list[str] = [
        "# Anomalies & Hypotheses",
        "",
        "## Detected Anomalies",
        "",
    ]

    if not anomalies:
        lines.extend([
            "No anomalies detected by rule-based heuristics.",
            "",
        ])
    else:
        for a in anomalies:
            lines.extend([
                f"### {a.get('id', '')}",
                "",
                f"- **Host**: `{a.get('host', '')}`",
                f"- **Role**: {a.get('role', 'unknown')}",
                f"- **Description**: {a.get('description', '')}",
                f"- **Evidence**: {a.get('evidence', '')}",
                "",
            ])

    lines.extend([
        "## Hypotheses for Threat Modeling",
        "",
    ])

    if llm_summary:
        lines.extend([f"{llm_summary}", ""])

    for h in hypotheses:
        prio = h.get("priority", "medium")
        lines.append(f"- [{prio}] {h.get('hypothesis', '')}")

    lines.extend([
        "",
        COVERAGE_GAPS_TEMPLATE,
    ])

    markdown_content = "\n".join(lines)

    anomaly_sources = {a["id"]: a.get("source", SOURCE_HTTP_PROBE) for a in anomalies}
    structured = {
        "anomalies": _to_structured_anomalies(anomalies),
        "hypotheses": _to_structured_hypotheses(hypotheses, anomaly_sources),
        "coverage_gaps": _build_coverage_gaps_structured(),
    }

    return markdown_content, structured
