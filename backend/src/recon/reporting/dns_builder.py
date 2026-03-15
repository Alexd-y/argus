"""DNS summary builder — produces dns_summary.md for Stage 1 report.

Reads parsed whois, dns records, resolved, cname_map, unresolved from recon dir.
Output: dns_summary.md with records summary, SPF/DKIM/DMARC, resolved vs unresolved,
wildcard hints, third-party infra, dangling CNAME candidates.
"""

import logging
import re
from pathlib import Path

from src.recon.parsers import parse_cname, parse_dns, parse_resolved, parse_whois

logger = logging.getLogger(__name__)

# Third-party infrastructure patterns (NS, CNAME, MX targets)
THIRD_PARTY_PATTERNS = [
    "vercel-dns",
    "vercel.app",
    "cloudflare",
    "outlook.com",
    "protection.outlook",
    "google.com",
    "googlemail.com",
    "amazonaws",
    "azure",
    "azureedge",
    "github.io",
    "herokuapp",
    "netlify",
    "fastly",
    "akamai",
    "sectigo",
    "letsencrypt",
    "pki.goog",
]

# Known dangling CNAME targets (often used for takeover)
DANGLING_CANDIDATE_PATTERNS = [
    "github.io",
    "herokuapp.com",
    "netlify.app",
    "s3-website",
    "azurewebsites.net",
    "cloudfront.net",
    "elasticbeanstalk.com",
]

_SPF_RE = re.compile(r"v=spf1", re.IGNORECASE)
_DMARC_RE = re.compile(r"v=DMARC1", re.IGNORECASE)
_DKIM_RE = re.compile(r"v=DKIM1|k=rsa", re.IGNORECASE)


def _read_unresolved(path: Path) -> set[str]:
    """Parse unresolved.txt — subdomains that did not resolve.

    Supports: one subdomain per line, or 'subdomain ->' format.
    """
    if not path.exists():
        return set()
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning(
            "Failed to read unresolved file",
            extra={"path": str(path), "error": str(e)},
        )
        return set()
    result: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        subdomain = line.split("->")[0].strip() if "->" in line else line
        if subdomain and "." in subdomain:
            result.add(subdomain)
    return result


def _extract_txt_observations(txt_records: list[dict]) -> dict[str, list[str]]:
    """Extract SPF, DKIM, DMARC from TXT records."""
    observations: dict[str, list[str]] = {"spf": [], "dkim": [], "dmarc": []}
    for rec in txt_records:
        val = rec.get("value", "")
        if _SPF_RE.search(val):
            observations["spf"].append(val)
        if _DMARC_RE.search(val):
            observations["dmarc"].append(val)
        if _DKIM_RE.search(val):
            observations["dkim"].append(val)
    for key in observations:
        observations[key] = list(dict.fromkeys(observations[key]))
    return observations


def _detect_third_party(value: str) -> list[str]:
    """Return matching third-party provider names from value."""
    val_lower = value.lower()
    return [p for p in THIRD_PARTY_PATTERNS if p.lower() in val_lower]


def _is_dangling_candidate(cname_target: str) -> bool:
    """Check if CNAME target is a known dangling/takeover candidate."""
    target_lower = cname_target.lower()
    return any(p.lower() in target_lower for p in DANGLING_CANDIDATE_PATTERNS)


def _detect_wildcard_hints(resolved: dict[str, list[str]]) -> list[str]:
    """Detect possible wildcard DNS — many subdomains sharing same IP set."""
    ip_to_subs: dict[frozenset, list[str]] = {}
    for sub, ips in resolved.items():
        if ips:
            key = frozenset(ips)
            ip_to_subs.setdefault(key, []).append(sub)
    hints: list[str] = []
    for ips, subs in ip_to_subs.items():
        if len(subs) >= 5:
            ips_str = ", ".join(sorted(ips)[:3])
            if len(ips) > 3:
                ips_str += ", ..."
            hints.append(
                f"{len(subs)} subdomains share same IP(s): {ips_str} — possible wildcard"
            )
    return hints


def build_dns_summary(recon_dir: str | Path) -> str:
    """Build dns_summary.md from recon Stage 1 artifacts.

    Args:
        recon_dir: Path to recon stage dir (e.g. .../recon/svalbard-stage1/)

    Returns:
        Markdown content for dns_summary.md
    """
    base = Path(recon_dir)
    domains_dir = base / "01_domains"
    dns_dir = base / "03_dns"

    # Load DNS records from multiple files
    dns_records: list[dict] = []
    for fname in ["dns_records.txt", "ns.txt", "mx.txt", "txt.txt", "caa.txt"]:
        dns_records.extend(parse_dns(domains_dir / fname))

    whois_data = parse_whois(domains_dir / "whois.txt")
    resolved = parse_resolved(dns_dir / "resolved.txt")
    cname_map = parse_cname(dns_dir / "cname_map.csv")
    unresolved = _read_unresolved(dns_dir / "unresolved.txt")

    # Group records by type
    by_type: dict[str, list[str]] = {}
    for rec in dns_records:
        rtype = rec.get("type", "UNKNOWN")
        val = rec.get("value", "")
        if rtype not in by_type:
            by_type[rtype] = []
        if val and val not in by_type[rtype]:
            by_type[rtype].append(val)

    # Add CNAME from cname_map
    cname_values: list[str] = []
    for row in cname_map:
        if row.get("record_type", "").upper() == "CNAME":
            target = row.get("value", "")
            host = row.get("host", "")
            if target:
                cname_values.append(f"{host} -> {target}")
    if cname_values:
        by_type.setdefault("CNAME", []).extend(cname_values)

    # TXT observations
    txt_records = [r for r in dns_records if r.get("type") == "TXT"]
    txt_obs = _extract_txt_observations(txt_records)

    # Third-party infrastructure
    third_party: list[str] = []
    for rec in dns_records:
        val = rec.get("value", "")
        for p in _detect_third_party(val):
            snippet = val[:60] + "..." if len(val) > 60 else val
            third_party.append(f"{rec.get('type', '')}: {p} ({snippet})")
    for row in cname_map:
        val = row.get("value", "")
        for p in _detect_third_party(val):
            third_party.append(
                f"CNAME: {p} ({row.get('host', '')} -> {val})"
            )

    third_party = list(dict.fromkeys(third_party))

    # Dangling CNAME candidates
    dangling: list[str] = []
    for row in cname_map:
        target = row.get("value", "")
        if target and _is_dangling_candidate(target):
            dangling.append(f"{row.get('host', '')} -> {target}")

    # Wildcard hints
    wildcard_hints = _detect_wildcard_hints(resolved)

    # Build markdown
    lines = [
        "# DNS Summary",
        "",
        "## Record Summary",
        "",
    ]

    for rtype in ["A", "AAAA", "CNAME", "MX", "TXT", "CAA", "NS"]:
        vals = by_type.get(rtype, [])
        if vals:
            lines.append(f"### {rtype} ({len(vals)})")
            lines.append("")
            for v in vals[:50]:
                lines.append(f"- `{v}`")
            if len(vals) > 50:
                lines.append(f"- ... and {len(vals) - 50} more")
            lines.append("")

    lines.append("## Nameservers (NS)")
    lines.append("")
    ns_vals = by_type.get("NS", [])
    if ns_vals:
        for ns in ns_vals:
            lines.append(f"- {ns}")
    else:
        lines.append("*No NS records parsed.*")
    lines.append("")

    lines.append("## SPF / DKIM / DMARC")
    lines.append("")
    if txt_obs["spf"]:
        lines.append("### SPF")
        for v in txt_obs["spf"]:
            lines.append(f"- `{v}`")
        lines.append("")
    else:
        lines.append("*No SPF (v=spf1) found in TXT records.*")
        lines.append("")

    if txt_obs["dmarc"]:
        lines.append("### DMARC")
        for v in txt_obs["dmarc"]:
            lines.append(f"- `{v}`")
        lines.append("")
    else:
        lines.append("*No DMARC (v=DMARC1) found in TXT records.*")
        lines.append("")

    if txt_obs["dkim"]:
        lines.append("### DKIM")
        for v in txt_obs["dkim"]:
            lines.append(f"- `{v}`")
        lines.append("")
    else:
        lines.append("*No DKIM found in TXT records.*")
        lines.append("")

    lines.append("## Resolved vs Unresolved Subdomains")
    lines.append("")
    lines.append(f"- **Resolved:** {len(resolved)}")
    lines.append(f"- **Unresolved:** {len(unresolved)}")
    lines.append("")
    if resolved:
        lines.append("### Resolved")
        for sub in sorted(resolved.keys())[:20]:
            ips = ", ".join(resolved[sub][:5])
            if len(resolved[sub]) > 5:
                ips += ", ..."
            lines.append(f"- `{sub}` — {ips}")
        if len(resolved) > 20:
            lines.append(f"- ... and {len(resolved) - 20} more")
        lines.append("")
    if unresolved:
        lines.append("### Unresolved")
        for sub in sorted(unresolved)[:20]:
            lines.append(f"- `{sub}`")
        if len(unresolved) > 20:
            lines.append(f"- ... and {len(unresolved) - 20} more")
        lines.append("")

    if wildcard_hints:
        lines.append("## Wildcard DNS Observations")
        lines.append("")
        for h in wildcard_hints:
            lines.append(f"- {h}")
        lines.append("")

    if third_party:
        lines.append("## Third-Party Infrastructure")
        lines.append("")
        for t in third_party:
            lines.append(f"- {t}")
        lines.append("")

    if dangling:
        lines.append("## Suspicious / Dangling CNAME Candidates")
        lines.append("")
        lines.append(
            "*CNAMEs pointing to known takeover-prone targets. Review manually.*"
        )
        lines.append("")
        for d in dangling:
            lines.append(f"- `{d}`")
        lines.append("")

    if whois_data.get("registrar"):
        lines.append("## WHOIS (Summary)")
        lines.append("")
        lines.append(f"- **Registrar:** {whois_data.get('registrar', '')}")
        lines.append(f"- **Expiry:** {whois_data.get('expiry', '')}")
        lines.append(f"- **Registrant:** {whois_data.get('registrant', '')}")
        lines.append("")

    lines.extend([
        "---",
        "",
        "*Generated by ARGUS Recon. All data from authorized reconnaissance.*",
    ])
    return "\n".join(lines)
