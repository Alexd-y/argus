"""Subdomain classification builder — produces subdomain_classification.csv for Stage 1 report.

Classifies subdomains by role (root/main, www, mail, hosting/admin, dev/test/stage,
special-purpose) using name patterns. Outputs confidence and priority for next-stage analysis.
"""

import csv
import io
import logging
from pathlib import Path

from src.recon.parsers import parse_cname, parse_resolved

logger = logging.getLogger(__name__)

# Role patterns: (role, [subdomain patterns], confidence)
# Patterns are matched against subdomain prefix or full name (lowercase)
ROLE_PATTERNS: list[tuple[str, list[str], str]] = [
    ("root/main", ["@", "apex", "root", "primary"], "high"),
    ("www", ["www."], "high"),
    (
        "mail",
        [
            "mail.",
            "smtp.",
            "imap.",
            "pop.",
            "autodiscover.",
            "webmail.",
            "exchange.",
            "owa.",
            "mx.",
        ],
        "high",
    ),
    (
        "hosting/admin",
        [
            "cpanel.",
            "cpcalendars.",
            "cpcontacts.",
            "admin.",
            "portal.",
            "dashboard.",
            "manage.",
            "control.",
            "hosting.",
            "plesk.",
            "whm.",
        ],
        "high",
    ),
    (
        "dev/test/stage",
        [
            "dev.",
            "test.",
            "staging.",
            "stage.",
            "uat.",
            "beta.",
            "alpha.",
            "preview.",
            "demo.",
            "sandbox.",
            "staging-",
            "dev-",
            "test-",
        ],
        "high",
    ),
    (
        "special-purpose",
        [
            "api.",
            "graphql.",
            "rest.",
            "ctf.",
            "vpn.",
            "git.",
            "jenkins.",
            "jira.",
            "confluence.",
            "wiki.",
            "docs.",
            "status.",
            "monitor.",
            "metrics.",
            "grafana.",
            "kibana.",
            "elastic.",
        ],
        "medium",
    ),
    (
        "cdn/static",
        ["cdn.", "static.", "assets.", "media.", "files.", "img.", "images.", "js.", "css."],
        "medium",
    ),
    ("auth/sso", ["auth.", "login.", "sso.", "oauth.", "saml.", "identity."], "high"),
    ("legacy", ["old.", "legacy.", "v1.", "v2.", "backup.", "archive."], "medium"),
]

# Fallback when no pattern matches
DEFAULT_ROLE = "other"
DEFAULT_CONFIDENCE = "low"

# Priority mapping: 1 = highest (admin, auth, dev/staging), 5 = lowest (cdn, static)
ROLE_PRIORITY: dict[str, int] = {
    "hosting/admin": 1,
    "auth/sso": 1,
    "dev/test/stage": 2,
    "mail": 2,
    "special-purpose": 2,
    "root/main": 3,
    "www": 3,
    "legacy": 3,
    "cdn/static": 4,
    "other": 5,
}


def _classify_subdomain(subdomain: str) -> tuple[str, str, list[str]]:
    """Classify subdomain by role, confidence, and notes.

    Returns: (role, confidence, notes)
    """
    sub_lower = subdomain.lower()
    notes: list[str] = []

    for role, patterns, conf in ROLE_PATTERNS:
        for pat in patterns:
            if pat.endswith("."):
                if sub_lower.startswith(pat) or f".{pat}" in f".{sub_lower}":
                    return role, conf, notes
            else:
                if pat in sub_lower:
                    return role, conf, notes

    return DEFAULT_ROLE, DEFAULT_CONFIDENCE, notes


def _load_subdomains(recon_dir: Path) -> set[str]:
    """Load subdomains from subdomains_clean.txt and resolved.txt."""
    subs: set[str] = set()
    subdomains_file = recon_dir / "02_subdomains" / "subdomains_clean.txt"
    if subdomains_file.exists():
        try:
            text = subdomains_file.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith(";") and "." in line:
                    subs.add(line)
        except OSError as e:
            logger.warning(
                "Failed to read subdomains_clean",
                extra={"path": str(subdomains_file), "error": str(e)},
            )
    dns_dir = recon_dir / "03_dns"
    resolved = parse_resolved(dns_dir / "resolved.txt")
    subs.update(resolved.keys())
    unresolved_file = dns_dir / "unresolved.txt"
    if unresolved_file.exists():
        try:
            text = unresolved_file.read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith(";"):
                    continue
                sub = line.split("->")[0].strip() if "->" in line else line
                if sub and "." in sub:
                    subs.add(sub)
        except OSError:
            pass
    return subs


def _build_notes(
    subdomain: str,
    resolved: dict[str, list[str]],
    cname_map: list[dict],
) -> str:
    """Build notes from resolution and CNAME data."""
    parts: list[str] = []
    if subdomain in resolved:
        ips = resolved[subdomain]
        if len(ips) <= 3:
            parts.append(f"resolved: {', '.join(ips)}")
        else:
            parts.append(f"resolved: {len(ips)} IPs")
    else:
        parts.append("unresolved")
    for row in cname_map:
        if row.get("host", "").lower() == subdomain.lower():
            target = row.get("value", "")
            comment = row.get("comment", "")
            if target:
                parts.append(f"CNAME->{target}")
            if comment:
                parts.append(comment)
            break
    return "; ".join(parts)


def build_subdomain_classification(recon_dir: str | Path) -> str:
    """Build subdomain_classification.csv from recon Stage 1 artifacts.

    Args:
        recon_dir: Path to recon stage dir (e.g. .../recon/svalbard-stage1/)

    Returns:
        CSV content for subdomain_classification.csv
    """
    base = Path(recon_dir)
    subdomains = _load_subdomains(base)
    resolved = parse_resolved(base / "03_dns" / "resolved.txt")
    cname_map = parse_cname(base / "03_dns" / "cname_map.csv")

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(["subdomain", "role", "confidence", "priority", "notes"])

    for sub in sorted(subdomains):
        role, confidence, _ = _classify_subdomain(sub)
        priority = ROLE_PRIORITY.get(role, 5)
        notes = _build_notes(sub, resolved, cname_map)
        writer.writerow([sub, role, confidence, priority, notes])

    return output.getvalue()
