"""Stage 2 inputs builder — produces stage2_inputs.md and stage2_structured.json for Threat Modeling.

Extracts priority hypotheses, candidate trust boundaries, critical assets,
and entry points from anomalies.md, subdomain_classification.csv, live_hosts_detailed.csv,
tech_profile.csv, and endpoint_inventory.csv. Emits structured data with type and source
per item for citations. Supports optional LLM enrichment with rule-based fallback.
"""

import csv
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import TypedDict

logger = logging.getLogger(__name__)

# Artifact paths for source attribution
SOURCE_ANOMALIES = "anomalies.md"
SOURCE_SUBDOMAIN_CLASSIFICATION = "subdomain_classification.csv"
SOURCE_LIVE_HOSTS = "live_hosts_detailed.csv"
SOURCE_TECH_PROFILE = "tech_profile.csv"
SOURCE_ENDPOINT_INVENTORY = "endpoint_inventory.csv"


class StructuredItem(TypedDict, total=False):
    """Structured item with type, source, and text. priority only for hypotheses."""

    type: str
    source: str
    text: str
    priority: str


class Stage2Structured(TypedDict):
    """Structured Stage 2 output for citations."""

    priority_hypotheses: list[StructuredItem]
    trust_boundaries: list[StructuredItem]
    critical_assets: list[StructuredItem]
    entry_points: list[StructuredItem]

STAGE2_PROMPT_TEMPLATE = """You are a security architect preparing inputs for threat modeling.

## Context
Stage 1 recon produced the following data. Use it to suggest Stage 2 inputs for threat modeling.

### Anomalies (excerpt)
{anomalies_excerpt}

### High-priority subdomains (by role)
{subdomains_json}

### Live hosts summary
{live_hosts_summary}

## Task
Produce structured suggestions for threat modeling:
1. **Priority hypotheses** — Top 3-5 hypotheses to validate first (from anomalies + classification)
2. **Candidate trust boundaries** — Logical boundaries (e.g. public CDN vs app vs admin)
3. **Candidate critical assets** — Subdomains/hosts that likely hold sensitive data
4. **Candidate entry points** — External-facing interfaces (auth, API, admin)

## Output Format (JSON)
Return valid JSON only:
{{
  "priority_hypotheses": ["...", "..."],
  "trust_boundaries": ["...", "..."],
  "critical_assets": ["...", "..."],
  "entry_points": ["...", "..."]
}}

If you cannot process, return: {{"error": "reason"}}
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


def _load_text(path: Path, max_chars: int = 4000) -> str:
    """Load text file. Returns excerpt if too long."""
    if not path.exists():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        if len(text) > max_chars:
            return text[:max_chars] + "\n\n[... truncated ...]"
        return text
    except OSError as e:
        logger.warning("Failed to load text", extra={"path": str(path), "error": str(e)})
        return ""


def _call_llm_default(_prompt: str, _context: dict) -> str:
    """Default no-op LLM callable when none configured."""
    return ""


def _extract_host_from_evidence(evidence: str) -> str | None:
    """Extract host/URL from tech_profile evidence (e.g. 'Server header on https://app.example.com')."""
    if not evidence or " on " not in evidence:
        return None
    part = evidence.split(" on ", 1)[-1].strip()
    return part if part else None


def _extract_rule_based_inputs(
    classification: list[dict],
    live_hosts: list[dict],
    anomalies_text: str,
    tech_profile: list[dict],
    endpoint_inventory: list[dict],
) -> Stage2Structured:
    """Extract Stage 2 inputs using rule-based logic. Returns structured items with type and source."""
    priority_hypotheses: list[StructuredItem] = []
    trust_boundaries: list[StructuredItem] = []
    critical_assets: list[StructuredItem] = []
    entry_points: list[StructuredItem] = []
    seen_assets: set[str] = set()
    seen_entry_points: set[str] = set()

    high_priority_roles = {"hosting/admin", "auth/sso", "mail"}
    by_role: dict[str, list[str]] = {}
    for row in classification:
        host = (row.get("subdomain") or "").strip()
        role = (row.get("role") or "other").strip()
        if not host:
            continue
        by_role.setdefault(role, []).append(host)

    for role in high_priority_roles:
        hosts = by_role.get(role, [])
        priority = "high" if role in {"hosting/admin", "auth/sso"} else "medium"
        for h in hosts[:5]:
            if role == "hosting/admin":
                priority_hypotheses.append({
                    "type": "hypothesis",
                    "source": SOURCE_SUBDOMAIN_CLASSIFICATION,
                    "text": f"Validate admin/hosting subdomain {h} — check exposure",
                    "priority": priority,
                })
            elif role == "auth/sso":
                priority_hypotheses.append({
                    "type": "hypothesis",
                    "source": SOURCE_SUBDOMAIN_CLASSIFICATION,
                    "text": f"Validate auth/SSO subdomain {h} — entry point for auth flows",
                    "priority": priority,
                })
            elif role == "mail":
                priority_hypotheses.append({
                    "type": "hypothesis",
                    "source": SOURCE_SUBDOMAIN_CLASSIFICATION,
                    "text": f"Validate mail subdomain {h} — check MX and webmail exposure",
                    "priority": "medium",
                })

    # Critical assets from tech_profile.csv (evidence contains host)
    for row in tech_profile:
        evidence = (row.get("evidence") or "").strip()
        host = _extract_host_from_evidence(evidence)
        if host and host not in seen_assets:
            seen_assets.add(host)
            critical_assets.append({
                "type": "observation",
                "source": SOURCE_TECH_PROFILE,
                "text": host,
            })

    # Entry points from endpoint_inventory.csv (urls where exists=yes)
    for row in endpoint_inventory:
        url = (row.get("url") or "").strip()
        exists = (row.get("exists") or "").strip().lower()
        if url and exists in ("yes", "true", "1") and url not in seen_entry_points:
            seen_entry_points.add(url)
            entry_points.append({
                "type": "hypothesis",
                "source": SOURCE_ENDPOINT_INVENTORY,
                "text": url,
            })

    # Trust boundaries from live_hosts_detailed.csv
    live_host_list = sorted({(r.get("host") or "").strip() for r in live_hosts if (r.get("host") or "").strip()})
    if live_host_list:
        trust_boundaries.append({
            "type": "inference",
            "source": SOURCE_LIVE_HOSTS,
            "text": "Public web tier (live hosts with HTTP response)",
        })
        trust_boundaries.append({
            "type": "inference",
            "source": SOURCE_LIVE_HOSTS,
            "text": "DNS/resolution layer (resolved vs unresolved)",
        })
    if by_role.get("hosting/admin") or by_role.get("auth/sso"):
        trust_boundaries.append({
            "type": "inference",
            "source": SOURCE_LIVE_HOSTS,
            "text": "Admin/auth boundary (hosting/admin, auth/sso subdomains)",
        })

    # Fallback entry points from live hosts (when endpoint_inventory empty)
    for h in live_host_list[:10]:
        if h and h not in seen_entry_points:
            seen_entry_points.add(h)
            entry_points.append({
                "type": "hypothesis",
                "source": SOURCE_LIVE_HOSTS,
                "text": h,
            })

    if anomalies_text and "anomaly" in anomalies_text.lower():
        priority_hypotheses.insert(0, {
            "type": "hypothesis",
            "source": SOURCE_ANOMALIES,
            "text": "Investigate anomalies from Stage 1 (see anomalies.md)",
            "priority": "high",
        })

    return {
        "priority_hypotheses": priority_hypotheses[:8],
        "trust_boundaries": trust_boundaries,
        "critical_assets": critical_assets[:15],
        "entry_points": entry_points[:15],
    }


def _strings_to_structured(
    strings: list[str],
    item_type: str,
    source: str,
    default_priority: str = "medium",
) -> list[StructuredItem]:
    """Convert plain strings to structured items with type and source."""
    result: list[StructuredItem] = []
    for s in strings:
        item: StructuredItem = {"type": item_type, "source": source, "text": s}
        if item_type == "hypothesis":
            item["priority"] = default_priority
        result.append(item)
    return result


def _enrich_with_llm(
    rule_inputs: Stage2Structured,
    anomalies_text: str,
    classification: list[dict],
    live_hosts: list[dict],
    call_llm: Callable[[str, dict], str],
) -> Stage2Structured:
    """Optionally enrich Stage 2 inputs via LLM. Falls back to rule_inputs on failure."""
    try:
        high_priority = [
            {"subdomain": r.get("subdomain"), "role": r.get("role"), "priority": r.get("priority")}
            for r in classification
            if (r.get("role") or "") in {"hosting/admin", "auth/sso", "mail"}
        ][:15]
        live_summary = [
            {"host": r.get("host"), "status": r.get("status"), "server": r.get("server")}
            for r in live_hosts[:20]
        ]
        prompt = STAGE2_PROMPT_TEMPLATE.format(
            anomalies_excerpt=anomalies_text[:2000] if anomalies_text else "None",
            subdomains_json=json.dumps(high_priority, indent=2),
            live_hosts_summary=json.dumps(live_summary, indent=2),
        )
        response = call_llm(prompt, {})
        if not response or not response.strip():
            return rule_inputs
        text = response.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(ln for ln in lines if not ln.startswith("```") and ln != "```")
        data = json.loads(text)
        if data.get("error"):
            return rule_inputs
        return {
            "priority_hypotheses": _strings_to_structured(
                data.get("priority_hypotheses") or [i["text"] for i in rule_inputs["priority_hypotheses"]],
                "hypothesis",
                SOURCE_SUBDOMAIN_CLASSIFICATION,
            ),
            "trust_boundaries": _strings_to_structured(
                data.get("trust_boundaries") or [i["text"] for i in rule_inputs["trust_boundaries"]],
                "inference",
                SOURCE_LIVE_HOSTS,
            ),
            "critical_assets": _strings_to_structured(
                data.get("critical_assets") or [i["text"] for i in rule_inputs["critical_assets"]],
                "observation",
                SOURCE_TECH_PROFILE,
            ),
            "entry_points": _strings_to_structured(
                data.get("entry_points") or [i["text"] for i in rule_inputs["entry_points"]],
                "hypothesis",
                SOURCE_ENDPOINT_INVENTORY,
            ),
        }
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.debug("LLM enrichment failed", extra={"error": str(e)})
        return rule_inputs


def _structured_to_markdown(structured: Stage2Structured) -> str:
    """Convert structured Stage 2 data to human-readable markdown."""
    lines: list[str] = [
        "# Stage 2 Inputs for Threat Modeling",
        "",
        "## Priority Hypotheses",
        "",
    ]
    for item in structured.get("priority_hypotheses", []):
        lines.append(f"- {item.get('text', '')}")
    lines.extend(["", "## Candidate Trust Boundaries", ""])
    for item in structured.get("trust_boundaries", []):
        lines.append(f"- {item.get('text', '')}")
    lines.extend(["", "## Candidate Critical Assets", ""])
    for item in structured.get("critical_assets", []):
        lines.append(f"- `{item.get('text', '')}`")
    lines.extend(["", "## Candidate Entry Points", ""])
    for item in structured.get("entry_points", []):
        lines.append(f"- `{item.get('text', '')}`")
    lines.append("")
    return "\n".join(lines)


def build_stage2_inputs(
    recon_dir: str | Path,
    call_llm: Callable[[str, dict], str] | None = None,
) -> tuple[str, Stage2Structured]:
    """Build stage2_inputs.md and stage2_structured.json from Stage 1 outputs.

    Args:
        recon_dir: Path to recon directory (e.g. .../recon/svalbard-stage1/)
        call_llm: Optional callable(prompt, context) -> str for AI enrichment.
                 If None or returns empty, uses rule-based extraction only.

    Returns:
        Tuple of (markdown content for stage2_inputs.md, structured dict for stage2_structured.json)
    """
    base = Path(recon_dir)
    classification = _load_csv(base / "subdomain_classification.csv")
    live_hosts = _load_csv(base / "live_hosts_detailed.csv")
    anomalies_text = _load_text(base / "anomalies.md")
    tech_profile = _load_csv(base / "tech_profile.csv")
    endpoint_inventory = _load_csv(base / "endpoint_inventory.csv")

    rule_inputs = _extract_rule_based_inputs(
        classification, live_hosts, anomalies_text, tech_profile, endpoint_inventory
    )

    llm = call_llm or _call_llm_default
    structured = _enrich_with_llm(rule_inputs, anomalies_text, classification, live_hosts, llm)

    markdown = _structured_to_markdown(structured)
    return markdown, structured
