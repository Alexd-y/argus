"""Deduplication logic for normalized recon findings."""

import hashlib
import logging
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def dedup_key(finding: dict[str, Any]) -> str:
    """Generate a deduplication key for a finding based on type and value."""
    finding_type = finding.get("finding_type", "")
    value = finding.get("value", "")

    if finding_type == "subdomain":
        normalized = value.lower().strip().rstrip(".")
        return f"subdomain:{normalized}"

    if finding_type == "dns_record":
        data = finding.get("data", {})
        return f"dns:{data.get('hostname', '')}:{data.get('record_type', '')}:{data.get('value', '')}"

    if finding_type == "ip_address":
        return f"ip:{value.strip()}"

    if finding_type == "url":
        try:
            parsed = urlparse(value)
            normalized_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            return f"url:{normalized_url.lower()}"
        except Exception:
            return f"url:{value.lower()}"

    if finding_type == "service":
        data = finding.get("data", {})
        return f"svc:{data.get('ip', '')}:{data.get('port', '')}:{data.get('protocol', '')}"

    if finding_type == "technology":
        return f"tech:{value.lower()}"

    if finding_type == "parameter":
        data = finding.get("data", {})
        return f"param:{data.get('url', '')}:{data.get('param_name', '')}"

    if finding_type == "api_endpoint":
        data = finding.get("data", {})
        return f"api:{data.get('base_url', '')}:{data.get('path', '')}:{data.get('method', '')}"

    return f"{finding_type}:{hashlib.sha256(value.encode()).hexdigest()[:16]}"


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Remove duplicate findings, keeping higher confidence entries."""
    seen: dict[str, dict[str, Any]] = {}

    for finding in findings:
        key = dedup_key(finding)
        if key in seen:
            existing_conf = seen[key].get("confidence", 0)
            new_conf = finding.get("confidence", 0)
            if new_conf > existing_conf:
                seen[key] = finding
        else:
            seen[key] = finding

    return list(seen.values())
