"""SIEM/SOAR/ITSM Integrations — Splunk, Jira, ServiceNow, generic webhooks.

Provides: forward findings to SIEM, create tickets in ITSM, trigger SOAR playbooks.
All integrations are optional — fail gracefully when not configured.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class IntegrationResult:
    success: bool
    provider: str
    action: str
    external_id: str = ""
    error: str = ""


# ===== Splunk =====

async def send_to_splunk(
    findings: list[dict[str, Any]],
    *,
    splunk_url: str = "",
    splunk_token: str = "",
    index: str = "argus_findings",
    source: str = "argus",
) -> IntegrationResult:
    """Send findings to Splunk HEC endpoint."""
    if not splunk_url or not splunk_token:
        return IntegrationResult(False, "splunk", "send", error="Not configured")

    events = []
    for f in findings:
        events.append({
            "time": datetime.now(UTC).timestamp(),
            "host": source,
            "source": source,
            "sourcetype": "argus:finding",
            "index": index,
            "event": {
                "finding_id": f.get("id", ""),
                "title": f.get("title", ""),
                "severity": f.get("severity", ""),
                "cwe": f.get("cwe", ""),
                "cvss": f.get("cvss", 0.0),
                "description": str(f.get("description", ""))[:500],
                "file_path": f.get("file_path", ""),
                "remediation": f.get("remediation", ""),
            },
        })

    try:
        url = f"{splunk_url.rstrip('/')}/services/collector/event"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                url,
                json={"events": events},
                headers={"Authorization": f"Splunk {splunk_token}"},
            )
            resp.raise_for_status()
        return IntegrationResult(True, "splunk", "send", external_id=str(len(events)))
    except Exception as exc:
        return IntegrationResult(False, "splunk", "send", error=str(exc))


# ===== Elasticsearch =====

async def send_to_elastic(
    findings: list[dict[str, Any]],
    *,
    elastic_url: str = "",
    elastic_api_key: str = "",
    index: str = "argus-findings",
) -> IntegrationResult:
    """Send findings to Elasticsearch."""
    if not elastic_url:
        return IntegrationResult(False, "elastic", "send", error="Not configured")

    bulk_lines = []
    for f in findings:
        bulk_lines.append(json.dumps({"index": {"_index": index}}))
        bulk_lines.append(json.dumps({
            "@timestamp": datetime.now(UTC).isoformat(),
            "finding": {
                "id": f.get("id", ""), "title": f.get("title", ""),
                "severity": f.get("severity", ""), "cwe": f.get("cwe", ""),
                "cvss": f.get("cvss", 0.0),
                "description": str(f.get("description", ""))[:500],
            },
        }))

    try:
        url = f"{elastic_url.rstrip('/')}/_bulk"
        headers = {"Content-Type": "application/x-ndjson"}
        if elastic_api_key:
            headers["Authorization"] = f"ApiKey {elastic_api_key}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(url, content="\n".join(bulk_lines) + "\n", headers=headers)
            resp.raise_for_status()
        return IntegrationResult(True, "elastic", "send", external_id=str(len(findings)))
    except Exception as exc:
        return IntegrationResult(False, "elastic", "send", error=str(exc))


# ===== Jira =====

async def create_jira_ticket(
    finding: dict[str, Any],
    *,
    jira_url: str = "",
    jira_user: str = "",
    jira_token: str = "",
    project_key: str = "SEC",
    issue_type: str = "Bug",
) -> IntegrationResult:
    """Create Jira ticket for a finding."""
    if not jira_url:
        return IntegrationResult(False, "jira", "create_ticket", error="Not configured")

    import base64
    auth = base64.b64encode(f"{jira_user}:{jira_token}".encode()).decode()

    summary = f"[{finding.get('severity', 'INFO').upper()}] {finding.get('title', 'Security Finding')}"[:150]
    description = f"""*Severity:* {finding.get('severity', 'unknown')}
*CWE:* {finding.get('cwe', 'N/A')}
*CVSS:* {finding.get('cvss', 'N/A')}
*File:* {finding.get('file_path', 'N/A')}:{finding.get('line_start', '?')}

*Description:* {finding.get('description', '')[:2000]}

*Remediation:* {finding.get('remediation', '')[:2000]}"""

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type},
            "labels": ["argus", "security", finding.get("severity", "unknown")],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{jira_url.rstrip('/')}/rest/api/2/issue",
                json=payload,
                headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
        return IntegrationResult(True, "jira", "create_ticket", external_id=data.get("key", ""))
    except Exception as exc:
        return IntegrationResult(False, "jira", "create_ticket", error=str(exc))


# ===== ServiceNow =====

async def create_servicenow_incident(
    finding: dict[str, Any],
    *,
    snow_url: str = "",
    snow_user: str = "",
    snow_password: str = "",
) -> IntegrationResult:
    """Create ServiceNow incident."""
    if not snow_url:
        return IntegrationResult(False, "servicenow", "create_incident", error="Not configured")

    payload = {
        "short_description": f"ARGUS: {finding.get('title', 'Security Finding')}"[:160],
        "description": str(finding.get("description", ""))[:4000],
        "severity": _map_severity_to_snow(finding.get("severity", "medium")),
        "category": "Security",
        "subcategory": "Vulnerability",
        "assignment_group": "Security Team",
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post(
                f"{snow_url.rstrip('/')}/api/now/table/incident",
                json=payload,
                auth=(snow_user, snow_password),
                headers={"Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()
        return IntegrationResult(True, "servicenow", "create_incident", external_id=data.get("result", {}).get("number", ""))
    except Exception as exc:
        return IntegrationResult(False, "servicenow", "create_incident", error=str(exc))


def _map_severity_to_snow(severity: str) -> str:
    mapping = {"critical": "1", "high": "2", "medium": "3", "low": "4", "info": "5"}
    return mapping.get(severity.lower(), "3")


# ===== Generic Webhook =====

async def send_webhook(
    url: str, payload: dict[str, Any],
    *, secret: str = "",
) -> IntegrationResult:
    """Send finding to generic webhook endpoint."""
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-Argus-Signature"] = __import__("hashlib").sha256(f"{secret}{json.dumps(payload, sort_keys=True)}".encode()).hexdigest()

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload, headers=headers)
            resp.raise_for_status()
        return IntegrationResult(True, "webhook", "send")
    except Exception as exc:
        return IntegrationResult(False, "webhook", "send", error=str(exc))
