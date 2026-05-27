from typing import Literal, Optional
from pydantic import BaseModel


class RemediationMatrixRow(BaseModel):
    finding_id: str
    title: str
    severity: str
    category: str
    affected_layer: Literal["infrastructure", "app/frontend", "app/backend", "app/database", "CI/CD"]
    owner_team: str
    config_component: str
    fix_action: str
    rollback_risk: Literal["low", "medium", "high"]
    rollback_steps: str
    verification_step: str
    acceptance_criteria: str
    priority: Literal["P0", "P1", "P2", "P3"]
    deadline: str
    layer_specific: str
    created_at: str
    updated_at: str
    notes: str = ""


def build_remediation_matrix_v2(
    findings: list[dict],
    tech_stack: dict
) -> list[RemediationMatrixRow]:
    matrix = []
    
    for finding in findings:
        row = build_remediation_row(finding, tech_stack)
        matrix.append(row)
    
    return sorted(matrix, key=lambda r: (
        priority_order(r.priority),
        severity_order(r.severity),
    ))


def build_remediation_row(finding: dict, tech_stack: dict) -> RemediationMatrixRow:
    layer, team = map_layer_to_owner(finding.get("category", ""), tech_stack)
    
    return RemediationMatrixRow(
        finding_id=finding.get("id", "UNKNOWN"),
        title=finding.get("title", "Unknown Vulnerability"),
        severity=finding.get("severity", "medium"),
        category=finding.get("category", "UNKNOWN"),
        affected_layer=layer,
        owner_team=team,
        config_component=tech_stack.get("component", "unknown"),
        fix_action=generate_fix_action(finding),
        rollback_risk="medium",
        rollback_steps="Revert configuration changes and reload",
        verification_step=generate_verification_command(finding),
        acceptance_criteria=generate_acceptance_criteria(finding),
        priority=determine_priority(finding.get("severity", "medium")),
        deadline=get_deadline(finding.get("severity", "medium")),
        layer_specific=generate_layer_specific(finding, layer),
        created_at="2026-05-27T00:00:00Z",
        updated_at="2026-05-27T00:00:00Z",
        notes="",
    )


def map_layer_to_owner(category: str, tech_stack: dict) -> tuple[str, str]:
    layer_mapping = {
        "CDN": ("infrastructure", "DevOps"),
        "cloudfront": ("infrastructure", "DevOps"),
        "akamai": ("infrastructure", "DevOps"),
        "nginx": ("app/backend", "Backend"),
        "apache": ("app/backend", "Backend"),
        "flask": ("app/backend", "Backend"),
        "django": ("app/backend", "Backend"),
        "express": ("app/frontend", "Frontend"),
        "react": ("app/frontend", "Frontend"),
        "vue": ("app/frontend", "Frontend"),
        "postgres": ("app/database", "Backend"),
        "mysql": ("app/database", "Backend"),
        "redis": ("app/database", "Backend"),
    }
    
    for key, (layer, team) in layer_mapping.items():
        if key in category.lower() or key in tech_stack.get("web_server", "").lower():
            return layer, team
    
    return "app/backend", "Backend"


def generate_fix_action(finding: dict) -> str:
    vuln_type = finding.get("type", finding.get("title", "")).lower()
    
    if "xss" in vuln_type:
        return "Implement context-aware output encoding and deploy Content Security Policy"
    elif "sqli" in vuln_type or "sql injection" in vuln_type:
        return "Use parameterized queries and input validation"
    elif "csrf" in vuln_type:
        return "Implement CSRF tokens and validate Origin/Referer headers"
    elif "command" in vuln_type or "injection" in vuln_type:
        return "Sanitize user input and use secure APIs"
    elif "hsts" in vuln_type:
        return "Configure HSTS header with max-age=31536000; includeSubDomains; preload"
    elif "csp" in vuln_type:
        return "Deploy Content Security Policy with nonce-based CSP"
    else:
        return "Implement appropriate input validation and output encoding"


def generate_verification_command(finding: dict) -> str:
    url = finding.get("url", "<target>")
    vuln_type = finding.get("type", finding.get("title", "")).lower()
    
    if "xss" in vuln_type:
        return f"curl -sS '{url}' | grep -i '<script>' || echo 'XSS mitigated'"
    elif "sqli" in vuln_type:
        return f"sqlmap --url '{url}' --batch"
    elif "csrf" in vuln_type:
        return f"curl -sS -X POST '{url}' -H 'X-CSRF-Token: valid' | grep -i 'forbidden'"
    else:
        return f"curl -sS '{url}' && echo 'Endpoint reachable'"


def generate_acceptance_criteria(finding: dict) -> str:
    vuln_type = finding.get("type", finding.get("title", "")).lower()
    
    if "xss" in vuln_type:
        return "All user input is properly encoded. No script execution in browser. CSP header configured."
    elif "sqli" in vuln_type:
        return "No SQL injection points detected by sqlmap. Parameterized queries in use."
    elif "csrf" in vuln_type:
        return "CSRF token validation effective. Origin/Referer checks in place."
    elif "command" in vuln_type:
        return "User input sanitized. No command execution possible. Safe APIs used."
    else:
        return "Vulnerability remediated. No重现 of issue. Tests passing."


def determine_priority(severity: str) -> Literal["P0", "P1", "P2", "P3"]:
    severity_map = {
        "critical": "P0",
        "high": "P1",
        "medium": "P2",
        "low": "P3",
    }
    return severity_map.get(severity.lower(), "P3")


def get_deadline(severity: str) -> str:
    deadline_map = {
        "critical": "48 hours",
        "high": "1 week",
        "medium": "2 weeks",
        "low": "1 month",
    }
    return deadline_map.get(severity.lower(), "1 month")


def generate_layer_specific(finding: dict, layer: str) -> str:
    if layer == "infrastructure":
        return "Configure at CDN/CloudFront level via AWS Console or Infrastructure-as-Code"
    elif layer == "app/frontend":
        return "Update in frontend template files or component configuration"
    elif layer == "app/backend":
        return "Modify application code or middleware configuration"
    elif layer == "app/database":
        return "Update database connection strings and query patterns"
    elif layer == "CI/CD":
        return "Update pipeline configuration and security scanning rules"
    return "Check infrastructure configuration"


def priority_order(priority: str) -> int:
    return {"P0": 0, "P1": 1, "P2": 2, "P3": 3}.get(priority, 4)


def severity_order(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity.lower(), 5)
