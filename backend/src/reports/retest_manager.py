from typing import Literal

from pydantic import BaseModel


class RetestResult(BaseModel):
    retest_timestamp: str
    retest_payload: str
    retest_result: Literal["PASS", "FAIL"]
    retest_screenshot_key: str | None = None
    retest_comments: str = ""


class RemediationTimeline(BaseModel):
    remediation_date: str
    verified_by: str
    retest_results: list[RetestResult] = []
    final_status: Literal["remediated", "partial", "not_remediated"] = "pending"


class RetestManager(BaseModel):
    finding_id: str
    remediation_timeline: RemediationTimeline
    verification_commands: list[str] = []
    acceptance_criteria: str = ""
    rollback_plan: str = ""


def generate_retest_commands(finding: dict) -> list[str]:
    vuln_type = finding.get("type", finding.get("title", "")).lower()
    url = finding.get("url", finding.get("target", ""))

    commands = []

    if "xss" in vuln_type:
        commands.append(f"curl -sS '{url}' | grep -i '<script>' || echo 'No XSS present'")
    if "sqli" in vuln_type or "sql" in vuln_type:
        commands.append(f"sqlmap --url '{url}' --batch")
    if "csrf" in vuln_type:
        commands.append(f"curl -sS -X POST '{url}' -H 'X-CSRF-Token: valid'")
    if "command" in vuln_type or "injection" in vuln_type:
        commands.append(f"curl -sS '{url}' | grep -i 'command' || echo 'No injection'")
    if "hsts" in vuln_type:
        commands.append(f"curl -sI '{url}' | grep -i 'strict-transport-security'")
    if "csp" in vuln_type:
        commands.append(f"curl -sI '{url}' | grep -i 'content-security-policy'")

    return commands


def build_remediation_timeline(
    finding_id: str,
    remediation_date: str,
    retest_results: list[dict]
) -> RemediationTimeline:
    return RemediationTimeline(
        remediation_date=remediation_date,
        verified_by="security_team",
        retest_results=[RetestResult(**r) for r in retest_results],
        final_status="remediated" if all(r.get("retest_result") == "PASS" for r in retest_results) else "not_remediated",
    )


def verify_remediation(retest_result: RetestResult, acceptance_criteria: str) -> bool:
    if retest_result.retest_result != "PASS":
        return False

    if "No XSS" in acceptance_criteria and retest_result.retest_result == "PASS":
        return True

    return True


def generate_acceptance_criteria(finding: dict) -> str:
    vuln_type = finding.get("type", finding.get("title", "")).lower()

    if "xss" in vuln_type:
        return "All user input properly encoded. No script execution. CSP configured."
    elif "sqli" in vuln_type or "sql" in vuln_type:
        return "No injection points detected. Parameterized queries in use."
    elif "csrf" in vuln_type:
        return "CSRF token validation effective. Origin/Referer checks in place."
    elif "command" in vuln_type or "injection" in vuln_type:
        return "User input sanitized. No command execution possible."
    elif "hsts" in vuln_type:
        return "HSTS header present with proper directives."
    elif "csp" in vuln_type:
        return "CSP header configured. Policy enforced."
    else:
        return "Vulnerability remediated. Tests passing."


def create_retest_manager(
    finding_id: str,
    finding: dict,
    remediation_date: str
) -> RetestManager:
    commands = generate_retest_commands(finding)
    criteria = generate_acceptance_criteria(finding)

    return RetestManager(
        finding_id=finding_id,
        remediation_timeline=build_remediation_timeline(finding_id, remediation_date, []),
        verification_commands=commands,
        acceptance_criteria=criteria,
        rollback_plan="Revert configuration and reload service",
    )
