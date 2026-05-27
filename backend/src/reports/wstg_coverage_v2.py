from typing import Literal, Optional
from pydantic import BaseModel


WSTG_TESTS = {
    "WSTG-INFO-01": {"name": "Information Leakage", "category": "Information Gathering"},
    "WSTG-INFO-02": {"name": "Framework Detection", "category": "Information Gathering"},
    "WSTG-INFO-03": {"name": "Application Entry Point", "category": "Information Gathering"},
    "WSTG-INFO-04": {"name": "Directory Traversal", "category": "Information Gathering"},
    "WSTG-INFO-05": {"name": "File Extension Handling", "category": "Information Gathering"},
    "WSTG-INFO-06": {"name": "Backup and Unused Files", "category": "Information Gathering"},
    "WSTG-INFO-07": {"name": "Subdomain Enumeration", "category": "Information Gathering"},
    "WSTG-INFO-08": {"name": "Host Header Injection", "category": "Information Gathering"},
    "WSTG-INFO-09": {"name": "SSL/TLS", "category": "Information Gathering"},
    "WSTG-INFO-10": {"name": "Web Server Detection", "category": "Information Gathering"},
    "WSTG-CONF-01": {"name": "Infrastructure Configuration", "category": "Configuration and Deployment"},
    "WSTG-CONF-02": {"name": "Application Configuration", "category": "Configuration and Deployment"},
    "WSTG-CONF-03": {"name": "File Permissions", "category": "Configuration and Deployment"},
    "WSTG-CONF-04": {"name": "HTTP Methods", "category": "Configuration and Deployment"},
    "WSTG-CONF-05": {"name": "HTTPS Client Certificate", "category": "Configuration and Deployment"},
    "WSTG-CONF-06": {"name": "Cookie Security", "category": "Configuration and Deployment"},
    "WSTG-CONF-07": {"name": "Authentication over Encrypted Channel", "category": "Configuration and Deployment"},
    "WSTG-CONF-08": {"name": "Server Side Include", "category": "Configuration and Deployment"},
    "WSTG-CONF-09": {"name": "Cross-Domain Configuration", "category": "Configuration and Deployment"},
    "WSTG-CONF-10": {"name": "Password Policy", "category": "Configuration and Deployment"},
    "WSTG-CONF-11": {"name": "Account Lockout", "category": "Configuration and Deployment"},
    "WSTG-IDNT-01": {"name": "Username Enumeration", "category": "Identity Management"},
    "WSTG-IDNT-02": {"name": "Account Provisioning", "category": "Identity Management"},
    "WSTG-IDNT-03": {"name": "Password Reset", "category": "Identity Management"},
    "WSTG-IDNT-04": {"name": "Password Reveal", "category": "Identity Management"},
    "WSTG-IDNT-05": {"name": "Security Questions", "category": "Identity Management"},
    "WSTG-ATHN-01": {"name": "Credential Estimation", "category": "Authentication"},
    "WSTG-ATHN-02": {"name": "Brute Force", "category": "Authentication"},
    "WSTG-ATHN-03": {"name": "Password Policy", "category": "Authentication"},
    "WSTG-ATHN-04": {"name": "Password Reuse", "category": "Authentication"},
    "WSTG-ATHN-05": {"name": "Password Policy Enforcement", "category": "Authentication"},
    "WSTG-ATHN-06": {"name": "Multi-Factor Authentication", "category": "Authentication"},
    "WSTG-ATHN-07": {"name": "Authentication Bypass", "category": "Authentication"},
    "WSTG-ATHN-08": {"name": "Session Fixation", "category": "Authentication"},
    "WSTG-ATHN-09": {"name": "Token Prediction", "category": "Authentication"},
    "WSTG-ATHN-10": {"name": "Certificate Validation", "category": "Authentication"},
    "WSTG-ATHZ-01": {"name": "Privilege Escalation", "category": "Authorization"},
    "WSTG-ATHZ-02": {"name": "Horizontal IDOR", "category": "Authorization"},
    "WSTG-ATHZ-03": {"name": "Vertical IDOR", "category": "Authorization"},
    "WSTG-ATHZ-04": {"name": "Bypass Authorization", "category": "Authorization"},
    "WSTG-SESS-01": {"name": "Session Hijacking", "category": "Session Management"},
    "WSTG-SESS-02": {"name": "Session Fixation", "category": "Session Management"},
    "WSTG-SESS-03": {"name": "Session Timeout", "category": "Session Management"},
    "WSTG-SESS-04": {"name": "Session Cookie Security", "category": "Session Management"},
    "WSTG-SESS-05": {"name": "CSRF", "category": "Session Management"},
    "WSTG-SESS-06": {"name": "Secret in URL", "category": "Session Management"},
    "WSTG-SESS-07": {"name": "Session Token Reuse", "category": "Session Management"},
    "WSTG-SESS-08": {"name": "Logout Functionality", "category": "Session Management"},
    "WSTG-SESS-09": {"name": "Token Expiration", "category": "Session Management"},
    "WSTG-INPV-01": {"name": "Reflected XSS", "category": "Input Validation"},
    "WSTG-INPV-02": {"name": "Stored XSS", "category": "Input Validation"},
    "WSTG-INPV-03": {"name": "DOM XSS", "category": "Input Validation"},
    "WSTG-INPV-04": {"name": "SQL Injection", "category": "Input Validation"},
    "WSTG-INPV-05": {"name": "LDAP Injection", "category": "Input Validation"},
    "WSTG-INPV-06": {"name": "OS Command Injection", "category": "Input Validation"},
    "WSTG-INPV-07": {"name": "XML Injection", "category": "Input Validation"},
    "WSTG-INPV-08": {"name": "SSTI", "category": "Input Validation"},
    "WSTG-INPV-09": {"name": "Path Traversal", "category": "Input Validation"},
    "WSTG-INPV-10": {"name": "Local File Inclusion", "category": "Input Validation"},
    "WSTG-INPV-11": {"name": "Remote File Inclusion", "category": "Input Validation"},
    "WSTG-INPV-12": {"name": "Type Confusion", "category": "Input Validation"},
    "WSTG-INPV-13": {"name": "Buffer Overflow", "category": "Input Validation"},
    "WSTG-INPV-14": {"name": "Format String", "category": "Input Validation"},
    "WSTG-INPV-15": {"name": "Integer Overflow", "category": "Input Validation"},
    "WSTG-INPV-16": {"name": "URL Redirection", "category": "Input Validation"},
    "WSTG-INPV-17": {"name": "Open Redirect", "category": "Input Validation"},
    "WSTG-INPV-18": {"name": "Content Spoofing", "category": "Input Validation"},
    "WSTG-INPV-19": {"name": "Header Injection", "category": "Input Validation"},
    "WSTG-ERRH-01": {"name": "Exception Handling", "category": "Error Handling"},
    "WSTG-ERRH-02": {"name": "Stack Traces", "category": "Error Handling"},
    "WSTG-CRYP-01": {"name": "TLS Configuration", "category": "Cryptography"},
    "WSTG-CRYP-02": {"name": "Cipher Suites", "category": "Cryptography"},
    "WSTG-CRYP-03": {"name": "Certificate Validity", "category": "Cryptography"},
    "WSTG-CRYP-04": {"name": "HSTS Configuration", "category": "Cryptography"},
    "WSTG-BUSL-01": {"name": "Business Logic Bypass", "category": "Business Logic"},
    "WSTG-BUSL-02": {"name": "Price Manipulation", "category": "Business Logic"},
    "WSTG-BUSL-03": {"name": "Quantity Manipulation", "category": "Business Logic"},
    "WSTG-BUSL-04": {"name": "Privilege Escalation", "category": "Business Logic"},
    "WSTG-BUSL-05": {"name": "Workflow Bypass", "category": "Business Logic"},
    "WSTG-BUSL-06": {"name": "Race Condition", "category": "Business Logic"},
    "WSTG-BUSL-07": {"name": "Mass Assignment", "category": "Business Logic"},
    "WSTG-BUSL-08": {"name": "Parameter Pollution", "category": "Business Logic"},
    "WSTG-BUSL-09": {"name": "Logic Brute Force", "category": "Business Logic"},
    "WSTG-CLNT-01": {"name": "DOM XSS", "category": "Client-Side"},
    "WSTG-CLNT-02": {"name": "CSP Bypass", "category": "Client-Side"},
    "WSTG-CLNT-03": {"name": "PostMessage", "category": "Client-Side"},
    "WSTG-CLNT-04": {"name": "LocalStorage", "category": "Client-Side"},
    "WSTG-CLNT-05": {"name": "Service Workers", "category": "Client-Side"},
    "WSTG-CLNT-06": {"name": "Cache Poisoning", "category": "Client-Side"},
    "WSTG-CLNT-07": {"name": "Cookie Manipulation", "category": "Client-Side"},
    "WSTG-CLNT-08": {"name": "Browser Storage", "category": "Client-Side"},
    "WSTG-CLNT-09": {"name": "Client-Side Validation", "category": "Client-Side"},
    "WSTG-CLNT-10": {"name": "CORS Configuration", "category": "Client-Side"},
    "WSTG-CLNT-11": {"name": "Clickjacking", "category": "Client-Side"},
    "WSTG-CLNT-12": {"name": "Frame Busting", "category": "Client-Side"},
    "WSTG-CLNT-13": {"name": "X-Frame-Options", "category": "Client-Side"},
}

WSTG_CATEGORIES = [
    "Information Gathering",
    "Configuration and Deployment",
    "Identity Management",
    "Authentication",
    "Authorization",
    "Session Management",
    "Input Validation",
    "Error Handling",
    "Cryptography",
    "Business Logic",
    "Client-Side",
]


class WstgTest(BaseModel):
    id: str
    name: str
    category: str
    status: Literal["covered", "partial", "not_covered"]
    tools: list[str]
    evidence_id: Optional[str] = None
    artifacts: list[str] = []


class WstgCoverage(BaseModel):
    summary: dict
    tests: list[WstgTest]
    missing_artifacts: list[dict] = []


def build_wstg_coverage_v2(
    tools_executed: list[str],
    findings: list[dict],
    evidence_inventory: list[dict]
) -> dict:
    tests = []
    missing_artifacts = []
    
    for test_id, test_data in WSTG_TESTS.items():
        tools_for_test = map_tool_to_wstg(test_id, tools_executed)
        evidence = find_evidence_for_test(test_id, evidence_inventory)
        
        if evidence:
            status = "covered"
        else:
            status = "not_covered"
            missing_artifacts.append({
                "test_id": test_id,
                "category": test_data["category"],
                "tool_hint": f"tool_{tools_for_test[0]}_stdout" if tools_for_test else "unknown",
                "artifact_hint": f"Not assessed: missing artifact for {test_id}",
            })
        
        tests.append(WstgTest(
            id=test_id,
            name=test_data["name"],
            category=test_data["category"],
            status=status,
            tools=tools_for_test,
            evidence_id=evidence.get("evidence_id") if evidence else None,
            artifacts=evidence.get("artifacts", []) if evidence else [],
        ))
    
    covered_count = sum(1 for t in tests if t.status == "covered")
    partial_count = sum(1 for t in tests if t.status == "partial")
    total = len(WSTG_TESTS)
    not_covered_count = sum(1 for t in tests if t.status == "not_covered")
    
    return {
        "summary": {
            "total_tests": total,
            "covered": covered_count,
            "partial": partial_count,
            "not_covered": not_covered_count,
            "coverage_pct": round(covered_count / max(total, 1) * 100, 1),
            "by_category": categorize_tests(tests),
            "missing_artifacts": missing_artifacts[:10]},
        "tests": tests,
        "missing_artifacts": missing_artifacts,
    }


def map_tool_to_wstg(test_id: str, tools_executed: list[str]) -> list[str]:
    tool_mapping = {
        "INFO": ["nmap", "httpx", "subfinder", "argus_recon"],
        "CONF": ["httpx", "testssl", "argus_active_scan"],
        "CRYP": ["testssl", "sslscan"],
        "AUTHN": ["httpx", "nuclei", "argus_active_scan"],
        "ATHZ": ["nuclei", "argus_active_scan"],
        "SESS": ["nuclei", "playwright", "argus_active_scan"],
        "INPV": ["dalfox", "sqlmap", "nuclei", "playwright", "argus_active_scan"],
        "ERRH": ["nuclei", "httpx"],
        "DATA": ["nuclei", "sqlmap"],
        "LOGG": ["nuclei"],
        "BUSL": ["nuclei", "playwright"],
        "CLNT": ["nuclei", "playwright"],
    }
    
    for prefix, tools in tool_mapping.items():
        if test_id.startswith(f"WSTG-{prefix}-"):
            return [t for t in tools if t in tools_executed]
    
    return []


def find_evidence_for_test(test_id: str, evidence_inventory: list[dict]) -> Optional[dict]:
    for evidence in evidence_inventory:
        if evidence.get("test_id") == test_id:
            return evidence
    return None


def categorize_tests(tests: list[WstgTest]) -> dict:
    categories = {}
    for test in tests:
        cat = test.category
        if cat not in categories:
            categories[cat] = {"total": 0, "covered": 0}
        categories[cat]["total"] += 1
        if test.status == "covered":
            categories[cat]["covered"] += 1
    return categories
