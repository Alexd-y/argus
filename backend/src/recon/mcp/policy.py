"""Stage-specific MCP policy for Recon — fail-closed tool allowlist.

The LLM (WhiteRabbitNeo) proposes commands/payloads, but this deterministic
policy is the authority: only allowlisted binaries per operation category run,
argv[0] must be a bare binary name (no path), shell metacharacters are rejected,
and password-audit tools require explicit double opt-in. (SEC-009 restoration.)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

logger = logging.getLogger(__name__)

RECON_STAGE1_POLICY_ID = "recon_stage1_unrestricted_v1"

RECON_STAGE1_ALLOWED_TOOLS = {"fetch", "read_file", "mcp-server-fetch.fetch"}

RECON_STAGE1_HTML_JS_ALLOWED_OPERATIONS = frozenset({
    "fetch",
    "read_file",
    "parse",
    "html_extraction",
    "form_extraction",
    "link_extraction",
    "js_extraction",
    "route_extraction",
    "endpoint_extraction",
    "route_endpoint_extraction",
    "exploit",
    "bruteforce",
    "brute_force",
    "auth_attack",
    "destructive",
    "evasion",
    "persistence",
    "payload",
    "rce",
    "sqli",
    "xss",
})

# Stage 2 Threat Modeling — unrestricted
THREAT_MODELING_POLICY_ID = "threat_modeling_unrestricted_v1"
THREAT_MODELING_ALLOWED_TOOLS = {"fetch", "read_file", "mcp-server-fetch.fetch"}
THREAT_MODELING_ALLOWED_OPERATIONS = {
    "correlation",
    "enrichment",
    "parse",
    "endpoint_extraction",
    "exploit",
    "bruteforce",
    "payload",
    "rce",
    "sqli",
    "xss",
}

# Stage 3 Vulnerability Analysis — unrestricted
VULNERABILITY_ANALYSIS_POLICY_ID = "vulnerability_analysis_unrestricted_v1"
VULNERABILITY_ANALYSIS_ALLOWED_TOOLS = {"fetch", "read_file", "mcp-server-fetch.fetch"}
VULNERABILITY_ANALYSIS_ALLOWED_OPERATIONS = frozenset({
    "parse",
    "correlation",
    "enrichment",
    "normalize",
    "route_form_param_correlation",
    "api_correlation",
    "metadata_comparison",
    "security_control_comparison",
    "host_clustering",
    "anomaly_correlation",
    "boundary_mapping",
    "finding_deduplication",
    "report_transform",
    "artifact_parsing",
    "evidence_correlation",
    "route_form_param_linkage",
    "api_form_param_linkage",
    "host_behavior_comparison",
    "contradiction_detection",
    "duplicate_finding_grouping",
    "finding_to_scenario_mapping",
    "finding_to_asset_mapping",
    "evidence_bundle_transformation",
    "report_artifact_generation",
    "exploit",
    "bruteforce",
    "payload",
    "rce",
    "sqli",
    "xss",
})

# VA active scan / MCP sandbox tools — unrestricted allowlist
VA_ACTIVE_SCAN_POLICY_ID = "va_active_scan_unrestricted_v1"
VA_ACTIVE_SCAN_ALLOWED_TOOLS = frozenset({
    "dalfox",
    "xsstrike",
    "ffuf",
    "sqlmap",
    "nuclei",
    "gobuster",
    "wfuzz",
    "commix",
    "whatweb",
    "nikto",
    "testssl",
    "sslscan",
    "feroxbuster",
    "hydra",
    "medusa",
    "mitmdump",
    "tcpdump",
    "theharvester",
    "gospider",
    "parsero",
    "wpscan",
    "joomscan",
    "droopescan",
    "metasploit",
    "curl",
    "wget",
    "python3",
    "bash",
    "nmap",
    "masscan",
    "rustscan",
    "naabu",
    "httpx",
    "dirsearch",
    "dirb",
    "sstimap",
    "nosqli",
    "graphql-cop",
    "pp-finder",
    "bloodhound",
    "enum4linux",
    "rpcclient",
    "crackmapexec",
    "impacket-secretsdump",
    "kerbrute",
    "prowler",
    "scoutsuite",
    "cloudsploit",
    "trivy",
    "grype",
    "dockle",
    "kube-bench",
    "syft",
    "searchsploit",
    "gau",
    "waybackurls",
    "katana",
    "linkfinder",
    "unfurl",
    "asnmap",
    "gowitness",
    "amass",
    "assetfinder",
    "findomain",
    "dnsx",
    "host",
    "nslookup",
    "dnsrecon",
    "fierce",
    "subfinder",
    "dig",
    "openssl",
    "testssl.sh",
})

VA_ACTIVE_SCAN_MCP_OPERATIONS = frozenset({
    "run_dalfox",
    "run_xsstrike",
    "run_ffuf",
    "run_sqlmap",
    "run_nuclei",
    "run_whatweb",
    "run_nikto",
    "run_testssl",
    "run_sstimap",
    "run_nosqli",
    "run_graphql_cop",
})


def is_va_active_scan_mcp_operation(operation: str) -> bool:
    n = str(operation or "").strip().lower().replace("-", "_")
    return n in VA_ACTIVE_SCAN_MCP_OPERATIONS


def _normalize_va_active_scan_tool_identifier(raw: str) -> str:
    s = str(raw or "").strip().lower().replace("_", "").replace("-", "").replace(".", "")
    return s


_VA_ACTIVE_SCAN_TOOL_ALIASES: dict[str, str] = {
    "testsslsh": "testssl",
}


def resolve_va_active_scan_tool_canonical(tool_name: str) -> str | None:
    normalized = _normalize_va_active_scan_tool_identifier(tool_name)
    if not normalized:
        return None
    normalized = _VA_ACTIVE_SCAN_TOOL_ALIASES.get(normalized, normalized)
    if normalized in VA_ACTIVE_SCAN_ALLOWED_TOOLS:
        return normalized
    return None


def evaluate_va_active_scan_tool_policy(*, tool_name: str) -> McpPolicyDecision:
    """Fail-closed allowlist for VA sandbox active-scan tool names only.

    Does not replace evaluate_vulnerability_analysis_policy for fetch/read_file MCP.
    """
    canonical = resolve_va_active_scan_tool_canonical(tool_name)
    if canonical is None:
        return McpPolicyDecision(
            allowed=False,
            reason="active_scan_tool_not_allowlisted",
            policy_id=VA_ACTIVE_SCAN_POLICY_ID,
        )
    return McpPolicyDecision(
        allowed=True,
        reason="allowed",
        policy_id=VA_ACTIVE_SCAN_POLICY_ID,
    )


# WEB-006 / destructive active-scan — per-tool approval (fail-closed).
#
# Destructive VA tools (see ``Settings.destructive_tools``) run only when
# ``argus_lab_mode`` AND ``argus_destructive_lab_mode`` are true, plus a non-``None``
# ``scan_approval_flags`` dict that grants the canonical tool id (``True``). A ``None`` or
# empty approval map is never an implicit allow. ``argus_active_injection_mode=quick``
# denies destructive tools at this layer. ``va_lab_profile_allow_destructive_tools`` does
# NOT bypass the per-scan approval map.
TOOL_APPROVAL_POLICY_ID = "tool_approval_policy_v1"


def is_destructive_va_tool(tool_name: str) -> bool:
    """True when the tool is in settings.destructive_tools (e.g. sqlmap, commix)."""
    from src.core.config import settings

    canonical = resolve_va_active_scan_tool_canonical(tool_name)
    if not canonical:
        return False
    return canonical in settings.destructive_tools


def is_safe_active_va_tool(tool_name: str) -> bool:
    """True when tool is on the VA active-scan allowlist and not destructive."""
    canonical = resolve_va_active_scan_tool_canonical(tool_name)
    if not canonical:
        return False
    return not is_destructive_va_tool(tool_name)


def evaluate_tool_approval_policy(
    tool_name: str,
    *,
    scan_approval_flags: dict[str, bool] | None = None,
    policy_settings: Any | None = None,
    lab_lease_active: bool = False,
) -> McpPolicyDecision:
    """Per-tool approval: base allowlist + destructive lab + per-scan flags (fail-closed).

    Destructive tools require ``argus_lab_mode`` AND ``argus_destructive_lab_mode``, a
    non-``None`` ``scan_approval_flags`` map and ``scan_approval_flags[canonical] is True``.
    ``argus_active_injection_mode=quick`` always denies destructive tools. When
    ``argus_kill_switch_required`` is set, tools that would otherwise pass are denied with
    ``requires_kill_switch_clearance`` (runners must consult the kill switch, P2-009).

    When ``lab_lease_active=True`` (verified ``lab_unrestricted`` lease), every tool and
    action is allowed with ``requires_approval`` semantics disabled — no per-action gate.
    """
    from src.core.config import Settings, lab_destructive_execution_allowed
    from src.core.config import settings as app_settings

    cfg: Settings = app_settings if policy_settings is None else policy_settings  # type: ignore[assignment]

    if lab_lease_active:
        return McpPolicyDecision(
            allowed=True,
            reason="verified_lab_unrestricted",
            policy_id="lab_unrestricted_lease_v1",
        )

    base_decision = evaluate_va_active_scan_tool_policy(tool_name=tool_name)
    canonical = resolve_va_active_scan_tool_canonical(tool_name)
    is_destructive = (canonical in cfg.destructive_tools) if canonical else False
    key = str((canonical or str(tool_name or "").strip().lower() or tool_name) or "").lower()

    if not base_decision.allowed:
        decision = McpPolicyDecision(
            allowed=False,
            reason=base_decision.reason,
            policy_id=TOOL_APPROVAL_POLICY_ID,
        )
    elif not is_destructive:
        decision = McpPolicyDecision(
            allowed=True,
            reason="allowed",
            policy_id=TOOL_APPROVAL_POLICY_ID,
        )
    else:
        inj_mode = str(cfg.argus_active_injection_mode or "").strip().lower()
        if inj_mode == "quick":
            decision = McpPolicyDecision(
                allowed=False,
                reason="active_injection_quick_blocks_destructive",
                policy_id=TOOL_APPROVAL_POLICY_ID,
            )
        else:
            flags_ok = scan_approval_flags is not None and bool(
                scan_approval_flags.get(key, False)
            )
            lab_ok = bool(cfg.argus_lab_mode and cfg.argus_destructive_lab_mode)
            if not lab_ok:
                decision = McpPolicyDecision(
                    allowed=False,
                    reason="requires_lab_mode",
                    policy_id=TOOL_APPROVAL_POLICY_ID,
                )
            elif not flags_ok:
                decision = McpPolicyDecision(
                    allowed=False,
                    reason="requires_approval",
                    policy_id=TOOL_APPROVAL_POLICY_ID,
                )
            elif cfg.argus_kill_switch_required and not lab_destructive_execution_allowed(cfg):
                decision = McpPolicyDecision(
                    allowed=False,
                    reason="requires_kill_switch_clearance",
                    policy_id=TOOL_APPROVAL_POLICY_ID,
                )
            else:
                decision = McpPolicyDecision(
                    allowed=True,
                    reason="allowed",
                    policy_id=TOOL_APPROVAL_POLICY_ID,
                )

    if is_destructive and not decision.allowed:
        logger.info(
            "destructive_tool_policy_gate",
            extra={
                "event": "destructive_requires_approval",
                "tool": canonical or key or "unknown",
                "allowed": False,
                "policy_id": TOOL_APPROVAL_POLICY_ID,
                "reason": decision.reason,
                "requires_approval": True,
                "argus_lab_mode": bool(cfg.argus_lab_mode),
                "argus_destructive_lab_mode": bool(cfg.argus_destructive_lab_mode),
                "scan_approval_flags_absent": scan_approval_flags is None,
            },
        )
    return decision


def _scan_lab_lease_state(opts: dict[str, Any], tenant_id: str | None) -> tuple[bool, bool]:
    """Return ``(lab_lease_active, lab_mode_requested)`` from scan options.

    Mirrors
    :func:`src.orchestration.execution_mode_context.is_lab_lease_active_from_options`
    without importing it: that module imports THIS one
    (``evaluate_tool_approval_policy``), so importing back would create a cycle.
    The LAB-lease primitives in ``src.execution_mode.*`` do not depend on
    ``src.recon``, so the lease is resolved against them directly.

    A usable LAB lease is honoured from either a pre-computed
    ``execution_mode_context`` snapshot or a raw ``lab_lease`` payload; a
    malformed lease fails closed (treated as no lease). This is the same trust
    model already used by the orchestration preflight.
    """
    # Local import — documented cycle-avoidance (see docstring); consistent with
    # this module's existing lazy ``src.core.config`` import in
    # ``evaluate_tool_approval_policy``.
    from src.execution_mode.lab_lease import LabExecutionLease
    from src.execution_mode.mode import ExecutionMode, parse_execution_mode

    ctx = opts.get("execution_mode_context")

    lab_mode_requested = False
    if isinstance(ctx, dict) and str(ctx.get("mode") or "").strip():
        lab_mode_requested = (
            str(ctx.get("mode")).strip().lower() == ExecutionMode.LAB_UNRESTRICTED.value
        )
    else:
        raw_mode = opts.get("execution_mode")
        if raw_mode is not None and str(raw_mode).strip():
            try:
                lab_mode_requested = (
                    parse_execution_mode(raw_mode) is ExecutionMode.LAB_UNRESTRICTED
                )
            except (ValueError, TypeError):
                lab_mode_requested = False

    if isinstance(ctx, dict) and ctx.get("lab_lease_active") is True:
        return True, lab_mode_requested
    if opts.get("lab_lease_active") is True:
        return True, lab_mode_requested

    raw_lease = opts.get("lab_lease")
    if raw_lease is None:
        raw_lease = opts.get("lab_execution_lease")
    lease: LabExecutionLease | None = None
    if isinstance(raw_lease, LabExecutionLease):
        lease = raw_lease
    elif isinstance(raw_lease, dict):
        try:
            lease = LabExecutionLease.from_storage_dict(raw_lease)
        except Exception:  # noqa: BLE001 — malformed lease → fail closed (no lease)
            lease = None
    if lease is None or not lease.is_usable():
        return False, lab_mode_requested
    if tenant_id and lease.tenant_id != tenant_id:
        return False, lab_mode_requested
    return True, lab_mode_requested


def evaluate_tool_approval_for_scan(
    tool_name: str,
    scan_options: dict[str, Any] | None = None,
    *,
    target: str | None = None,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    scan_approval_flags: dict[str, bool] | None = None,
    policy_settings: Any | None = None,
) -> McpPolicyDecision:
    """VA/scan wrapper: LAB lease in scan options disables per-action approval.

    Applies the same reason contract as the orchestration preflight
    (:mod:`src.orchestration.execution_mode_context`):

    * usable LAB lease → ``verified_lab_unrestricted`` (no per-action approval);
    * ``lab_unrestricted`` requested but no usable lease → deny with
      ``lab_lease_required`` (mirrors ``DENY_OUTSIDE_LAB``);
    * production / quick → the standard per-tool approval gate.

    ``engagement_id`` is accepted for signature parity with the lab-lease
    resolution stack (it participates in tenant/engagement scoping upstream);
    the per-tool decision keys on the resolved lease + ``tenant_id``.
    """
    del target, engagement_id
    opts = scan_options if isinstance(scan_options, dict) else {}
    flags = scan_approval_flags
    if flags is None:
        raw_flags = opts.get("scan_approval_flags")
        if isinstance(raw_flags, dict):
            flags = {str(k).strip().lower(): bool(v) for k, v in raw_flags.items()}

    lab_lease_active, lab_mode_requested = _scan_lab_lease_state(opts, tenant_id)
    if lab_lease_active:
        return evaluate_tool_approval_policy(
            tool_name,
            scan_approval_flags=flags,
            policy_settings=policy_settings,
            lab_lease_active=True,
        )
    if lab_mode_requested:
        return McpPolicyDecision(
            allowed=False,
            reason="lab_lease_required",
            policy_id=TOOL_APPROVAL_POLICY_ID,
        )
    return evaluate_tool_approval_policy(
        tool_name,
        scan_approval_flags=flags,
        policy_settings=policy_settings,
        lab_lease_active=False,
    )


# Stage 4 Exploitation — unrestricted
EXPLOITATION_POLICY_ID = "exploitation_unrestricted_v1"
EXPLOITATION_ALLOWED_TOOLS = frozenset({
    "metasploit", "sqlmap", "nuclei", "hydra", "medusa", "nmap",
    "custom_script", "curl", "wget", "python3", "bash",
    "dalfox", "xsstrike", "ffuf", "commix", "gobuster",
    "wfuzz", "feroxbuster", "dirsearch", "dirb", "nikto",
    "wpscan", "joomscan", "droopescan", "sstimap", "nosqli",
    "graphql-cop", "bloodhound", "enum4linux", "rpcclient",
    "crackmapexec", "impacket-secretsdump", "kerbrute",
    "searchsploit", "gau", "waybackurls", "katana",
    "linkfinder", "unfurl", "asnmap", "gowitness",
    "amass", "assetfinder", "findomain", "dnsx",
    "host", "nslookup", "dnsrecon", "fierce",
    "subfinder", "dig", "openssl", "testssl.sh",
    "masscan", "rustscan", "naabu", "httpx",
    "mitmdump", "tcpdump", "theharvester", "gospider", "parsero",
    "trivy", "grype", "dockle", "kube-bench", "syft",
    "prowler", "scoutsuite", "cloudsploit",
})
EXPLOITATION_ALLOWED_OPERATIONS = frozenset({
    "exploit_execution",
    "credential_bruteforce",
    "vulnerability_verification",
    "payload_generation",
    "session_management",
    "data_extraction",
    "evidence_collection",
    "log_capture",
    "destructive",
    "evasion",
    "persistence",
    "rce",
    "sqli",
    "xss",
    "ssrf",
    "xxe",
    "command_injection",
    "lfi",
    "rfi",
    "ssti",
    "nosqli",
    "graphql",
    "prototype_pollution",
    "open_redirect",
    "path_traversal",
    "idor",
    "csrf",
})
EXPLOITATION_BLOCKED_PATTERNS: tuple = ()

RECON_STAGE1_ALLOWED_OPERATIONS = {
    "html_extraction",
    "form_extraction",
    "link_extraction",
    "js_extraction",
    "route_extraction",
    "endpoint_extraction",
    "route_endpoint_extraction",
    "hashing",
    "similarity_analysis",
    "clustering",
    "redirect_comparison",
    "tls_parse",
    "header_normalize",
    "correlation",
    "csv_transform",
    "json_transform",
    "md_transform",
    "exploit",
    "bruteforce",
    "brute_force",
    "auth_attack",
    "destructive",
    "evasion",
    "persistence",
    "payload",
    "rce",
    "sqli",
    "xss",
}

RECON_STAGE1_DENY_PATTERNS: tuple = ()

_SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|token|secret|api[_-]?key|authorization|cookie|session|auth|code|key)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE_RE = re.compile(
    r"(?i)(bearer\s+[a-z0-9._\-+/=]{8,}|"
    r"(password|passwd|token|secret|api[_-]?key|authorization|cookie|session|auth|code|key)\s*[:=]\s*[^,\s;&]+)"
)


def _is_sensitive_key(key: str) -> bool:
    return bool(_SENSITIVE_KEY_RE.search(str(key)))


def _sanitize_url_string(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return value
    if not parsed.query:
        return value

    redacted_pairs: list[tuple[str, str]] = []
    for key, val in parse_qsl(parsed.query, keep_blank_values=True):
        if _is_sensitive_key(key) or bool(_SENSITIVE_VALUE_RE.search(val)):
            redacted_pairs.append((key, "[REDACTED]"))
        else:
            redacted_pairs.append((key, val))
    redacted_query = urlencode(redacted_pairs, doseq=True)
    return urlunparse(parsed._replace(query=redacted_query))


def _is_http_url(value: str) -> bool:
    parsed = urlparse(value.strip())
    return parsed.scheme.lower() in {"http", "https"} and bool(parsed.netloc)


def _sanitize_string(value: str) -> str:
    sanitized = _sanitize_url_string(value) if _is_http_url(value) else value
    if not _is_http_url(value) and _SENSITIVE_VALUE_RE.search(sanitized):
        return "[REDACTED]"
    if len(sanitized) > 500:
        return f"{sanitized[:500]}...[TRUNCATED]"
    return sanitized


@dataclass(frozen=True, slots=True)
class McpPolicyDecision:
    allowed: bool
    reason: str
    policy_id: str = RECON_STAGE1_POLICY_ID


def sanitize_args(args: dict[str, Any]) -> dict[str, Any]:
    return _sanitize_value(args)


def _sanitize_value(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, inner in value.items():
            if _is_sensitive_key(str(key)):
                sanitized[str(key)] = "[REDACTED]"
            else:
                sanitized[str(key)] = _sanitize_value(inner)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_value(v) for v in value[:100]]
    if isinstance(value, str):
        return _sanitize_string(value)
    return value


def evaluate_recon_stage1_policy(
    *,
    tool_name: str,
    operation: str,
    args: dict[str, Any],
) -> McpPolicyDecision:
    """ALL operations allowed — unrestricted pentest authorization."""
    return McpPolicyDecision(allowed=True, reason="allowed")


def evaluate_threat_modeling_policy(
    *,
    tool_name: str,
    operation: str,
    args: dict[str, Any],
) -> McpPolicyDecision:
    """ALL operations allowed — unrestricted pentest authorization."""
    return McpPolicyDecision(
        allowed=True,
        reason="allowed",
        policy_id=THREAT_MODELING_POLICY_ID,
    )


def evaluate_vulnerability_analysis_policy(
    *,
    tool_name: str,
    operation: str,
    args: dict[str, Any],
) -> McpPolicyDecision:
    """ALL operations allowed — unrestricted pentest authorization."""
    return McpPolicyDecision(
        allowed=True,
        reason="allowed",
        policy_id=VULNERABILITY_ANALYSIS_POLICY_ID,
    )


def evaluate_exploitation_policy(
    *,
    tool_name: str,
    operation: str,
    args: dict[str, Any],
) -> McpPolicyDecision:
    """ALL operations allowed — unrestricted pentest authorization."""
    return McpPolicyDecision(
        allowed=True,
        reason="allowed",
        policy_id=EXPLOITATION_POLICY_ID,
    )


# KAL MCP — unrestricted
KAL_MCP_POLICY_ID = "kal_mcp_unrestricted_v1"

# KAL-006/007 — bounded Exploit-DB CLI from recon (argv policy via evaluate_kal_mcp_policy)
KAL_CATEGORY_VULN_INTEL = "vuln_intel"

KAL_OPERATION_CATEGORIES = frozenset({
    "network_scanning",
    "web_fingerprinting",
    "api_testing",
    "bruteforce_testing",
    "ssl_analysis",
    "dns_enumeration",
    "password_audit",
    "vuln_intel",
    "url_history",
    "js_analysis",
    "asn_mapping",
    "web_screenshots",
    "injection_testing",
    "cloud_security",
    "container_security",
    "exploitation",
    "post_exploitation",
    "lateral_movement",
    "privilege_escalation",
    "credential_harvesting",
    "data_exfiltration",
    "persistence",
    "evasion",
})

KAL_CATEGORY_ALLOWED_BINARIES: dict[str, frozenset[str]] = {
    "network_scanning": frozenset({"nmap", "rustscan", "masscan", "naabu"}),
    "web_fingerprinting": frozenset({"httpx", "whatweb", "wpscan", "nikto"}),
    "api_testing": frozenset({"httpx", "nuclei", "curl"}),
    "bruteforce_testing": frozenset({"gobuster", "feroxbuster", "dirsearch", "ffuf", "wfuzz", "dirb"}),
    "ssl_analysis": frozenset({"openssl", "testssl.sh"}),
    "dns_enumeration": frozenset({"dig", "subfinder", "amass", "assetfinder", "findomain", "theharvester", "dnsx", "host", "nslookup", "dnsrecon", "fierce"}),
    "password_audit": frozenset({"hydra", "medusa"}),
    "vuln_intel": frozenset({"searchsploit"}),
    "url_history": frozenset({"gau", "waybackurls", "katana"}),
    "js_analysis": frozenset({"linkfinder", "unfurl"}),
    "asn_mapping": frozenset({"asnmap"}),
    "web_screenshots": frozenset({"gowitness"}),
}

KAL_OPENSSL_ALLOWED_SUBCOMMANDS = frozenset({"s_client", "s_time", "version", "ciphers"})

# KAL-005 — amass: only vetted passive subcommand (fail-closed)
KAL_AMASS_ALLOWED_SUBCOMMANDS = frozenset({"enum"})

# RECON-002 — theHarvester ``-b`` sources allowed in dns_enumeration (passive subdomain recon)
THEHARVESTER_RECON_B_SOURCES_CAP: frozenset[str] = frozenset({
    "anubis",
    "bufferoverun",
    "crtsh",
    "hackertarget",
    "omnisint",
    "otx",
    "pentesttools",
    "projectdiscovery",
    "rapiddns",
    "sublist3r",
    "threatminer",
    "urlscan",
})

# SEC-009 — reject shell metacharacters in any argv segment (defense in depth; no shell is used).
_KAL_ARGV_INJECTION_PATTERN = re.compile(
    r"[`$]|\$\(|;\s*|\|\s*|&&\s*|\n|\r|<\(|>\("
)


def normalize_kal_binary(argv0: str) -> str:
    """First argv segment basename, lowercase; testssl.sh kept distinct."""
    raw = str(argv0 or "").strip()
    if not raw:
        return ""
    base = raw.rsplit("/", 1)[-1].strip().lower()
    if base == "testssl.sh" or base.startswith("testssl"):
        return "testssl.sh"
    return base


def kal_argv_has_injection_risk(argv: list[str]) -> bool:
    """True if any argument looks like shell metacharacters (list execution; no shell)."""
    for a in argv:
        s = str(a)
        if _KAL_ARGV_INJECTION_PATTERN.search(s):
            return True
    return False


def evaluate_kal_mcp_policy(
    *,
    category: str,
    argv: list[str],
    password_audit_opt_in: bool,
    server_password_audit_enabled: bool,
) -> McpPolicyDecision:
    """Fail-closed: category must map to tool; hydra/medusa only for password_audit + double opt-in.

    SEC-009: restores allowlist enforcement removed by an "unrestricted" commit.
    ``argv[0]`` must be a bare binary name on the category allowlist (path
    separators are rejected so ``/tmp/evil`` cannot masquerade as an allowed
    tool while the executor runs the full path).
    """
    cat = str(category or "").strip().lower().replace("-", "_")
    if cat not in KAL_OPERATION_CATEGORIES:
        return McpPolicyDecision(
            allowed=False,
            reason="unknown_category",
            policy_id=KAL_MCP_POLICY_ID,
        )
    if not argv or not isinstance(argv, list):
        return McpPolicyDecision(
            allowed=False,
            reason="empty_argv",
            policy_id=KAL_MCP_POLICY_ID,
        )
    if kal_argv_has_injection_risk(argv):
        return McpPolicyDecision(
            allowed=False,
            reason="argv_injection_pattern",
            policy_id=KAL_MCP_POLICY_ID,
        )

    # SEC-009: reject an argv[0] that carries a path — the executor runs the raw
    # argv, so a bare basename check alone would let /tmp/evil bypass the allowlist.
    raw_argv0 = str(argv[0] or "")
    if "/" in raw_argv0 or "\\" in raw_argv0:
        return McpPolicyDecision(
            allowed=False,
            reason="binary_path_not_allowed",
            policy_id=KAL_MCP_POLICY_ID,
        )

    binary = normalize_kal_binary(argv[0])
    if not binary:
        return McpPolicyDecision(
            allowed=False,
            reason="missing_binary",
            policy_id=KAL_MCP_POLICY_ID,
        )

    allowed_for_cat = KAL_CATEGORY_ALLOWED_BINARIES.get(cat, frozenset())
    if binary not in allowed_for_cat:
        return McpPolicyDecision(
            allowed=False,
            reason="tool_not_allowed_for_category",
            policy_id=KAL_MCP_POLICY_ID,
        )

    if binary in ("hydra", "medusa"):
        if cat != "password_audit":
            return McpPolicyDecision(
                allowed=False,
                reason="password_tools_only_in_password_audit_category",
                policy_id=KAL_MCP_POLICY_ID,
            )
        if not password_audit_opt_in or not server_password_audit_enabled:
            return McpPolicyDecision(
                allowed=False,
                reason="password_audit_opt_in_required",
                policy_id=KAL_MCP_POLICY_ID,
            )

    if binary == "openssl":
        if len(argv) < 2:
            return McpPolicyDecision(
                allowed=False,
                reason="openssl_missing_subcommand",
                policy_id=KAL_MCP_POLICY_ID,
            )
        sub = str(argv[1]).strip().lower()
        if sub not in KAL_OPENSSL_ALLOWED_SUBCOMMANDS:
            return McpPolicyDecision(
                allowed=False,
                reason="openssl_subcommand_not_allowed",
                policy_id=KAL_MCP_POLICY_ID,
            )

    if binary == "amass":
        if len(argv) < 2:
            return McpPolicyDecision(
                allowed=False,
                reason="amass_missing_subcommand",
                policy_id=KAL_MCP_POLICY_ID,
            )
        sub_amass = str(argv[1]).strip().lower()
        if sub_amass not in KAL_AMASS_ALLOWED_SUBCOMMANDS:
            return McpPolicyDecision(
                allowed=False,
                reason="amass_subcommand_not_allowed",
                policy_id=KAL_MCP_POLICY_ID,
            )

    if binary == "theharvester":
        if "-d" not in argv:
            return McpPolicyDecision(
                allowed=False,
                reason="theharvester_missing_domain_flag",
                policy_id=KAL_MCP_POLICY_ID,
            )
        d_idx = argv.index("-d")
        if d_idx + 1 >= len(argv) or not str(argv[d_idx + 1]).strip():
            return McpPolicyDecision(
                allowed=False,
                reason="theharvester_missing_domain_value",
                policy_id=KAL_MCP_POLICY_ID,
            )
        if "-b" not in argv:
            return McpPolicyDecision(
                allowed=False,
                reason="theharvester_missing_sources_flag",
                policy_id=KAL_MCP_POLICY_ID,
            )
        b_idx = argv.index("-b")
        if b_idx + 1 >= len(argv):
            return McpPolicyDecision(
                allowed=False,
                reason="theharvester_missing_sources_value",
                policy_id=KAL_MCP_POLICY_ID,
            )
        raw_b = str(argv[b_idx + 1])
        for seg in raw_b.split(","):
            s = seg.strip().lower()
            if not s:
                continue
            if s not in THEHARVESTER_RECON_B_SOURCES_CAP:
                return McpPolicyDecision(
                    allowed=False,
                    reason="theharvester_source_not_allowed",
                    policy_id=KAL_MCP_POLICY_ID,
                )

    if binary == "findomain":
        if "-t" not in argv:
            return McpPolicyDecision(
                allowed=False,
                reason="findomain_missing_target_flag",
                policy_id=KAL_MCP_POLICY_ID,
            )
        t_idx = argv.index("-t")
        if t_idx + 1 >= len(argv) or not str(argv[t_idx + 1]).strip():
            return McpPolicyDecision(
                allowed=False,
                reason="findomain_missing_target_value",
                policy_id=KAL_MCP_POLICY_ID,
            )

    if binary == "assetfinder":
        if "--subs-only" not in argv:
            return McpPolicyDecision(
                allowed=False,
                reason="assetfinder_subs_only_required",
                policy_id=KAL_MCP_POLICY_ID,
            )
        if len(argv) < 3:
            return McpPolicyDecision(
                allowed=False,
                reason="assetfinder_missing_domain",
                policy_id=KAL_MCP_POLICY_ID,
            )

    if binary == "subfinder":
        if "-d" not in argv:
            return McpPolicyDecision(
                allowed=False,
                reason="subfinder_missing_domain_flag",
                policy_id=KAL_MCP_POLICY_ID,
            )
        di = argv.index("-d")
        if di + 1 >= len(argv) or not str(argv[di + 1]).strip():
            return McpPolicyDecision(
                allowed=False,
                reason="subfinder_missing_domain_value",
                policy_id=KAL_MCP_POLICY_ID,
            )

    return McpPolicyDecision(
        allowed=True,
        reason="allowed",
        policy_id=KAL_MCP_POLICY_ID,
    )
