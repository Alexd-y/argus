"""Integration test: load and audit the production tool catalog.

Loads the real ``backend/config/tools/`` registry and asserts the invariants
documented in the ARG-003/ARG-011..ARG-019 cycle plans and Backlog/dev1_md
§4.1-§4.19:

* All 157 expected ``tool_id`` s are present (35 from cycle 1 + 9 ARG-011
  covering HTTP fingerprinting / tech-stack / screenshot tooling +
  10 ARG-012 covering content / path / parameter discovery and fuzzing +
  8 ARG-013 covering crawler / JS / endpoint extraction +
  8 ARG-014 covering §4.7 CMS / platform-specific scanners +
  7 ARG-015 covering §4.8 web vulnerability scanners +
  6 ARG-016 covering §4.9 SQL injection scanners +
  5 ARG-016 covering §4.10 XSS scanners +
  6 ARG-017 covering §4.11 SSRF / OAST / OOB tooling +
  11 ARG-017 covering §4.12 Auth / bruteforce credentials testing +
  5 ARG-017 covering §4.13 Hash / crypto offline cracking +
  7 ARG-018 covering §4.14 API / GraphQL / gRPC tooling +
  12 ARG-018 covering §4.15 Cloud / IaC / container scanning +
  8 ARG-018 covering §4.16 IaC / code / secrets static analysis +
  10 ARG-019 covering §4.17 network protocol / AD / poisoning +
  5 ARG-019 covering §4.18 binary / mobile / firmware analysis +
  5 ARG-019 covering §4.19 browser / headless / OAST verifiers).
* Every command_template passes the sandbox allow-list check.
* Phase grouping matches the §4.x classification.
* Per-batch ``requires_approval`` matches the documented contract.
* Every descriptor declares a non-empty cpu/memory limit and the canonical
  ``runtime/default`` seccomp profile.

The fixture ``loaded_registry`` loads once per session — Ed25519 verification
is the slow path and re-running it 60+ times would dominate the test wall
time for no extra coverage. Individual tests still inspect the same
:class:`ToolRegistry` instance.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Final

import pytest

from src.pipeline.contracts.phase_io import ScanPhase
from src.pipeline.contracts.tool_job import RiskLevel
from src.sandbox.adapter_base import ToolCategory, ToolDescriptor
from src.sandbox.templating import validate_template
from src.sandbox.tool_registry import ToolRegistry


# ---------------------------------------------------------------------------
# Expected catalog inventory (matches Backlog/dev1_md §4.1-§4.3 verbatim).
# Hard-coded so adding/removing a tool is a deliberate test edit — we never
# want a silent shrink of the catalog to slip past CI.
# ---------------------------------------------------------------------------


PASSIVE_RECON_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "amass_passive",
        "subfinder",
        "assetfinder",
        "findomain",
        "chaos",
        "theharvester",
        "crt_sh",
        "shodan_cli",
        "censys",
        "securitytrails",
        "whois_rdap",
        "dnsx",
        "dnsrecon",
        "fierce",
        "github_search",
        "urlscan",
        "otx_alienvault",
    }
)

ACTIVE_RECON_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "nmap_tcp_top",
        "nmap_tcp_full",
        "nmap_udp",
        "nmap_version",
        "nmap_vuln",
        "masscan",
        "rustscan",
        "naabu",
        "unicornscan",
        "smbmap",
        "enum4linux_ng",
        "rpcclient_enum",
    }
)

TLS_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "testssl",
        "sslyze",
        "sslscan",
        "ssl_enum_ciphers",
        "tlsx",
        "mkcert_verify",
    }
)

# §4.4 HTTP fingerprinting / tech-stack / screenshot batch (added in ARG-011).
# All passive-risk recon tools, network policy ``recon-passive``, image
# ``argus-kali-web:latest``.
HTTP_FINGERPRINT_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "httpx",
        "whatweb",
        "wappalyzer_cli",
        "webanalyze",
        "aquatone",
        "gowitness",
        "eyewitness",
        "favfreak",
        "jarm",
    }
)

# §4.5 content / path / parameter discovery and fuzzing batch (added in
# ARG-012). Mostly low-risk active scans against the in-scope target via
# ``recon-active-tcp``; ``paramspider`` is the only passive entry (queries
# the Wayback Machine archive). Image: ``argus-kali-web:latest`` for all.
CONTENT_DISCOVERY_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "ffuf_dir",
        "ffuf_vhost",
        "ffuf_param",
        "feroxbuster",
        "gobuster_dir",
        "dirsearch",
        "kiterunner",
        "arjun",
        "paramspider",
        "wfuzz",
    }
)

# §4.6 crawler / JS / endpoint extraction batch (added in ARG-013).
# Three active crawlers (katana / gospider / hakrawler) + four passive
# endpoint miners (waybackurls / gau / linkfinder / subjs) + one
# secret-discovery tool (secretfinder, the only vuln_analysis entry in
# the batch). Image: ``argus-kali-web:latest`` for all eight.
CRAWLER_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "katana",
        "gospider",
        "hakrawler",
        "waybackurls",
        "gau",
        "linkfinder",
        "subjs",
        "secretfinder",
    }
)

# §4.7 CMS / platform-specific scanners batch (added in ARG-014).  Five
# CMS-focused tools (wpscan / joomscan / droopescan / cmsmap / magescan)
# plus three nuclei wrappers targeting framework-specific exposure
# (nextjs_check / spring_boot_actuator / jenkins_enum).  Every entry runs
# inside the ``argus-kali-web:latest`` image behind the
# ``recon-active-tcp`` policy and is approval-free (the deeper exploit
# paths sit on the Cycle 3 backlog).
CMS_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "wpscan",
        "joomscan",
        "droopescan",
        "cmsmap",
        "magescan",
        "nextjs_check",
        "spring_boot_actuator",
        "jenkins_enum",
    }
)

# §4.8 web vulnerability scanners batch (added in ARG-015). Seven generic
# web-VA tools that complement the §4.7 CMS family with broad-spectrum
# vulnerability surfacing. ``nuclei`` is the flagship template-driven
# scanner whose JSONL parser is shared with the three §4.7 nuclei wrappers
# under ``ParseStrategy.NUCLEI_JSONL``. Three of the seven (``arachni``,
# ``skipfish``, ``w3af_console``) are ``risk_level=medium`` /
# ``requires_approval=true`` because they fire active payload probes
# (XSS / SQLi / RCE checks) against the target. Image:
# ``argus-kali-web:latest`` for all seven.
WEB_VULN_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "nuclei",
        "nikto",
        "wapiti",
        "arachni",
        "skipfish",
        "w3af_console",
        "zap_baseline",
    }
)

# §4.9 SQL-injection batch (added in ARG-016).  Six SQLi scanners — two
# sqlmap variants (``sqlmap_safe`` = passive detection, ``sqlmap_confirm`` =
# error-based exploitation pass) plus four lighter-weight specialists
# (``ghauri`` / ``jsql`` / ``tplmap`` / ``nosqlmap``).  Every entry runs
# inside ``argus-kali-web:latest`` behind ``recon-active-tcp``; every
# entry except ``sqlmap_safe`` requires operator approval (active
# injection probes / data exfiltration).
SQLI_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "sqlmap_safe",
        "sqlmap_confirm",
        "ghauri",
        "jsql",
        "tplmap",
        "nosqlmap",
    }
)

# §4.10 XSS batch (added in ARG-016).  Five XSS scanners — flagship
# ``dalfox`` (parsed in Cycle 2) plus three lighter probes
# (``xsstrike`` / ``kxss`` / ``xsser``) and one headless verifier
# (``playwright_xss_verify``, runs in ``argus-kali-browser:latest``).
# Every entry is approval-free: dalfox/xsstrike/xsser ride low-risk
# reflection payloads only, kxss is a pure stdin grep wrapper, and
# playwright only ever fires the supplied {canary} marker.
XSS_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "dalfox",
        "xsstrike",
        "kxss",
        "xsser",
        "playwright_xss_verify",
    }
)

# §4.11 SSRF / OAST / OOB batch (added in ARG-017). Six tools that work
# in concert against blind-injection chains:
#
# * ``interactsh_client`` / ``oastify_client`` — the OAST receivers; both
#   route through :func:`src.sandbox.parsers.interactsh_parser.parse_interactsh_jsonl`
#   which graduates HTTP / SMTP callbacks to ``SSRF / CONFIRMED`` and
#   DNS-only callbacks to ``INFO / LIKELY``.
# * ``ssrfmap`` — automated SSRF exploitation pipeline (operator-supplied
#   request envelope under ``{in_dir}/req.txt``).
# * ``gopherus`` — offline payload-template generator (no egress).
# * ``oast_dns_probe`` — single-shot canary DNS query used to confirm the
#   OAST plane is reachable before dispatching the heavier SSRF tooling.
# * ``cloud_metadata_check`` — IMDS SSRF probe (AWS / GCE / Azure
#   metadata services). Reviewer C1 (cycle 2) restored this Backlog
#   §4.11 entry to close the cloud-metadata blast-radius gap. Unlike
#   the rest of the §4.11 batch it is approval-gated, runs under the
#   ``argus-kali-cloud:latest`` image with the ``recon-active-tcp``
#   network policy, and lives in ``ScanPhase.EXPLOITATION`` because it
#   reaches a privileged endpoint — see the explicit allow-listing in
#   the relevant OAST invariants below.
#
# All six live in ``ToolCategory.OAST`` or ``ToolCategory.WEB_VA``.
# Approval gating is no longer monolithic: ``ssrfmap`` and
# ``cloud_metadata_check`` require operator approval; the rest stay
# approval-free.
OAST_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "interactsh_client",
        "oastify_client",
        "ssrfmap",
        "gopherus",
        "oast_dns_probe",
        "cloud_metadata_check",
    }
)

# §4.12 Auth / credential bruteforce batch (added in ARG-017). Eleven tools
# covering network credential testing across the major Windows /
# *nix authenticated services and HTTP-form bruteforce. Every active
# credential-test ships with ``requires_approval=true`` because lockout
# policies and IDS noise on auth services are the textbook way to burn an
# engagement; the read-only entries (``snmp_check``) and the
# response-fingerprint vuln-analysis fuzzer (``gobuster_auth``,
# reviewer C2 cycle 2) stay approval-free.
AUTH_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "hydra",
        "medusa",
        "patator",
        "ncrack",
        "crackmapexec",
        "kerbrute",
        "smbclient",
        "snmp_check",
        "evil_winrm",
        "impacket_examples",
        "gobuster_auth",
    }
)


# Per-tool image expectations for the §4.12 auth cohort.
# ARG-058 / T03 relocated the 6 AD/SMB/SNMP/Kerberos/WinRM tools to the
# dedicated ``argus-kali-network`` image; the 4 generic brute-forcers
# (hydra / medusa / patator / ncrack) plus the response-fingerprint
# HTTP-form fuzzer (``gobuster_auth``) stay on ``argus-kali-web``
# because they target HTTP/HTTPS auth surfaces packaged in the web image.
AUTH_IMAGE_BY_TOOL: Final[Mapping[str, str]] = {
    "gobuster_auth": "argus-kali-web:latest",
    "hydra": "argus-kali-web:latest",
    "medusa": "argus-kali-web:latest",
    "ncrack": "argus-kali-web:latest",
    "patator": "argus-kali-web:latest",
    "crackmapexec": "argus-kali-network:latest",
    "evil_winrm": "argus-kali-network:latest",
    "impacket_examples": "argus-kali-network:latest",
    "kerbrute": "argus-kali-network:latest",
    "smbclient": "argus-kali-network:latest",
    "snmp_check": "argus-kali-network:latest",
}


# Lock-step guard: the per-tool image map MUST cover exactly the
# §4.12 auth roster — neither dropping a tool nor adding a stranger.
assert AUTH_IMAGE_BY_TOOL.keys() == set(AUTH_TOOLS), (
    "AUTH_IMAGE_BY_TOOL keys must lock-step with AUTH_TOOLS"
)

# §4.13 Hash / crypto offline cracking batch (added in ARG-017). Five
# offline crackers / classifiers — every entry runs behind the
# ``offline-no-egress`` policy so a malicious wordlist or rule pack
# cannot phone home with the operator's hashes. The two
# classifiers (``hashid`` / ``hash_analyzer``) are approval-free; the
# three crackers (``hashcat`` / ``john`` / ``ophcrack``) require
# operator approval because they consume large CPU / memory budgets and
# operate on captured credentials.
HASH_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "hashcat",
        "john",
        "ophcrack",
        "hashid",
        "hash_analyzer",
    }
)

# §4.14 API / GraphQL / gRPC batch (added in ARG-018). Seven tools that
# probe API surfaces. Five web_va vuln_analysis entries
# (``openapi_scanner`` / ``clairvoyance`` / ``inql`` / ``graphql_cop`` /
# ``postman_newman``), one web_va recon entry (``graphw00f``) and one
# network recon entry (``grpcurl_probe``). All approval-free in Cycle 2 —
# the deeper exploit paths (mutation fuzzing, GraphQL DoS, gRPC RCE) sit
# on the Cycle 3 backlog.
API_GRAPHQL_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "openapi_scanner",
        "graphw00f",
        "clairvoyance",
        "inql",
        "graphql_cop",
        "grpcurl_probe",
        "postman_newman",
    }
)

# §4.15 Cloud / IaC / container batch (added in ARG-018). Twelve tools.
# Cloud auditors (``prowler`` / ``scoutsuite`` / ``cloudsploit`` /
# ``pacu``) require operator approval because they authenticate with
# live cloud credentials. ``pacu`` graduates to ``exploitation`` phase
# with ``risk_level=high`` (true offensive framework).  The active K8s
# scanner ``kube_hunter`` is medium-risk + approval-gated
# (--remote {host} probes the cluster control plane).  Remaining seven
# tools (Trivy image+fs / Grype / Syft / Dockle / kube_bench / Checkov)
# are passive and approval-free.
CLOUD_IAC_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "prowler",
        "scoutsuite",
        "cloudsploit",
        "pacu",
        "trivy_image",
        "trivy_fs",
        "grype",
        "syft",
        "dockle",
        "kube_bench",
        "kube_hunter",
        "checkov",
    }
)

# §4.16 IaC / code / secrets batch (added in ARG-018). Eight tools — all
# passive offline analysis of operator-mounted source/IaC at {path}.
# Every entry runs behind ``offline-no-egress`` so a malicious rule pack
# or detector update cannot exfiltrate the source bundle.  Approval-free.
CODE_SECRETS_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "terrascan",
        "tfsec",
        "kics",
        "semgrep",
        "bandit",
        "gitleaks",
        "trufflehog",
        "detect_secrets",
    }
)

# §4.17 Network protocol / AD / poisoning batch (added in ARG-019).  Ten
# tools that operate at the lower-level network/AD layer:
#
# * Active LLMNR/NBT poisoning: ``responder``, ``ntlmrelayx``.
# * Credential extraction: ``impacket_secretsdump``.
# * AD enumeration: ``bloodhound_python``, ``ldapsearch``.
# * SNMP enumeration: ``snmpwalk``, ``onesixtyone``.
# * VPN / IPsec enumeration: ``ike_scan``.
# * Database probes: ``redis_cli_probe``, ``mongodb_probe``.
#
# All ten run inside ``argus-kali-web:latest`` (the Kali web image
# bundles the Python / Ruby / native CLI ARGUS supports) behind the
# ``auth-bruteforce`` policy (the only existing policy that opens the
# specialised AD / SNMP / IKE port set; reusing it avoids carving a
# new policy when the egress profile is identical).  Approval gating
# splits four/six: the four active poisoners + credential-extraction
# tools require approval; the six read-only enumerators stay
# approval-free.
NETWORK_PROTOCOL_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "responder",
        "impacket_secretsdump",
        "ntlmrelayx",
        "bloodhound_python",
        "ldapsearch",
        "snmpwalk",
        "onesixtyone",
        "ike_scan",
        "redis_cli_probe",
        "mongodb_probe",
    }
)

# §4.18 Binary / mobile / firmware analysis batch (added in ARG-019).
# Five tools that operate purely on operator-mounted binary samples
# under ``/in/``: ``mobsf_api`` (mobile static analysis), ``apktool``
# (APK reverse-engineering), ``jadx`` (Java/Dalvik decompiler),
# ``binwalk`` (firmware extraction), ``radare2_info`` (ELF/PE static
# triage).  Every entry runs in ``argus-kali-binary:latest`` behind
# the ``offline-no-egress`` policy so a malicious sample cannot reach
# the network or exfiltrate the operator's analysis bundle.
# Approval-free across the board (no live target, no egress).
BINARY_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "mobsf_api",
        "apktool",
        "jadx",
        "binwalk",
        "radare2_info",
    }
)

# §4.19 Browser / headless / OAST verifiers batch (added in ARG-019).
# Five browser-automation tools driven by a Chromium runtime:
#
# * ``playwright_runner`` — generic scenario runner for arbitrary
#   sandbox-mounted ``{script}`` files.
# * ``puppeteer_screens`` — passive screenshot-only harvester
#   (``recon-passive`` policy, no JS execution beyond page load).
# * ``chrome_csp_probe`` / ``cors_probe`` / ``cookie_probe`` — three
#   targeted misconfig probes (CSP gaps, CORS pre-flight, cookie
#   security flags).
#
# All five live in ``argus-kali-browser:latest``.  Only
# ``playwright_runner`` is approval-gated (cycle-2 reviewer H1 — its
# operator-supplied ``{script}`` can drive arbitrary state-changing
# browser actions: form submissions, OAuth consent flows, multi-step
# DOM mutations, file uploads, authenticated session capture).  The
# remaining four targeted probes stay approval-free in Cycle 2 (the
# deeper exploitation paths — XSS via headless, prototype pollution
# chains — sit on the Cycle 3 backlog).
BROWSER_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "playwright_runner",
        "puppeteer_screens",
        "chrome_csp_probe",
        "cors_probe",
        "cookie_probe",
    }
)

EXPECTED_TOOLS: Final[frozenset[str]] = (
    PASSIVE_RECON_TOOLS
    | ACTIVE_RECON_TOOLS
    | TLS_TOOLS
    | HTTP_FINGERPRINT_TOOLS
    | CONTENT_DISCOVERY_TOOLS
    | CRAWLER_TOOLS
    | CMS_TOOLS
    | WEB_VULN_TOOLS
    | SQLI_TOOLS
    | XSS_TOOLS
    | OAST_TOOLS
    | AUTH_TOOLS
    | HASH_TOOLS
    | API_GRAPHQL_TOOLS
    | CLOUD_IAC_TOOLS
    | CODE_SECRETS_TOOLS
    | NETWORK_PROTOCOL_TOOLS
    | BINARY_TOOLS
    | BROWSER_TOOLS
)

# §4.8 tools that ship with ``requires_approval=true`` because they fire
# active payload probes (XSS / SQLi / RCE checks) and would generate
# noisy WAF / IDS alerts on a production-like target. Distinct from the
# rest of the §4.8 batch which is approval-free.
WEB_VULN_APPROVAL_REQUIRED: Final[frozenset[str]] = frozenset(
    {"arachni", "skipfish", "w3af_console"}
)

# §4.9 SQLi tools that ship with ``requires_approval=true``.  Reviewer
# M1 (cycle 2) elevated ``sqlmap_safe`` into this set as well — even
# the conservative ``--technique=BT --level 2 --risk 1`` profile
# generates WAF noise + DB log churn that violates the ARGUS
# default-deny security posture, so every §4.9 entry is approval-gated.
SQLI_APPROVAL_REQUIRED: Final[frozenset[str]] = SQLI_TOOLS

# §4.11 SSRF / OAST batch — ``ssrfmap`` and ``cloud_metadata_check``
# (reviewer C1 cycle 2) are the approval-required entries: the former
# actively probes internal services through the SSRF chain, the latter
# touches privileged cloud-IMDS endpoints (AWS / GCE / Azure) and must
# only run with explicit scope permission.  The two OAST receivers
# (``interactsh_client`` / ``oastify_client``), the offline payload
# generator (``gopherus``) and the lightweight canary
# (``oast_dns_probe``) stay approval-free.
OAST_APPROVAL_REQUIRED: Final[frozenset[str]] = frozenset(
    {"ssrfmap", "cloud_metadata_check"}
)

# §4.12 Auth / bruteforce batch — every active credential test requires
# operator approval.  ``snmp_check`` (read-only SNMPv1/v2c walk) and
# ``gobuster_auth`` (response-fingerprint HTTP fuzzer, reviewer C2
# cycle 2) stay approval-free because neither produces credential
# material on its own.
AUTH_APPROVAL_REQUIRED: Final[frozenset[str]] = AUTH_TOOLS - {
    "snmp_check",
    "gobuster_auth",
}

# §4.13 Hash / crypto batch — the three crackers require approval; the
# two classifiers (``hashid`` / ``hash_analyzer``) stay approval-free.
HASH_APPROVAL_REQUIRED: Final[frozenset[str]] = frozenset(
    {"hashcat", "john", "ophcrack"}
)

# §4.14 API / GraphQL / gRPC batch — uniformly approval-free in Cycle 2.
# Every entry only emits read-only / introspection-style probes; the
# deeper exploit paths (mutation fuzzing, GraphQL DoS, gRPC RCE) sit on
# the Cycle 3 backlog and will land with approval gates of their own.
API_GRAPHQL_APPROVAL_REQUIRED: Final[frozenset[str]] = frozenset()

# §4.15 Cloud / IaC / container batch — five approval-required entries:
# the four cloud auditors (``prowler`` / ``scoutsuite`` / ``cloudsploit``
# / ``pacu``) authenticate with live cloud credentials, and the active
# K8s scanner ``kube_hunter`` issues real probes against the cluster
# control plane (--remote {host}).  The seven container/image/IaC
# scanners (``trivy_image`` / ``trivy_fs`` / ``grype`` / ``syft`` /
# ``dockle`` / ``kube_bench`` / ``checkov``) stay approval-free — they
# only read images / config and never reach a live target.
CLOUD_IAC_APPROVAL_REQUIRED: Final[frozenset[str]] = frozenset(
    {"prowler", "scoutsuite", "cloudsploit", "pacu", "kube_hunter"}
)

# §4.16 IaC / code / secrets batch — uniformly approval-free.  Every
# entry runs offline against the operator-mounted code/IaC bundle
# at {path}; no live target, no credentials, no egress.
CODE_SECRETS_APPROVAL_REQUIRED: Final[frozenset[str]] = frozenset()

# §4.17 Network protocol / AD / poisoning batch — four approval-required
# entries.  ``responder`` and ``ntlmrelayx`` perform LLMNR/NBT-NS
# poisoning + NTLM relay (active credential abuse, IDS-noisy).
# ``impacket_secretsdump`` extracts SAM/LSA/NTDS.dit secrets.
# ``bloodhound_python`` enumerates AD with authenticated LDAP queries
# and writes session traces.  The six read-only enumerators
# (``ldapsearch`` / ``snmpwalk`` / ``onesixtyone`` / ``ike_scan`` /
# ``redis_cli_probe`` / ``mongodb_probe``) stay approval-free.
NETWORK_PROTOCOL_APPROVAL_REQUIRED: Final[frozenset[str]] = frozenset(
    {
        "responder",
        "impacket_secretsdump",
        "ntlmrelayx",
        "bloodhound_python",
    }
)

# §4.18 Binary analysis batch — uniformly approval-free.  Every entry
# operates on operator-mounted samples behind ``offline-no-egress``;
# no live target, no credentials, no egress.
BINARY_APPROVAL_REQUIRED: Final[frozenset[str]] = frozenset()

# §4.19 Browser / headless batch — only ``playwright_runner`` is
# approval-gated (cycle-2 reviewer H1: its operator-supplied
# ``{script}`` can drive arbitrary state-changing browser actions —
# form submissions, OAuth consent flows, multi-step DOM mutations,
# file uploads, authenticated session capture).  The four targeted
# probes (``puppeteer_screens`` / ``chrome_csp_probe`` / ``cors_probe``
# / ``cookie_probe``) stay approval-free.  Deeper exploitation paths
# (XSS via headless, prototype pollution chains) land in Cycle 3.
BROWSER_APPROVAL_REQUIRED: Final[frozenset[str]] = frozenset({"playwright_runner"})

# Tools that intentionally live in vuln_analysis even though their group
# header in §4.x sits next to recon tools.
_CONTENT_DISCOVERY_VULN_ANALYSIS_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "ffuf_dir",
        "ffuf_param",
        "feroxbuster",
        "gobuster_dir",
        "dirsearch",
        "kiterunner",
        "arjun",
        "wfuzz",
    }
)
# §4.6 secretfinder is the only crawler-batch tool that lives in
# vuln_analysis (it produces a secret-leak finding, not a recon artefact).
_CRAWLER_VULN_ANALYSIS_TOOLS: Final[frozenset[str]] = frozenset({"secretfinder"})
# §4.9 SQLi tools live in vuln_analysis (lightweight detection) **except**
# ``sqlmap_confirm`` which graduates to ``exploitation`` because it actively
# dumps schema / data on confirmed injection points.
_SQLI_VULN_ANALYSIS_TOOLS: Final[frozenset[str]] = SQLI_TOOLS - {"sqlmap_confirm"}
# §4.10 XSS tools live in vuln_analysis **except** ``playwright_xss_verify``
# which Backlog §4.10 lists under "validation"; ARG-016 maps that to
# ``exploitation`` (low risk, approval-free) so the headless verifier
# only ever fires the supplied {canary} marker.
_XSS_VULN_ANALYSIS_TOOLS: Final[frozenset[str]] = XSS_TOOLS - {"playwright_xss_verify"}
# §4.11 SSRF / OAST tools live in vuln_analysis (their findings populate
# the OAST evidence stream).  ``ssrfmap`` keeps ``vuln_analysis``
# placement because the approval gate already cordons it from default
# scans.  Reviewer C1 (cycle 2) introduced one outlier:
# ``cloud_metadata_check`` graduates to ``exploitation`` because IMDS
# probing reaches a privileged cloud endpoint.
_OAST_EXPLOITATION_TOOLS: Final[frozenset[str]] = frozenset({"cloud_metadata_check"})
_OAST_VULN_ANALYSIS_TOOLS: Final[frozenset[str]] = OAST_TOOLS - _OAST_EXPLOITATION_TOOLS
# §4.12 Auth / bruteforce — most entries graduate to ``exploitation``
# (active credential testing produces post-auth findings).
# ``snmp_check`` is the read-only outlier and lives in ``recon``;
# ``evil_winrm`` graduates further to ``post_exploitation`` because it
# spawns an interactive shell on the victim with stolen credentials.
# ``gobuster_auth`` (reviewer C2 cycle 2) lives in ``vuln_analysis``
# because its bruteforce is response-fingerprint enumeration of HTTP
# login surfaces (no credential exfil, no follow-on exploitation).
_AUTH_RECON_TOOLS: Final[frozenset[str]] = frozenset({"snmp_check"})
_AUTH_POST_EXPLOITATION_TOOLS: Final[frozenset[str]] = frozenset({"evil_winrm"})
_AUTH_VULN_ANALYSIS_TOOLS: Final[frozenset[str]] = frozenset({"gobuster_auth"})
_AUTH_EXPLOITATION_TOOLS: Final[frozenset[str]] = (
    AUTH_TOOLS
    - _AUTH_RECON_TOOLS
    - _AUTH_POST_EXPLOITATION_TOOLS
    - _AUTH_VULN_ANALYSIS_TOOLS
)
# §4.13 Hash / crypto — every entry runs after credentials / hashes
# have been collected, so the whole batch lives in ``post_exploitation``.
_HASH_POST_EXPLOITATION_TOOLS: Final[frozenset[str]] = HASH_TOOLS
# §4.14 API / GraphQL — two recon-phase fingerprints (``graphw00f`` /
# ``grpcurl_probe``); the rest live in vuln_analysis.
_API_GRAPHQL_RECON_TOOLS: Final[frozenset[str]] = frozenset(
    {"graphw00f", "grpcurl_probe"}
)
_API_GRAPHQL_VULN_ANALYSIS_TOOLS: Final[frozenset[str]] = (
    API_GRAPHQL_TOOLS - _API_GRAPHQL_RECON_TOOLS
)
# §4.15 Cloud / IaC — ``pacu`` graduates to exploitation; the rest are
# vuln_analysis (passive image / config / posture scans + active
# kube_hunter which still classifies as vuln_analysis under Backlog §4.15).
_CLOUD_IAC_EXPLOITATION_TOOLS: Final[frozenset[str]] = frozenset({"pacu"})
_CLOUD_IAC_VULN_ANALYSIS_TOOLS: Final[frozenset[str]] = (
    CLOUD_IAC_TOOLS - _CLOUD_IAC_EXPLOITATION_TOOLS
)
# §4.16 Code / secrets — every entry is vuln_analysis (offline SAST /
# secret-scan against the operator-mounted source bundle).
_CODE_SECRETS_VULN_ANALYSIS_TOOLS: Final[frozenset[str]] = CODE_SECRETS_TOOLS
# §4.17 Network protocol / AD / poisoning — split four ways.
#
# * ``recon`` — read-only enumerators (LDAP / SNMP / IKE / DB
#   pre-auth probes).
# * ``exploitation`` — active poisoners (``responder`` / ``ntlmrelayx``)
#   that produce credential material on the wire.
# * ``post_exploitation`` — credential-extraction + AD enumeration that
#   *requires* prior credentials (``impacket_secretsdump`` /
#   ``bloodhound_python``).
_NETWORK_PROTOCOL_RECON_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "ldapsearch",
        "snmpwalk",
        "onesixtyone",
        "ike_scan",
        "redis_cli_probe",
        "mongodb_probe",
    }
)
_NETWORK_PROTOCOL_EXPLOITATION_TOOLS: Final[frozenset[str]] = frozenset(
    {"responder", "ntlmrelayx"}
)
_NETWORK_PROTOCOL_POST_EXPLOITATION_TOOLS: Final[frozenset[str]] = frozenset(
    {"impacket_secretsdump", "bloodhound_python"}
)
# §4.18 Binary analysis — every entry runs FULLY OFFLINE on operator
# samples and lives in ``vuln_analysis``.
_BINARY_VULN_ANALYSIS_TOOLS: Final[frozenset[str]] = BINARY_TOOLS
# §4.19 Browser — split between recon (passive screenshots) and
# vuln_analysis (active misconfig probes / runner).
_BROWSER_RECON_TOOLS: Final[frozenset[str]] = frozenset({"puppeteer_screens"})
_BROWSER_VULN_ANALYSIS_TOOLS: Final[frozenset[str]] = (
    BROWSER_TOOLS - _BROWSER_RECON_TOOLS
)
# §4.9 / §4.10 / §4.11 / §4.12 / §4.15 / §4.17 tools that escalate to
# the exploitation phase.  Reviewer C1 (cycle 2) added the §4.11
# ``cloud_metadata_check`` entry — it shares the IMDS-touching
# exploitation profile; ARG-018 adds ``pacu`` for the same reason
# (active AWS post-exploitation framework).  ARG-019 adds the §4.17
# poisoners (``responder`` / ``ntlmrelayx``) that turn captured
# challenges into hashes on the wire.
_EXPLOITATION_PHASE_TOOLS: Final[frozenset[str]] = (
    frozenset({"sqlmap_confirm", "playwright_xss_verify"})
    | _AUTH_EXPLOITATION_TOOLS
    | _OAST_EXPLOITATION_TOOLS
    | _CLOUD_IAC_EXPLOITATION_TOOLS
    | _NETWORK_PROTOCOL_EXPLOITATION_TOOLS
)
# §4.12/§4.13/§4.17 tools that escalate to the post_exploitation phase.
# ARG-019 adds the §4.17 credential-dependent enumerators
# (``impacket_secretsdump`` / ``bloodhound_python``).
_POST_EXPLOITATION_PHASE_TOOLS: Final[frozenset[str]] = (
    _AUTH_POST_EXPLOITATION_TOOLS
    | _HASH_POST_EXPLOITATION_TOOLS
    | _NETWORK_PROTOCOL_POST_EXPLOITATION_TOOLS
)
VULN_ANALYSIS_TOOLS: Final[frozenset[str]] = (
    TLS_TOOLS
    | {"nmap_vuln"}
    | _CONTENT_DISCOVERY_VULN_ANALYSIS_TOOLS
    | _CRAWLER_VULN_ANALYSIS_TOOLS
    | CMS_TOOLS
    | WEB_VULN_TOOLS
    | _SQLI_VULN_ANALYSIS_TOOLS
    | _XSS_VULN_ANALYSIS_TOOLS
    | _OAST_VULN_ANALYSIS_TOOLS
    | _AUTH_VULN_ANALYSIS_TOOLS
    | _API_GRAPHQL_VULN_ANALYSIS_TOOLS
    | _CLOUD_IAC_VULN_ANALYSIS_TOOLS
    | _CODE_SECRETS_VULN_ANALYSIS_TOOLS
    | _BINARY_VULN_ANALYSIS_TOOLS
    | _BROWSER_VULN_ANALYSIS_TOOLS
)
RECON_PHASE_TOOLS: Final[frozenset[str]] = (
    EXPECTED_TOOLS
    - VULN_ANALYSIS_TOOLS
    - _EXPLOITATION_PHASE_TOOLS
    - _POST_EXPLOITATION_PHASE_TOOLS
)


@pytest.fixture(scope="session")
def catalog_dir() -> Path:
    """Resolve ``backend/config/tools/`` from this test file's location.

    Walks up the test path so the fixture stays correct regardless of where
    pytest is invoked (``backend/`` cwd, repo root, or container).
    """
    here = Path(__file__).resolve()
    backend_dir = here.parents[3]  # tests/integration/sandbox/test_*.py -> backend/
    catalog = backend_dir / "config" / "tools"
    assert catalog.is_dir(), f"expected catalog dir at {catalog}"
    return catalog


@pytest.fixture(scope="session")
def loaded_registry(catalog_dir: Path) -> ToolRegistry:
    """Load the real signed catalog exactly as the application does at startup."""
    registry = ToolRegistry(tools_dir=catalog_dir)
    summary = registry.load()
    assert summary.total >= 157, (
        f"catalog shrunk: expected at least 157 tools, got {summary.total}"
    )
    return registry


# ---------------------------------------------------------------------------
# Catalog inventory
# ---------------------------------------------------------------------------


def test_catalog_loads_and_contains_every_expected_tool(
    loaded_registry: ToolRegistry,
) -> None:
    loaded = set(loaded_registry)
    missing = EXPECTED_TOOLS - loaded
    assert not missing, f"missing tool ids: {sorted(missing)}"


def test_catalog_total_meets_arg003_threshold(
    loaded_registry: ToolRegistry,
) -> None:
    assert len(loaded_registry) >= len(EXPECTED_TOOLS)


# ---------------------------------------------------------------------------
# Per-tool conformance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", sorted(EXPECTED_TOOLS))
def test_descriptor_template_is_in_allowlist(
    loaded_registry: ToolRegistry, tool_id: str
) -> None:
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None, f"{tool_id} is missing from the catalog"
    # ``validate_template`` raises on any forbidden placeholder; reaching the
    # assert means the catalog is allow-list-clean for this tool.
    placeholders = validate_template(descriptor.command_template)
    assert isinstance(placeholders, set)


@pytest.mark.parametrize("tool_id", sorted(EXPECTED_TOOLS))
def test_descriptor_uses_runtime_default_seccomp(
    loaded_registry: ToolRegistry, tool_id: str
) -> None:
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None
    assert descriptor.seccomp_profile == "runtime/default"


@pytest.mark.parametrize("tool_id", sorted(EXPECTED_TOOLS))
def test_descriptor_declares_resource_limits(
    loaded_registry: ToolRegistry, tool_id: str
) -> None:
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None
    assert descriptor.cpu_limit, f"{tool_id} has empty cpu_limit"
    assert descriptor.memory_limit, f"{tool_id} has empty memory_limit"


@pytest.mark.parametrize("tool_id", sorted(EXPECTED_TOOLS))
def test_descriptor_has_non_empty_description(
    loaded_registry: ToolRegistry, tool_id: str
) -> None:
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None
    assert descriptor.description, f"{tool_id} has empty description"
    assert "§4." in descriptor.description, (
        f"{tool_id} description must reference Backlog §4.x"
    )


_APPROVAL_REQUIRED: Final[frozenset[str]] = (
    WEB_VULN_APPROVAL_REQUIRED
    | SQLI_APPROVAL_REQUIRED
    | OAST_APPROVAL_REQUIRED
    | AUTH_APPROVAL_REQUIRED
    | HASH_APPROVAL_REQUIRED
    | API_GRAPHQL_APPROVAL_REQUIRED
    | CLOUD_IAC_APPROVAL_REQUIRED
    | CODE_SECRETS_APPROVAL_REQUIRED
    | NETWORK_PROTOCOL_APPROVAL_REQUIRED
    | BINARY_APPROVAL_REQUIRED
    | BROWSER_APPROVAL_REQUIRED
)


@pytest.mark.parametrize("tool_id", sorted(EXPECTED_TOOLS))
def test_descriptor_approval_matches_risk_profile(
    loaded_registry: ToolRegistry, tool_id: str
) -> None:
    """Pin ``requires_approval`` to the §4.x batch contract.

    The §4.1-§4.7 catalog is uniformly approval-free (passive recon and
    low-risk vuln analysis). ARG-015's §4.8 batch introduces the first
    approval-gated entries: ``arachni`` / ``skipfish`` / ``w3af_console``
    fire active payload probes (XSS / SQLi / RCE) that need an explicit
    operator green-light to dispatch. The remaining four §4.8 tools
    (``nuclei`` / ``nikto`` / ``wapiti`` / ``zap_baseline``) stay
    approval-free because they either run curated templates only or
    operate in an explicitly safe mode (e.g. zap baseline = passive only).

    ARG-016 extends the gated set with five §4.9 SQLi tools:

    * ``sqlmap_confirm`` — error-based exploitation + ``--dbs --count``
      schema dumping.
    * ``ghauri`` / ``jsql`` — automated SQLi exploitation pipelines.
    * ``tplmap`` — server-side template-injection RCE attempts.
    * ``nosqlmap`` — NoSQL injection brute force.

    ``sqlmap_safe`` stays approval-free thanks to its conservative
    ``--technique=BT --level 2 --risk 1`` profile. The §4.10 XSS batch is
    fully approval-free (reflection-only payloads + canary-only Playwright
    verifier).

    ARG-017 introduces three more approval-gated batches:

    * §4.11 — only ``ssrfmap`` (active SSRF exploitation pipeline).
      The two OAST receivers (``interactsh_client`` / ``oastify_client``),
      the offline payload generator (``gopherus``) and the lightweight
      DNS canary stay approval-free.
    * §4.12 — every active credential test (hydra / medusa / patator /
      ncrack / crackmapexec / kerbrute / smbclient / evil_winrm /
      impacket_examples). ``snmp_check`` is the read-only outlier and
      stays approval-free.
    * §4.13 — the three crackers (hashcat / john / ophcrack). The two
      classifiers (``hashid`` / ``hash_analyzer``) stay approval-free
      since they only inspect hash format, never crack.

    ARG-018 introduces five more approval-gated entries (all in §4.15):

    * The four cloud auditors (``prowler`` / ``scoutsuite`` /
      ``cloudsploit`` / ``pacu``) authenticate with live cloud
      credentials and produce auditable cross-account API noise.
    * ``kube_hunter`` (``--remote {host}``) issues real probes against
      the cluster control plane and may trip IDS / audit-log alerts.

    The §4.14 API / GraphQL batch (7 tools) and §4.16 IaC / code /
    secrets batch (8 tools) stay approval-free in Cycle 2 — the §4.14
    entries are read-only / introspection-style probes; the §4.16
    entries are passive offline analysis of operator-mounted bundles.

    ARG-019 introduces four more approval-gated entries (all in §4.17):

    * ``responder`` / ``ntlmrelayx`` — active LLMNR/NBT-NS poisoning
      and NTLM relay (loud on the wire, IDS-noisy).
    * ``impacket_secretsdump`` — SAM/LSA/NTDS.dit credential extraction.
    * ``bloodhound_python`` — authenticated AD enumeration that writes
      a session trace tied to the operator's principal.

    The remaining six §4.17 entries (``ldapsearch`` / ``snmpwalk`` /
    ``onesixtyone`` / ``ike_scan`` / ``redis_cli_probe`` /
    ``mongodb_probe``) are read-only enumeration and stay
    approval-free.  The five §4.18 binary-analysis tools are
    uniformly approval-free in Cycle 2.

    Cycle-2 reviewer H1 (ARG-019 closure) escalates one §4.19 entry
    into the approval-gated set: ``playwright_runner`` (generic
    scenario runner — its operator-supplied ``{script}`` can drive
    arbitrary state-changing browser actions: form submissions,
    OAuth consent flows, multi-step DOM mutations, file uploads,
    authenticated session capture).  The four targeted §4.19 probes
    (``puppeteer_screens`` / ``chrome_csp_probe`` / ``cors_probe`` /
    ``cookie_probe``) stay approval-free.
    """
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None
    if tool_id in _APPROVAL_REQUIRED:
        assert descriptor.requires_approval is True, (
            f"{tool_id}: active-payload / exploitation tools must require approval"
        )
    else:
        assert descriptor.requires_approval is False, (
            f"{tool_id} unexpectedly requires approval; only the documented "
            f"active-payload / exploitation / cracking tools may opt in"
        )


# Tools whose canonical output lives on stdout (no ``--output`` flag).  Their
# parsers — when they exist — fall back to ``raw_stdout``; the YAML therefore
# legitimately ships an empty ``evidence_artifacts`` list.  Adding an entry
# here is a deliberate, reviewable signal.
_STDOUT_ONLY_TOOLS: Final[frozenset[str]] = frozenset(
    {
        "magescan",  # ARG-014: scan:all only writes JSON to stdout
    }
)


@pytest.mark.parametrize("tool_id", sorted(EXPECTED_TOOLS))
def test_descriptor_declares_evidence_artifacts(
    loaded_registry: ToolRegistry, tool_id: str
) -> None:
    descriptor = loaded_registry.get(tool_id)
    assert descriptor is not None
    if tool_id in _STDOUT_ONLY_TOOLS:
        assert descriptor.evidence_artifacts == [], (
            f"{tool_id} is whitelisted as stdout-only — evidence_artifacts "
            f"must be empty (got {descriptor.evidence_artifacts!r})"
        )
        return
    assert descriptor.evidence_artifacts, (
        f"{tool_id} must declare at least one evidence artifact path"
    )
    for artifact in descriptor.evidence_artifacts:
        assert artifact.startswith("/out/"), (
            f"{tool_id} evidence path {artifact!r} must live under /out/"
        )


# ---------------------------------------------------------------------------
# Phase / category grouping
# ---------------------------------------------------------------------------


def test_grouping_by_phase_matches_backlog(loaded_registry: ToolRegistry) -> None:
    recon_ids = {d.tool_id for d in loaded_registry.list_by_phase(ScanPhase.RECON)}
    vuln_ids = {
        d.tool_id for d in loaded_registry.list_by_phase(ScanPhase.VULN_ANALYSIS)
    }

    # Recon must include every passive-recon tool plus active-recon tools that
    # are not the medium-risk nmap_vuln (which §4.2 places in vuln_analysis).
    assert RECON_PHASE_TOOLS.issubset(recon_ids), (
        f"recon phase missing: {sorted(RECON_PHASE_TOOLS - recon_ids)}"
    )
    assert VULN_ANALYSIS_TOOLS.issubset(vuln_ids), (
        f"vuln_analysis phase missing: {sorted(VULN_ANALYSIS_TOOLS - vuln_ids)}"
    )

    # Threshold checks that survive future additions to other phases.
    assert len(recon_ids) >= len(RECON_PHASE_TOOLS)
    assert len(vuln_ids) >= len(VULN_ANALYSIS_TOOLS)


def test_passive_recon_tools_are_passive_risk(
    loaded_registry: ToolRegistry,
) -> None:
    for tool_id in sorted(PASSIVE_RECON_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.risk_level is RiskLevel.PASSIVE, (
            f"{tool_id} expected RiskLevel.PASSIVE, got {descriptor.risk_level}"
        )
        assert descriptor.category is ToolCategory.RECON


def test_active_recon_tools_have_low_or_medium_risk(
    loaded_registry: ToolRegistry,
) -> None:
    for tool_id in sorted(ACTIVE_RECON_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        if tool_id == "nmap_vuln":
            assert descriptor.risk_level is RiskLevel.MEDIUM
            assert descriptor.phase is ScanPhase.VULN_ANALYSIS
        else:
            assert descriptor.risk_level is RiskLevel.LOW
            assert descriptor.phase is ScanPhase.RECON
        assert descriptor.category is ToolCategory.NETWORK


def test_tls_tools_are_low_risk_web_va(loaded_registry: ToolRegistry) -> None:
    for tool_id in sorted(TLS_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.risk_level is RiskLevel.LOW
        assert descriptor.category is ToolCategory.WEB_VA
        assert descriptor.phase is ScanPhase.VULN_ANALYSIS


# ---------------------------------------------------------------------------
# Network policy classification
# ---------------------------------------------------------------------------


def test_network_policy_names_are_consistent(loaded_registry: ToolRegistry) -> None:
    """Ensure each tool sits behind the expected NetworkPolicyRef name."""
    expected_policy: dict[str, str] = {}
    for tid in PASSIVE_RECON_TOOLS:
        expected_policy[tid] = "recon-passive"
    for tid in ACTIVE_RECON_TOOLS:
        if tid in {"nmap_udp", "unicornscan"}:
            expected_policy[tid] = "recon-active-udp"
        elif tid in {"smbmap", "enum4linux_ng", "rpcclient_enum"}:
            expected_policy[tid] = "recon-smb"
        else:
            expected_policy[tid] = "recon-active-tcp"
    for tid in TLS_TOOLS:
        expected_policy[tid] = "tls-handshake"
    for tid in HTTP_FINGERPRINT_TOOLS:
        expected_policy[tid] = "recon-passive"
    # §4.5 content discovery batch (ARG-012). Everything probes the
    # in-scope target over HTTP/HTTPS, so they live behind
    # ``recon-active-tcp`` — except ``paramspider`` which only queries the
    # Wayback Machine archive (no traffic to the target).
    for tid in CONTENT_DISCOVERY_TOOLS:
        if tid == "paramspider":
            expected_policy[tid] = "recon-passive"
        else:
            expected_policy[tid] = "recon-active-tcp"
    # §4.6 crawler / JS / endpoint extraction batch (ARG-013). Three
    # active crawlers (katana / gospider / hakrawler) hit the in-scope
    # target → ``recon-active-tcp``. The five passive tools either query
    # archive APIs (waybackurls / gau) or fetch static JS / consume local
    # files (linkfinder / subjs / secretfinder) → ``recon-passive``.
    crawler_active = frozenset({"katana", "gospider", "hakrawler"})
    for tid in CRAWLER_TOOLS:
        if tid in crawler_active:
            expected_policy[tid] = "recon-active-tcp"
        else:
            expected_policy[tid] = "recon-passive"
    # §4.7 CMS scanners (ARG-014). Every entry probes the in-scope target
    # over HTTP/HTTPS — including the three nuclei wrappers — so they all
    # live behind ``recon-active-tcp``.  No archive-only entries exist in
    # this batch.
    for tid in CMS_TOOLS:
        expected_policy[tid] = "recon-active-tcp"
    # §4.8 web vulnerability scanners (ARG-015). Every entry — including
    # the flagship ``nuclei`` and the approval-gated active scanners —
    # talks to the in-scope target over HTTP/HTTPS, so they all live
    # behind ``recon-active-tcp``.
    for tid in WEB_VULN_TOOLS:
        expected_policy[tid] = "recon-active-tcp"
    # §4.9 SQLi (ARG-016). Every entry — both passive sqlmap_safe and
    # the gated exploitation tools — sits behind ``recon-active-tcp``;
    # they all probe the in-scope HTTP target.
    for tid in SQLI_TOOLS:
        expected_policy[tid] = "recon-active-tcp"
    # §4.10 XSS (ARG-016). Same treatment: dalfox / xsstrike / xsser fire
    # against the in-scope target, kxss reads its URL list from stdin via
    # the runtime wrapper but still talks to the same target, and the
    # headless playwright verifier loads the in-scope URL with a canary
    # payload — all behind ``recon-active-tcp``.
    for tid in XSS_TOOLS:
        expected_policy[tid] = "recon-active-tcp"
    # §4.11 SSRF / OAST (ARG-017). The OAST receivers + ssrfmap + the
    # canary DNS probe all need to talk to the dedicated OAST plane
    # (10.244.250.0/24) plus the in-scope target, so they live behind
    # the new ``oast-egress`` policy. ``gopherus`` runs offline (it's a
    # pure payload-string generator — no network egress) so it lives
    # behind ``offline-no-egress`` for defence-in-depth.
    for tid in OAST_TOOLS:
        if tid == "gopherus":
            expected_policy[tid] = "offline-no-egress"
        elif tid == "cloud_metadata_check":
            # Reviewer C1 (cycle 2) restored Backlog §4.11 IMDS probe.
            # The wrapper script speaks plain HTTP to the metadata
            # endpoints (AWS / GCE / Azure) and reuses the existing
            # ``recon-active-tcp`` policy rather than the
            # OAST-receiver-specific ``oast-egress`` egress allow-list.
            expected_policy[tid] = "recon-active-tcp"
        else:
            expected_policy[tid] = "oast-egress"
    # §4.12 Auth / bruteforce (ARG-017). Every credential-test entry
    # hits authenticated services on the in-scope target only — no
    # archive APIs, no upstream registries — so they all live behind
    # the ``auth-bruteforce`` policy that opens the common Windows /
    # *nix auth ports.  The reviewer C2 (cycle 2) addition
    # ``gobuster_auth`` is the lone outlier: it fuzzes HTTP login
    # surfaces over plain TCP and reuses ``recon-active-tcp``.
    for tid in AUTH_TOOLS:
        if tid == "gobuster_auth":
            expected_policy[tid] = "recon-active-tcp"
        else:
            expected_policy[tid] = "auth-bruteforce"
    # §4.13 Hash / crypto (ARG-017). Every cracker / classifier runs
    # FULLY OFFLINE behind the ``offline-no-egress`` policy (no DNS,
    # no egress) so a malicious wordlist or rule pack cannot exfiltrate
    # the captured hashes.
    for tid in HASH_TOOLS:
        expected_policy[tid] = "offline-no-egress"
    # §4.14 API / GraphQL / gRPC (ARG-018). Every entry probes a live
    # API surface (HTTP for REST/GraphQL, raw TCP for gRPC reflection),
    # so they all live behind ``recon-active-tcp``.  No archive-only
    # entries in this batch.
    for tid in API_GRAPHQL_TOOLS:
        expected_policy[tid] = "recon-active-tcp"
    # §4.15 Cloud / IaC / container (ARG-018). Three policy buckets:
    #   * ``recon-passive`` (broad TCP/443 to cloud + registry APIs):
    #     prowler / scoutsuite / cloudsploit / pacu hit AWS APIs;
    #     trivy_image / trivy_fs / grype / syft / dockle pull from the
    #     image registry and refresh their vuln DBs.  Cycle 4 will pin
    #     these to a dedicated ``cloud-aws`` policy with explicit
    #     AWS endpoint allow-listing.
    #   * ``offline-no-egress`` for the local-config scanners
    #     (``kube_bench`` reads /etc/kubernetes manifests; ``checkov``
    #     analyses the operator-mounted IaC bundle).
    #   * ``recon-active-tcp`` for the active K8s control-plane probe
    #     (``kube_hunter --remote {host}``) — egress restricted to
    #     the per-job target CIDR.
    cloud_iac_offline = frozenset({"kube_bench", "checkov"})
    cloud_iac_active = frozenset({"kube_hunter"})
    for tid in CLOUD_IAC_TOOLS:
        if tid in cloud_iac_offline:
            expected_policy[tid] = "offline-no-egress"
        elif tid in cloud_iac_active:
            expected_policy[tid] = "recon-active-tcp"
        else:
            expected_policy[tid] = "recon-passive"
    # §4.16 IaC / code / secrets (ARG-018). Every entry runs FULLY
    # OFFLINE (offline-no-egress) — rule packs and detectors ship
    # bundled inside the image; analysis target is the operator-mounted
    # source bundle at {path}.
    for tid in CODE_SECRETS_TOOLS:
        expected_policy[tid] = "offline-no-egress"
    # §4.17 Network protocol / AD / poisoning (ARG-019).  Every entry
    # in this batch reuses ``auth-bruteforce`` because the egress
    # profile (Windows / *nix auth services + AD ports + SNMP / IKE /
    # DB pre-auth) lines up exactly with what the policy already opens.
    # Carving a dedicated ``ad-network`` policy was deferred to Cycle 3
    # so we don't duplicate the egress allow-list for 10 tools.
    for tid in NETWORK_PROTOCOL_TOOLS:
        expected_policy[tid] = "auth-bruteforce"
    # §4.18 Binary analysis (ARG-019).  Every entry runs FULLY OFFLINE
    # behind ``offline-no-egress`` because the inputs are
    # operator-mounted samples under ``/in/`` — a malicious APK / ELF /
    # firmware blob must NOT be able to reach the network.
    for tid in BINARY_TOOLS:
        expected_policy[tid] = "offline-no-egress"
    # §4.19 Browser / headless (ARG-019).  ``puppeteer_screens`` is
    # passive (page load + screenshot, no JS interaction) so it lives
    # behind ``recon-passive``.  The four active probes (runner +
    # CSP / CORS / cookie checks) target the in-scope HTTP surface
    # over ``recon-active-tcp``.
    for tid in BROWSER_TOOLS:
        if tid == "puppeteer_screens":
            expected_policy[tid] = "recon-passive"
        else:
            expected_policy[tid] = "recon-active-tcp"

    mismatches: list[str] = []
    for tool_id, want in sorted(expected_policy.items()):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        got = descriptor.network_policy.name
        if got != want:
            mismatches.append(f"{tool_id}: expected {want}, got {got}")
    assert not mismatches, "network policy mismatches:\n" + "\n".join(mismatches)


# ---------------------------------------------------------------------------
# §4.4 HTTP fingerprinting batch (ARG-011)
# ---------------------------------------------------------------------------


def test_http_fingerprint_tools_are_passive_recon(
    loaded_registry: ToolRegistry,
) -> None:
    """All §4.4 tools must be passive-risk recon-phase web-VA imageries."""
    for tool_id in sorted(HTTP_FINGERPRINT_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        assert descriptor.risk_level is RiskLevel.PASSIVE, (
            f"{tool_id} expected RiskLevel.PASSIVE, got {descriptor.risk_level}"
        )
        assert descriptor.phase is ScanPhase.RECON
        assert descriptor.category is ToolCategory.RECON
        assert descriptor.requires_approval is False
        assert descriptor.image == "argus-kali-web:latest", (
            f"{tool_id} expected image argus-kali-web:latest, got {descriptor.image!r}"
        )


def test_http_fingerprint_tools_have_owasp_wstg_hints(
    loaded_registry: ToolRegistry,
) -> None:
    """Every §4.4 tool must carry the WSTG-INFO-02 / WSTG-INFO-08 hints."""
    required = {"WSTG-INFO-02", "WSTG-INFO-08"}
    for tool_id in sorted(HTTP_FINGERPRINT_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        got = set(descriptor.owasp_wstg)
        missing = required - got
        assert not missing, f"{tool_id} missing OWASP WSTG hints: {sorted(missing)}"


def test_descriptors_are_frozen_pydantic_instances(
    loaded_registry: ToolRegistry,
) -> None:
    """Defence-in-depth: the registry hands out immutable descriptors."""
    for descriptor in loaded_registry.all_descriptors():
        assert isinstance(descriptor, ToolDescriptor)
        with pytest.raises(Exception):
            descriptor.tool_id = "tampered"


# ---------------------------------------------------------------------------
# §4.6 crawler / JS / endpoint extraction batch (ARG-013)
# ---------------------------------------------------------------------------


def test_crawler_tools_run_on_argus_kali_web(loaded_registry: ToolRegistry) -> None:
    """All §4.6 tools must use ``argus-kali-web:latest`` (Kali web tooling image)."""
    for tool_id in sorted(CRAWLER_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        assert descriptor.image == "argus-kali-web:latest", (
            f"{tool_id} expected image argus-kali-web:latest, got {descriptor.image!r}"
        )
        assert descriptor.requires_approval is False, (
            f"{tool_id}: §4.6 tools are pre-approved (low-risk crawler / passive miner)"
        )


def test_crawler_tools_have_owasp_wstg_hints(loaded_registry: ToolRegistry) -> None:
    """Every §4.6 tool must carry at least one WSTG hint (endpoint discovery /
    secret leak — see :mod:`tests.unit.sandbox.test_yaml_crawler_semantics`).
    """
    for tool_id in sorted(CRAWLER_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.owasp_wstg, (
            f"{tool_id}: §4.6 tools must declare at least one OWASP WSTG hint"
        )


# ---------------------------------------------------------------------------
# §4.7 CMS / platform-specific scanners batch (ARG-014)
# ---------------------------------------------------------------------------


def test_cms_tools_run_on_argus_kali_web(loaded_registry: ToolRegistry) -> None:
    """All §4.7 tools must use ``argus-kali-web:latest`` (Kali web tooling image)."""
    for tool_id in sorted(CMS_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        assert descriptor.image == "argus-kali-web:latest", (
            f"{tool_id} expected image argus-kali-web:latest, got {descriptor.image!r}"
        )
        assert descriptor.requires_approval is False, (
            f"{tool_id}: §4.7 ARG-014 batch is approval-free "
            f"(brute-force / exploit paths deferred to Cycle 3)"
        )


def test_cms_tools_classify_as_low_risk_web_va(
    loaded_registry: ToolRegistry,
) -> None:
    """§4.7 batch is low-risk vuln_analysis web_va — no recon/network tools.

    The eight tools intentionally sit in vuln_analysis even though some of
    them (e.g. ``droopescan``) emit info-class findings only — the placement
    follows the user-facing taxonomy of "platform-aware vulnerability
    surfacing".
    """
    for tool_id in sorted(CMS_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.risk_level is RiskLevel.LOW
        assert descriptor.phase is ScanPhase.VULN_ANALYSIS
        assert descriptor.category is ToolCategory.WEB_VA


def test_cms_tools_have_cwe_and_owasp_hints(loaded_registry: ToolRegistry) -> None:
    """Every §4.7 tool must declare CWE-200 (sensitive info exposure) and the
    OWASP WSTG-CONF-04 hint (security-misconfiguration class) to feed the
    normaliser's classification path.

    CWE-200 is the universal floor of the §4.7 batch — every CMS / platform
    scanner exposes at least one info-disclosure surface (versions, endpoint
    fingerprinting, enumerated users / modules / actuator endpoints). The
    five pure CMS scanners additionally carry CWE-1395 (vulnerable
    component). Among the three nuclei wrappers the picture is mixed:
    ``nextjs_check`` keeps CWE-1395 (CVE-2025-29927 is a framework vuln),
    ``jenkins_enum`` carries both CWE-1395 and CWE-287 (vulnerable plugins
    *and* unauthenticated script-console exposure), and only
    ``spring_boot_actuator`` drops CWE-1395 in favour of CWE-16 / CWE-287
    because its primary failure mode is misconfiguration, not a vulnerable
    upstream package — a deliberate, reviewable choice.
    """
    for tool_id in sorted(CMS_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert 200 in descriptor.cwe_hints, (
            f"{tool_id}: §4.7 CMS scanners must declare CWE-200 "
            f"(exposure of sensitive information to an unauthorised actor); "
            f"got {descriptor.cwe_hints}"
        )
        assert "WSTG-CONF-04" in descriptor.owasp_wstg, (
            f"{tool_id}: §4.7 CMS scanners must declare WSTG-CONF-04 "
            f"(security misconfiguration); got {descriptor.owasp_wstg}"
        )


def test_cms_tools_parse_strategy_distribution(
    loaded_registry: ToolRegistry,
) -> None:
    """Pin the §4.7 parse-strategy distribution to catch silent regressions.

    * ``json_object`` (2): wpscan, droopescan — wired in ARG-014.
    * ``text_lines`` (3): joomscan, cmsmap, magescan — full parsers
      deferred to Cycle 3.
    * ``nuclei_jsonl`` (3): nextjs_check, spring_boot_actuator,
      jenkins_enum — wired in ARG-015 (shared parser).
    """
    expected: dict[str, str] = {
        "wpscan": "json_object",
        "droopescan": "json_object",
        "joomscan": "text_lines",
        "cmsmap": "text_lines",
        "magescan": "text_lines",
        "nextjs_check": "nuclei_jsonl",
        "spring_boot_actuator": "nuclei_jsonl",
        "jenkins_enum": "nuclei_jsonl",
    }
    mismatches: list[str] = []
    for tool_id, want in expected.items():
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        got = descriptor.parse_strategy.value
        if got != want:
            mismatches.append(f"{tool_id}: expected {want}, got {got}")
    assert not mismatches, "§4.7 parse_strategy mismatches:\n" + "\n".join(mismatches)


# ---------------------------------------------------------------------------
# §4.8 Web vulnerability scanners batch (ARG-015)
# ---------------------------------------------------------------------------


def test_web_vuln_tools_run_on_argus_kali_web(loaded_registry: ToolRegistry) -> None:
    """All §4.8 tools must use ``argus-kali-web:latest`` (Kali web tooling image)."""
    for tool_id in sorted(WEB_VULN_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        assert descriptor.image == "argus-kali-web:latest", (
            f"{tool_id} expected image argus-kali-web:latest, got {descriptor.image!r}"
        )


def test_web_vuln_tools_classify_as_web_va(
    loaded_registry: ToolRegistry,
) -> None:
    """§4.8 batch is web_va vuln_analysis with risk profile pinned per-tool.

    Approval-gated active scanners ride at ``risk_level=medium``; the
    template-driven / passive entries stay at ``risk_level=low`` so their
    cost summary surfaces as the operator default.
    """
    for tool_id in sorted(WEB_VULN_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.phase is ScanPhase.VULN_ANALYSIS
        assert descriptor.category is ToolCategory.WEB_VA
        if tool_id in WEB_VULN_APPROVAL_REQUIRED:
            assert descriptor.risk_level is RiskLevel.MEDIUM, (
                f"{tool_id}: active-payload §4.8 tools must classify as MEDIUM"
            )
        else:
            assert descriptor.risk_level is RiskLevel.LOW, (
                f"{tool_id}: template-driven / passive §4.8 tools stay LOW"
            )


def test_web_vuln_tools_parse_strategy_distribution(
    loaded_registry: ToolRegistry,
) -> None:
    """Pin the §4.8 parse-strategy distribution.

    * ``nuclei_jsonl`` (1): ``nuclei`` — flagship parser shared with §4.7
      wrappers via :func:`src.sandbox.parsers.nuclei_parser.parse_nuclei_jsonl`.
    * ``json_object`` (2): nikto, wapiti — dedicated parsers ship in
      ARG-015 (:func:`src.sandbox.parsers.nuclei_parser.parse_nikto_json` /
      :func:`parse_wapiti_json`).
    * ``text_lines`` (4): arachni, skipfish, w3af_console, zap_baseline.
      The first three emit report-tree / binary AFR / plain text;
      ``zap_baseline`` is JSON-emitting but its dedicated parser is
      deferred to Cycle 3 — text_lines keeps the dispatch layer honest
      about the lack of finding extraction (the JSON / HTML / XML
      reports still land in evidence_artifacts).
    """
    expected: dict[str, str] = {
        "nuclei": "nuclei_jsonl",
        "nikto": "json_object",
        "wapiti": "json_object",
        "zap_baseline": "text_lines",
        "arachni": "text_lines",
        "skipfish": "text_lines",
        "w3af_console": "text_lines",
    }
    mismatches: list[str] = []
    for tool_id, want in expected.items():
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        got = descriptor.parse_strategy.value
        if got != want:
            mismatches.append(f"{tool_id}: expected {want}, got {got}")
    assert not mismatches, "§4.8 parse_strategy mismatches:\n" + "\n".join(mismatches)


def test_web_vuln_tools_have_cwe_and_owasp_hints(
    loaded_registry: ToolRegistry,
) -> None:
    """Every §4.8 tool must declare at least one CWE hint and one WSTG hint.

    The §4.8 batch covers wide classification surfaces (XSS, SQLi, RCE,
    misconfig, exposure) so we don't pin a specific CWE — but each tool
    must surface non-empty hints so the normaliser has a starting point.
    """
    for tool_id in sorted(WEB_VULN_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.cwe_hints, (
            f"{tool_id}: §4.8 tools must declare at least one CWE hint"
        )
        assert descriptor.owasp_wstg, (
            f"{tool_id}: §4.8 tools must declare at least one OWASP WSTG hint"
        )


# ---------------------------------------------------------------------------
# §4.9 SQL-injection scanners batch (ARG-016)
# ---------------------------------------------------------------------------


def test_sqli_tools_run_on_argus_kali_web(loaded_registry: ToolRegistry) -> None:
    """All §4.9 SQLi tools must use ``argus-kali-web:latest``."""
    for tool_id in sorted(SQLI_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        assert descriptor.image == "argus-kali-web:latest", (
            f"{tool_id} expected image argus-kali-web:latest, got {descriptor.image!r}"
        )


def test_sqli_tools_phase_split(loaded_registry: ToolRegistry) -> None:
    """``sqlmap_confirm`` is the only §4.9 entry that escalates to exploitation.

    The other five SQLi tools live in ``vuln_analysis``: ``sqlmap_safe``
    is conservative passive detection, while ``ghauri`` / ``jsql`` /
    ``tplmap`` / ``nosqlmap`` declare ``vuln_analysis`` even though they
    fire active payloads (the approval gate is what keeps them honest;
    phase placement matches the §4.9 backlog header). ``sqlmap_confirm``
    moves to ``exploitation`` because it actively dumps schema + counts.
    """
    for tool_id in sorted(SQLI_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.category is ToolCategory.WEB_VA
        if tool_id == "sqlmap_confirm":
            assert descriptor.phase is ScanPhase.EXPLOITATION, (
                f"{tool_id} must escalate to exploitation phase"
            )
        else:
            assert descriptor.phase is ScanPhase.VULN_ANALYSIS, (
                f"{tool_id} expected ScanPhase.VULN_ANALYSIS, got {descriptor.phase}"
            )


def test_sqli_tools_risk_level_distribution(loaded_registry: ToolRegistry) -> None:
    """Pin the §4.9 risk-level distribution for cost / approval bookkeeping.

    * ``sqlmap_safe`` — ``MEDIUM`` (boolean+time-based blind only, but
      approval-gated → ARG-020 invariant requires risk >= MEDIUM).
    * ``ghauri`` / ``jsql`` / ``nosqlmap`` — ``MEDIUM`` (active SQLi).
    * ``sqlmap_confirm`` / ``tplmap`` — ``HIGH`` (data exfil / SSTI RCE).
    """
    expected: dict[str, RiskLevel] = {
        "sqlmap_safe": RiskLevel.MEDIUM,
        "sqlmap_confirm": RiskLevel.HIGH,
        "ghauri": RiskLevel.MEDIUM,
        "jsql": RiskLevel.MEDIUM,
        "tplmap": RiskLevel.HIGH,
        "nosqlmap": RiskLevel.MEDIUM,
    }
    mismatches: list[str] = []
    for tool_id, want in expected.items():
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        if descriptor.risk_level is not want:
            mismatches.append(
                f"{tool_id}: expected {want}, got {descriptor.risk_level}"
            )
    assert not mismatches, "§4.9 risk_level mismatches:\n" + "\n".join(mismatches)


def test_sqli_tools_have_correct_cwe_hints(loaded_registry: ToolRegistry) -> None:
    """Pin per-tool CWE hints for the §4.9 batch.

    Most §4.9 entries surface CWE-89 (SQL Injection). Two outliers are
    grouped with the SQLi family in Backlog §4.9 even though their
    primary CWE is different:

    * ``nosqlmap`` — primary CWE-943 (Improper Neutralization of Special
      Elements used in a Data Query Logic, the parent class for NoSQLi)
      with CWE-89 carried as a fallback for NoSQL clusters that proxy
      SQL queries.
    * ``tplmap`` — server-side template injection (CWE-1336 / CWE-94 /
      CWE-78) — NOT SQLi.  It's grouped under §4.9 in the backlog
      because it shares the "active injection probe" risk profile, not
      because it produces SQLi findings.  Its CWEs are pinned exactly
      so a future regression that adds CWE-89 here surfaces immediately.
    """
    expected: dict[str, set[int]] = {
        "sqlmap_safe": {89},
        "sqlmap_confirm": {89},
        "ghauri": {89},
        "jsql": {89},
        "nosqlmap": {943},
        "tplmap": {1336, 94, 78},
    }
    mismatches: list[str] = []
    for tool_id, required in expected.items():
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        cwes = set(descriptor.cwe_hints)
        missing = required - cwes
        if missing:
            mismatches.append(
                f"{tool_id}: missing CWE hints {sorted(missing)}, got {sorted(cwes)}"
            )
    assert not mismatches, "§4.9 CWE hint mismatches:\n" + "\n".join(mismatches)


def test_sqli_tools_have_inpv_wstg_hints(loaded_registry: ToolRegistry) -> None:
    """Every §4.9 tool must surface at least one WSTG-INPV-* hint.

    The WSTG INPV (input validation) family covers SQLi (INPV-05),
    NoSQLi (INPV-13), template injection (INPV-18) and the broader
    "test for injection" suite — all relevant to §4.9.
    """
    for tool_id in sorted(SQLI_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert any(tag.startswith("WSTG-INPV") for tag in descriptor.owasp_wstg), (
            f"{tool_id}: §4.9 tools must declare at least one WSTG-INPV-* hint; "
            f"got {descriptor.owasp_wstg}"
        )


def test_sqli_tools_parse_strategy_distribution(
    loaded_registry: ToolRegistry,
) -> None:
    """Pin the §4.9 parse-strategy distribution.

    * ``text_lines`` (5): ``sqlmap_safe`` / ``sqlmap_confirm`` (both
      wired in ARG-016 via
      :func:`src.sandbox.parsers.sqlmap_parser.parse_sqlmap_output`),
      plus ``ghauri`` / ``tplmap`` / ``nosqlmap`` whose full parsers
      are deferred to Cycle 3 (dispatch falls through to
      ``unmapped_tool``).
    * ``json_object`` (1): ``jsql`` — emits a JSON report per probe;
      full parser deferred to Cycle 3.
    """
    expected: dict[str, str] = {
        "sqlmap_safe": "text_lines",
        "sqlmap_confirm": "text_lines",
        "ghauri": "text_lines",
        "jsql": "json_object",
        "tplmap": "text_lines",
        "nosqlmap": "text_lines",
    }
    mismatches: list[str] = []
    for tool_id, want in expected.items():
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        got = descriptor.parse_strategy.value
        if got != want:
            mismatches.append(f"{tool_id}: expected {want}, got {got}")
    assert not mismatches, "§4.9 parse_strategy mismatches:\n" + "\n".join(mismatches)


# ---------------------------------------------------------------------------
# §4.10 XSS scanners batch (ARG-016)
# ---------------------------------------------------------------------------


def test_xss_tools_use_correct_image(loaded_registry: ToolRegistry) -> None:
    """All §4.10 XSS tools must use ``argus-kali-web:latest`` **except**
    ``playwright_xss_verify`` which lives in ``argus-kali-browser:latest``
    (Chromium + Playwright runtime).
    """
    for tool_id in sorted(XSS_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        if tool_id == "playwright_xss_verify":
            assert descriptor.image == "argus-kali-browser:latest", (
                f"{tool_id} must use argus-kali-browser:latest, "
                f"got {descriptor.image!r}"
            )
        else:
            assert descriptor.image == "argus-kali-web:latest", (
                f"{tool_id} expected argus-kali-web:latest, got {descriptor.image!r}"
            )


def test_xss_tools_phase_split(loaded_registry: ToolRegistry) -> None:
    """``playwright_xss_verify`` is the only §4.10 entry that escalates to
    exploitation. The other four XSS tools live in ``vuln_analysis``.

    Backlog §4.10 lists the playwright verifier under "validation" — a
    phase that does not exist in :class:`ScanPhase`. ARG-016 maps it to
    ``exploitation`` with ``risk_level=low`` so the canary-only verifier
    stays approval-free while still surfacing a distinct phase.
    """
    for tool_id in sorted(XSS_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        if tool_id == "playwright_xss_verify":
            assert descriptor.phase is ScanPhase.EXPLOITATION, (
                f"{tool_id} must escalate to exploitation phase"
            )
            assert descriptor.category is ToolCategory.BROWSER, (
                f"{tool_id} must classify as ToolCategory.BROWSER, "
                f"got {descriptor.category}"
            )
        else:
            assert descriptor.phase is ScanPhase.VULN_ANALYSIS, (
                f"{tool_id} expected ScanPhase.VULN_ANALYSIS, got {descriptor.phase}"
            )
            assert descriptor.category is ToolCategory.WEB_VA, (
                f"{tool_id} expected ToolCategory.WEB_VA, got {descriptor.category}"
            )


def test_xss_tools_risk_level_distribution(loaded_registry: ToolRegistry) -> None:
    """Pin the §4.10 risk-level distribution.

    * ``kxss`` — ``PASSIVE`` (pure stdin grep / archive parser).
    * ``dalfox`` / ``xsstrike`` / ``xsser`` / ``playwright_xss_verify`` —
      ``LOW`` (reflection-only payloads + canary-only headless verifier).
    """
    expected: dict[str, RiskLevel] = {
        "dalfox": RiskLevel.LOW,
        "xsstrike": RiskLevel.LOW,
        "kxss": RiskLevel.PASSIVE,
        "xsser": RiskLevel.LOW,
        "playwright_xss_verify": RiskLevel.LOW,
    }
    mismatches: list[str] = []
    for tool_id, want in expected.items():
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        if descriptor.risk_level is not want:
            mismatches.append(
                f"{tool_id}: expected {want}, got {descriptor.risk_level}"
            )
    assert not mismatches, "§4.10 risk_level mismatches:\n" + "\n".join(mismatches)


def test_xss_tools_have_cwe79_and_inpv_hints(loaded_registry: ToolRegistry) -> None:
    """Every §4.10 tool must surface CWE-79 (XSS) and at least one
    WSTG-INPV-* hint (the WSTG XSS family lives in INPV-01 / INPV-02).
    """
    for tool_id in sorted(XSS_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert 79 in descriptor.cwe_hints, (
            f"{tool_id}: §4.10 XSS tools must declare CWE-79 "
            f"(Cross-Site Scripting); got {descriptor.cwe_hints}"
        )
        assert any(tag.startswith("WSTG-INPV") for tag in descriptor.owasp_wstg), (
            f"{tool_id}: §4.10 tools must declare at least one WSTG-INPV-* "
            f"hint; got {descriptor.owasp_wstg}"
        )


def test_xss_tools_parse_strategy_distribution(loaded_registry: ToolRegistry) -> None:
    """Pin the §4.10 parse-strategy distribution.

    * ``json_object`` (4): ``dalfox`` (parsed in Cycle 2, ARG-016 via
      :func:`src.sandbox.parsers.dalfox_parser.parse_dalfox_json`) +
      ``xsstrike`` / ``xsser`` (each emits a JSON report, full parsers
      deferred to Cycle 3) + ``playwright_xss_verify`` (verifier emits a
      JSON verdict; full parser deferred to Cycle 3 ARG-019).
    * ``text_lines`` (1): ``kxss`` — pure stdin grep wrapper, plain text
      output; parser deferred to Cycle 3.
    """
    expected: dict[str, str] = {
        "dalfox": "json_object",
        "xsstrike": "json_object",
        "xsser": "json_object",
        "playwright_xss_verify": "json_object",
        "kxss": "text_lines",
    }
    mismatches: list[str] = []
    for tool_id, want in expected.items():
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        got = descriptor.parse_strategy.value
        if got != want:
            mismatches.append(f"{tool_id}: expected {want}, got {got}")
    assert not mismatches, "§4.10 parse_strategy mismatches:\n" + "\n".join(mismatches)


def test_arg016_phase_placement_matches_grouping_constants(
    loaded_registry: ToolRegistry,
) -> None:
    """Cross-check the §4.9 / §4.10 phase split against the module-level
    grouping constants.

    Walking the registry by phase and asserting the two §4.9/§4.10 entries
    that escalate to ``exploitation`` lock the contract from both
    directions: the per-tool tests above check each descriptor has the
    right phase, and this test confirms ``list_by_phase`` surfaces the
    same two tool IDs (no silent drift between metadata and dispatch).
    """
    exploitation_ids = {
        d.tool_id for d in loaded_registry.list_by_phase(ScanPhase.EXPLOITATION)
    }
    arg016_exploitation = exploitation_ids & (SQLI_TOOLS | XSS_TOOLS)
    expected_arg016 = frozenset({"sqlmap_confirm", "playwright_xss_verify"})
    assert arg016_exploitation == expected_arg016, (
        f"§4.9/§4.10 exploitation drift: "
        f"expected {sorted(expected_arg016)}, "
        f"got {sorted(arg016_exploitation)}"
    )


# ---------------------------------------------------------------------------
# §4.11 SSRF / OAST / OOB batch (ARG-017)
# ---------------------------------------------------------------------------


def test_oast_tools_use_correct_image(loaded_registry: ToolRegistry) -> None:
    """§4.11 image distribution.

    Most §4.11 tools share ``argus-kali-web:latest`` because the SSRF
    payloads + OAST receivers ride the standard Kali web tooling image.
    The cycle-2 reviewer-restored ``cloud_metadata_check`` (Backlog
    §4.11) is the lone outlier: it lives in ``argus-kali-cloud:latest``
    because the wrapper script bundling the AWS / GCE / Azure IMDS
    probes only ships in the cloud-tooling image.
    """
    cloud_image_tools = {"cloud_metadata_check"}
    for tool_id in sorted(OAST_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        expected_image = (
            "argus-kali-cloud:latest"
            if tool_id in cloud_image_tools
            else "argus-kali-web:latest"
        )
        assert descriptor.image == expected_image, (
            f"{tool_id} expected {expected_image}, got {descriptor.image!r}"
        )


def test_oast_tools_phase_classification(loaded_registry: ToolRegistry) -> None:
    """§4.11 phase split.

    Every §4.11 tool lives in ``vuln_analysis`` (OAST findings populate
    the SSRF evidence stream).  Two exceptions:

    * ``ssrfmap`` keeps ``vuln_analysis`` placement but requires
      operator approval (active SSRF exploitation).
    * ``cloud_metadata_check`` (reviewer C1 cycle 2) graduates to
      ``exploitation`` because IMDS probing reaches a privileged
      endpoint, and is approval-gated for the same reason.

    The default-deny entries (``interactsh_client`` / ``oastify_client``
    / ``gopherus`` / ``oast_dns_probe``) stay approval-free.
    """
    exploitation_oast = {"cloud_metadata_check"}
    approval_oast = {"ssrfmap", "cloud_metadata_check"}
    for tool_id in sorted(OAST_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        expected_phase = (
            ScanPhase.EXPLOITATION
            if tool_id in exploitation_oast
            else ScanPhase.VULN_ANALYSIS
        )
        assert descriptor.phase is expected_phase, (
            f"{tool_id} expected {expected_phase!r}, got {descriptor.phase}"
        )
        expected_approval = tool_id in approval_oast
        assert descriptor.requires_approval is expected_approval, (
            f"{tool_id} requires_approval={descriptor.requires_approval} "
            f"contradicts §4.11 approval gate (expected {expected_approval})"
        )


def test_oast_tools_have_cwe918_and_inpv19_hints(
    loaded_registry: ToolRegistry,
) -> None:
    """Every §4.11 tool must surface CWE-918 (SSRF) and WSTG-INPV-19."""
    for tool_id in sorted(OAST_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert 918 in descriptor.cwe_hints, (
            f"{tool_id}: §4.11 OAST tools must declare CWE-918 (SSRF); "
            f"got {descriptor.cwe_hints}"
        )
        assert "WSTG-INPV-19" in descriptor.owasp_wstg, (
            f"{tool_id}: §4.11 OAST tools must declare WSTG-INPV-19; "
            f"got {descriptor.owasp_wstg}"
        )


def test_oast_tools_parse_strategy_distribution(
    loaded_registry: ToolRegistry,
) -> None:
    """Pin the §4.11 parse-strategy distribution.

    * ``json_lines`` (2): ``interactsh_client`` / ``oastify_client`` —
      both routed through
      :func:`src.sandbox.parsers.interactsh_parser.parse_interactsh_jsonl`.
    * ``text_lines`` (4): ``ssrfmap`` / ``gopherus`` / ``oast_dns_probe``
      / ``cloud_metadata_check`` — full parsers deferred to Cycle 3.
    """
    expected: dict[str, str] = {
        "interactsh_client": "json_lines",
        "oastify_client": "json_lines",
        "ssrfmap": "text_lines",
        "gopherus": "text_lines",
        "oast_dns_probe": "text_lines",
        "cloud_metadata_check": "text_lines",
    }
    mismatches: list[str] = []
    for tool_id, want in expected.items():
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        got = descriptor.parse_strategy.value
        if got != want:
            mismatches.append(f"{tool_id}: expected {want}, got {got}")
    assert not mismatches, "§4.11 parse_strategy mismatches:\n" + "\n".join(mismatches)


# ---------------------------------------------------------------------------
# §4.12 Auth / bruteforce batch (ARG-017)
# ---------------------------------------------------------------------------


def test_auth_tools_use_correct_image(loaded_registry: ToolRegistry) -> None:
    """§4.12 tools carry the correct per-tool image after ARG-058 / T03.

    The auth cohort is no longer monolithic-web after T03:
    - HTTP/HTTPS surface tooling (``gobuster_auth`` + the four generic
      brute-forcers ``hydra`` / ``medusa`` / ``ncrack`` / ``patator``)
      stays on ``argus-kali-web:latest``.
    - The 6 AD / SMB / SNMP / Kerberos / WinRM tools moved to the
      dedicated ``argus-kali-network:latest`` image, which carves out
      that footprint so the heavier web image stays HTTP-focused.

    Pinned via :data:`AUTH_IMAGE_BY_TOOL` (lock-step guarded against
    :data:`AUTH_TOOLS` at module load time).
    """
    for tool_id in sorted(AUTH_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        expected_image = AUTH_IMAGE_BY_TOOL[tool_id]
        assert descriptor.image == expected_image, (
            f"{tool_id}: expected {expected_image}, got {descriptor.image}"
        )


def test_auth_tools_phase_split(loaded_registry: ToolRegistry) -> None:
    """§4.12 phase split.

    * ``snmp_check`` lives in ``recon`` (read-only SNMP walk).
    * ``evil_winrm`` graduates to ``post_exploitation`` (interactive
      shell with stolen credentials).
    * ``gobuster_auth`` (reviewer C2 cycle 2) lives in
      ``vuln_analysis`` because its bruteforce is response-fingerprint
      enumeration of HTTP login surfaces, not credential exfiltration.
    * The remaining eight tools live in ``exploitation`` (active
      credential testing on the in-scope target).
    """
    for tool_id in sorted(AUTH_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        if tool_id == "snmp_check":
            assert descriptor.phase is ScanPhase.RECON, (
                f"{tool_id} expected ScanPhase.RECON, got {descriptor.phase}"
            )
        elif tool_id == "evil_winrm":
            assert descriptor.phase is ScanPhase.POST_EXPLOITATION, (
                f"{tool_id} expected ScanPhase.POST_EXPLOITATION, "
                f"got {descriptor.phase}"
            )
        elif tool_id == "gobuster_auth":
            assert descriptor.phase is ScanPhase.VULN_ANALYSIS, (
                f"{tool_id} expected ScanPhase.VULN_ANALYSIS, got {descriptor.phase}"
            )
        else:
            assert descriptor.phase is ScanPhase.EXPLOITATION, (
                f"{tool_id} expected ScanPhase.EXPLOITATION, got {descriptor.phase}"
            )


def test_auth_tools_have_cwe287_or_307_hints(loaded_registry: ToolRegistry) -> None:
    """Every §4.12 tool must surface at least one of:
    CWE-287 (improper authentication), CWE-307 (improper restriction of
    excessive authentication attempts), or — for the read-only outliers
    (``snmp_check`` / ``kerbrute``) — CWE-200 (info exposure) /
    CWE-204 (response discrepancy).
    """
    auth_cwes = {287, 307, 200, 204, 522, 521, 78}
    for tool_id in sorted(AUTH_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        cwes = set(descriptor.cwe_hints)
        assert cwes & auth_cwes, (
            f"{tool_id}: §4.12 tools must declare at least one of "
            f"CWE-{sorted(auth_cwes)}; got {sorted(cwes)}"
        )


# ---------------------------------------------------------------------------
# §4.13 Hash / crypto batch (ARG-017)
# ---------------------------------------------------------------------------


def test_hash_tools_use_correct_image(loaded_registry: ToolRegistry) -> None:
    """All §4.13 tools run inside ``argus-kali-cloud:latest`` (CPU/GPU
    crackers benefit from the cloud image's larger compute profile).
    """
    for tool_id in sorted(HASH_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        assert descriptor.image == "argus-kali-cloud:latest", (
            f"{tool_id} expected argus-kali-cloud:latest, got {descriptor.image!r}"
        )


def test_hash_tools_phase_classification(loaded_registry: ToolRegistry) -> None:
    """Every §4.13 entry lives in ``post_exploitation`` (cracking happens
    after credentials / hashes have been collected) under
    ``ToolCategory.MISC`` (no dedicated crypto category yet — Cycle 3).
    """
    for tool_id in sorted(HASH_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.phase is ScanPhase.POST_EXPLOITATION, (
            f"{tool_id} expected ScanPhase.POST_EXPLOITATION, got {descriptor.phase}"
        )


def test_hash_tools_run_offline_no_egress(loaded_registry: ToolRegistry) -> None:
    """Every §4.13 tool MUST run behind ``offline-no-egress`` so a
    malicious wordlist or rule pack cannot exfiltrate captured hashes.
    """
    for tool_id in sorted(HASH_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.network_policy.name == "offline-no-egress", (
            f"{tool_id}: hash crackers MUST sit behind 'offline-no-egress'; "
            f"got {descriptor.network_policy.name!r}"
        )


def test_hash_tools_have_cwe916_or_326_hints(loaded_registry: ToolRegistry) -> None:
    """Every §4.13 tool must surface at least one cracker-relevant CWE:
    CWE-916 (use of password hash with insufficient computational effort)
    or CWE-326 (inadequate encryption strength).
    """
    cracker_cwes = {916, 326, 327}
    for tool_id in sorted(HASH_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        cwes = set(descriptor.cwe_hints)
        assert cwes & cracker_cwes, (
            f"{tool_id}: §4.13 tools must declare at least one of "
            f"CWE-{sorted(cracker_cwes)}; got {sorted(cwes)}"
        )


def test_arg017_phase_placement_matches_grouping_constants(
    loaded_registry: ToolRegistry,
) -> None:
    """Cross-check the §4.11/§4.12/§4.13 phase split against the
    module-level grouping constants.

    Locks the contract from both directions:

    * Per-tool tests above pin each descriptor's phase explicitly.
    * This test confirms ``list_by_phase`` surfaces exactly the same
      tool IDs (no silent drift between metadata and dispatch).

    Reviewer C1 (cycle 2) added the §4.11 ``cloud_metadata_check``
    entry to the exploitation slice; reviewer C2 (cycle 2) parked
    ``gobuster_auth`` in vuln_analysis.  Both invariants are re-asserted
    here so future drift cannot silently re-collapse the §4.11 / §4.12
    phase splits.
    """
    exploitation_ids = {
        d.tool_id for d in loaded_registry.list_by_phase(ScanPhase.EXPLOITATION)
    }
    arg017_exploitation = exploitation_ids & AUTH_TOOLS
    assert arg017_exploitation == _AUTH_EXPLOITATION_TOOLS, (
        f"§4.12 exploitation drift: "
        f"expected {sorted(_AUTH_EXPLOITATION_TOOLS)}, "
        f"got {sorted(arg017_exploitation)}"
    )

    arg011_exploitation = exploitation_ids & OAST_TOOLS
    assert arg011_exploitation == _OAST_EXPLOITATION_TOOLS, (
        f"§4.11 exploitation drift: "
        f"expected {sorted(_OAST_EXPLOITATION_TOOLS)}, "
        f"got {sorted(arg011_exploitation)}"
    )

    vuln_analysis_ids = {
        d.tool_id for d in loaded_registry.list_by_phase(ScanPhase.VULN_ANALYSIS)
    }
    arg012_vuln_analysis = vuln_analysis_ids & AUTH_TOOLS
    assert arg012_vuln_analysis == _AUTH_VULN_ANALYSIS_TOOLS, (
        f"§4.12 vuln_analysis drift: "
        f"expected {sorted(_AUTH_VULN_ANALYSIS_TOOLS)}, "
        f"got {sorted(arg012_vuln_analysis)}"
    )

    post_exploitation_ids = {
        d.tool_id for d in loaded_registry.list_by_phase(ScanPhase.POST_EXPLOITATION)
    }
    arg017_post = post_exploitation_ids & (AUTH_TOOLS | HASH_TOOLS)
    arg017_expected = _AUTH_POST_EXPLOITATION_TOOLS | _HASH_POST_EXPLOITATION_TOOLS
    assert arg017_post == arg017_expected, (
        f"§4.12/§4.13 post_exploitation drift: "
        f"expected {sorted(arg017_expected)}, "
        f"got {sorted(arg017_post)}"
    )


# ---------------------------------------------------------------------------
# §4.17 Network protocol / AD / poisoning batch (ARG-019)
# ---------------------------------------------------------------------------


def test_network_protocol_tools_use_correct_image(
    loaded_registry: ToolRegistry,
) -> None:
    """All §4.17 tools must run inside ``argus-kali-network:latest``.

    ARG-058 / T03 carved out the dedicated ``argus-kali-network`` image
    that bundles every Impacket / BloodHound / SNMP / IKE / Redis /
    Mongo CLI ARGUS supports, so the §4.17 batch lives in the network
    image instead of the heavier web image (which stays focused on
    HTTP-stack tooling).
    """
    for tool_id in sorted(NETWORK_PROTOCOL_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        assert descriptor.image == "argus-kali-network:latest", (
            f"{tool_id} expected argus-kali-network:latest, "
            f"got {descriptor.image!r}"
        )


def test_network_protocol_tools_phase_split(loaded_registry: ToolRegistry) -> None:
    """§4.17 phase split.

    * ``recon`` — read-only enumerators (LDAP / SNMP / IKE / DB
      pre-auth probes).
    * ``exploitation`` — active poisoners (``responder`` /
      ``ntlmrelayx``) that produce credential material on the wire.
    * ``post_exploitation`` — credential-extraction + AD enumeration
      that *requires* prior credentials (``impacket_secretsdump`` /
      ``bloodhound_python``).
    """
    for tool_id in sorted(NETWORK_PROTOCOL_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        if tool_id in _NETWORK_PROTOCOL_RECON_TOOLS:
            assert descriptor.phase is ScanPhase.RECON, (
                f"{tool_id} expected ScanPhase.RECON, got {descriptor.phase}"
            )
        elif tool_id in _NETWORK_PROTOCOL_EXPLOITATION_TOOLS:
            assert descriptor.phase is ScanPhase.EXPLOITATION, (
                f"{tool_id} expected ScanPhase.EXPLOITATION, got {descriptor.phase}"
            )
        elif tool_id in _NETWORK_PROTOCOL_POST_EXPLOITATION_TOOLS:
            assert descriptor.phase is ScanPhase.POST_EXPLOITATION, (
                f"{tool_id} expected ScanPhase.POST_EXPLOITATION, "
                f"got {descriptor.phase}"
            )
        else:
            pytest.fail(f"{tool_id} not classified into any §4.17 phase grouping")


def test_network_protocol_tools_run_under_auth_bruteforce_policy(
    loaded_registry: ToolRegistry,
) -> None:
    """Every §4.17 tool MUST sit behind ``auth-bruteforce``.

    ``auth-bruteforce`` is the only existing policy that opens the
    specialised AD / SNMP / IKE / DB port set (LDAP/389/636,
    SNMP/161, IKE/500, MS-RPC/135, SMB/445, Redis/6379, Mongo/27017).
    Reusing it avoids carving a new policy when the egress profile
    is identical.
    """
    for tool_id in sorted(NETWORK_PROTOCOL_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.network_policy.name == "auth-bruteforce", (
            f"{tool_id}: §4.17 tools MUST sit behind 'auth-bruteforce'; "
            f"got {descriptor.network_policy.name!r}"
        )


def test_network_protocol_tools_approval_split(
    loaded_registry: ToolRegistry,
) -> None:
    """The four active poisoners + credential-extraction tools require
    operator approval; the six read-only enumerators stay approval-free.
    """
    for tool_id in sorted(NETWORK_PROTOCOL_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        expected_approval = tool_id in NETWORK_PROTOCOL_APPROVAL_REQUIRED
        assert descriptor.requires_approval is expected_approval, (
            f"{tool_id} requires_approval={descriptor.requires_approval} "
            f"contradicts §4.17 approval gate (expected {expected_approval})"
        )


def test_network_protocol_tools_classify_as_network(
    loaded_registry: ToolRegistry,
) -> None:
    """Every §4.17 entry classifies as ``ToolCategory.NETWORK`` — the
    credential-extraction post-exploitation tools (``impacket_secretsdump``,
    ``bloodhound_python``) inherit the category from their wire-level
    transport (LDAP/SMB/RPC) rather than promoting to ``EXPLOIT``;
    Cycle 3 will introduce a dedicated ``CREDENTIAL`` category once the
    matching cost / scheduling profile lands.

    No §4.17 tool classifies as ``WEB_VA`` (which is reserved for
    HTTP-surface tooling).
    """
    for tool_id in sorted(NETWORK_PROTOCOL_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.category is ToolCategory.NETWORK, (
            f"{tool_id}: §4.17 tools must classify as NETWORK; "
            f"got {descriptor.category}"
        )


def test_network_protocol_tools_have_cwe_and_owasp_hints(
    loaded_registry: ToolRegistry,
) -> None:
    """Every §4.17 tool must declare at least one CWE hint and one WSTG
    hint.  The §4.17 batch covers wide classification surfaces (broken
    auth, weak crypto, info disclosure, missing access controls) so we
    don't pin a specific CWE — but each tool must surface non-empty
    hints so the normaliser has a starting point.
    """
    for tool_id in sorted(NETWORK_PROTOCOL_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.cwe_hints, (
            f"{tool_id}: §4.17 tools must declare at least one CWE hint"
        )
        assert descriptor.owasp_wstg, (
            f"{tool_id}: §4.17 tools must declare at least one OWASP WSTG hint"
        )


# ---------------------------------------------------------------------------
# §4.18 Binary / mobile / firmware analysis batch (ARG-019)
# ---------------------------------------------------------------------------


def test_binary_tools_use_correct_image(loaded_registry: ToolRegistry) -> None:
    """All §4.18 binary-analysis tools MUST run inside
    ``argus-kali-binary:latest``.  The dedicated binary-tooling image
    bundles MobSF / apktool / jadx / binwalk / radare2 — pulling the
    heavier web image for these would waste registry bandwidth.
    """
    for tool_id in sorted(BINARY_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        assert descriptor.image == "argus-kali-binary:latest", (
            f"{tool_id} expected argus-kali-binary:latest, got {descriptor.image!r}"
        )


def test_binary_tools_run_offline_no_egress(loaded_registry: ToolRegistry) -> None:
    """Every §4.18 entry MUST sit behind ``offline-no-egress``.

    Binary-analysis tools operate on operator-mounted samples under
    ``/in/``; granting them network egress would let a malicious sample
    phone home or exfiltrate the operator's analysis bundle.
    """
    for tool_id in sorted(BINARY_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.network_policy.name == "offline-no-egress", (
            f"{tool_id}: §4.18 binary tools MUST sit behind "
            f"'offline-no-egress'; got {descriptor.network_policy.name!r}"
        )


def test_binary_tools_classify_as_binary_vuln_analysis(
    loaded_registry: ToolRegistry,
) -> None:
    """Every §4.18 entry must classify as ``ToolCategory.BINARY`` and
    live in ``ScanPhase.VULN_ANALYSIS``.  Approval-free across the
    board (no live target, no egress).
    """
    for tool_id in sorted(BINARY_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.phase is ScanPhase.VULN_ANALYSIS, (
            f"{tool_id} expected ScanPhase.VULN_ANALYSIS, got {descriptor.phase}"
        )
        assert descriptor.category is ToolCategory.BINARY, (
            f"{tool_id} expected ToolCategory.BINARY, got {descriptor.category}"
        )
        assert descriptor.requires_approval is False, (
            f"{tool_id}: §4.18 binary tools are uniformly approval-free"
        )


def test_binary_tools_have_cwe_and_owasp_hints(
    loaded_registry: ToolRegistry,
) -> None:
    """Every §4.18 tool must declare at least one CWE hint and one WSTG
    hint.  The §4.18 batch covers wide classification surfaces (hard-
    coded credentials, weak crypto, debug exposure, sensitive APK
    permissions) so we don't pin a specific CWE — but each tool must
    surface non-empty hints so the normaliser has a starting point.
    """
    for tool_id in sorted(BINARY_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.cwe_hints, (
            f"{tool_id}: §4.18 tools must declare at least one CWE hint"
        )
        assert descriptor.owasp_wstg, (
            f"{tool_id}: §4.18 tools must declare at least one OWASP WSTG hint"
        )


# ---------------------------------------------------------------------------
# §4.19 Browser / headless / OAST verifiers batch (ARG-019)
# ---------------------------------------------------------------------------


def test_browser_tools_use_correct_image(loaded_registry: ToolRegistry) -> None:
    """All §4.19 browser tools MUST run inside
    ``argus-kali-browser:latest`` (Chromium + Playwright runtime).
    """
    for tool_id in sorted(BROWSER_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        assert descriptor.image == "argus-kali-browser:latest", (
            f"{tool_id} expected argus-kali-browser:latest, got {descriptor.image!r}"
        )


def test_browser_tools_phase_split(loaded_registry: ToolRegistry) -> None:
    """§4.19 phase split.

    * ``recon`` — passive screenshot-only harvester
      (``puppeteer_screens``, ``recon-passive`` policy, no JS execution
      beyond page load).
    * ``vuln_analysis`` — every other browser entry: scenario runner +
      misconfig probes (CSP / CORS / cookies).

    Approval gating: ``playwright_runner`` is approval-required
    (cycle-2 reviewer H1 — arbitrary state-changing browser actions);
    the four targeted probes stay approval-free.
    """
    for tool_id in sorted(BROWSER_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        if tool_id in _BROWSER_RECON_TOOLS:
            assert descriptor.phase is ScanPhase.RECON, (
                f"{tool_id} expected ScanPhase.RECON, got {descriptor.phase}"
            )
        else:
            assert descriptor.phase is ScanPhase.VULN_ANALYSIS, (
                f"{tool_id} expected ScanPhase.VULN_ANALYSIS, got {descriptor.phase}"
            )
        assert descriptor.category is ToolCategory.BROWSER, (
            f"{tool_id}: §4.19 tools must classify as BROWSER; "
            f"got {descriptor.category}"
        )
        expected_approval = tool_id in BROWSER_APPROVAL_REQUIRED
        assert descriptor.requires_approval is expected_approval, (
            f"{tool_id}: requires_approval={descriptor.requires_approval} "
            f"contradicts §4.19 approval matrix; expected={expected_approval}"
        )


def test_browser_tools_network_policy_split(
    loaded_registry: ToolRegistry,
) -> None:
    """§4.19 network-policy split.

    * ``recon-passive`` — the passive screenshot harvester
      (``puppeteer_screens``).
    * ``recon-active-tcp`` — every other browser entry: scenario
      runner + misconfig probes that issue real HTTP requests against
      the in-scope target.
    """
    for tool_id in sorted(BROWSER_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        if tool_id in _BROWSER_RECON_TOOLS:
            expected = "recon-passive"
        else:
            expected = "recon-active-tcp"
        assert descriptor.network_policy.name == expected, (
            f"{tool_id} expected policy {expected!r}, "
            f"got {descriptor.network_policy.name!r}"
        )


def test_browser_tools_have_cwe_and_owasp_hints(
    loaded_registry: ToolRegistry,
) -> None:
    """Every §4.19 tool must declare at least one CWE hint and one WSTG
    hint.  The §4.19 batch covers wide classification surfaces (CSP /
    CORS misconfig, cookie security, screenshot evidence) so we don't
    pin a specific CWE — but each tool must surface non-empty hints so
    the normaliser has a starting point.
    """
    for tool_id in sorted(BROWSER_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        assert descriptor.cwe_hints, (
            f"{tool_id}: §4.19 tools must declare at least one CWE hint"
        )
        assert descriptor.owasp_wstg, (
            f"{tool_id}: §4.19 tools must declare at least one OWASP WSTG hint"
        )


def test_arg019_phase_placement_matches_grouping_constants(
    loaded_registry: ToolRegistry,
) -> None:
    """Cross-check the §4.17 / §4.18 / §4.19 phase split against the
    module-level grouping constants.

    Locks the contract from both directions:

    * Per-tool tests above pin each descriptor's phase explicitly.
    * This test confirms ``list_by_phase`` surfaces exactly the same
      tool IDs (no silent drift between metadata and dispatch).

    Any addition or re-classification of an ARG-019 tool that does not
    land in the matching phase frozenset breaks this assertion.
    """
    arg019_tools = NETWORK_PROTOCOL_TOOLS | BINARY_TOOLS | BROWSER_TOOLS

    recon_ids = {d.tool_id for d in loaded_registry.list_by_phase(ScanPhase.RECON)}
    arg019_recon = recon_ids & arg019_tools
    expected_recon = _NETWORK_PROTOCOL_RECON_TOOLS | _BROWSER_RECON_TOOLS
    assert arg019_recon == expected_recon, (
        f"§4.17/§4.19 recon drift: "
        f"expected {sorted(expected_recon)}, got {sorted(arg019_recon)}"
    )

    vuln_analysis_ids = {
        d.tool_id for d in loaded_registry.list_by_phase(ScanPhase.VULN_ANALYSIS)
    }
    arg019_vuln = vuln_analysis_ids & arg019_tools
    expected_vuln = _BINARY_VULN_ANALYSIS_TOOLS | _BROWSER_VULN_ANALYSIS_TOOLS
    assert arg019_vuln == expected_vuln, (
        f"§4.18/§4.19 vuln_analysis drift: "
        f"expected {sorted(expected_vuln)}, got {sorted(arg019_vuln)}"
    )

    exploitation_ids = {
        d.tool_id for d in loaded_registry.list_by_phase(ScanPhase.EXPLOITATION)
    }
    arg019_exploit = exploitation_ids & arg019_tools
    assert arg019_exploit == _NETWORK_PROTOCOL_EXPLOITATION_TOOLS, (
        f"§4.17 exploitation drift: "
        f"expected {sorted(_NETWORK_PROTOCOL_EXPLOITATION_TOOLS)}, "
        f"got {sorted(arg019_exploit)}"
    )

    post_exploitation_ids = {
        d.tool_id for d in loaded_registry.list_by_phase(ScanPhase.POST_EXPLOITATION)
    }
    arg019_post = post_exploitation_ids & arg019_tools
    assert arg019_post == _NETWORK_PROTOCOL_POST_EXPLOITATION_TOOLS, (
        f"§4.17 post_exploitation drift: "
        f"expected {sorted(_NETWORK_PROTOCOL_POST_EXPLOITATION_TOOLS)}, "
        f"got {sorted(arg019_post)}"
    )


def test_arg019_total_tool_count_closes_catalog(
    loaded_registry: ToolRegistry,
) -> None:
    """ARG-019 closes the long-term Backlog §4 catalog at exactly 157 tools
    (137 from ARG-001..ARG-018 + 20 ARG-019 entries).

    A silent shrink (someone deletes a YAML) or accidental duplicate
    (two YAMLs for the same tool_id) would slip past the per-batch
    inventories above; this hard equality keeps the catalog locked at
    its long-term target.
    """
    assert len(loaded_registry) == 157, (
        f"catalog drift: expected exactly 157 tools, got {len(loaded_registry)}"
    )
    arg019_total = len(NETWORK_PROTOCOL_TOOLS | BINARY_TOOLS | BROWSER_TOOLS)
    assert arg019_total == 20, (
        f"ARG-019 frozenset drift: expected 20 tools, got {arg019_total}"
    )


# ---------------------------------------------------------------------------
# §4.17 / §4.18 / §4.19 stricter pinning (ARG-019, supplements above)
# ---------------------------------------------------------------------------


def test_network_protocol_tools_risk_level_distribution(
    loaded_registry: ToolRegistry,
) -> None:
    """Pin the §4.17 risk-level distribution.

    * ``LOW`` (6) — the read-only enumerators in
      ``_NETWORK_PROTOCOL_RECON_TOOLS``.
    * ``MEDIUM`` (1) — ``bloodhound_python`` (authenticated LDAP query
      explosion + session trace persistence).
    * ``HIGH`` (3) — ``responder`` / ``ntlmrelayx``
      / ``impacket_secretsdump`` (active credential
      poisoning / relay / extraction).
    """
    expected: dict[str, RiskLevel] = {
        "responder": RiskLevel.HIGH,
        "impacket_secretsdump": RiskLevel.HIGH,
        "ntlmrelayx": RiskLevel.HIGH,
        "bloodhound_python": RiskLevel.MEDIUM,
        "ldapsearch": RiskLevel.LOW,
        "snmpwalk": RiskLevel.LOW,
        "onesixtyone": RiskLevel.LOW,
        "ike_scan": RiskLevel.LOW,
        "redis_cli_probe": RiskLevel.LOW,
        "mongodb_probe": RiskLevel.LOW,
    }
    mismatches: list[str] = []
    for tool_id, want in expected.items():
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None, f"{tool_id} missing from catalog"
        if descriptor.risk_level is not want:
            mismatches.append(
                f"{tool_id}: expected {want}, got {descriptor.risk_level}"
            )
    assert not mismatches, "§4.17 risk_level mismatches:\n" + "\n".join(mismatches)


def test_network_protocol_tools_have_relevant_cwe_hints(
    loaded_registry: ToolRegistry,
) -> None:
    """Every §4.17 tool must surface at least one of the AD / network
    weakness CWEs that the batch is designed to detect.

    * CWE-200 / CWE-204 — info exposure / response discrepancy
      (LDAP / SNMP / DB read-only enumerators).
    * CWE-287 / CWE-294 / CWE-307 / CWE-521 — auth weaknesses
      (relay / replay / weak credential).
    * CWE-522 — insufficiently protected credentials
      (secretsdump / bloodhound).
    """
    network_cwes = {200, 204, 287, 294, 307, 319, 521, 522, 798}
    for tool_id in sorted(NETWORK_PROTOCOL_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        cwes = set(descriptor.cwe_hints)
        assert cwes & network_cwes, (
            f"{tool_id}: §4.17 tools must declare at least one of "
            f"CWE-{sorted(network_cwes)}; got {sorted(cwes)}"
        )


def test_binary_tools_have_relevant_cwe_hints(
    loaded_registry: ToolRegistry,
) -> None:
    """Every §4.18 tool must surface at least one binary / mobile
    weakness CWE.  The batch covers a wide surface (insecure storage
    / hard-coded creds / outdated component / weak crypto / etc.) so
    we accept any CWE in the binary-relevant superset rather than
    pinning a specific one.
    """
    binary_cwes = {22, 78, 89, 200, 215, 311, 312, 327, 502, 798, 919, 1395}
    for tool_id in sorted(BINARY_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        cwes = set(descriptor.cwe_hints)
        assert cwes & binary_cwes, (
            f"{tool_id}: §4.18 tools must declare at least one of "
            f"CWE-{sorted(binary_cwes)}; got {sorted(cwes)}"
        )


def test_browser_tools_pin_risk_level(
    loaded_registry: ToolRegistry,
) -> None:
    """Pin the §4.19 risk-level distribution.

    * ``PASSIVE`` — the screenshot-only harvester
      (``puppeteer_screens``).
    * ``MEDIUM`` — the generic scenario runner
      (``playwright_runner``, cycle-2 reviewer H1 — arbitrary
      state-changing browser actions warrant a higher risk band
      alongside the approval gate).
    * ``LOW`` — the four targeted misconfig probes
      (``chrome_csp_probe`` / ``cors_probe`` / ``cookie_probe``)
      that don't fire payloads.
    """
    for tool_id in sorted(BROWSER_TOOLS):
        descriptor = loaded_registry.get(tool_id)
        assert descriptor is not None
        if tool_id in _BROWSER_RECON_TOOLS:
            expected = RiskLevel.PASSIVE
        elif tool_id == "playwright_runner":
            expected = RiskLevel.MEDIUM
        else:
            expected = RiskLevel.LOW
        assert descriptor.risk_level is expected, (
            f"{tool_id} expected {expected}, got {descriptor.risk_level}"
        )
