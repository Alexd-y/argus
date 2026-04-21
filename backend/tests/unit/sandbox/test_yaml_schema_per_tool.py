"""Per-tool YAML schema unit tests.

Parametrised over every ``tool_id`` shipped by the current catalog scope
(ARG-003 §4.1 + §4.2 + §4.3 + ARG-011 §4.4 + ARG-012 §4.5 + ARG-013 §4.6
+ ARG-014 §4.7 + ARG-015 §4.8 + ARG-016 §4.9 + §4.10 + ARG-017 §4.11 +
§4.12 + §4.13 + ARG-018 §4.14 + §4.15 + §4.16 + ARG-019 §4.17 + §4.18 +
§4.19).  For each tool we:

* Read ``backend/config/tools/<tool_id>.yaml`` directly (no signature check —
  the integration test in ``backend/tests/integration/sandbox`` covers that).
* Parse it through :class:`ToolDescriptor` to lock in the Pydantic schema.
* Assert filename and ``tool_id`` agree (a registry-load contract that
  prevents two YAMLs from claiming the same id).
* Assert the descriptor's ``description`` references Backlog §4.x so future
  refactors cannot strip the documentation pointer.

These tests run without touching the network, the DB, or any subprocess.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

import pytest
import yaml
from pydantic import ValidationError

from src.sandbox.adapter_base import ToolDescriptor
from src.sandbox.templating import (
    TemplateRenderError,
    extract_placeholders,
    validate_template,
)


# Hard-coded so a silent removal of any tool YAML breaks CI immediately.
EXPECTED_TOOL_IDS: Final[tuple[str, ...]] = (
    # §4.1 Passive recon / OSINT (17)
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
    # §4.2 Active recon / port & service (12)
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
    # §4.3 TLS/SSL (6)
    "testssl",
    "sslyze",
    "sslscan",
    "ssl_enum_ciphers",
    "tlsx",
    "mkcert_verify",
    # §4.4 HTTP fingerprinting / tech stack / screenshots (9, ARG-011)
    "httpx",
    "whatweb",
    "wappalyzer_cli",
    "webanalyze",
    "aquatone",
    "gowitness",
    "eyewitness",
    "favfreak",
    "jarm",
    # §4.5 Content / path discovery & fuzzing (10, ARG-012)
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
    # §4.6 Crawler / JS / endpoint extraction (8, ARG-013)
    "katana",
    "gospider",
    "hakrawler",
    "waybackurls",
    "gau",
    "linkfinder",
    "subjs",
    "secretfinder",
    # §4.7 CMS / platform-specific scanners (8, ARG-014)
    "wpscan",
    "joomscan",
    "droopescan",
    "cmsmap",
    "magescan",
    "nextjs_check",
    "spring_boot_actuator",
    "jenkins_enum",
    # §4.8 Web vulnerability scanners (7, ARG-015)
    "nuclei",
    "nikto",
    "wapiti",
    "arachni",
    "skipfish",
    "w3af_console",
    "zap_baseline",
    # §4.9 SQL injection (6, ARG-016)
    "sqlmap_safe",
    "sqlmap_confirm",
    "ghauri",
    "jsql",
    "tplmap",
    "nosqlmap",
    # §4.10 Cross-site scripting (5, ARG-016)
    "dalfox",
    "xsstrike",
    "kxss",
    "xsser",
    "playwright_xss_verify",
    # §4.11 SSRF / OAST / OOB (6, ARG-017 + cycle 2 reviewer C1)
    "interactsh_client",
    "oastify_client",
    "ssrfmap",
    "gopherus",
    "oast_dns_probe",
    "cloud_metadata_check",
    # §4.12 Auth / bruteforce (11, ARG-017 + cycle 2 reviewer C2)
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
    # §4.13 Hash / crypto (5, ARG-017)
    "hashcat",
    "john",
    "ophcrack",
    "hashid",
    "hash_analyzer",
    # §4.14 API / GraphQL / gRPC (7, ARG-018)
    "openapi_scanner",
    "graphw00f",
    "clairvoyance",
    "inql",
    "graphql_cop",
    "grpcurl_probe",
    "postman_newman",
    # §4.15 Cloud / IaC / container (12, ARG-018)
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
    # §4.16 IaC / code / secrets (8, ARG-018)
    "terrascan",
    "tfsec",
    "kics",
    "semgrep",
    "bandit",
    "gitleaks",
    "trufflehog",
    "detect_secrets",
    # §4.17 Network protocol / AD / poisoning (10, ARG-019)
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
    # §4.18 Binary / mobile / firmware (5, ARG-019)
    "mobsf_api",
    "apktool",
    "jadx",
    "binwalk",
    "radare2_info",
    # §4.19 Browser / headless / OAST verifiers (5, ARG-019)
    "playwright_runner",
    "puppeteer_screens",
    "chrome_csp_probe",
    "cors_probe",
    "cookie_probe",
)


def _catalog_dir() -> Path:
    """Locate ``backend/config/tools/`` from this test file's path."""
    here = Path(__file__).resolve()
    backend_dir = here.parents[3]  # tests/unit/sandbox/test_*.py -> backend/
    return backend_dir / "config" / "tools"


@pytest.fixture(scope="module")
def catalog_dir() -> Path:
    catalog = _catalog_dir()
    assert catalog.is_dir(), f"expected catalog dir at {catalog}"
    return catalog


# ---------------------------------------------------------------------------
# Catalog completeness
# ---------------------------------------------------------------------------


def test_expected_count_matches_current_scope() -> None:
    """Current scope ships
    17 + 12 + 6 + 9 + 10 + 8 + 8 + 7 + 6 + 5 + 6 + 11 + 5
    + 7 + 12 + 8 + 10 + 5 + 5 = 157 YAMLs
    (ARG-003 + ARG-011..ARG-017 + cycle-2 reviewer restorations
    ``cloud_metadata_check`` (Backlog §4.11) and ``gobuster_auth``
    (Backlog §4.12) + ARG-018 §4.14 / §4.15 / §4.16 + ARG-019 §4.17 /
    §4.18 / §4.19).
    """
    assert len(EXPECTED_TOOL_IDS) == 157
    assert len(set(EXPECTED_TOOL_IDS)) == 157  # no duplicates in the inventory


def test_every_expected_yaml_exists(catalog_dir: Path) -> None:
    missing = [
        tid for tid in EXPECTED_TOOL_IDS if not (catalog_dir / f"{tid}.yaml").is_file()
    ]
    assert not missing, f"missing YAML files: {missing}"


def test_no_unexpected_yaml_files(catalog_dir: Path) -> None:
    """The catalog directory carries exactly the current cycle scope.

    ARG-003 + ARG-011..ARG-019 today (157 tools); future cycles extend
    ``EXPECTED_TOOL_IDS``. Any orphan YAML is a sign of a botched rebase
    or a stale rename.
    """
    on_disk = {p.stem for p in catalog_dir.glob("*.yaml")}
    extras = sorted(on_disk - set(EXPECTED_TOOL_IDS))
    assert not extras, f"unexpected YAML files: {extras}"


# ---------------------------------------------------------------------------
# Per-tool schema conformance
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", EXPECTED_TOOL_IDS)
def test_yaml_parses_into_tool_descriptor(catalog_dir: Path, tool_id: str) -> None:
    yaml_path = catalog_dir / f"{tool_id}.yaml"
    payload = yaml.safe_load(yaml_path.read_bytes())
    assert isinstance(payload, dict), (
        f"{tool_id}.yaml must be a YAML mapping at the top level"
    )
    try:
        descriptor = ToolDescriptor(**payload)
    except ValidationError as exc:  # pragma: no cover - assertion message
        pytest.fail(f"{tool_id}.yaml schema invalid: {exc.error_count()} errors")
    assert descriptor.tool_id == tool_id, (
        f"{tool_id}.yaml declares tool_id={descriptor.tool_id!r}; "
        "filename and id must agree"
    )


@pytest.mark.parametrize("tool_id", EXPECTED_TOOL_IDS)
def test_command_template_uses_only_allowlisted_placeholders(
    catalog_dir: Path, tool_id: str
) -> None:
    payload = yaml.safe_load((catalog_dir / f"{tool_id}.yaml").read_bytes())
    descriptor = ToolDescriptor(**payload)
    try:
        found = validate_template(descriptor.command_template)
    except TemplateRenderError as exc:  # pragma: no cover - assertion message
        pytest.fail(
            f"{tool_id}.yaml template uses forbidden placeholder "
            f"{exc.placeholder!r}: {exc.reason}"
        )
    extracted = extract_placeholders(descriptor.command_template)
    assert found == extracted


@pytest.mark.parametrize("tool_id", EXPECTED_TOOL_IDS)
def test_descriptor_description_present_and_references_backlog(
    catalog_dir: Path, tool_id: str
) -> None:
    payload = yaml.safe_load((catalog_dir / f"{tool_id}.yaml").read_bytes())
    descriptor = ToolDescriptor(**payload)
    assert descriptor.description, f"{tool_id} description is empty"
    assert len(descriptor.description) <= 500
    assert "§4." in descriptor.description, (
        f"{tool_id} description must reference Backlog §4.x"
    )


@pytest.mark.parametrize("tool_id", EXPECTED_TOOL_IDS)
def test_descriptor_image_uses_argus_kali_namespace(
    catalog_dir: Path, tool_id: str
) -> None:
    payload = yaml.safe_load((catalog_dir / f"{tool_id}.yaml").read_bytes())
    descriptor = ToolDescriptor(**payload)
    assert descriptor.image.startswith("argus-kali-"), (
        f"{tool_id} image {descriptor.image!r} must be in argus-kali-* namespace"
    )


@pytest.mark.parametrize("tool_id", EXPECTED_TOOL_IDS)
def test_descriptor_default_timeout_within_safe_bounds(
    catalog_dir: Path, tool_id: str
) -> None:
    """Bound the timeout to the registry's hard ceiling (24h) and a sane floor."""
    payload = yaml.safe_load((catalog_dir / f"{tool_id}.yaml").read_bytes())
    descriptor = ToolDescriptor(**payload)
    assert 30 <= descriptor.default_timeout_s <= 86_400, (
        f"{tool_id} default_timeout_s={descriptor.default_timeout_s}s out of range"
    )
