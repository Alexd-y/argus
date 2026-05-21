"""VHL-TOOL-001 — Master registry of 100+ security testing tools with full metadata.

Each tool entry contains 12 fields: name, capability, version_command, safe_command_template,
output_format, parser, risk_level, requires_auth, requires_explicit_permission,
display_name, category, notes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolRegistryEntry:
    """Immutable tool metadata. Used by tool health summary and WSTG coverage."""

    name: str
    capability: str
    version_command: str = ""
    safe_command_template: str = ""
    output_format: str = "text"
    parser: str = "text_stdout"
    risk_level: str = "safe"
    requires_auth: bool = False
    requires_explicit_permission: bool = False
    display_name: str = ""
    category: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "capability": self.capability,
            "version_command": self.version_command,
            "safe_command_template": self.safe_command_template,
            "output_format": self.output_format,
            "parser": self.parser,
            "risk_level": self.risk_level,
            "requires_auth": self.requires_auth,
            "requires_explicit_permission": self.requires_explicit_permission,
            "display_name": self.display_name,
            "category": self.category,
            "notes": self.notes,
        }


# Master registry — sorted alphabetically within each capability
_TOOLS: list[ToolRegistryEntry] = [
    # ── DNS / ASN / Surface Discovery ──
    ToolRegistryEntry("amass", "dns_asn", "amass -version", "amass enum -d {target}", "text", "text_stdout", "safe", False, False, "Amass"),
    ToolRegistryEntry("assetfinder", "dns_asn", "assetfinder -version", "assetfinder {target}", "text", "text_lines", "safe", False, False, "Assetfinder"),
    ToolRegistryEntry("dig", "dns_asn", "dig -v", "dig {target} ANY", "text", "text_stdout", "safe", False, False, "dig"),
    ToolRegistryEntry("dnsx", "dns_asn", "dnsx -version", "dnsx -d {target} -silent", "text", "text_lines", "safe", False, False, "dnsx"),
    ToolRegistryEntry("dnsrecon", "dns_asn", "dnsrecon -h", "dnsrecon -d {target}", "text", "text_stdout", "safe", False, False, "DNSRecon"),
    ToolRegistryEntry("fierce", "dns_asn", "fierce -h", "fierce -dns {target}", "text", "text_stdout", "safe", False, False, "Fierce"),
    ToolRegistryEntry("host", "dns_asn", "host -V", "host -a {target}", "text", "text_stdout", "safe", False, False, "host"),
    ToolRegistryEntry("shuffledns", "dns_asn", "shuffledns -version", "shuffledns -d {target} -w wordlist.txt", "text", "text_lines", "safe", False, False, "ShuffleDNS"),
    ToolRegistryEntry("subfinder", "dns_asn", "subfinder -version", "subfinder -d {target}", "text", "text_lines", "safe", False, False, "Subfinder"),
    ToolRegistryEntry("sublist3r", "dns_asn", "sublist3r -h", "sublist3r -d {target}", "text", "text_stdout", "safe", False, False, "Sublist3r"),
    ToolRegistryEntry("whois", "dns_asn", "whois --version", "whois {target}", "text", "text_stdout", "safe", False, False, "whois"),
    ToolRegistryEntry("asnmap", "dns_asn", "asnmap -version", "asnmap -d {target}", "text", "text_lines", "safe", False, False, "ASNMap"),

    # ── URL / Live Host / Crawler ──
    ToolRegistryEntry("httpx", "url_history", "httpx -version", "httpx -u {target} -silent", "text", "text_lines", "safe", False, False, "httpx"),
    ToolRegistryEntry("httprobe", "url_history", "httprobe -h", "httprobe -c 50 < {target}_subs.txt", "text", "text_lines", "safe", False, False, "httprobe"),
    ToolRegistryEntry("gau", "url_history", "gau -version", "gau {target}", "text", "text_lines", "safe", False, False, "gau"),
    ToolRegistryEntry("waybackurls", "url_history", "waybackurls -h", "waybackurls {target}", "text", "text_lines", "safe", False, False, "waybackurls"),
    ToolRegistryEntry("katana", "url_history", "katana -version", "katana -u {target} -silent", "text", "text_lines", "safe", False, False, "Katana"),
    ToolRegistryEntry("hakrawler", "url_history", "hakrawler -h", "hakrawler -url {target} -depth 2", "text", "text_lines", "safe", False, False, "Hakrawler"),
    ToolRegistryEntry("gospider", "url_history", "gospider -h", "gospider -s {target}", "text", "text_lines", "safe", False, False, "GoSpider"),
    ToolRegistryEntry("gowitness", "url_history", "gowitness version", "gowitness scan file -f urls.txt", "png", "binary_files", "safe", False, False, "GoWitness"),
    ToolRegistryEntry("eyewitness", "url_history", "eyewitness --version", "eyewitness -f urls.txt --web", "png", "binary_files", "safe", False, False, "EyeWitness"),
    ToolRegistryEntry("aquatone", "url_history", "aquatone -version", "aquatone -out screenshots -ports 80,443", "png", "binary_files", "safe", False, False, "Aquatone"),
    ToolRegistryEntry("curl", "url_history", "curl --version", "curl -sS {target} -v 2>&1", "text", "text_stdout", "safe", False, False, "curl"),
    ToolRegistryEntry("httpie", "url_history", "http --version", "http {target}", "text", "text_stdout", "safe", False, False, "HTTPie"),

    # ── Port / Service Mapping ──
    ToolRegistryEntry("nmap", "port_discovery", "nmap --version", "nmap -sV -p- {target}", "text", "nmap_stdout", "safe", False, False, "Nmap"),
    ToolRegistryEntry("naabu", "port_discovery", "naabu -version", "naabu -host {target} -p 1-65535", "text", "text_lines", "safe", False, False, "Naabu"),
    ToolRegistryEntry("masscan", "port_discovery", "masscan --version", "masscan {target} -p1-65535 --rate=1000", "text", "text_lines", "safe", False, True, "Masscan", notes="requires_explicit_permission due to high scan rate"),
    ToolRegistryEntry("rustscan", "port_discovery", "rustscan --version", "rustscan -a {target} --range 1-65535 --timeout 2000", "text", "text_lines", "safe", False, False, "RustScan"),
    ToolRegistryEntry("zmap", "port_discovery", "zmap --version", "zmap -p 443 {cidr}", "text", "text_lines", "safe", False, True, "ZMap", notes="requires_explicit_permission — network-wide scan"),
    ToolRegistryEntry("amap", "port_discovery", "amap -v", "amap -bqv {target} {port}", "text", "amap_stdout", "safe", False, False, "Amap"),
    ToolRegistryEntry("netcat", "port_discovery", "nc -h", "nc -zv {target} {port}", "text", "text_stdout", "safe", False, False, "netcat"),
    ToolRegistryEntry("tlsx", "tls_assessment", "tlsx -version", "tlsx -host {target} -port 443 -silent", "json", "json_parser", "safe", False, False, "tlsx"),

    # ── TLS / SSL Assessment ──
    ToolRegistryEntry("testssl", "tls_assessment", "testssl --version", "testssl --quiet {target}", "text", "testssl_parser", "safe", False, False, "testssl.sh"),
    ToolRegistryEntry("sslscan", "tls_assessment", "sslscan --version", "sslscan {target}:443", "text", "sslscan_parser", "safe", False, False, "sslscan"),
    ToolRegistryEntry("sslyze", "tls_assessment", "sslyze --version", "sslyze --regular {target}", "json", "json_parser", "safe", False, False, "SSLyze"),
    ToolRegistryEntry("openssl", "tls_assessment", "openssl version", "openssl s_client -connect {target}:443 -servername {target}", "text", "openssl_parser", "safe", False, False, "OpenSSL"),
    ToolRegistryEntry("zgrab2", "tls_assessment", "zgrab2 --version", "zgrab2 tls --port 443 {target}", "json", "json_parser", "safe", False, False, "ZGrab2"),
    ToolRegistryEntry("cfssl", "tls_assessment", "cfssl version", "cfssl certinfo -domain {target}", "json", "json_parser", "safe", False, False, "CFSSL"),

    # ── Security Headers / WAF ──
    ToolRegistryEntry("wafw00f", "security_headers", "wafw00f --version", "wafw00f {target}", "text", "wafw00f_parser", "safe", False, False, "WafW00f"),
    ToolRegistryEntry("corsy", "security_headers", "corsy --help", "corsy -u {target}", "text", "text_stdout", "safe", False, False, "Corsy"),
    ToolRegistryEntry("corscanner", "security_headers", "python3 corscanner.py --help", "python3 corscanner.py -u {target}", "text", "text_stdout", "safe", False, False, "CORScanner"),
    ToolRegistryEntry("crlfuzz", "security_headers", "crlfuzz --help", "crlfuzz -u {target}", "text", "text_stdout", "safe", False, False, "CRLFuzz"),
    ToolRegistryEntry("smuggler", "security_headers", "python smuggler.py --help", "python smuggler.py -u {target}", "text", "text_stdout", "safe", False, False, "Smuggler"),
    ToolRegistryEntry("h2csmuggler", "security_headers", "h2csmuggler --help", "h2csmuggler -url {target}", "text", "text_stdout", "safe", False, False, "H2C Smuggler"),

    # ── Web Server Scanning ──
    ToolRegistryEntry("nikto", "web_server_scan", "nikto -Version", "nikto -h {target} -Tuning 1,2,3,4,5,6,7,8,9", "text", "nikto_parser", "moderate", False, False, "Nikto"),
    ToolRegistryEntry("jaeles", "web_server_scan", "jaeles version", "jaeles scan -s signatures/ -u {target}", "text", "json_parser", "moderate", False, False, "Jaeles"),
    ToolRegistryEntry("interactsh", "vuln_active_scan", "interactsh-client -version", "interactsh-client -o output.txt", "text", "text_stdout", "safe", False, False, "Interactsh"),

    # ── Technology Fingerprinting ──
    ToolRegistryEntry("whatweb", "technology_fingerprinting", "whatweb --version", "whatweb {target}", "text/json", "whatweb_parser", "safe", False, False, "WhatWeb"),
    ToolRegistryEntry("wappalyzer", "technology_fingerprinting", "wappalyzer --version", "wappalyzer {target}", "json", "json_parser", "safe", False, False, "Wappalyzer"),
    ToolRegistryEntry("builtwith", "technology_fingerprinting", "builtwith --version", "builtwith -d {target}", "json", "json_parser", "safe", False, False, "BuiltWith"),

    # ── Active Scanning ──
    ToolRegistryEntry("nuclei", "vuln_active_scan", "nuclei -version", "nuclei -u {target} -t ~/nuclei-templates/", "text", "nuclei_parser", "high", False, False, "Nuclei", notes="high risk — generates live traffic"),
    ToolRegistryEntry("dalfox", "vuln_active_scan", "dalfox version", "dalfox url {target} --silence", "text", "dalfox_parser", "high", False, False, "Dalfox", notes="XSS scanning — requires permission"),
    ToolRegistryEntry("ffuf", "vuln_active_scan", "ffuf -V", "ffuf -u {target}/FUZZ -w wordlist.txt -mc 200", "text", "ffuf_parser", "moderate", False, False, "ffuf"),
    ToolRegistryEntry("feroxbuster", "vuln_active_scan", "feroxbuster --version", "feroxbuster -u {target} -w wordlist.txt --silent", "text", "feroxbuster_parser", "moderate", False, False, "Feroxbuster"),
    ToolRegistryEntry("gobuster", "vuln_active_scan", "gobuster version", "gobuster dir -u {target} -w wordlist.txt", "text", "gobuster_parser", "moderate", False, False, "Gobuster"),
    ToolRegistryEntry("dirsearch", "vuln_active_scan", "dirsearch --version", "dirsearch -u {target} -e php,html,js", "text", "dirsearch_parser", "moderate", False, False, "Dirsearch"),
    ToolRegistryEntry("wfuzz", "vuln_active_scan", "wfuzz --version", "wfuzz -c -z file,wordlist.txt --hc 404 {target}/FUZZ", "text", "wfuzz_parser", "moderate", False, False, "Wfuzz"),
    ToolRegistryEntry("xsstrike", "vuln_active_scan", "xsstrike --version", "xsstrike -u {target} --crawl", "text", "xsstrike_parser", "high", False, False, "XSStrike", notes="XSS scanning — requires permission"),
    ToolRegistryEntry("sqlmap", "vuln_active_scan", "sqlmap --version", "sqlmap -u {target} --batch --level=2 --risk=2", "text", "sqlmap_parser", "critical", False, True, "SQLMap", notes="critical risk — database write possible; requires explicit authorization"),
    ToolRegistryEntry("commix", "vuln_active_scan", "commix --version", "commix --url {target} --data \"param=1\" --batch", "text", "commix_parser", "critical", False, True, "Commix", notes="critical risk — OS command execution possible; requires explicit authorization"),
    ToolRegistryEntry("tplmap", "vuln_active_scan", "tplmap --version", "tplmap -u {target}", "text", "tplmap_parser", "critical", False, True, "Tplmap", notes="critical risk — server-side template injection; requires explicit authorization"),
    ToolRegistryEntry("arjun", "vuln_active_scan", "arjun --version", "arjun -u {target} -m GET", "text", "arjun_parser", "safe", False, False, "Arjun"),
    ToolRegistryEntry("paramspider", "vuln_active_scan", "paramspider --version", "paramspider -d {target}", "text", "text_lines", "safe", False, False, "ParamSpider"),
    ToolRegistryEntry("kxss", "vuln_active_scan", "kxss --version", "kxss {target}", "text", "text_lines", "safe", False, False, "kxss"),
    ToolRegistryEntry("gf", "vuln_active_scan", "gf --help", "gf sqli urls.txt", "text", "text_lines", "safe", False, False, "gf"),
    ToolRegistryEntry("uro", "vuln_active_scan", "uro --version", "uro urls.txt", "text", "text_lines", "safe", False, False, "uro"),
    ToolRegistryEntry("qsreplace", "vuln_active_scan", "echo test | qsreplace --help", "qsreplace payload.txt < urls.txt", "text", "text_lines", "safe", False, False, "qsreplace"),
    ToolRegistryEntry("va_active_scan", "vuln_active_scan", "", "", "text", "argus_parser", "high", False, False, "ARGUS Active Scan"),
    ToolRegistryEntry("va_active_scan_tool", "vuln_active_scan", "", "", "text", "argus_parser", "high", False, False, "ARGUS Tool Dispatcher"),

    # ── SCA / Dependencies ──
    ToolRegistryEntry("trivy", "sca_dependencies", "trivy --version", "trivy fs --scanners vuln,secret,config {path}", "json", "trivy_parser", "safe", False, False, "Trivy"),
    ToolRegistryEntry("grype", "sca_dependencies", "grype version", "grype {image}:{tag}", "json", "grype_parser", "safe", False, False, "Grype"),
    ToolRegistryEntry("syft", "sca_dependencies", "syft version", "syft {image}:{tag} -o json", "json", "syft_parser", "safe", False, False, "Syft"),
    ToolRegistryEntry("osv-scanner", "sca_dependencies", "osv-scanner --version", "osv-scanner --docker {image}:{tag}", "json", "osv_parser", "safe", False, False, "OSV Scanner"),
    ToolRegistryEntry("retire.js", "sca_dependencies", "retire --version", "retire --jspath {path}", "json", "retire_parser", "safe", False, False, "Retire.js"),
    ToolRegistryEntry("safety", "sca_dependencies", "safety --version", "safety check -r requirements.txt --json", "json", "json_parser", "safe", False, False, "Safety"),
    ToolRegistryEntry("pip-audit", "sca_dependencies", "pip-audit --version", "pip-audit -r requirements.txt", "json", "json_parser", "safe", False, False, "pip-audit"),
    ToolRegistryEntry("npm", "sca_dependencies", "npm --version", "npm audit --json", "json", "json_parser", "safe", False, False, "npm audit"),
    ToolRegistryEntry("yarn audit", "sca_dependencies", "yarn --version", "yarn audit --json", "json", "json_parser", "safe", False, False, "yarn audit"),
    ToolRegistryEntry("pnpm audit", "sca_dependencies", "pnpm --version", "pnpm audit --json", "json", "json_parser", "safe", False, False, "pnpm audit"),
    ToolRegistryEntry("composer audit", "sca_dependencies", "composer --version", "composer audit --format=json", "json", "json_parser", "safe", False, False, "Composer"),
    ToolRegistryEntry("bundle-audit", "sca_dependencies", "bundle-audit version", "bundle-audit check --update", "text", "text_stdout", "safe", False, False, "Bundle Audit"),
    ToolRegistryEntry("cargo audit", "sca_dependencies", "cargo audit --version", "cargo audit", "json", "json_parser", "safe", False, False, "Cargo Audit"),
    ToolRegistryEntry("govulncheck", "sca_dependencies", "govulncheck -version", "govulncheck ./...", "text", "text_stdout", "safe", False, False, "Go Vulncheck"),

    # ── Secret Scanning ──
    ToolRegistryEntry("gitleaks", "sca_dependencies", "gitleaks version", "gitleaks detect --source {path} --verbose", "json", "json_parser", "safe", False, False, "Gitleaks"),
    ToolRegistryEntry("trufflehog", "sca_dependencies", "trufflehog --version", "trufflehog filesystem {path} --json", "json", "json_parser", "safe", False, False, "TruffleHog"),
    ToolRegistryEntry("detect-secrets", "sca_dependencies", "detect-secrets --version", "detect-secrets scan {path}", "json", "json_parser", "safe", False, False, "Detect Secrets"),
    ToolRegistryEntry("git-secrets", "sca_dependencies", "git secrets --version", "git secrets --scan {path}", "text", "text_stdout", "safe", False, False, "Git Secrets"),
    ToolRegistryEntry("semgrep", "sca_dependencies", "semgrep --version", "semgrep --config auto {path}", "json", "semgrep_parser", "safe", False, False, "Semgrep"),

    # ── CMS Scanning ──
    ToolRegistryEntry("wpscan", "cms_scan", "wpscan --version", "wpscan --url {target} --enumerate p,u,t,tt --api-token $WPSCAN_API_TOKEN", "text", "wpscan_parser", "moderate", False, False, "WPScan", notes="recommended: set WPSCAN_API_TOKEN"),
    ToolRegistryEntry("droopescan", "cms_scan", "droopescan --version", "droopescan scan drupal -u {target}", "text", "text_stdout", "moderate", False, False, "Droopescan"),
    ToolRegistryEntry("cmseek", "cms_scan", "cmseek --version", "cmseek -u {target}", "text", "text_stdout", "safe", False, False, "CMSeek"),
    ToolRegistryEntry("cmsmap", "cms_scan", "cmsmap --version", "cmsmap {target}", "text", "text_stdout", "moderate", False, False, "CMSMap"),

    # ── API Security ──
    ToolRegistryEntry("jwt_tool", "api_security", "jwt_tool --version", "jwt_tool {token}", "text", "jwt_parser", "safe", False, False, "JWT Tool"),
    ToolRegistryEntry("jwt-hack", "api_security", "jwt-hack --version", "jwt-hack {token}", "text", "text_stdout", "safe", False, False, "JWT Hack"),
    ToolRegistryEntry("graphql-cop", "api_security", "graphql-cop --version", "graphql-cop -t {target}/graphql", "text", "text_stdout", "safe", False, False, "GraphQL Cop"),
    ToolRegistryEntry("clairvoyance", "api_security", "clairvoyance --version", "clairvoyance {target}/graphql", "text", "text_stdout", "safe", False, False, "Clairvoyance"),
    ToolRegistryEntry("inql", "api_security", "inql --version", "inql -t {target}/graphql", "text", "text_stdout", "safe", False, False, "InQL"),
    ToolRegistryEntry("kiterunner", "api_security", "kiterunner version", "kiterunner scan -w routes.kite {target}", "text", "text_lines", "moderate", False, False, "Kiterunner"),
    ToolRegistryEntry("schemathesis", "api_security", "schemathesis --version", "schemathesis run {target}/openapi.json", "text", "json_parser", "moderate", False, False, "Schemathesis"),
    ToolRegistryEntry("postman", "api_security", "postman --version", "newman run collection.json -e env.json", "json", "json_parser", "safe", True, False, "Postman / Newman"),

    # ── Auth / Brute Force ──
    ToolRegistryEntry("hydra", "auth_testing", "hydra -h", "hydra -L users.txt -P passwords.txt {target} http-post-form '/login:user=^USER^&pass=^PASS^:Invalid'", "text", "hydra_parser", "critical", True, True, "Hydra", notes="critical risk — account lockout possible; requires explicit permission"),
    ToolRegistryEntry("patator", "auth_testing", "patator --version", "patator http_fuzz url={target}/login method=POST body='user=FILE0&pass=FILE1' 0=users.txt 1=passwords.txt", "text", "patator_parser", "critical", True, True, "Patator"),

    # ── Cloud Security ──
    ToolRegistryEntry("cloud_enum", "cloud_security", "cloud_enum --version", "cloud_enum -k {keyword} -m {mutations}", "text", "text_lines", "safe", False, False, "Cloud Enum"),
    ToolRegistryEntry("s3scanner", "cloud_security", "s3scanner --version", "s3scanner -bucket {bucket}", "text", "text_lines", "safe", False, False, "S3Scanner"),
    ToolRegistryEntry("gcpbucketbrute", "cloud_security", "gcpbucketbrute --version", "gcpbucketbrute -k {keyword}", "text", "text_lines", "safe", False, False, "GCPBucketBrute"),
    ToolRegistryEntry("scout-suite", "cloud_security", "scout --version", "scout aws", "json", "json_parser", "safe", False, True, "ScoutSuite", notes="requires valid cloud credentials"),
    ToolRegistryEntry("prowler", "cloud_security", "prowler --version", "prowler aws", "json", "json_parser", "safe", False, True, "Prowler", notes="requires AWS credentials"),

    # ── Container / Kubernetes Security ──
    ToolRegistryEntry("kube-hunter", "container_security", "kube-hunter --version", "kube-hunter --remote {target}", "text", "text_stdout", "high", False, True, "Kube-Hunter", notes="active scanning of K8s cluster; requires explicit permission"),
    ToolRegistryEntry("kube-bench", "container_security", "kube-bench --version", "kube-bench run --targets master,node", "text", "text_stdout", "safe", False, False, "Kube-Bench"),
    ToolRegistryEntry("kube-score", "container_security", "kube-score version", "kube-score score deployment.yaml", "text", "text_stdout", "safe", False, False, "Kube-Score"),
    ToolRegistryEntry("checkov", "container_security", "checkov --version", "checkov -d {path}", "json", "json_parser", "safe", False, False, "Checkov"),
    ToolRegistryEntry("terrascan", "container_security", "terrascan version", "terrascan scan -d {path}", "json", "json_parser", "safe", False, False, "Terrascan"),
    ToolRegistryEntry("tfsec", "container_security", "tfsec --version", "tfsec {path}", "text", "text_stdout", "safe", False, False, "tfsec"),
    ToolRegistryEntry("kubeaudit", "container_security", "kubeaudit --version", "kubeaudit all -f manifest.yaml", "text", "text_stdout", "safe", False, False, "Kubeaudit"),
    ToolRegistryEntry("kube-linter", "container_security", "kube-linter version", "kube-linter lint {path}", "text", "text_stdout", "safe", False, False, "Kube-Linter"),
    ToolRegistryEntry("kube-no-trouble", "container_security", "kubent --version", "kubent", "text", "text_stdout", "safe", False, False, "KubeNoTrouble"),

    # ── Email / OSINT ──
    ToolRegistryEntry("theharvester", "email_osint", "theHarvester --version", "theHarvester -d {target} -b all", "text", "harvester_parser", "safe", False, False, "theHarvester"),
    ToolRegistryEntry("hibp", "credential_exposure", "", "", "json", "hibp_parser", "safe", True, False, "HIBP API", notes="requires HIBP_API_KEY"),
    ToolRegistryEntry("shodan", "email_osint", "", "", "json", "json_parser", "safe", True, False, "Shodan", notes="requires SHODAN_API_KEY"),
    ToolRegistryEntry("censys", "email_osint", "", "", "json", "json_parser", "safe", True, False, "Censys", notes="requires CENSYS_API_KEY"),
    ToolRegistryEntry("securitytrails", "email_osint", "", "", "json", "json_parser", "safe", True, False, "SecurityTrails", notes="requires SECURITYTRAILS_API_KEY"),
    ToolRegistryEntry("virustotal", "email_osint", "", "", "json", "json_parser", "safe", True, False, "VirusTotal", notes="requires VIRUSTOTAL_API_KEY"),
    ToolRegistryEntry("abuseipdb", "email_osint", "", "", "json", "json_parser", "safe", True, False, "AbuseIPDB", notes="requires ABUSEIPDB_API_KEY"),
    ToolRegistryEntry("urlscan", "email_osint", "", "", "json", "json_parser", "safe", True, False, "urlscan.io", notes="requires URLSCAN_API_KEY"),

    # ── Browser / DAST ──
    ToolRegistryEntry("playwright", "content_discovery", "playwright --version", "", "png/json", "browser_parser", "safe", True, False, "Playwright"),
    ToolRegistryEntry("selenium", "content_discovery", "selenium --version", "", "png/json", "browser_parser", "safe", True, False, "Selenium"),
    ToolRegistryEntry("zap-baseline", "vuln_active_scan", "", "", "json", "zap_parser", "moderate", False, True, "ZAP Baseline"),
    ToolRegistryEntry("zap-full-scan", "vuln_active_scan", "", "", "json", "zap_parser", "high", False, True, "ZAP Full Scan", notes="high risk — active scanning suite"),
    ToolRegistryEntry("zap-api-scan", "vuln_active_scan", "", "", "json", "zap_parser", "moderate", False, True, "ZAP API Scan"),
    ToolRegistryEntry("burp", "vuln_active_scan", "", "", "xml/json", "burp_parser", "high", False, True, "Burp Suite Scanner", notes="commercial tool — requires license"),
    ToolRegistryEntry("mitmproxy", "content_discovery", "mitmproxy --version", "", "text", "text_stdout", "safe", False, False, "mitmproxy"),
    ToolRegistryEntry("nuclei-templates", "vuln_active_scan", "nuclei -version", "nuclei -u {target} -t ~/nuclei-templates/", "text", "nuclei_parser", "high", False, False, "Nuclei Templates"),
    ToolRegistryEntry("nmap scripts", "port_discovery", "nmap --version", "nmap --script vuln {target}", "text", "nmap_parser", "moderate", False, False, "Nmap NSE Scripts"),
    ToolRegistryEntry("vulners nse", "port_discovery", "nmap --version", "nmap --script vulners {target}", "text", "nmap_parser", "safe", False, False, "Vulners NSE"),
]


_TOOLS_BY_NAME: dict[str, ToolRegistryEntry] = {t.name: t for t in _TOOLS}


def get_tool_registry() -> list[ToolRegistryEntry]:
    """Return the full registry (immutable list)."""
    return list(_TOOLS)


def get_tool_by_name(name: str) -> ToolRegistryEntry | None:
    """Look up a tool by its canonical name."""
    return _TOOLS_BY_NAME.get(name.lower().replace("_", "").replace("-", "").replace(".", "").replace(" ", ""))


def get_tools_by_capability(capability: str) -> list[ToolRegistryEntry]:
    """Return all tools registered for a given capability."""
    return [t for t in _TOOLS if t.capability == capability]


def get_all_capabilities() -> list[str]:
    """Return sorted list of all unique capabilities."""
    seen: dict[str, bool] = {}
    for t in _TOOLS:
        seen[t.capability] = True
    return sorted(seen)


def get_tool_names() -> list[str]:
    """Return list of all canonical tool names."""
    return [t.name for t in _TOOLS]


def get_tool_count() -> int:
    """Return total number of registered tools."""
    return len(_TOOLS)
