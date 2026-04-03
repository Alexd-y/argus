"""
ToolRecoverySystem — automatic fallback to alternative tools when primary fails.

Stateful tools (sessions) are never auto-replaced. Alternatives are consulted from
``TOOL_ALTERNATIVES``; callers that use the sandbox allowlist should filter alts
against ``ALLOWED_TOOLS`` before executing.
"""

from __future__ import annotations

import logging
import shlex
from typing import Any

logger = logging.getLogger(__name__)

MAX_RECOVERY_ATTEMPTS = 3

_TOOL_RAW: list[tuple[str, list[str]]] = [
    ("nmap", ["rustscan", "masscan", "naabu"]),
    ("rustscan", ["nmap", "masscan", "naabu"]),
    ("masscan", ["nmap", "rustscan", "naabu"]),
    ("naabu", ["rustscan", "nmap", "masscan"]),
    ("subfinder", ["amass", "assetfinder", "findomain", "sublist3r"]),
    ("amass", ["subfinder", "assetfinder", "findomain", "sublist3r"]),
    ("assetfinder", ["subfinder", "amass", "findomain"]),
    ("findomain", ["subfinder", "amass", "assetfinder"]),
    ("sublist3r", ["subfinder", "amass", "assetfinder"]),
    ("dig", ["host", "nslookup", "dnsx", "dnsrecon"]),
    ("host", ["dig", "nslookup", "dnsx"]),
    ("nslookup", ["dig", "host", "dnsx"]),
    ("dnsx", ["dig", "host", "dnsrecon"]),
    ("dnsrecon", ["dig", "dnsx", "fierce"]),
    ("fierce", ["dnsrecon", "dnsx", "dig"]),
    ("whatweb", ["httpx", "wappalyzer", "webanalyze"]),
    ("httpx", ["whatweb", "curl"]),
    ("wappalyzer", ["whatweb", "httpx"]),
    ("webanalyze", ["whatweb", "httpx"]),
    ("gobuster", ["feroxbuster", "dirsearch", "dirb", "ffuf", "wfuzz"]),
    ("feroxbuster", ["gobuster", "dirsearch", "dirb", "ffuf"]),
    ("dirsearch", ["gobuster", "feroxbuster", "dirb", "ffuf"]),
    ("dirb", ["gobuster", "feroxbuster", "dirsearch", "ffuf"]),
    ("ffuf", ["gobuster", "feroxbuster", "dirsearch", "wfuzz"]),
    ("wfuzz", ["ffuf", "gobuster", "feroxbuster"]),
    ("nikto", ["nuclei", "wpscan"]),
    ("nuclei", ["nikto", "wpscan"]),
    ("wpscan", ["nikto", "nuclei"]),
    ("dalfox", ["xsstrike", "nuclei"]),
    ("xsstrike", ["dalfox", "nuclei"]),
    ("testssl", ["sslyze", "openssl"]),
    ("sslyze", ["testssl", "openssl"]),
    ("openssl", ["testssl", "sslyze"]),
    ("theharvester", ["recon-ng", "spiderfoot"]),
    ("recon-ng", ["theharvester", "spiderfoot"]),
    ("spiderfoot", ["theharvester", "recon-ng"]),
    ("whois", ["dig", "host", "curl"]),
    ("gau", ["waybackurls", "waymore"]),
    ("waybackurls", ["gau", "waymore"]),
    ("waymore", ["gau", "waybackurls"]),
    ("gitleaks", ["trufflehog", "semgrep"]),
    ("trufflehog", ["gitleaks", "semgrep"]),
    ("semgrep", ["gitleaks", "trufflehog"]),
    ("trivy", ["checkov", "terrascan", "grype", "syft"]),
    ("checkov", ["trivy", "terrascan"]),
    ("terrascan", ["trivy", "checkov"]),
    ("grype", ["trivy", "syft"]),
    ("syft", ["trivy", "grype"]),
    ("prowler", ["scout"]),
    ("scout", ["prowler"]),
    ("joomscan", ["droopescan", "nuclei"]),
    ("droopescan", ["joomscan", "wpscan"]),
    ("arjun", ["paramspider", "ffuf"]),
    ("paramspider", ["arjun", "gau"]),
    ("gowitness", ["eyewitness", "aquatone"]),
    ("eyewitness", ["gowitness", "aquatone"]),
    ("aquatone", ["gowitness", "eyewitness"]),
    ("curl", ["httpx", "wget"]),
    ("wget", ["curl"]),
    ("sqlmap", ["nuclei"]),
    ("hydra", ["medusa"]),
    ("medusa", ["hydra"]),
    ("searchsploit", ["nuclei", "curl"]),
    ("nxc", ["crackmapexec"]),
    ("crackmapexec", ["nxc"]),
    ("enum4linux", ["enum4linux-ng"]),
    ("enum4linux-ng", ["enum4linux"]),
    ("smbmap", ["crackmapexec"]),
    ("rpcclient", ["enum4linux"]),
    ("ldapsearch", ["windapsearch"]),
    ("windapsearch", ["ldapsearch"]),
    ("aircrack-ng", []),
    ("bettercap", []),
    ("gdb", []),
    ("radare2", ["ghidra"]),
    ("ghidra", ["radare2"]),
    ("metasploit", []),
    ("msfconsole", []),
    ("burpsuite", []),
    ("zaproxy", []),
    ("beef-xss", []),
    ("empire", []),
    ("cobaltstrike", []),
    ("responder", []),
    ("mitmdump", []),
    ("katana", ["gau", "hakrawler"]),
    ("hakrawler", ["katana", "gau"]),
    ("uro", ["katana", "ffuf"]),
    ("nbtscan", ["nmap"]),
    ("rpcinfo", ["nmap"]),
    ("showmount", ["nmap"]),
    ("dotdotpwn", ["gobuster", "ffuf"]),
    ("xsser", ["dalfox", "nuclei"]),
    ("commix", ["sqlmap", "nuclei"]),
    ("tplmap", ["sqlmap", "nuclei"]),
    ("jwt_tool", ["hashcat"]),
    ("hashcat", ["john"]),
    ("john", ["hashcat"]),
]

TOOL_ALTERNATIVES: dict[str, list[str]] = {}
for _name, _alts in _TOOL_RAW:
    TOOL_ALTERNATIVES[_name] = _alts

STATEFUL_TOOLS: frozenset[str] = frozenset(
    {
        "sqlmap",
        "hydra",
        "medusa",
        "metasploit",
        "burpsuite",
        "zaproxy",
        "beef-xss",
        "empire",
        "cobaltstrike",
        "msfconsole",
        "responder",
        "mitmdump",
        "bettercap",
    }
)


def _replace_tool_in_command(command: str, old_tool: str, new_tool: str) -> str:
    """Replace the first argv token (tool binary) with *new_tool*; preserve safe quoting."""
    parts = shlex.split(command, posix=True)
    if not parts:
        return command
    if parts[0].lower() != old_tool.lower():
        return command
    parts[0] = new_tool
    return " ".join(shlex.quote(p) for p in parts)


class ToolRecoverySystem:
    """Maps failed runs to alternative tools and builds structured recovery metadata."""

    def get_alternatives(self, tool_name: str) -> list[str]:
        if self.is_stateful(tool_name):
            return []
        return list(TOOL_ALTERNATIVES.get(tool_name.lower(), []))

    def is_stateful(self, tool_name: str) -> bool:
        return tool_name.lower() in STATEFUL_TOOLS

    def should_retry(self, tool_name: str, attempt: int) -> bool:
        if attempt >= MAX_RECOVERY_ATTEMPTS:
            return False
        if self.is_stateful(tool_name):
            return False
        return len(self.get_alternatives(tool_name)) > 0

    def next_alternative(self, tool_name: str, attempt: int) -> str | None:
        alts = self.get_alternatives(tool_name)
        idx = attempt - 1
        if 0 <= idx < len(alts):
            return alts[idx]
        return None

    def build_recovery_info(
        self,
        original_tool: str,
        final_tool: str,
        attempts: list[dict[str, Any]],
        *,
        from_cache: bool = False,
    ) -> dict[str, Any]:
        orig_l = original_tool.lower()
        fin_l = final_tool.lower()
        return {
            "original_tool": original_tool,
            "final_tool": final_tool,
            "recovery_used": orig_l != fin_l,
            "attempts": attempts,
            "total_attempts": len(attempts),
            "is_stateful": self.is_stateful(original_tool),
            "from_cache": from_cache,
            "alternatives_available": self.get_alternatives(original_tool),
        }


_tool_recovery_singleton: ToolRecoverySystem | None = None


def get_tool_recovery_system() -> ToolRecoverySystem:
    global _tool_recovery_singleton
    if _tool_recovery_singleton is None:
        _tool_recovery_singleton = ToolRecoverySystem()
    return _tool_recovery_singleton


def classify_error(stderr: str, return_code: int) -> str:
    if return_code == -1 and "timed out" in (stderr or "").lower():
        return "timeout"
    if return_code == -1:
        return "execution_error"
    if return_code != 0:
        return "nonzero_exit"
    return "success"


def log_recovery_attempt(
    *,
    original_tool: str,
    attempted_tool: str,
    command_preview: str,
    return_code: int,
    error_type: str,
    duration_sec: float,
) -> None:
    logger.info(
        "sandbox_tool_recovery_attempt",
        extra={
            "event": "argus.sandbox.tool_recovery_attempt",
            "original_tool": original_tool,
            "attempted_tool": attempted_tool,
            "return_code": return_code,
            "error_type": error_type,
            "duration_sec": round(duration_sec, 4),
            "command_len": len(command_preview),
        },
    )
