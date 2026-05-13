"""Binary Static Analysis Worker — ELF/PE/Mach-O triage via WhiteRabbitNeo.

Extracts: file metadata, strings, imports/exports, packer/obfuscation heuristics,
capability labeling (capa-style), control-flow characteristics.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import struct
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class BinaryFormat(str, Enum):
    ELF = "elf"
    PE = "pe"
    MACH_O = "mach-o"
    UNKNOWN = "unknown"


class AnalysisConfidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class BinaryMetadata:
    """Extracted binary metadata."""

    format: BinaryFormat = BinaryFormat.UNKNOWN
    file_path: str = ""
    file_size: int = 0
    sha256: str = ""
    md5: str = ""
    architecture: str = ""       # x86, x86-64, ARM, ARM64, ...
    entry_point: int = 0
    sections: list[dict[str, Any]] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    strings_suspicious: list[str] = field(default_factory=list)
    strings_all_count: int = 0
    packer_hints: list[str] = field(default_factory=list)
    obfuscation_score: float = 0.0
    capabilities: list[str] = field(default_factory=list)  # capa-style
    yara_matches: list[dict[str, str]] = field(default_factory=list)


@dataclass
class BinaryAnalysisResult:
    """Full binary analysis output."""

    id: str = ""
    tenant_id: str = ""
    sample_id: str = ""
    metadata: BinaryMetadata = field(default_factory=BinaryMetadata)
    wb_analysis: dict[str, Any] = field(default_factory=dict)  # WRB output
    risk_score: float = 0.0
    verdict: str = ""  # malicious | suspicious | clean | inconclusive
    mitre_attck: list[dict[str, str]] = field(default_factory=list)
    indicators: list[dict[str, str]] = field(default_factory=list)
    error: str = ""


def _detect_binary_format(data: bytes) -> BinaryFormat:
    if data[:4] == b"\x7fELF":
        return BinaryFormat.ELF
    if data[:2] == b"MZ":
        return BinaryFormat.PE
    magic = struct.unpack(">I", data[:4])[0]
    if magic in (
        0xFEEDFACE, 0xFEEDFACF, 0xCAFEBABE, 0xBEBAFECA,
        0xCFFAEDFE, 0xCEFAEDFE, 0xCAFEBABE,
    ):
        return BinaryFormat.MACH_O
    return BinaryFormat.UNKNOWN


def _extract_strings(data: bytes, min_length: int = 4) -> list[str]:
    import re
    ascii_re = re.compile(rb'[\x20-\x7e]{%d,}' % min_length)
    matches = ascii_re.findall(data)
    return [m.decode("ascii", errors="replace") for m in matches]


def _detect_packer_hints(strings_list: list[str], data: bytes) -> list[str]:
    packers = {
        "UPX": "UPX",
        "Aspack": "ASPack",
        "PECompact": "PECompact",
        "Themida": "Themida",
        "VMProtect": "VMProtect",
        "Enigma": "Enigma Protector",
        "obsidium": "Obsidium",
        "yoda": "yoda's Protector",
        "petite": "PEtite",
        "fsg": "FSG",
        "mpress": "MPRESS",
        "nsPack": "NsPack",
        "upx0": "UPX section",
        ".aspack": "ASPack section",
        ".vmp": "VMProtect section",
        "Nullsoft": "NSIS Installer",
        "PyInstaller": "PyInstaller",
        "Inno Setup": "InnoSetup",
    }
    found = []
    blob = " ".join(strings_list[:5000]).lower()
    for hint, label in packers.items():
        if hint.lower() in blob:
            found.append(label)

    entropy = _calc_entropy(data[:100_000])
    if entropy > 7.5:
        found.append(f"High entropy ({entropy:.1f}/8.0) — possible packing/encryption")
    return found


def _calc_entropy(data: bytes) -> float:
    from collections import Counter
    if not data:
        return 0.0
    n = len(data)
    freq = Counter(data)
    return -sum((c / n) * (__import__("math").log2(c / n)) for c in freq.values())


def _classify_capabilities(strings_list: list[str]) -> list[str]:
    capabilities = []
    patterns: dict[str, list[str]] = {
        "creates_process": ["CreateProcess", "exec", "system(", "popen", "ShellExecute"],
        "network_communication": ["http://", "https://", "socket", "connect(", "send(", "WSASocket"],
        "file_manipulation": ["CreateFile", "WriteFile", "ReadFile", "fopen", "open("],
        "registry_modification": ["RegOpenKey", "RegSetValue", "HKEY_"],
        "service_manipulation": ["CreateService", "StartService", "OpenSCManager"],
        "credential_access": ["lsass", "sam", "credential", "token", "password", "login"],
        "defense_evasion": ["VirtualProtect", "WriteProcessMemory", "Process Hollowing", "injection"],
        "persistence": ["Run\\", "RunOnce", "Scheduled Task", "Startup", "svchost"],
        "c2_communication": ["beacon", "callback", "botnet", "c2", "command and control"],
        "data_exfiltration": ["POST /", "upload", "exfil", "ftp://", "curl"],
    }
    blob = " ".join(strings_list[:5000]).lower()
    for cap, keywords in patterns.items():
        if any(kw.lower() in blob for kw in keywords):
            capabilities.append(cap)
    return capabilities


async def _call_wb_for_binary_analysis(
    metadata: BinaryMetadata, tenant_id: str = ""
) -> dict[str, Any]:
    """Call WhiteRabbitNeo for binary analysis verdict."""
    from src.llm.facade import call_llm_unified
    from src.llm.task_router import LLMTask

    prompt = f"""Analyse this binary for malicious intent. Provide a security verdict.

=== BINARY METADATA ===
Format: {metadata.format.value}
Architecture: {metadata.architecture}
Size: {metadata.file_size} bytes
SHA256: {metadata.sha256}
Entry point: 0x{metadata.entry_point:x}
Sections: {len(metadata.sections)}
Imports ({len(metadata.imports)}): {', '.join(metadata.imports[:30])}
Suspicious strings ({len(metadata.strings_suspicious)}): {', '.join(metadata.strings_suspicious[:20])}
Packer hints: {', '.join(metadata.packer_hints) or 'none'}
Obfuscation score: {metadata.obfuscation_score:.1f}/8.0
Detected capabilities: {', '.join(metadata.capabilities) or 'none'}

=== TASK ===
Respond with JSON:
{{"verdict": "malicious|suspicious|clean|inconclusive",
 "risk_score": 0.0-10.0,
 "mitre_attck": [{{"tactic": "...", "technique_id": "T...", "technique": "..."}}],
 "indicators": [{{"type": "...", "value": "..."}}],
 "rationale": "..."}}"""

    system = (
        "You are a malware analyst performing binary triage. "
        "Analayse the provided metadata and strings to determine threat level. "
        "Respond ONLY with valid JSON."
    )

    try:
        resp = await call_llm_unified(system, prompt, task=LLMTask.ZERO_DAY_ANALYSIS, phase="binary_triage")
        return json.loads(resp)
    except Exception:
        return {}


async def analyse_binary(
    file_path: str, data: bytes | None = None,
    *, tenant_id: str = "", sample_id: str = "",
) -> BinaryAnalysisResult:
    """Run full static binary analysis pipeline."""
    result = BinaryAnalysisResult(
        id=str(uuid.uuid4()), tenant_id=tenant_id,
        sample_id=sample_id or file_path,
    )

    if data is None:
        try:
            data = Path(file_path).read_bytes()
        except Exception as exc:
            result.error = f"Cannot read file: {exc}"
            return result

    meta = BinaryMetadata(
        file_path=file_path,
        file_size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data).hexdigest(),
        format=_detect_binary_format(data),
        strings_all_count=0,
    )
    result.metadata = meta

    if meta.format == BinaryFormat.UNKNOWN:
        result.verdict = "inconclusive"
        result.error = "Unknown binary format"
        return result

    # Architecture & entry point
    if meta.format == BinaryFormat.PE:
        try:
            pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
            if data[pe_offset:pe_offset+4] == b"PE\0\0":
                coff = data[pe_offset+4:pe_offset+24]
                machine = struct.unpack("<H", coff[0:2])[0]
                arch_map = {0x014C: "x86", 0x8664: "x86-64", 0x01C4: "ARM", 0xAA64: "ARM64"}
                meta.architecture = arch_map.get(machine, f"0x{machine:x}")
                meta.entry_point = struct.unpack("<I", coff[16:20])[0]
                num_sections = struct.unpack("<H", coff[2:4])[0]
                opt_header_size = struct.unpack("<H", coff[16:18])[0]
                section_start = pe_offset + 24 + opt_header_size
                for i in range(num_sections):
                    off = section_start + i * 40
                    if off + 40 <= len(data):
                        name = data[off:off+8].rstrip(b"\0").decode("ascii", errors="replace")
                        vsize = struct.unpack("<I", data[off+8:off+12])[0]
                        meta.sections.append({"name": name, "virtual_size": vsize})
        except Exception:
            pass
    elif meta.format == BinaryFormat.ELF:
        try:
            elf_class = data[4]
            arch_map = {1: "x86", 2: "x86-64", 0x28: "ARM", 0xB7: "ARM64", 0x3E: "x86-64"}
            meta.architecture = arch_map.get(data[18] if elf_class == 1 else data[18] | (data[19] << 8), f"0x{(data[18]):x}")
            meta.entry_point = struct.unpack("<I" if data[4] == 1 else "<Q", data[24:24+(4 if data[4]==1 else 8)])[0]
        except Exception:
            pass

    # Strings
    all_strings = _extract_strings(data)
    meta.strings_all_count = len(all_strings)

    suspicious_keywords = [
        "hack", "exploit", "inject", "payload", "shellcode", "backdoor",
        "trojan", "keylog", "ransom", "crypt", "bitcoin", "monero",
        "tor", "onion", "darknet", "malware", "rootkit", "reverse shell",
        "cmd.exe", "powershell", "wget", "curl -", "netcat",
        "127.0.0.1", "192.168.", "10.0.", "172.16.",
        "meterpreter", "msfvenom", "metasploit",
    ]
    meta.strings_suspicious = [
        s[:100] for s in all_strings
        if any(kw.lower() in s.lower() for kw in suspicious_keywords)
    ][:30]

    meta.packer_hints = _detect_packer_hints(all_strings, data)
    meta.obfuscation_score = _calc_entropy(data[:100_000])
    meta.capabilities = _classify_capabilities(all_strings)

    # WRB analysis
    wb = await _call_wb_for_binary_analysis(meta, tenant_id)
    result.wb_analysis = wb
    result.verdict = wb.get("verdict", "inconclusive")
    result.risk_score = wb.get("risk_score", meta.obfuscation_score * 1.25)
    result.mitre_attck = wb.get("mitre_attck", [])
    result.indicators = wb.get("indicators", [])

    return result
