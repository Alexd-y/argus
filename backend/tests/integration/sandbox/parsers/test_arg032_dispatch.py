"""Integration test: ARG-032 batch-4 dispatch (Cycle 4 §3 ARG-032).

Sister suite to :mod:`tests.integration.sandbox.parsers.test_arg029_dispatch`.

Pins the ARG-032 contract that the **thirty** new parsers shipped in
Cycle 4 batch 4 — covering 6 browser tools + 4 binary tools + 6
subdomain reconnaissance tools + 8 credential-bruteforce / NTLM-relay
tools + 6 network / OSINT / probes — route through the dispatch
table, write per-tool sidecars, preserve cross-tool isolation, and
honour the security gates the security-auditor will enforce in Cycle
4 close.

Tools covered:

* Browser (4a) ::
    playwright_runner, puppeteer_screens, chrome_csp_probe,
    webanalyze, gowitness, whatweb
* Binary (4b) ::
    radare2_info, apktool, binwalk, jadx
* Subdomain recon (4b) ::
    amass_passive, subfinder, assetfinder, dnsrecon, fierce,
    findomain
* Credential bruteforce / NTLM relay (4c) ::
    hydra, medusa, patator, ncrack, crackmapexec, responder,
    hashcat, ntlmrelayx
* Network / OSINT / probes (4c) ::
    dnsx, chaos, censys, mongodb_probe, redis_cli_probe,
    unicornscan

Guardrails enforced in this suite:

* Every ARG-032 tool is registered in the per-tool dispatch table.
* Dispatch from a representative payload yields ``len(findings) >= 1``
  for every tool.
* Each parser writes its own dedicated sidecar file (no overwrites
  between parsers in a shared ``/out`` directory).
* Cross-tool routing isolation: a payload shaped for tool A pushed
  through tool B's ``tool_id`` produces 0 real findings.
* Determinism: re-running the same payload twice produces byte-identical
  sidecars.
* CRITICAL — Browser parsers strip ``Cookie`` / ``Set-Cookie`` /
  ``Authorization`` / ``Proxy-Authorization`` headers and inline
  URL credentials BEFORE any record reaches the FindingDTO + sidecar.
* CRITICAL — Binary parsers redact memory addresses
  (``0x[0-9a-fA-F]{8,}``) before evidence persistence so ASLR
  offsets do not leak.
* CRITICAL — Credential parsers redact cleartext passwords; only
  the canonical ``[REDACTED-PASSWORD]`` marker plus a length hint
  survives in the sidecar.
* CRITICAL — ``responder`` / ``hashcat`` / ``ntlmrelayx`` /
  ``crackmapexec`` redact the entire NTLM hash blob; only the
  protocol / username / fingerprint survive.
* Heartbeat fallback survives — unmapped tools still produce one
  observability finding through the strategy handler.
* Prior-cycle parsers (ARG-021/-022/-029) survive ARG-032 wiring.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

import pytest

from src.pipeline.contracts.finding_dto import FindingDTO
from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import (
    dispatch_parse,
    get_registered_tool_parsers,
    reset_registry,
)
from src.sandbox.parsers.amass_passive_parser import (
    EVIDENCE_SIDECAR_NAME as AMASS_PASSIVE_SIDECAR,
)
from src.sandbox.parsers.apktool_parser import (
    EVIDENCE_SIDECAR_NAME as APKTOOL_SIDECAR,
)
from src.sandbox.parsers.assetfinder_parser import (
    EVIDENCE_SIDECAR_NAME as ASSETFINDER_SIDECAR,
)
from src.sandbox.parsers.binwalk_parser import (
    EVIDENCE_SIDECAR_NAME as BINWALK_SIDECAR,
)
from src.sandbox.parsers.censys_parser import (
    EVIDENCE_SIDECAR_NAME as CENSYS_SIDECAR,
)
from src.sandbox.parsers.chaos_parser import (
    EVIDENCE_SIDECAR_NAME as CHAOS_SIDECAR,
)
from src.sandbox.parsers.chrome_csp_probe_parser import (
    EVIDENCE_SIDECAR_NAME as CHROME_CSP_PROBE_SIDECAR,
)
from src.sandbox.parsers.crackmapexec_parser import (
    EVIDENCE_SIDECAR_NAME as CRACKMAPEXEC_SIDECAR,
)
from src.sandbox.parsers.dnsrecon_parser import (
    EVIDENCE_SIDECAR_NAME as DNSRECON_SIDECAR,
)
from src.sandbox.parsers.dnsx_parser import (
    EVIDENCE_SIDECAR_NAME as DNSX_SIDECAR,
)
from src.sandbox.parsers.fierce_parser import (
    EVIDENCE_SIDECAR_NAME as FIERCE_SIDECAR,
)
from src.sandbox.parsers.findomain_parser import (
    EVIDENCE_SIDECAR_NAME as FINDOMAIN_SIDECAR,
)
from src.sandbox.parsers.gowitness_parser import (
    EVIDENCE_SIDECAR_NAME as GOWITNESS_SIDECAR,
)
from src.sandbox.parsers.hashcat_parser import (
    EVIDENCE_SIDECAR_NAME as HASHCAT_SIDECAR,
)
from src.sandbox.parsers.hydra_parser import (
    EVIDENCE_SIDECAR_NAME as HYDRA_SIDECAR,
)
from src.sandbox.parsers.jadx_parser import (
    EVIDENCE_SIDECAR_NAME as JADX_SIDECAR,
)
from src.sandbox.parsers.medusa_parser import (
    EVIDENCE_SIDECAR_NAME as MEDUSA_SIDECAR,
)
from src.sandbox.parsers.mongodb_probe_parser import (
    EVIDENCE_SIDECAR_NAME as MONGODB_PROBE_SIDECAR,
)
from src.sandbox.parsers.ncrack_parser import (
    EVIDENCE_SIDECAR_NAME as NCRACK_SIDECAR,
)
from src.sandbox.parsers.ntlmrelayx_parser import (
    EVIDENCE_SIDECAR_NAME as NTLMRELAYX_SIDECAR,
)
from src.sandbox.parsers.patator_parser import (
    EVIDENCE_SIDECAR_NAME as PATATOR_SIDECAR,
)
from src.sandbox.parsers.playwright_runner_parser import (
    EVIDENCE_SIDECAR_NAME as PLAYWRIGHT_RUNNER_SIDECAR,
)
from src.sandbox.parsers.puppeteer_screens_parser import (
    EVIDENCE_SIDECAR_NAME as PUPPETEER_SCREENS_SIDECAR,
)
from src.sandbox.parsers.radare2_info_parser import (
    EVIDENCE_SIDECAR_NAME as RADARE2_INFO_SIDECAR,
)
from src.sandbox.parsers.redis_cli_probe_parser import (
    EVIDENCE_SIDECAR_NAME as REDIS_CLI_PROBE_SIDECAR,
)
from src.sandbox.parsers.responder_parser import (
    EVIDENCE_SIDECAR_NAME as RESPONDER_SIDECAR,
)
from src.sandbox.parsers.subfinder_parser import (
    EVIDENCE_SIDECAR_NAME as SUBFINDER_SIDECAR,
)
from src.sandbox.parsers.unicornscan_parser import (
    EVIDENCE_SIDECAR_NAME as UNICORNSCAN_SIDECAR,
)
from src.sandbox.parsers.webanalyze_parser import (
    EVIDENCE_SIDECAR_NAME as WEBANALYZE_SIDECAR,
)
from src.sandbox.parsers.whatweb_parser import (
    EVIDENCE_SIDECAR_NAME as WHATWEB_SIDECAR,
)


# ---------------------------------------------------------------------------
# Hermetic registry fixture
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _restore_registry() -> Iterator[None]:
    yield
    reset_registry()


# ---------------------------------------------------------------------------
# Pinned tool_id sets
# ---------------------------------------------------------------------------


# Every ARG-032 tool that MUST have a parser registered post-Cycle 4 batch 4.
ARG032_TOOL_IDS: Final[tuple[str, ...]] = (
    # 4a — browser
    "playwright_runner",
    "puppeteer_screens",
    "chrome_csp_probe",
    "webanalyze",
    "gowitness",
    "whatweb",
    # 4b — binary
    "radare2_info",
    "apktool",
    "binwalk",
    "jadx",
    # 4b — subdomain recon
    "amass_passive",
    "subfinder",
    "assetfinder",
    "dnsrecon",
    "fierce",
    "findomain",
    # 4c — credential bruteforce / NTLM relay
    "hydra",
    "medusa",
    "patator",
    "ncrack",
    "crackmapexec",
    "responder",
    "hashcat",
    "ntlmrelayx",
    # 4c — network / OSINT / probes
    "dnsx",
    "chaos",
    "censys",
    "mongodb_probe",
    "redis_cli_probe",
    "unicornscan",
)


# Each ARG-032 tool's canonical sidecar filename.
ARG032_TOOL_SIDECARS: Final[dict[str, str]] = {
    "playwright_runner": PLAYWRIGHT_RUNNER_SIDECAR,
    "puppeteer_screens": PUPPETEER_SCREENS_SIDECAR,
    "chrome_csp_probe": CHROME_CSP_PROBE_SIDECAR,
    "webanalyze": WEBANALYZE_SIDECAR,
    "gowitness": GOWITNESS_SIDECAR,
    "whatweb": WHATWEB_SIDECAR,
    "radare2_info": RADARE2_INFO_SIDECAR,
    "apktool": APKTOOL_SIDECAR,
    "binwalk": BINWALK_SIDECAR,
    "jadx": JADX_SIDECAR,
    "amass_passive": AMASS_PASSIVE_SIDECAR,
    "subfinder": SUBFINDER_SIDECAR,
    "assetfinder": ASSETFINDER_SIDECAR,
    "dnsrecon": DNSRECON_SIDECAR,
    "fierce": FIERCE_SIDECAR,
    "findomain": FINDOMAIN_SIDECAR,
    "hydra": HYDRA_SIDECAR,
    "medusa": MEDUSA_SIDECAR,
    "patator": PATATOR_SIDECAR,
    "ncrack": NCRACK_SIDECAR,
    "crackmapexec": CRACKMAPEXEC_SIDECAR,
    "responder": RESPONDER_SIDECAR,
    "hashcat": HASHCAT_SIDECAR,
    "ntlmrelayx": NTLMRELAYX_SIDECAR,
    "dnsx": DNSX_SIDECAR,
    "chaos": CHAOS_SIDECAR,
    "censys": CENSYS_SIDECAR,
    "mongodb_probe": MONGODB_PROBE_SIDECAR,
    "redis_cli_probe": REDIS_CLI_PROBE_SIDECAR,
    "unicornscan": UNICORNSCAN_SIDECAR,
}


# YAML-declared parse strategy per tool (matches backend/config/tools/*.yaml).
ARG032_TOOL_STRATEGIES: Final[dict[str, ParseStrategy]] = {
    # 4a browser
    "playwright_runner": ParseStrategy.JSON_OBJECT,
    "puppeteer_screens": ParseStrategy.JSON_OBJECT,
    "chrome_csp_probe": ParseStrategy.JSON_OBJECT,
    "webanalyze": ParseStrategy.JSON_OBJECT,
    "gowitness": ParseStrategy.JSON_OBJECT,
    "whatweb": ParseStrategy.JSON_OBJECT,
    # 4b binary
    "radare2_info": ParseStrategy.JSON_OBJECT,
    "apktool": ParseStrategy.TEXT_LINES,
    "binwalk": ParseStrategy.TEXT_LINES,
    "jadx": ParseStrategy.TEXT_LINES,
    # 4b subdomain recon
    "amass_passive": ParseStrategy.JSON_LINES,
    "subfinder": ParseStrategy.JSON_OBJECT,
    "assetfinder": ParseStrategy.TEXT_LINES,
    "dnsrecon": ParseStrategy.JSON_OBJECT,
    "fierce": ParseStrategy.JSON_OBJECT,
    "findomain": ParseStrategy.TEXT_LINES,
    # 4c auth
    "hydra": ParseStrategy.TEXT_LINES,
    "medusa": ParseStrategy.TEXT_LINES,
    "patator": ParseStrategy.TEXT_LINES,
    "ncrack": ParseStrategy.TEXT_LINES,
    "crackmapexec": ParseStrategy.TEXT_LINES,
    "responder": ParseStrategy.TEXT_LINES,
    "hashcat": ParseStrategy.TEXT_LINES,
    "ntlmrelayx": ParseStrategy.TEXT_LINES,
    # 4c network/probes
    "dnsx": ParseStrategy.JSON_LINES,
    "chaos": ParseStrategy.TEXT_LINES,
    "censys": ParseStrategy.JSON_OBJECT,
    "mongodb_probe": ParseStrategy.TEXT_LINES,
    "redis_cli_probe": ParseStrategy.TEXT_LINES,
    "unicornscan": ParseStrategy.TEXT_LINES,
}


# ---------------------------------------------------------------------------
# Per-tool minimal-but-realistic payloads (inline so the suite is hermetic)
# ---------------------------------------------------------------------------


# ARG-032 batch-4 fixtures live inline rather than under
# ``tests/fixtures/sandbox_outputs`` because the security-gate assertions
# below need to inject very specific bait blobs (HAR cookie strings, ASLR
# memory addresses, NTLM hash bytes, cleartext passwords).  Keeping the
# bait inline, next to the assertions that consume it, makes the
# regression visible in one place when a future parser change re-leaks
# the secret.
_HAR_COOKIE_BAIT: Final[str] = "session=ABC-COOKIE-BAIT-1234567890"
_HAR_AUTH_BAIT: Final[str] = "Bearer EYJ-BEARER-BAIT-9876543210ABCDEF"
_MEMORY_ADDR_BAIT: Final[str] = "0xdeadbeef12345678"
_NTLM_HASH_BAIT: Final[str] = (
    "bob::CORP:1122334455667788:"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:"
    "0101000000000000A1B2C3D4E5F60708FFFFFFFFFFFFFFFF"
)
_PASSWORD_BAIT: Final[str] = "hunter2-PASSWORD-BAIT"

# A HAR envelope that drops the C12 bait headers + a credentials-in-URL
# embed.  Reused across the four browser-fixture builders.
_HAR_ENVELOPE: Final[dict[str, object]] = {
    "log": {
        "version": "1.2",
        "creator": {"name": "argus-test", "version": "1.0"},
        "entries": [
            {
                "startedDateTime": "2026-04-19T12:00:00Z",
                "request": {
                    "method": "GET",
                    "url": f"https://leak:{_PASSWORD_BAIT}@example.com/api/users",
                    "headers": [
                        {"name": "Cookie", "value": _HAR_COOKIE_BAIT},
                        {"name": "Authorization", "value": _HAR_AUTH_BAIT},
                        {"name": "User-Agent", "value": "argus-test/1.0"},
                    ],
                    "postData": {
                        "mimeType": "application/json",
                        "text": '{"k":"' + _PASSWORD_BAIT + '"}',
                    },
                },
                "response": {
                    "status": 200,
                    "headers": [
                        {"name": "Set-Cookie", "value": _HAR_COOKIE_BAIT},
                        {"name": "Content-Type", "value": "application/json"},
                    ],
                },
            },
            {
                "startedDateTime": "2026-04-19T12:00:01Z",
                "request": {
                    "method": "POST",
                    "url": "https://example.com/api/login",
                    "headers": [],
                },
                "response": {"status": 500, "headers": []},
            },
        ],
    }
}


def _write_browser_har(artifacts_dir: Path, tool_id: str) -> None:
    """Materialise a HAR sidecar at the canonical location for ``tool_id``."""
    canonical = {
        "playwright_runner": "playwright",
        "puppeteer_screens": "puppeteer",
    }.get(tool_id)
    if canonical is None:
        return
    target_dir = artifacts_dir / canonical
    target_dir.mkdir(parents=True, exist_ok=True)
    (target_dir / "index.har").write_bytes(
        json.dumps(_HAR_ENVELOPE, sort_keys=True).encode("utf-8")
    )


def _make_payload(tool_id: str) -> bytes:
    """Return a representative stdout payload for ``tool_id``.

    The payloads are intentionally minimal but realistic enough to
    trigger ≥1 finding through the parser's happy path.  Each browser
    payload also carries the C12 bait blobs (cookies, bearer tokens,
    URL-embedded credentials) so the redaction guardrails downstream
    have something to reject.
    """
    if tool_id == "playwright_runner":
        return json.dumps(
            {
                "errors": [
                    {"message": "ReferenceError: leak is not defined"},
                    {"message": "TypeError: Cannot read property 'foo'"},
                ]
            }
        ).encode("utf-8")
    if tool_id == "puppeteer_screens":
        return json.dumps(
            [
                {
                    "url": f"https://leak:{_PASSWORD_BAIT}@example.com/",
                    "screenshot": "home.png",
                },
                {"url": "https://example.com/about", "screenshot": "about.png"},
            ]
        ).encode("utf-8")
    if tool_id == "chrome_csp_probe":
        return json.dumps(
            {
                "url": "https://example.com/",
                "csp": {"Content-Security-Policy": "default-src 'self'; script-src *"},
                "violations": [
                    {
                        "directive": "script-src",
                        "value": "'unsafe-inline'",
                        "where": "header",
                    },
                    {
                        "directive": "default-src",
                        "value": "*",
                        "where": "header",
                    },
                ],
                "missing": ["Content-Security-Policy"],
                "report_only": False,
            }
        ).encode("utf-8")
    if tool_id == "webanalyze":
        return json.dumps(
            [
                {
                    "hostname": "example.com",
                    "matches": [
                        {
                            "app_name": "Apache",
                            "version": "2.4.41",
                            "confidence": 100,
                            "categories": ["Web servers"],
                        },
                        {
                            "app_name": "PHP",
                            "version": "7.4.3",
                            "confidence": 80,
                            "categories": ["Programming languages"],
                        },
                    ],
                }
            ]
        ).encode("utf-8")
    if tool_id == "gowitness":
        return json.dumps(
            [
                {
                    "url": f"https://leak:{_PASSWORD_BAIT}@example.com",
                    "title": "Example Domain",
                    "status": 200,
                    "filename": "https-example-com.png",
                }
            ]
        ).encode("utf-8")
    if tool_id == "whatweb":
        return json.dumps(
            [
                {
                    "target": "http://example.com",
                    "http_status": 200,
                    "plugins": {
                        "Apache": {"version": ["2.4.41"]},
                        "PHP": {"string": ["7.4.3"]},
                    },
                }
            ]
        ).encode("utf-8")
    if tool_id == "radare2_info":
        return json.dumps(
            {
                "imports": [
                    {"name": "system", "vaddr": _MEMORY_ADDR_BAIT},
                    {"name": "strcpy", "vaddr": "0xdeadbeefcafebabe"},
                ],
                "sections": [
                    {
                        "name": ".text",
                        "vaddr": _MEMORY_ADDR_BAIT,
                        "size": 4096,
                        "perm": "rwx",
                        "entropy": 7.5,
                    }
                ],
            }
        ).encode("utf-8")
    if tool_id == "apktool":
        return (
            b"I: Using Apktool 2.7.0\n"
            b"I: Loading resource table...\n"
            b'W: AndroidManifest.xml: android:debuggable="true"\n'
            b'W: AndroidManifest.xml: android:allowBackup="true"\n'
            b"W: AndroidManifest.xml: cleartextTrafficPermitted=true\n"
        )
    if tool_id == "binwalk":
        return (
            b"DECIMAL       HEXADECIMAL     DESCRIPTION\n"
            b"--------------------------------------------------------\n"
            b"0             " + _MEMORY_ADDR_BAIT.encode("ascii") + b"             "
            b"ELF, 64-bit LSB executable, x86-64\n"
            b'16384         0x4000          Linux kernel version "5.15.0"\n'
            b"65536         0x10000         RSA private key, 2048 bits\n"
        )
    if tool_id == "jadx":
        return (
            b"INFO  - loading ...\n"
            b"INFO  - processing AndroidManifest.xml\n"
            b"WARN  - failed to decompile method "
            + _MEMORY_ADDR_BAIT.encode("ascii")
            + b" in com.example.A\n"
            b"ERROR - cannot resolve type Lcom/example/B; at "
            + _MEMORY_ADDR_BAIT.encode("ascii")
            + b"\n"
        )
    if tool_id == "amass_passive":
        return (
            b'{"name":"api.example.com","domain":"example.com","sources":["crtsh"]}\n'
            b'{"name":"cdn.example.com","domain":"example.com","sources":["chaos"]}\n'
        )
    if tool_id == "subfinder":
        return (
            b'{"host":"api.example.com","input":"example.com","source":"crtsh"}\n'
            b'{"host":"cdn.example.com","input":"example.com","source":"chaos"}\n'
        )
    if tool_id == "assetfinder":
        return b"api.example.com\ncdn.example.com\nwww.example.com\n"
    if tool_id == "dnsrecon":
        return json.dumps(
            [
                {"name": "api.example.com", "type": "A", "address": "10.0.0.1"},
                {"name": "cdn.example.com", "type": "A", "address": "10.0.0.2"},
            ]
        ).encode("utf-8")
    if tool_id == "fierce":
        return json.dumps(
            {
                "domain": "example.com",
                "found_dns": [
                    {"name": "api.example.com", "ip": "10.0.0.1"},
                    {"name": "cdn.example.com", "ip": "10.0.0.2"},
                ],
            }
        ).encode("utf-8")
    if tool_id == "findomain":
        return b"api.example.com\ncdn.example.com\nwww.example.com\n"
    if tool_id == "hydra":
        return (
            b"[22][ssh] host: 10.0.0.1   login: root   password: "
            + _PASSWORD_BAIT.encode("ascii")
            + b"\n"
            b"[443][https] host: web.example.com   login: admin   password: secret123\n"
        )
    if tool_id == "medusa":
        return (
            b"ACCOUNT FOUND: [ssh] Host: 10.0.0.1 User: root Password: "
            + _PASSWORD_BAIT.encode("ascii")
            + b" [SUCCESS]\n"
        )
    if tool_id == "patator":
        return (
            b"INFO - 0 14:36:05 ssh_login - Trying...\n"
            b"INFO - 0 14:36:08 ssh_login - 0 1.234 | "
            b"host=10.0.0.1:22:user=root:pass="
            + _PASSWORD_BAIT.encode("ascii")
            + b" [Found]\n"
        )
    if tool_id == "ncrack":
        return (
            b"Discovered credentials on ssh://10.0.0.1:22\n"
            b"10.0.0.1 22/tcp ssh: 'root' '" + _PASSWORD_BAIT.encode("ascii") + b"'\n"
        )
    if tool_id == "crackmapexec":
        return (
            b"SMB         10.0.0.1  445  DC01      [+] CORP\\admin:"
            + _PASSWORD_BAIT.encode("ascii")
            + b" (Pwn3d!)\n"
            b"SMB         10.0.0.1  445  DC01      [+] CORP\\svc_sql:"
            b"aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n"
        )
    if tool_id == "responder":
        return (
            b"[SMB] NTLMv2-SSP Client   : 10.0.0.10\n"
            b"[SMB] NTLMv2-SSP Username : CORP\\bob\n"
            b"[SMB] NTLMv2-SSP Hash     : " + _NTLM_HASH_BAIT.encode("ascii") + b"\n"
            b"[HTTP] NTLMv1 Client      : 10.0.0.20\n"
            b"[HTTP] NTLMv1 Username    : CORP\\alice\n"
            b"[HTTP] NTLMv1 Hash        : "
            b"alice::CORP:0011223344556677:"
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:"
            b"00112233445566778899AABBCCDDEEFF\n"
        )
    if tool_id == "hashcat":
        return (
            b"5f4dcc3b5aa765d61d8327deb882cf99:"
            + _PASSWORD_BAIT.encode("ascii")
            + b"\n"
            b"$2a$12$abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQR:bcryptpwd\n"
        )
    if tool_id == "ntlmrelayx":
        return (
            b"[*] Servers started, waiting for connections\n"
            b"[*] HTTPD: Received connection from 10.0.0.10\n"
            b"[*] Authenticating against smb://10.0.0.20 as CORP/bob SUCCEED\n"
            b"[*] Target system bootKey: 0x" + b"a" * 32 + b"\n"
            b"[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)\n"
            b"Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
            b"31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        )
    if tool_id == "dnsx":
        return (
            b'{"host":"api.example.com","a":["10.0.0.1"],"cname":["api-prod.example.com"]}\n'
            b'{"host":"cdn.example.com","a":["10.0.0.2"]}\n'
        )
    if tool_id == "chaos":
        return b"api.example.com\ncdn.example.com\nwww.example.com\n"
    if tool_id == "censys":
        return json.dumps(
            [
                {
                    "ip": "10.0.0.1",
                    "services": [
                        {
                            "port": 443,
                            "service_name": "HTTPS",
                            "transport_protocol": "TCP",
                        }
                    ],
                }
            ]
        ).encode("utf-8")
    if tool_id == "mongodb_probe":
        return json.dumps(
            {
                "host": "10.0.0.10:27017",
                "version": "4.4.6",
                "auth_required": False,
                "databases": [{"name": "admin"}, {"name": "users"}],
            }
        ).encode("utf-8")
    if tool_id == "redis_cli_probe":
        return b"requirepass:false\nredis_version:6.2.6\nrole:master\n"
    if tool_id == "unicornscan":
        return (
            b"TCP open                  http[   80]    from 10.0.0.1   ttl 64\n"
            b"TCP open                  https[  443]   from 10.0.0.1   ttl 64\n"
        )
    raise AssertionError(f"missing payload for {tool_id!r} — extend _make_payload")


def _read_sidecar(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


# ---------------------------------------------------------------------------
# Per-tool registration surface
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG032_TOOL_IDS)
def test_arg032_tool_is_registered(tool_id: str) -> None:
    """Every ARG-032 tool must be wired into the per-tool dispatch table."""
    registered = get_registered_tool_parsers()
    assert tool_id in registered, (
        f"{tool_id} missing from per-tool parser registry — broken wiring "
        f"in src.sandbox.parsers.__init__._DEFAULT_TOOL_PARSERS"
    )


def test_arg032_does_not_drop_prior_cycle_registrations() -> None:
    """Sanity: every prior-cycle tool slot survives the ARG-032 batch."""
    registered = get_registered_tool_parsers()
    # Sample of legacy parsers from ARG-021/-022/-029.
    legacy_tools = (
        # ARG-021
        "checkov",
        "dockle",
        "grype",
        "trivy_image",
        "bandit",
        "gitleaks",
        "semgrep",
        # ARG-022
        "impacket_secretsdump",
        "evil_winrm",
        "kerbrute",
        "snmpwalk",
        "ldapsearch",
        "smbclient",
        "smbmap",
        "enum4linux_ng",
        # ARG-029
        "trufflehog",
        "naabu",
        "masscan",
        "prowler",
        "detect_secrets",
        "openapi_scanner",
        "graphql_cop",
        "postman_newman",
        "zap_baseline",
        "syft",
        "cloudsploit",
        "hashid",
        "hash_analyzer",
        "jarm",
        "wappalyzer_cli",
    )
    for legacy in legacy_tools:
        assert legacy in registered, f"{legacy} slot must survive ARG-032 registration"


def test_registered_count_matches_catalog_ratchet() -> None:
    """Pinned count must match ``MAPPED_PARSER_COUNT`` in test_tool_catalog_coverage."""
    assert len(get_registered_tool_parsers()) == 118


# ---------------------------------------------------------------------------
# Routing — happy path for every ARG-032 tool
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG032_TOOL_IDS)
def test_dispatch_routes_each_arg032_tool(tool_id: str, tmp_path: Path) -> None:
    """Every ARG-032 tool routes via its strategy and yields >=1 finding."""
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    _write_browser_har(artifacts_dir, tool_id)
    findings = dispatch_parse(
        ARG032_TOOL_STRATEGIES[tool_id],
        _make_payload(tool_id),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id}: dispatch produced no findings"
    assert all(isinstance(f, FindingDTO) for f in findings)


@pytest.mark.parametrize("tool_id", ARG032_TOOL_IDS)
def test_dispatch_writes_per_tool_sidecar(tool_id: str, tmp_path: Path) -> None:
    """Each ARG-032 dispatch writes its dedicated sidecar tagged with tool_id."""
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    _write_browser_har(artifacts_dir, tool_id)
    findings = dispatch_parse(
        ARG032_TOOL_STRATEGIES[tool_id],
        _make_payload(tool_id),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings
    sidecar = artifacts_dir / ARG032_TOOL_SIDECARS[tool_id]
    assert sidecar.is_file(), (
        f"{tool_id}: parser must write evidence sidecar at {sidecar}"
    )
    parsed = _read_sidecar(sidecar)
    assert parsed, f"{tool_id}: sidecar is empty"
    assert all(rec["tool_id"] == tool_id for rec in parsed), (
        f"{tool_id}: every sidecar record must tag its source tool_id"
    )


def test_arg032_tools_use_distinct_sidecar_filenames() -> None:
    """All 30 ARG-032 sidecar filenames must be unique across the batch."""
    sidecars = list(ARG032_TOOL_SIDECARS.values())
    assert len(set(sidecars)) == len(sidecars), (
        "ARG-032 parsers collide on sidecar filenames; one tool would "
        "overwrite another in shared /out"
    )


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tool_id", ARG032_TOOL_IDS)
def test_arg032_dispatch_is_deterministic(tool_id: str, tmp_path: Path) -> None:
    """Two dispatches on the same payload produce byte-identical sidecars."""
    payload = _make_payload(tool_id)
    artifacts_a = tmp_path / "a" / tool_id
    artifacts_b = tmp_path / "b" / tool_id
    artifacts_a.mkdir(parents=True)
    artifacts_b.mkdir(parents=True)
    _write_browser_har(artifacts_a, tool_id)
    _write_browser_har(artifacts_b, tool_id)
    dispatch_parse(
        ARG032_TOOL_STRATEGIES[tool_id],
        payload,
        b"",
        artifacts_a,
        tool_id=tool_id,
    )
    dispatch_parse(
        ARG032_TOOL_STRATEGIES[tool_id],
        payload,
        b"",
        artifacts_b,
        tool_id=tool_id,
    )
    sidecar_name = ARG032_TOOL_SIDECARS[tool_id]
    a_bytes = (artifacts_a / sidecar_name).read_bytes()
    b_bytes = (artifacts_b / sidecar_name).read_bytes()
    assert a_bytes == b_bytes, (
        f"{tool_id}: sidecar bytes drift between runs — non-deterministic parser"
    )


# ---------------------------------------------------------------------------
# CRITICAL — Browser parsers strip cookie / authorization / URL-creds
# ---------------------------------------------------------------------------


_BROWSER_HAR_TOOLS: Final[tuple[str, ...]] = (
    "playwright_runner",
    "puppeteer_screens",
)


@pytest.mark.parametrize("tool_id", _BROWSER_HAR_TOOLS)
def test_browser_har_strips_cookie_and_auth_headers(
    tool_id: str, tmp_path: Path
) -> None:
    """Browser parsers MUST scrub Cookie / Set-Cookie / Authorization in HAR.

    The C12 bait blob (``session=ABC-COOKIE-BAIT-...``) and the bearer
    token (``EYJ-BEARER-BAIT-...``) MUST NOT survive into the FindingDTO
    or the per-tool sidecar.  This test pins the Cycle-4 ARG-032
    security gate that the browser batch cannot leak HTTP credentials
    through the HAR walker.
    """
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    _write_browser_har(artifacts_dir, tool_id)
    findings = dispatch_parse(
        ARG032_TOOL_STRATEGIES[tool_id],
        _make_payload(tool_id),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id}: dispatch must yield >=1 finding"
    sidecar = artifacts_dir / ARG032_TOOL_SIDECARS[tool_id]
    text = sidecar.read_text(encoding="utf-8")
    assert _HAR_COOKIE_BAIT not in text, (
        f"{tool_id}: HAR Cookie bait LEAKED into sidecar — browser redaction broken"
    )
    assert _HAR_AUTH_BAIT not in text, (
        f"{tool_id}: HAR Authorization bait LEAKED into sidecar — "
        "browser redaction broken"
    )
    assert _PASSWORD_BAIT not in text, (
        f"{tool_id}: URL-embedded password LEAKED into sidecar — "
        "browser redaction broken"
    )


@pytest.mark.parametrize("tool_id", ("puppeteer_screens", "gowitness", "whatweb"))
def test_browser_url_credentials_redacted(tool_id: str, tmp_path: Path) -> None:
    """URL-embedded credentials (``user:pw@host``) are masked before sidecar."""
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    _write_browser_har(artifacts_dir, tool_id)
    findings = dispatch_parse(
        ARG032_TOOL_STRATEGIES[tool_id],
        _make_payload(tool_id),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id}: dispatch must yield >=1 finding"
    sidecar = artifacts_dir / ARG032_TOOL_SIDECARS[tool_id]
    text = sidecar.read_text(encoding="utf-8")
    assert _PASSWORD_BAIT not in text, (
        f"{tool_id}: URL-embedded password LEAKED — redact_password_in_text gate broken"
    )


# ---------------------------------------------------------------------------
# CRITICAL — Binary parsers redact memory addresses (ASLR offsets)
# ---------------------------------------------------------------------------


_MEM_ADDR_RE: Final[re.Pattern[str]] = re.compile(r"0x[0-9a-fA-F]{8,}")


@pytest.mark.parametrize("tool_id", ("radare2_info", "binwalk", "jadx"))
def test_binary_parsers_redact_memory_addresses(tool_id: str, tmp_path: Path) -> None:
    """Binary parsers MUST redact ``0x[0-9a-fA-F]{8,}`` from sidecar evidence.

    ASLR offsets leak the host's load address layout — they must be
    masked via :func:`scrub_evidence_strings` before any sidecar
    bytes are persisted.
    """
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    findings = dispatch_parse(
        ARG032_TOOL_STRATEGIES[tool_id],
        _make_payload(tool_id),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id}: dispatch must yield >=1 finding"
    sidecar = artifacts_dir / ARG032_TOOL_SIDECARS[tool_id]
    text = sidecar.read_text(encoding="utf-8")
    leaked = _MEM_ADDR_RE.findall(text)
    assert leaked == [], f"{tool_id}: ASLR offset(s) LEAKED into sidecar: {leaked[:3]}"


# ---------------------------------------------------------------------------
# CRITICAL — Credential bruteforce parsers redact cleartext passwords
# ---------------------------------------------------------------------------


_PASSWORD_PARSERS: Final[tuple[str, ...]] = (
    "hydra",
    "medusa",
    "patator",
    "ncrack",
    "crackmapexec",
)


@pytest.mark.parametrize("tool_id", _PASSWORD_PARSERS)
def test_credential_parsers_redact_cleartext_password(
    tool_id: str, tmp_path: Path
) -> None:
    """Hydra/Medusa/Patator/Ncrack/Crackmapexec MUST mask cleartext passwords.

    The bait password (``hunter2-PASSWORD-BAIT``) must be replaced by
    ``[REDACTED-PASSWORD]`` before any FindingDTO is built.  Only the
    canonical marker plus a length hint (``password_length``) is allowed
    in the sidecar.
    """
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    findings = dispatch_parse(
        ARG032_TOOL_STRATEGIES[tool_id],
        _make_payload(tool_id),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id}: dispatch must yield >=1 finding"
    sidecar = artifacts_dir / ARG032_TOOL_SIDECARS[tool_id]
    text = sidecar.read_text(encoding="utf-8")
    assert _PASSWORD_BAIT not in text, (
        f"{tool_id}: cleartext password LEAKED — credential redaction gate broken"
    )


# ---------------------------------------------------------------------------
# CRITICAL — NTLM hash redaction (responder, hashcat, ntlmrelayx, crackmapexec)
# ---------------------------------------------------------------------------


# Stable, recognisable substring of the NTLMv2 hash bait. We pin a
# distinctive run that does NOT collide with the synthetic
# fingerprint the parser computes.
_NTLM_HASH_FINGERPRINT_BAIT: Final[str] = "0101000000000000A1B2C3D4E5F60708"


@pytest.mark.parametrize(
    "tool_id",
    ("responder", "hashcat", "ntlmrelayx", "crackmapexec"),
)
def test_ntlm_hash_redaction(tool_id: str, tmp_path: Path) -> None:
    """NTLM hash bytes MUST NOT survive into responder/hashcat/ntlmrelayx sidecars.

    All four parsers see legitimate hash material (responder captures
    NTLMv1/v2 hashes from on-the-wire poisoning; hashcat persists cracked
    rows; ntlmrelayx dumps SAM bootkeys; crackmapexec PtH output carries
    NTLM hashes).  The C12 bait NTLMv2 fingerprint
    ``0101000000000000A1B2C3D4E5F60708`` MUST be masked before sidecar
    persistence.
    """
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    findings = dispatch_parse(
        ARG032_TOOL_STRATEGIES[tool_id],
        _make_payload(tool_id),
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id}: dispatch must yield >=1 finding"
    sidecar = artifacts_dir / ARG032_TOOL_SIDECARS[tool_id]
    text = sidecar.read_text(encoding="utf-8")
    assert _NTLM_HASH_FINGERPRINT_BAIT not in text, (
        f"{tool_id}: NTLM hash bytes LEAKED into sidecar — "
        "redact_hash_string gate broken"
    )


# ---------------------------------------------------------------------------
# Subdomain recon parsers — strict hostname validation
# ---------------------------------------------------------------------------


_SUBDOMAIN_TOOLS: Final[tuple[str, ...]] = (
    "amass_passive",
    "subfinder",
    "assetfinder",
    "dnsrecon",
    "fierce",
    "findomain",
    "chaos",
)


@pytest.mark.parametrize("tool_id", _SUBDOMAIN_TOOLS)
def test_subdomain_parsers_drop_noise_lines(tool_id: str, tmp_path: Path) -> None:
    """Subdomain parsers MUST reject noise lines that fail RFC-1035 validation.

    Feed a mixture of valid hostnames and free-text noise. Only the
    valid hostnames may surface as findings.
    """
    if tool_id == "amass_passive":
        noisy_payload = (
            b"[+] processing noise line\n"
            b'{"name":"valid.example.com","domain":"example.com"}\n'
            b'{"name":"NOT VALID","domain":"example.com"}\n'
        )
    elif tool_id == "subfinder":
        noisy_payload = (
            b"[+] processing noise line\n"
            b'{"host":"valid.example.com","input":"example.com","source":"crtsh"}\n'
            b'{"host":"NOT VALID","input":"example.com","source":"crtsh"}\n'
        )
    elif tool_id == "dnsrecon":
        noisy_payload = json.dumps(
            [
                {"name": "valid.example.com", "type": "A", "address": "10.0.0.1"},
                {"name": "NOT VALID", "type": "A", "address": "10.0.0.2"},
            ]
        ).encode("utf-8")
    elif tool_id == "fierce":
        noisy_payload = json.dumps(
            {
                "domain": "example.com",
                "found_dns": [
                    {"name": "valid.example.com", "ip": "10.0.0.1"},
                    {"name": "NOT VALID", "ip": "10.0.0.2"},
                ],
            }
        ).encode("utf-8")
    else:
        # Plain-text tools: assetfinder / findomain / chaos.
        noisy_payload = b"[+] processing noise\nvalid.example.com\nNOT VALID\n"
    artifacts_dir = tmp_path / tool_id
    artifacts_dir.mkdir()
    findings = dispatch_parse(
        ARG032_TOOL_STRATEGIES[tool_id],
        noisy_payload,
        b"",
        artifacts_dir,
        tool_id=tool_id,
    )
    assert findings, f"{tool_id}: dispatch must yield >=1 finding"
    sidecar = artifacts_dir / ARG032_TOOL_SIDECARS[tool_id]
    text = sidecar.read_text(encoding="utf-8")
    assert "valid.example.com" in text
    assert "NOT VALID" not in text, (
        f"{tool_id}: noise line LEAKED through hostname validator"
    )


# ---------------------------------------------------------------------------
# Heartbeat fallback survives — unmapped tools still observable
# ---------------------------------------------------------------------------


def test_heartbeat_fallback_for_unmapped_tool_id(tmp_path: Path) -> None:
    """Unmapped tool_id over a known strategy still emits one heartbeat finding."""
    findings = dispatch_parse(
        ParseStrategy.JSON_OBJECT,
        b'{"foo": "bar"}',
        b"",
        tmp_path,
        tool_id="unknown_tool_arg032_xyz",
    )
    assert len(findings) == 1
    assert findings[0].cvss_v3_score == 0.0


# ---------------------------------------------------------------------------
# Multi-tool same /out directory — sidecar isolation
# ---------------------------------------------------------------------------


def test_all_arg032_parsers_in_single_artifacts_dir_keeps_sidecars_intact(
    tmp_path: Path,
) -> None:
    """Running all 30 ARG-032 parsers in the same dir leaves sidecars intact."""
    for tool_id in ARG032_TOOL_IDS:
        _write_browser_har(tmp_path, tool_id)
        dispatch_parse(
            ARG032_TOOL_STRATEGIES[tool_id],
            _make_payload(tool_id),
            b"",
            tmp_path,
            tool_id=tool_id,
        )

    for tool_id, sidecar_name in ARG032_TOOL_SIDECARS.items():
        sidecar = tmp_path / sidecar_name
        assert sidecar.is_file(), (
            f"{tool_id}: sidecar {sidecar_name} missing after multi-tool run"
        )
        records = _read_sidecar(sidecar)
        assert records, f"{tool_id}: sidecar {sidecar_name} is empty"
        assert all(r["tool_id"] == tool_id for r in records), (
            f"{tool_id}: cross-tool contamination in {sidecar_name}"
        )
