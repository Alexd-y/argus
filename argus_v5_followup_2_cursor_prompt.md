# ARGUS v5-followup-2 — Cursor Agent Prompt
# Дата: 2026-04-04
# Контекст: v5 + v5-followup завершены, все HTTP 501 убраны, security adapters и data sources реализованы
# Цель: закрыть 9 intel-адаптеров, ExploitDB client, последние текстовые хвосты

---

## КОНТЕКСТ ПРОЕКТА

ARGUS — AI-powered penetration testing SaaS.
Backend: `backend/` (FastAPI + Celery + PostgreSQL + Redis).
MCP: `mcp-server/` (FastMCP).

**Что СДЕЛАНО (v5 + v5-followup, всё в main):**
- ✅ Все HTTP 501 убраны из API
- ✅ ScanKnowledgeBase, ToolRecoverySystem, Cache API (10 endpoints)
- ✅ Auth: реальный login по DB, API key через ARGUS_API_KEYS, admin secure-by-default
- ✅ PoC runner: `_run_poc_safe` вместо `_run_poc_stub`
- ✅ Data sources: censys, securitytrails, virustotal, hibp — полные клиенты
- ✅ Security adapters: trufflehog, checkov, terrascan, prowler, scoutsuite — parse/normalize
- ✅ VA HTTP audit: переименование stub→audit
- ✅ Новые endpoints: timeline, false-positive, remediation, statistics
- ✅ MCP: 40 @mcp.tool() + 150 kali, `.cursor/rules/argus-mcp.md`
- ✅ Тесты: 144 в срезе, зелёные

**Что ОСТАЛОСЬ (этот промт):**

### Главное: 9 intel-адаптеров — заглушки с `"Stub — not implemented"`
Все в `backend/src/recon/adapters/intel/`:
```
censys_adapter.py       → "Stub — not implemented"
securitytrails_adapter.py → "Stub — not implemented"
virustotal_adapter.py   → "Stub — not implemented"
otx_adapter.py          → "Stub — not implemented"
greynoise_adapter.py    → "Stub — not implemented"
abuseipdb_adapter.py    → "Stub — not implemented"
urlscan_adapter.py      → "Stub — not implemented"
exploitdb_adapter.py    → "Stub — not implemented"
github_adapter.py       → "Stub — not implemented"
```
Рабочие примеры: `shodan_adapter.py`, `crtsh_adapter.py`, `rdap_adapter.py`, `nvd_adapter.py`.

### Второстепенное:
- `backend/src/data_sources/exploitdb_client.py` — stub, `query() → {}`
- `backend/src/agents/va_orchestrator.py:168` — `Phase 3: Collect` (текст в комментарии)

---

## АРХИТЕКТУРА INTEL-АДАПТЕРОВ

Каждый адаптер:
1. Наследует `IntelAdapter` из `backend/src/recon/adapters/intel/base.py`
2. Реализует `name`, `env_key`, `async fetch(domain: str) -> dict`
3. Возвращает `{"source": str, "findings": list[dict], "skipped": bool, "error": str|None, "raw": dict|None}`
4. Findings создаются через `_finding(finding_type, value, data, source_tool, confidence)`
5. FindingType из `backend/src/recon/schemas/base.py`: `SUBDOMAIN`, `DNS_RECORD`, `IP_ADDRESS`, `SERVICE`, `URL`, `PARAMETER`, `TECHNOLOGY`, `TLS_INFO`, `JS_FINDING`, `SECRET_CANDIDATE`, `VULNERABILITY`, `OSINT_ENTRY`

**Принцип:** адаптер вызывает соответствующий `data_sources/*` клиент (если есть) ИЛИ делает HTTP-запрос напрямую. При отсутствии ключа — `skipped: True`. При ошибке — `error: str`, пустые findings.

---

## БЛОК 1 — Intel-адаптеры: 3 с существующими data_source клиентами

Эти адаптеры имеют ГОТОВЫЕ клиенты в `backend/src/data_sources/` — нужно только связать.

### 1.1. `censys_adapter.py` — использовать `CensysClient`

```python
"""Censys intel adapter — host/certificate intelligence via CENSYS_API_KEY."""

from typing import Any

from src.data_sources.censys_client import CensysClient
from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType


class CensysIntelAdapter(IntelAdapter):
    """Censys API adapter for host and certificate discovery."""

    @property
    def name(self) -> str:
        return "censys"

    @property
    def env_key(self) -> str | None:
        return "CENSYS_API_KEY"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {"source": self.name, "findings": [], "skipped": True, "error": None, "raw": None}

        client = CensysClient()
        findings: list[dict[str, Any]] = []

        # Search hosts by domain
        try:
            data = await client.query(type="search", target=domain, limit=25)
        except Exception:
            return {"source": self.name, "findings": [], "skipped": False, "error": "Censys query failed", "raw": None}

        if data.get("error"):
            return {"source": self.name, "findings": [], "skipped": False, "error": data["error"], "raw": None}

        hits = []
        raw_data = data.get("data") or {}
        if isinstance(raw_data, dict):
            result = raw_data.get("result") or {}
            hits = result.get("hits") or []

        for hit in hits[:20]:
            ip = hit.get("ip") or ""
            if not ip:
                continue
            services = hit.get("services") or []
            for svc in services[:10]:
                port = svc.get("port")
                service_name = svc.get("service_name") or svc.get("extended_service_name") or ""
                if port:
                    findings.append(_finding(
                        FindingType.SERVICE,
                        f"{ip}:{port}",
                        {"ip": ip, "port": port, "service": service_name, "source": self.name},
                        self.name, 0.85,
                    ))
            # Add IP as finding
            findings.append(_finding(
                FindingType.IP_ADDRESS, ip,
                {"ip": ip, "source": self.name, "domain": domain},
                self.name, 0.8,
            ))

        # Certificate transparency search
        try:
            cert_data = await client.query(type="certificates", target=domain, limit=25)
            cert_raw = cert_data.get("data") or {}
            cert_hits = (cert_raw.get("result") or {}).get("hits") or [] if isinstance(cert_raw, dict) else []
            seen_names: set[str] = set()
            for cert in cert_hits[:20]:
                names = cert.get("names") or []
                for n in names:
                    sub = n.strip().lstrip("*.").lower().rstrip(".")
                    if sub and "." in sub and sub not in seen_names and domain in sub:
                        seen_names.add(sub)
                        findings.append(_finding(
                            FindingType.SUBDOMAIN, sub,
                            {"source": self.name, "parent_domain": domain, "from_cert": True},
                            self.name, 0.85,
                        ))
        except Exception:
            pass  # Certificate search is supplementary

        return {"source": self.name, "findings": findings, "skipped": False, "error": None,
                "raw": {"hits_count": len(hits)}}
```

### 1.2. `securitytrails_adapter.py` — использовать `SecurityTrailsClient`

```python
"""SecurityTrails intel adapter — domain/subdomain intelligence via SECURITYTRAILS_API_KEY."""

from typing import Any

from src.data_sources.securitytrails_client import SecurityTrailsClient
from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType


class SecurityTrailsIntelAdapter(IntelAdapter):
    """SecurityTrails adapter for subdomain and DNS history intelligence."""

    @property
    def name(self) -> str:
        return "securitytrails"

    @property
    def env_key(self) -> str | None:
        return "SECURITYTRAILS_API_KEY"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {"source": self.name, "findings": [], "skipped": True, "error": None, "raw": None}

        client = SecurityTrailsClient()
        findings: list[dict[str, Any]] = []

        # Subdomain enumeration
        try:
            sub_data = await client.query(domain=domain, type="subdomains")
        except Exception:
            return {"source": self.name, "findings": [], "skipped": False,
                    "error": "SecurityTrails query failed", "raw": None}

        if sub_data.get("error"):
            return {"source": self.name, "findings": [], "skipped": False,
                    "error": sub_data["error"], "raw": None}

        raw = sub_data.get("data") or {}
        subdomains = raw.get("subdomains") or []
        for prefix in subdomains[:200]:
            sub = f"{prefix}.{domain}".lower()
            findings.append(_finding(
                FindingType.SUBDOMAIN, sub,
                {"source": self.name, "parent_domain": domain},
                self.name, 0.9,
            ))

        # Domain info for tech/DNS
        try:
            domain_data = await client.query(domain=domain, type="domain")
            d_raw = domain_data.get("data") or {}
            current_dns = d_raw.get("current_dns") or {}
            for record_type, records in current_dns.items():
                if not isinstance(records, dict):
                    continue
                for val in (records.get("values") or [])[:10]:
                    v = val.get("ip") or val.get("value") or ""
                    if v:
                        findings.append(_finding(
                            FindingType.DNS_RECORD,
                            f"{domain} {record_type.upper()} {v}",
                            {"hostname": domain, "record_type": record_type.upper(), "value": v, "source": self.name},
                            self.name, 0.9,
                        ))
        except Exception:
            pass  # Domain info supplementary

        return {"source": self.name, "findings": findings, "skipped": False, "error": None,
                "raw": {"subdomains_count": len(subdomains)}}
```

### 1.3. `virustotal_adapter.py` — использовать `VirusTotalClient`

```python
"""VirusTotal intel adapter — domain/IP reputation via VIRUSTOTAL_API_KEY."""

from typing import Any

from src.data_sources.virustotal_client import VirusTotalClient
from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType


class VirusTotalIntelAdapter(IntelAdapter):
    """VirusTotal adapter for domain reputation and subdomain discovery."""

    @property
    def name(self) -> str:
        return "virustotal"

    @property
    def env_key(self) -> str | None:
        return "VIRUSTOTAL_API_KEY"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {"source": self.name, "findings": [], "skipped": True, "error": None, "raw": None}

        client = VirusTotalClient()
        findings: list[dict[str, Any]] = []

        try:
            data = await client.query(domain=domain, type="domain")
        except Exception:
            return {"source": self.name, "findings": [], "skipped": False,
                    "error": "VirusTotal query failed", "raw": None}

        if data.get("error"):
            return {"source": self.name, "findings": [], "skipped": False,
                    "error": data["error"], "raw": None}

        vt_data = (data.get("data") or {}).get("data") or {}
        attrs = vt_data.get("attributes") or {}

        # Subdomains from last_dns_records
        for record in (attrs.get("last_dns_records") or [])[:30]:
            rtype = record.get("type", "")
            value = record.get("value", "")
            if value:
                findings.append(_finding(
                    FindingType.DNS_RECORD,
                    f"{domain} {rtype} {value}",
                    {"hostname": domain, "record_type": rtype, "value": value, "source": self.name},
                    self.name, 0.85,
                ))

        # Reputation / detection stats
        analysis = attrs.get("last_analysis_stats") or {}
        malicious = analysis.get("malicious", 0)
        suspicious = analysis.get("suspicious", 0)
        if malicious > 0 or suspicious > 0:
            findings.append(_finding(
                FindingType.OSINT_ENTRY,
                f"vt_reputation:{domain}",
                {"domain": domain, "malicious": malicious, "suspicious": suspicious,
                 "harmless": analysis.get("harmless", 0), "source": self.name},
                self.name, 0.9,
            ))

        # Categories
        categories = attrs.get("categories") or {}
        if categories:
            findings.append(_finding(
                FindingType.OSINT_ENTRY,
                f"vt_categories:{domain}",
                {"domain": domain, "categories": categories, "source": self.name},
                self.name, 0.7,
            ))

        return {"source": self.name, "findings": findings, "skipped": False, "error": None,
                "raw": {"analysis_stats": analysis}}
```

---

## БЛОК 2 — Intel-адаптеры: 6 с прямыми HTTP-вызовами

Эти адаптеры НЕ имеют готовых клиентов в data_sources — делают HTTP-запросы напрямую через httpx.

### 2.1. `otx_adapter.py` — AlienVault OTX

```python
"""OTX (AlienVault Open Threat Exchange) intel adapter — requires OTX_API_KEY."""

import os
from typing import Any

import httpx

from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType

OTX_BASE = "https://otx.alienvault.com/api/v1"


class OtxIntelAdapter(IntelAdapter):
    """OTX adapter for threat intelligence on domains."""

    @property
    def name(self) -> str:
        return "otx"

    @property
    def env_key(self) -> str | None:
        return "OTX_API_KEY"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {"source": self.name, "findings": [], "skipped": True, "error": None, "raw": None}

        key = (os.environ.get("OTX_API_KEY") or "").strip()
        headers = {"X-OTX-API-KEY": key, "Accept": "application/json"}
        findings: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                # General info
                resp = await client.get(f"{OTX_BASE}/indicators/domain/{domain}/general", headers=headers)
                if resp.status_code != 200:
                    return {"source": self.name, "findings": [], "skipped": False,
                            "error": f"HTTP {resp.status_code}", "raw": None}
                data = resp.json()

                # Pulse count = threat indicator
                pulse_info = data.get("pulse_info") or {}
                pulse_count = pulse_info.get("count", 0)
                if pulse_count > 0:
                    findings.append(_finding(
                        FindingType.OSINT_ENTRY, f"otx_pulses:{domain}",
                        {"domain": domain, "pulse_count": pulse_count, "source": self.name},
                        self.name, 0.8,
                    ))

                # Passive DNS for subdomains
                pdns_resp = await client.get(
                    f"{OTX_BASE}/indicators/domain/{domain}/passive_dns", headers=headers)
                if pdns_resp.status_code == 200:
                    pdns = pdns_resp.json()
                    seen: set[str] = set()
                    for entry in (pdns.get("passive_dns") or [])[:100]:
                        hostname = (entry.get("hostname") or "").lower().rstrip(".")
                        if hostname and "." in hostname and hostname not in seen and domain in hostname:
                            seen.add(hostname)
                            findings.append(_finding(
                                FindingType.SUBDOMAIN, hostname,
                                {"source": self.name, "parent_domain": domain,
                                 "address": entry.get("address", "")},
                                self.name, 0.75,
                            ))

                return {"source": self.name, "findings": findings, "skipped": False,
                        "error": None, "raw": {"pulse_count": pulse_count}}
        except Exception as e:
            return {"source": self.name, "findings": [], "skipped": False,
                    "error": f"OTX query failed: {type(e).__name__}", "raw": None}
```

### 2.2. `greynoise_adapter.py`

```python
"""GreyNoise intel adapter — IP noise/RIOT classification via GREYNOISE_API_KEY."""

import os
import socket
from typing import Any

import httpx

from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType

GN_BASE = "https://api.greynoise.io/v3/community"


class GreyNoiseIntelAdapter(IntelAdapter):
    """GreyNoise adapter — classifies IPs as noise/RIOT/malicious."""

    @property
    def name(self) -> str:
        return "greynoise"

    @property
    def env_key(self) -> str | None:
        return "GREYNOISE_API_KEY"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {"source": self.name, "findings": [], "skipped": True, "error": None, "raw": None}

        # Resolve domain to IP
        try:
            ip = socket.gethostbyname(domain)
        except (socket.gaierror, OSError):
            return {"source": self.name, "findings": [], "skipped": False,
                    "error": f"Cannot resolve {domain}", "raw": None}

        key = (os.environ.get("GREYNOISE_API_KEY") or "").strip()
        headers = {"key": key, "Accept": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(f"{GN_BASE}/{ip}", headers=headers)
                if resp.status_code != 200:
                    return {"source": self.name, "findings": [], "skipped": False,
                            "error": f"HTTP {resp.status_code}", "raw": None}
                data = resp.json()

            noise = data.get("noise", False)
            riot = data.get("riot", False)
            classification = data.get("classification", "unknown")
            findings: list[dict[str, Any]] = []

            findings.append(_finding(
                FindingType.OSINT_ENTRY, f"greynoise:{ip}",
                {"ip": ip, "domain": domain, "noise": noise, "riot": riot,
                 "classification": classification, "name": data.get("name", ""),
                 "source": self.name},
                self.name, 0.85,
            ))

            return {"source": self.name, "findings": findings, "skipped": False,
                    "error": None, "raw": data}
        except Exception as e:
            return {"source": self.name, "findings": [], "skipped": False,
                    "error": f"GreyNoise failed: {type(e).__name__}", "raw": None}
```

### 2.3. `abuseipdb_adapter.py`

```python
"""AbuseIPDB intel adapter — IP abuse reports via ABUSEIPDB_API_KEY."""

import os
import socket
from typing import Any

import httpx

from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType

ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2/check"


class AbuseIpDbIntelAdapter(IntelAdapter):
    """AbuseIPDB adapter for IP reputation scoring."""

    @property
    def name(self) -> str:
        return "abuseipdb"

    @property
    def env_key(self) -> str | None:
        return "ABUSEIPDB_API_KEY"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {"source": self.name, "findings": [], "skipped": True, "error": None, "raw": None}

        try:
            ip = socket.gethostbyname(domain)
        except (socket.gaierror, OSError):
            return {"source": self.name, "findings": [], "skipped": False,
                    "error": f"Cannot resolve {domain}", "raw": None}

        key = (os.environ.get("ABUSEIPDB_API_KEY") or "").strip()
        headers = {"Key": key, "Accept": "application/json"}

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(ABUSEIPDB_BASE, params={"ipAddress": ip, "maxAgeInDays": "90"},
                                        headers=headers)
                if resp.status_code != 200:
                    return {"source": self.name, "findings": [], "skipped": False,
                            "error": f"HTTP {resp.status_code}", "raw": None}
                body = resp.json()
                data = body.get("data") or {}

            abuse_score = data.get("abuseConfidenceScore", 0)
            total_reports = data.get("totalReports", 0)
            findings: list[dict[str, Any]] = []

            findings.append(_finding(
                FindingType.OSINT_ENTRY, f"abuseipdb:{ip}",
                {"ip": ip, "domain": domain, "abuse_score": abuse_score,
                 "total_reports": total_reports, "isp": data.get("isp", ""),
                 "country": data.get("countryCode", ""), "source": self.name},
                self.name, 0.85,
            ))

            return {"source": self.name, "findings": findings, "skipped": False,
                    "error": None, "raw": {"abuse_score": abuse_score, "total_reports": total_reports}}
        except Exception as e:
            return {"source": self.name, "findings": [], "skipped": False,
                    "error": f"AbuseIPDB failed: {type(e).__name__}", "raw": None}
```

### 2.4. `urlscan_adapter.py`

```python
"""urlscan.io intel adapter — URLSCAN_API_KEY optional (higher rate limit)."""

import os
from typing import Any

import httpx

from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType

URLSCAN_BASE = "https://urlscan.io/api/v1"


class UrlScanIntelAdapter(IntelAdapter):
    """urlscan.io adapter for website analysis and technology detection."""

    @property
    def name(self) -> str:
        return "urlscan"

    @property
    def env_key(self) -> str | None:
        return "URLSCAN_API_KEY"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {"source": self.name, "findings": [], "skipped": True, "error": None, "raw": None}

        key = (os.environ.get("URLSCAN_API_KEY") or "").strip()
        headers = {"API-Key": key, "Accept": "application/json"} if key else {"Accept": "application/json"}
        findings: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(f"{URLSCAN_BASE}/search/",
                                        params={"q": f"domain:{domain}", "size": 10}, headers=headers)
                if resp.status_code != 200:
                    return {"source": self.name, "findings": [], "skipped": False,
                            "error": f"HTTP {resp.status_code}", "raw": None}
                data = resp.json()

            results = data.get("results") or []
            seen_urls: set[str] = set()
            for r in results[:10]:
                page = r.get("page") or {}
                url = page.get("url") or ""
                server = page.get("server") or ""
                ip = page.get("ip") or ""

                if url and url not in seen_urls:
                    seen_urls.add(url)
                    findings.append(_finding(
                        FindingType.URL, url,
                        {"domain": domain, "server": server, "ip": ip, "source": self.name},
                        self.name, 0.75,
                    ))
                if ip:
                    findings.append(_finding(
                        FindingType.IP_ADDRESS, ip,
                        {"domain": domain, "source": self.name},
                        self.name, 0.7,
                    ))

            return {"source": self.name, "findings": findings, "skipped": False,
                    "error": None, "raw": {"results_count": len(results)}}
        except Exception as e:
            return {"source": self.name, "findings": [], "skipped": False,
                    "error": f"urlscan failed: {type(e).__name__}", "raw": None}
```

### 2.5. `github_adapter.py` — использовать `GitHubClient`

```python
"""GitHub intel adapter — security advisories via GITHUB_TOKEN."""

from typing import Any

from src.data_sources.github_client import GitHubClient
from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType


class GitHubIntelAdapter(IntelAdapter):
    """GitHub adapter for security advisory search."""

    @property
    def name(self) -> str:
        return "github"

    @property
    def env_key(self) -> str | None:
        return "GITHUB_TOKEN"

    async def fetch(self, domain: str) -> dict[str, Any]:
        if not self.is_available():
            return {"source": self.name, "findings": [], "skipped": True, "error": None, "raw": None}

        client = GitHubClient()
        keyword = domain.split(".")[0] if "." in domain else domain
        findings: list[dict[str, Any]] = []

        try:
            data = await client.query(
                endpoint="advisories",
                params={"keyword": keyword, "per_page": 10, "type": "reviewed"},
            )
            advisories = data if isinstance(data, list) else []

            for adv in advisories[:10]:
                ghsa_id = adv.get("ghsa_id", "")
                cve_id = adv.get("cve_id") or ""
                summary = (adv.get("summary") or "")[:300]
                severity = (adv.get("severity") or "medium").lower()

                if ghsa_id:
                    findings.append(_finding(
                        FindingType.VULNERABILITY,
                        cve_id or ghsa_id,
                        {"ghsa_id": ghsa_id, "cve_id": cve_id, "summary": summary,
                         "severity": severity, "keyword": keyword, "source": self.name},
                        self.name, 0.7,
                    ))

            return {"source": self.name, "findings": findings, "skipped": False,
                    "error": None, "raw": {"advisories_count": len(advisories)}}
        except Exception as e:
            return {"source": self.name, "findings": [], "skipped": False,
                    "error": f"GitHub query failed: {type(e).__name__}", "raw": None}
```

### 2.6. `exploitdb_adapter.py` — поиск через ExploitDB

```python
"""Exploit-DB intel adapter — public exploit search."""

from typing import Any

import httpx

from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.schemas.base import FindingType

EXPLOITDB_SEARCH = "https://exploitdb.com/search"


class ExploitDbIntelAdapter(IntelAdapter):
    """Exploit-DB adapter for public exploit search by keyword."""

    @property
    def name(self) -> str:
        return "exploitdb"

    @property
    def env_key(self) -> str | None:
        return None  # Public, no key required

    async def fetch(self, domain: str) -> dict[str, Any]:
        keyword = domain.split(".")[0] if "." in domain else domain
        findings: list[dict[str, Any]] = []

        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                resp = await client.get(
                    "https://www.exploit-db.com/search",
                    params={"q": keyword},
                    headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
                )
                if resp.status_code != 200:
                    return {"source": self.name, "findings": [], "skipped": False,
                            "error": f"HTTP {resp.status_code}", "raw": None}

                data = resp.json()
                records = data.get("data") or data.get("recordsTotal") or []
                if isinstance(records, list):
                    for rec in records[:10]:
                        edb_id = rec.get("id") or ""
                        title = rec.get("description") or rec.get("title") or ""
                        if edb_id and title:
                            findings.append(_finding(
                                FindingType.VULNERABILITY,
                                f"EDB-{edb_id}",
                                {"edb_id": edb_id, "title": title[:300],
                                 "platform": rec.get("platform", {}).get("platform", ""),
                                 "type": rec.get("type", {}).get("name", ""),
                                 "keyword": keyword, "source": self.name},
                                self.name, 0.6,
                            ))

            return {"source": self.name, "findings": findings, "skipped": False,
                    "error": None, "raw": {"keyword": keyword}}
        except Exception as e:
            return {"source": self.name, "findings": [], "skipped": False,
                    "error": f"ExploitDB failed: {type(e).__name__}", "raw": None}
```

---

## БЛОК 3 — ExploitDB data_sources client

**Файл: `backend/src/data_sources/exploitdb_client.py`** — заменить полностью:

```python
"""Exploit-DB client — public search, no API key required."""

from typing import Any

import httpx


class ExploitDBClient:
    """Exploit-DB public API client for exploit search."""

    _base_url = "https://www.exploit-db.com"

    async def query(self, **kwargs: Any) -> dict[str, Any]:
        """Search Exploit-DB by keyword or CVE."""
        keyword = kwargs.get("keyword") or kwargs.get("q") or ""
        if not keyword:
            return {"results": [], "error": "No keyword provided"}

        try:
            async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
                resp = await client.get(
                    f"{self._base_url}/search",
                    params={"q": keyword},
                    headers={"Accept": "application/json", "X-Requested-With": "XMLHttpRequest"},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    records = data.get("data") or []
                    return {"results": records if isinstance(records, list) else [], "total": data.get("recordsTotal", 0)}
                return {"results": [], "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"results": [], "error": str(e)}
```

---

## БЛОК 4 — Последние текстовые хвосты

### 4.1. `backend/src/agents/va_orchestrator.py` строка ~168:
```python
# было: Phase 3: Collect and merge findings
# стало: Step 3: Collect and merge findings
```
(Или оставить — «Phase» здесь это бизнес-термин, не «stub Phase 3+». Решение: оставить как есть, это не заглушка.)

---

## БЛОК 5 — Тесты для intel-адаптеров

### `backend/tests/test_intel_adapters.py`

Для каждого из 9 адаптеров:

```python
"""Tests for recon intel adapters — verify fetch returns correct structure."""

import pytest
from unittest.mock import AsyncMock, patch

# Паттерн для каждого адаптера:

class TestOtxIntelAdapter:
    def test_skipped_when_no_key(self):
        """Without OTX_API_KEY, adapter returns skipped=True."""
        from src.recon.adapters.intel.otx_adapter import OtxIntelAdapter
        adapter = OtxIntelAdapter()
        # env без ключа
        with patch.dict("os.environ", {}, clear=True):
            import asyncio
            result = asyncio.run(adapter.fetch("example.com"))
            assert result["skipped"] is True
            assert result["error"] is None
            assert result["findings"] == []

    @pytest.mark.asyncio
    async def test_fetch_returns_findings(self):
        """With mock HTTP, adapter returns structured findings."""
        # Mock httpx response with OTX data
        ...

# Повторить для: Censys, SecurityTrails, VirusTotal, GreyNoise, AbuseIPDB, UrlScan, GitHub, ExploitDB

class TestAllIntelAdaptersContract:
    """Verify all adapters implement the contract."""

    def test_no_stub_not_implemented(self):
        """No adapter returns 'Stub — not implemented'."""
        from src.recon.adapters.intel import get_available_intel_adapters
        import asyncio
        # Test with empty env (all should skip gracefully)
        with patch.dict("os.environ", {}, clear=False):
            for AdapterClass in [OtxIntelAdapter, GreyNoiseIntelAdapter, AbuseIpDbIntelAdapter,
                                  UrlScanIntelAdapter, CensysIntelAdapter, SecurityTrailsIntelAdapter,
                                  VirusTotalIntelAdapter, GitHubIntelAdapter, ExploitDbIntelAdapter]:
                adapter = AdapterClass()
                result = asyncio.run(adapter.fetch("example.com"))
                assert "Stub" not in str(result.get("error", "")), f"{adapter.name} still has stub"
                assert result["source"] == adapter.name
```

---

## ПОРЯДОК ВЫПОЛНЕНИЯ

1. **Блок 1** — 3 intel-адаптера с готовыми клиентами (censys, securitytrails, virustotal)
2. **Блок 2** — 6 intel-адаптеров с httpx (otx, greynoise, abuseipdb, urlscan, github, exploitdb)
3. **Блок 3** — ExploitDB data_sources client
4. **Блок 4** — текстовые хвосты (минимально)
5. **Блок 5** — тесты

После каждого блока:
```powershell
cd backend
python -m ruff check src/recon/adapters/intel/ src/data_sources/
python -m pytest tests/test_intel_adapters.py -v
```

---

## ЗАПРЕЩЕНО

1. `"Stub — not implemented"` в ответе любого адаптера
2. `fetch() → {"error": "Stub..."}` — заменить на реальный HTTP-вызов
3. `parse_output() → []` / `normalize() → []` без попытки
4. Пустой `query() → {}` в data_sources клиентах
5. `"stub"` / `"Stub"` в docstring (кроме `tier_stubs` в шаблонах отчётов)
