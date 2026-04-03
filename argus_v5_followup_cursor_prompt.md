# ARGUS v5-followup — Cursor Agent Prompt
# Дата: 2026-04-03
# Контекст: v5 оркестрация (T01–T10) запушена в main, бэклог задокументирован
# Цель: закрыть оставшиеся минимальные реализации, устаревшие docstring'ы, адаптеры, auth, PoC runner

---

## КОНТЕКСТ

Проект ARGUS — AI-powered penetration testing SaaS.
Код: `backend/` (FastAPI + Celery + PostgreSQL + Redis), `mcp-server/` (FastMCP), `infra/` (Docker Compose).

**Что РЕАЛЬНО СДЕЛАНО в v5 (уже в main):**
- ✅ `ScanKnowledgeBase` (`src/cache/scan_knowledge_base.py`) + warm_cache в lifespan
- ✅ `ToolRecoverySystem` (`src/cache/tool_recovery.py`) + `execute_command_with_recovery` в executor
- ✅ legacy recovery helper в tool_cache полностью удалён — нигде не используется
- ✅ Cache API router (`src/api/routers/cache.py`) — 10 admin-эндпоинтов
- ✅ Knowledge router (`src/api/routers/knowledge.py`)
- ✅ Sandbox: processes/kill/python — реальные ответы, 0 строк с HTTP_501
- ✅ Scans: memory-summary и report path — без 501
- ✅ Findings: PoC → 200 с can_generate/hint; validate → 503 (не 501); poc/generate → 503
- ✅ Миграция 017 (FindingNote, false_positive, duration_sec, ToolRun)
- ✅ DB models: FindingNote, ToolRun, false_positive/false_positive_reason на Finding
- ✅ MCP: `_build_scan_request`, 36 @mcp.tool() + 150 kali, ArgusClient расширен
- ✅ argus-mcp.json обновлён (ARGUS_ADMIN_KEY, description, alwaysAllow)
- ✅ Тесты: test_scan_knowledge_base, test_tool_recovery, test_cache_router

**Что ОСТАЛОСЬ (grep по коду подтверждает):**

### Устаревшие тексты (14 мест) — исторический список до чистки
```
mcp-server/main.py:1          → устаревший docstring entrypoint
mcp-server/argus_mcp.py:1201  → устаревший текст про 501 (get_scan_memory_summary)
mcp-server/argus_mcp.py:1206  → устаревший текст про 501 (get_process_list)
mcp-server/argus_mcp.py:1211  → устаревший текст про 501 (kill_process)
backend/src/api/routers/tools.py:1   → устаревшая шапка модуля
backend/src/api/routers/tools.py:254 → устаревший комментарий маршрутов
backend/src/api/routers/auth.py:30   → устаревший комментарий валидации пользователя
backend/src/api/schemas.py:202       → устаревшее описание recovery
backend/src/tools/executor.py:35     → устаревший комментарий use_cache
backend/src/core/auth.py:57          → устаревший комментарий API key
backend/src/core/tenant.py:3         → устаревший комментарий tenant
backend/main.py:4                    → устаревший комментарий auth scope
```

### Минимальные / нерабочие участки (исторический список)
```
backend/src/api/routers/auth.py:31         → dev fallback user id
backend/src/orchestration/exploit_verify.py:68-74  → legacy no-op PoC (ARGUS-008)
backend/src/data_sources/censys_client.py    → устаревший docstring, parse_output пуст
backend/src/data_sources/securitytrails_client.py → минимальный клиент
backend/src/data_sources/virustotal_client.py    → минимальный клиент
backend/src/data_sources/hibp_client.py          → минимальный клиент
backend/src/recon/adapters/security/prowler_adapter.py    → parse_output() → [], normalize() → []
backend/src/recon/adapters/security/checkov_adapter.py    → parse_output() → [], normalize() → []
backend/src/recon/adapters/security/terrascan_adapter.py  → parse_output() → [], normalize() → []
backend/src/recon/adapters/security/scoutsuite_adapter.py → parse_output() → [], normalize() → []
backend/src/recon/adapters/security/trufflehog_adapter.py → parse_output() → [], normalize() → []
```

### Не создано в v5 (несмотря на отчёт)
```
.cursor/rules/argus-mcp.md — НЕ СОЗДАН (есть только api-contract.mdc)
```

### Отсутствующие endpoint'ы из бэклога
```
GET  /api/v1/scans/{id}/timeline
POST /api/v1/findings/{id}/false-positive
GET  /api/v1/findings/{id}/remediation
GET  /api/v1/scans/{id}/findings/statistics
```

### Безопасность
```
admin require_admin() → при пустом ADMIN_API_KEY пропускает всех (cache API открыт)
```

---

## ПОРЯДОК РАБОТЫ

Работай последовательно блок за блоком. После каждого блока:
```powershell
cd backend
python -m ruff check .
python -m pytest tests/ -x --tb=short -q
```

---

## БЛОК 1 — Устаревшие docstring'ы и комментарии (14 мест)

Замени точечно, ничего больше не трогая:

**1.1. `mcp-server/main.py` строка 1:**
```python
# было: устаревший one-liner docstring у MCP entrypoint
# стало: """ARGUS MCP Server — entrypoint for stdio and HTTP transport."""
```

**1.2. `mcp-server/argus_mcp.py` строки 1201, 1206, 1211:**
```python
# строка 1201 было: устаревший docstring про 501
# стало: """Compressed scan context: findings summary, technologies, phases, costs."""

# строка 1206 было: устаревший docstring про 501
# стало: """List running processes in the sandbox container."""

# строка 1211 было: устаревший docstring про 501
# стало: """Terminate a process in the sandbox container by PID."""
```

**1.3. `backend/src/api/routers/tools.py`:**
```python
# строка 1 — заменить весь docstring модуля:
# было: устаревший module docstring tools router
# стало: """Tools router — POST /tools/* for security scanner execution."""

# строка 254 — заменить комментарий:
# было: # Tool endpoints (устаревший комментарий про маршрутизацию)
# стало: # Tool endpoints — dedicated per-tool routes
```

**1.4. `backend/src/api/schemas.py` строка 202:**
```python
# было: устаревшее description поля recovery
# стало: description="Tool recovery metadata: original tool, alternatives tried, final result"
```

**1.5. `backend/src/tools/executor.py` строка 35:**
```python
# было: use_cache: устаревший комментарий про кеш
# стало: use_cache: Reserved for ToolResultCache integration
```

**1.6. `backend/src/core/auth.py` строка 57:**
```python
# было: # API key validation — устаревший комментарий про env/DB
# стало: # API key validation — checks ARGUS_API_KEYS env or admin key
```

**1.7. `backend/src/core/tenant.py` строка 3:**
```python
# было: устаревший комментарий DEFAULT_TENANT_ID / X-Tenant-ID
# стало: Uses DEFAULT_TENANT_ID from env. Optional X-Tenant-ID header for MCP/API clients.
```

**1.8. `backend/main.py` строка 4:**
```python
# было: устаревший комментарий про публичность scans/reports
# стало: Auth middleware ready; tenant-scoped API.
```

**1.9. `backend/src/api/routers/auth.py` строка 30:**
```python
# было: # устаревший комментарий про валидацию пользователя
# стало: # DEV fallback: accepts any credentials when DB is empty and DEBUG=true.
```

---

## БЛОК 2 — Auth: реальная валидация

### 2.1. `backend/src/api/routers/auth.py` — заменить login() полностью:

```python
import logging
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

from src.core.auth import create_access_token, get_required_auth
from src.core.config import settings
from src.db.models import User
from src.db.session import async_session_factory

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    mail: str
    password: str


@router.post("/login")
async def login(req: LoginRequest) -> dict:
    """Login — validates credentials against users table, returns JWT."""
    if not settings.jwt_secret:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="JWT_SECRET missing")

    async with async_session_factory() as session:
        result = await session.execute(
            select(User).where(User.email == req.mail, User.is_active == True)  # noqa: E712
        )
        user = result.scalar_one_or_none()

    if user:
        try:
            from passlib.context import CryptContext
            if CryptContext(schemes=["bcrypt"], deprecated="auto").verify(req.password, user.password_hash):
                token = create_access_token(user_id=user.id, tenant_id=user.tenant_id)
                return {"status": "success", "access_token": token, "token_type": "bearer",
                        "user_id": user.id, "tenant_id": user.tenant_id}
        except Exception:
            logger.exception("Password verification error")

    # DEV fallback: accepts any credentials when DB is empty and DEBUG=true.
    if settings.debug:
        logger.warning("DEV MODE: accepting login for %s without DB validation", req.mail)
        token = create_access_token(user_id="dev-user", tenant_id=settings.default_tenant_id)
        return {"status": "success", "access_token": token, "token_type": "bearer", "dev_mode": True}

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


@router.get("/me")
async def me(auth=Depends(get_required_auth)) -> dict:
    return {"user_id": auth.user_id, "tenant_id": auth.tenant_id, "is_api_key": auth.is_api_key}
```

Добавить `passlib[bcrypt]` в `backend/requirements.txt` если нет.

### 2.2. `backend/src/core/auth.py` — реальная API key валидация:

Заменить блок в `get_optional_auth()` где обрабатывается `api_key`:
```python
    if api_key:
        import os
        # API key validation — checks ARGUS_API_KEYS env or admin key
        allowed = [k.strip() for k in (os.environ.get("ARGUS_API_KEYS") or "").split(",") if k.strip()]
        if api_key in allowed:
            return AuthContext(user_id="api-key", tenant_id=settings.default_tenant_id, is_api_key=True)
        if settings.admin_api_key and api_key == settings.admin_api_key:
            return AuthContext(user_id="admin", tenant_id=settings.default_tenant_id, is_api_key=True)
```

### 2.3. Admin — secure by default:

В `backend/src/api/routers/admin.py`, заменить `require_admin()`:
```python
async def require_admin(request: Request, admin_key: str | None = Depends(admin_key_header)) -> None:
    """Require admin auth. Secure by default: deny when ADMIN_API_KEY not set (except DEBUG)."""
    expected = settings.admin_api_key
    if not expected:
        if settings.debug:
            return
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="ADMIN_API_KEY not configured")
    if not admin_key or admin_key != expected:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid X-Admin-Key")
```

---

## БЛОК 3 — PoC Runner: заменить legacy no-op на `_run_poc_safe`

**Файл: `backend/src/orchestration/exploit_verify.py`** — полная замена.

Удалить legacy no-op runner и зафиксировать работу **ARGUS-008**. Реализовать `_run_poc_safe()` с httpx HTTP-пробами.
Signature `verify_exploit_poc(candidate)` остаётся той же. Внутри вместо прежнего no-op вызова:

```python
async def _run_poc_safe(candidate: dict[str, Any]) -> dict[str, Any]:
    """Safe PoC — HTTP probe only, no shell, no eval."""
    import httpx
    from urllib.parse import urlparse

    target = str(candidate.get("target") or "").strip()
    if not target:
        return {"success": False, "evidence": "No target URL"}
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return {"success": False, "evidence": "Invalid URL"}
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True, verify=False) as c:
            resp = await c.get(target)
            return {"success": True, "evidence": f"HTTP {resp.status_code}, {len(resp.content)} bytes",
                    "status_code": resp.status_code}
    except httpx.TimeoutException:
        return {"success": False, "evidence": "Timeout"}
    except httpx.RequestError as e:
        return {"success": False, "evidence": str(e)[:200]}
```

В `verify_exploit_poc()` вызывать `asyncio.run(_run_poc_safe(sanitized))` вместо прежнего no-op.

---

## БЛОК 4 — Data Source клиенты: полная реализация

Для каждого из 4 файлов: обновить docstring, реализовать полный `query()` с реальными HTTP-вызовами.

### 4.1. `backend/src/data_sources/censys_client.py` — полная замена
Docstring: `"""Censys API v2 — host search, view, certificates."""`
Добавить `_auth()` для basic auth (CENSYS_API_KEY + CENSYS_API_SECRET).
`query()`: типы `hosts`, `search`, `certificates`. При 200 → `{"source": "censys", "data": resp.json()}`.

### 4.2. `backend/src/data_sources/securitytrails_client.py` — полная замена
Docstring: `"""SecurityTrails API v1 — domain info, subdomains, DNS history."""`
Header: `APIKEY`. Типы: `domain`, `subdomains`, `dns_history`, `whois`.

### 4.3. `backend/src/data_sources/virustotal_client.py` — полная замена
Docstring: `"""VirusTotal API v3 — domain, URL, IP analysis."""`
Header: `x-apikey`. Типы: `domain`, `ip`, `url` (base64 ID).

### 4.4. `backend/src/data_sources/hibp_client.py` — полная замена
Docstring: `"""Have I Been Pwned API v3 — breach data, paste data."""`
Header: `hibp-api-key` + User-Agent. Типы: `breachedaccount`, `breaches`, `pasteaccount`. 404 → not breached.

**Для всех:** возвращать `{"available": False, "source": "..."}` когда ключ отсутствует. Обрабатывать 429 rate limit.

---

## БЛОК 5 — Security адаптеры: parse_output и normalize

5 адаптеров в `backend/src/recon/adapters/security/`: `trufflehog`, `checkov`, `terrascan`, `prowler`, `scoutsuite`.
У всех `parse_output() → []` и `normalize() → []`. Реализовать JSON-парсинг.

### 5.1. `trufflehog_adapter.py` — JSONL (одна строка = один JSON)
`parse_output`: split по строкам, `json.loads()` каждую.
`normalize`: DetectorName → title, Verified → severity (high/medium), CWE-798.

### 5.2. `checkov_adapter.py` — JSON `results.failed_checks`
`parse_output`: `data["results"]["failed_checks"]`
`normalize`: check_id + name → title, severity map, CWE-1032.

### 5.3. `terrascan_adapter.py` — JSON `results.violations`
`parse_output`: `data["results"]["violations"]`
`normalize`: rule_name → title, severity map, CWE-1032.

### 5.4. `prowler_adapter.py` — JSONL, фильтр Status=FAIL
`parse_output`: split по строкам, json.loads.
`normalize`: только FAIL. CheckTitle → title, Severity → severity.

### 5.5. `scoutsuite_adapter.py` — JS prefix `scoutsuite_results = {...}`
`parse_output`: strip JS prefix, json.loads, flatten `services[*].findings`.
`normalize`: только flagged_items > 0. description → title.

**Для всех 5:** привести docstring в соответствие реализации.

---

## БЛОК 6 — Переименование va_http_audit (placeholder → audit)

Это audit trail для MinIO, не полный HTTP-реплей. Переименовать для ясности:

В `backend/src/recon/vulnerability_analysis/va_http_audit.py`:
- константа лимита длины HTTP-аудита → `_MAX_VA_HTTP_AUDIT_CHARS`
- фабрика HTTP-аудита для VA tool → `build_va_tool_http_audit`
- комментарии: единая терминология `VA HTTP audit`

Обновить imports в:
- `backend/src/recon/vulnerability_analysis/active_scan/va_active_scan_phase.py` (~строки 141, 871, 920-921)
- `backend/src/recon/vulnerability_analysis/pipeline.py` (~строки 62, 178-179)

Имена типов артефактов: прежний префикс `http_*` для audit → `http_audit`.

---

## БЛОК 7 — Новые backend endpoint'ы

### 7.1. `GET /api/v1/scans/{id}/timeline` — в `scans.py`
Хронология ScanEvent с gap_from_previous_sec и total_duration_sec.

### 7.2. `POST /api/v1/findings/{id}/false-positive` — в `findings.py`
Body: `{"reason": str}`. UPDATE findings SET false_positive=True, false_positive_reason, dedup_status='false_positive'.

### 7.3. `GET /api/v1/findings/{id}/remediation` — в `findings.py`
Загрузка skills через ScanKnowledgeBase → CWE/OWASP → skill names → извлечение remediation секций. Опционально LLM.

### 7.4. `GET /api/v1/scans/{id}/findings/statistics` — в `scans.py`
by_severity, by_owasp, by_confidence, unique_cwes, validated, false_positives, risk_score (weighted).

---

## БЛОК 8 — MCP: 4 новых tool'а + cursor rule

### 8.1. Добавить в `setup_mcp_server()`:
- `get_scan_timeline(scan_id)` → GET `/scans/{id}/timeline`
- `mark_finding_false_positive(finding_id, reason)` → POST `/findings/{id}/false-positive`
- `get_finding_remediation(finding_id)` → GET `/findings/{id}/remediation`
- `get_findings_statistics(scan_id)` → GET `/scans/{id}/findings/statistics`

### 8.2. `argus-mcp.json` — добавить в alwaysAllow:
`"get_scan_timeline"`, `"get_findings_statistics"`, `"get_finding_remediation"`

### 8.3. Создать `.cursor/rules/argus-mcp.md` — naming conventions, parameter types, return contract.

---

## БЛОК 9 — Тесты

- `test_auth_login.py` — 503 без JWT_SECRET, dev fallback, reject bad password, admin deny
- `test_exploit_verify.py` — missing finding_id, invalid scheme, valid probe (mock httpx)
- `test_data_sources_full.py` — each client: unavailable без key, parses 200, handles error
- `test_security_adapters_parse.py` — trufflehog JSONL, checkov failed_checks, prowler FAIL only, terrascan violations, scoutsuite JS prefix
- `test_new_endpoints.py` — timeline, false-positive, remediation, statistics

---

## ЗАПРЕЩЕНО В ФИНАЛЬНОМ КОДЕ

1. Маркеры незавершёнки и ярлыки ранней фазы в исходниках (исключение: ключ шаблона `tier_stubs` в reporting — подсказки по тиру, не внешний API)
2. `raise HTTPException(status_code=501)` — нигде
3. Жёстко зашитый dev user id — только в dev fallback с предупреждением в логах
4. `parse_output() -> []` без попытки JSON-парсинга
5. `normalize() -> []` без маппинга полей
6. Legacy no-op PoC runner — удалить полностью
7. Менять frontend.
8. Нарушать существующие API‑контракты.