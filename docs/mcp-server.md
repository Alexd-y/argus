# ARGUS MCP Server & KAL API

**Version:** 0.1  
**Code:** `mcp-server/argus_mcp.py`, backend `src/api/routers/tools.py`, `src/recon/mcp/policy.py`, `src/recon/mcp/kal_executor.py`

---

## 1. Назначение

Процесс **MCP** (FastMCP) проксирует вызовы в HTTP API бэкенда. Для категорийных Kali-запусков используется единая точка **`POST /api/v1/tools/kal/run`** (KAL-002): argv проходит fail-closed политику, выполнение — в песочнице при **`SANDBOX_ENABLED=true`**, опционально выгрузка stdout/stderr в MinIO.

**Аутентификация клиента к API:** заголовок `Authorization: Bearer <ARGUS_API_KEY>` (если задан `ARGUS_API_KEY`). Тенант: `X-Tenant-ID` из env `ARGUS_TENANT_ID` или явно в теле KAL-запроса.

---

## 2. HTTP: `POST /api/v1/tools/kal/run`

**Rate limit:** по IP, ключ `kal_run:<client_ip>` (см. router `tools`).

### 2.1 Тело запроса (`KalRunRequest`)

| Поле | Тип | Обязательно | Описание |
|------|-----|---------------|----------|
| `category` | string | да | Категория политики (ниже); нормализация: lower-case, `-` → `_` |
| `argv` | string[] | да | 1…64 аргументов, каждый ≤ 4096 символов; **без shell** — список передаётся в exec |
| `target` | string | да | Цель для guardrails (host/URL); 1…2048 |
| `tenant_id` | string | нет | Для MinIO raw: `{tenant}/{scan}/recon/raw/...` |
| `scan_id` | string | нет | В паре с `tenant_id` включает загрузку артефактов |
| `password_audit_opt_in` | bool | нет | Для **hydra/medusa**: клиентский opt-in (плюс серверный `KAL_ALLOW_PASSWORD_AUDIT`) |

### 2.2 Ответ (успех / отказ политики / валидация)

Типовые поля:

| Поле | Описание |
|------|----------|
| `success` | Успех выполнения процесса |
| `stdout`, `stderr` | Вывод инструмента |
| `return_code` | Код завершения |
| `execution_time` | Длительность (сек) |
| `policy_reason` | При отказе: например `unknown_category`, `tool_not_allowed_for_category`, `password_audit_opt_in_required`, `argv_injection_pattern`, `target_validation_failed`; при успехе часто `null` |
| `minio_keys` | Ключи загруженных объектов (если заданы `tenant_id` и `scan_id`) |

Политика **`kal_mcp_gated_tools_v1`** (`KAL_MCP_POLICY_ID` в коде).

---

## 3. Категории политики KAL (`KAL_OPERATION_CATEGORIES`)

Разрешённый **первый** элемент `argv` (бинарник) для категории:

| Категория | Разрешённые бинарники | Примечания |
|-----------|----------------------|------------|
| `network_scanning` | `nmap`, `rustscan`, `masscan` | Цикл recon nmap завязан на эту категорию |
| `web_fingerprinting` | `httpx`, `whatweb`, `wpscan`, `nikto` | |
| `api_testing` | `httpx`, `nuclei`, `curl` | Удобно вызывать через **`run_tool`** с `argv_json` |
| `bruteforce_testing` | `gobuster`, `feroxbuster`, `dirsearch`, `ffuf`, `wfuzz`, `dirb` | Не **hydra** — см. `password_audit` |
| `ssl_analysis` | `openssl`, `testssl.sh` | Для `openssl` только подкоманды: `s_client`, `s_time`, `version`, `ciphers` |
| `dns_enumeration` | `dig`, `subfinder`, `amass`, `dnsx`, `host`, `nslookup`, `dnsrecon`, `fierce` | Для **amass** только подкоманда `enum` |
| `password_audit` | `hydra`, `medusa` | Нужны **`password_audit_opt_in=true`** и **`KAL_ALLOW_PASSWORD_AUDIT=true`** на сервере |
| `vuln_intel` | `searchsploit` | Разведка/intel по argv |

В argv запрещены шаблоны внедрения shell-метасимволов (см. `kal_argv_has_injection_risk`).

---

## 4. Инструменты MCP (KAL-002)

Регистрируются в **`_register_kal_mcp_tools`**. Все ниже вызывают тот же **`kal_run`** → `POST /api/v1/tools/kal/run`.

### 4.1 `run_network_scan`

- **Категория:** `network_scanning`
- **Параметры:** `tenant_id`, `scan_id`, `target`, `tool` (`nmap` \| `rustscan` \| `masscan`), `extra_args` (строка, парсится `shlex.split`)
- **Поведение:** для `nmap` argv = `["nmap", *extras, target]`; для `masscan` при пустых extras добавляется `-p 1-1000 --rate 1000`

### 4.2 `run_web_scan`

- **Категория:** `web_fingerprinting`
- **Инструменты:** `httpx` (по умолчанию `-u target`, при необходимости `-silent`), `whatweb`, `wpscan`, `nikto`

### 4.3 `run_ssl_test`

- **Категория:** `ssl_analysis`
- **Реализация:** только **`openssl s_client`** (+ `-servername`, `-connect host:port`); порт по умолчанию `443`, из URL извлекается хост/порт
- **testssl.sh:** через **`run_tool`** с `category=ssl_analysis` и `argv_json`, например `["testssl.sh", "--openssl", "/usr/bin/openssl", "https://host"]` (уточняйте флаги под образ sandbox)

### 4.4 `run_dns_enum`

- **Категория:** `dns_enumeration`
- **Инструменты:** `dig`, `subfinder`, `amass`, `dnsx`, `host`, `nslookup` (обёртки с типовыми флагами)
- **dnsrecon / fierce:** в политике сервера разрешены, но отдельных MCP-обёрток нет — используйте **`run_tool`**

### 4.5 `run_bruteforce`

- **Категория:** `bruteforce_testing`
- **Инструменты:** `gobuster`, `feroxbuster`, `dirsearch`, `ffuf`, `wfuzz`, `dirb` с дефолтным wordlist `/usr/share/wordlists/dirb/common.txt` в argv

### 4.6 `run_tool`

- **Универсальный вызов:** `category`, `tenant_id`, `scan_id`, `target`, **`argv_json`** (JSON-массив строк), опционально `password_audit_opt_in`
- Используйте для **api_testing**, **vuln_intel**, **testssl.sh**, **dnsrecon**/**fierce**, кастомных безопасных argv в рамках категории

---

## 5. Прочие MCP-инструменты (контекст)

- **Реестр Kali (`kali_*`):** вызовы унаследованных эндпоинтов `run_tool` по имени инструмента (не путать с KAL category API).
- **`va_enqueue_sandbox_scanner`:** очередь Celery для VA (dalfox, xsstrike, …) через `POST /api/v1/internal/va-tools/enqueue`, может требовать **`ARGUS_ADMIN_KEY`**.

---

## 6. Связанные документы

- [deployment.md](./deployment.md) — `SANDBOX_ENABLED`, `SANDBOX_PROFILE`, `KAL_ALLOW_PASSWORD_AUDIT`, NMAP-флаги
- [scan-state-machine.md](./scan-state-machine.md) — цикл nmap, DNS recon, VA whatweb/nikto/feroxbuster/testssl, флаги searchsploit/trivy/HIBP
