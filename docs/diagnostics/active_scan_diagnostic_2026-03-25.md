# Диагностика: почему XSS может не обнаруживаться (active scan), цель `https://alf.nu/alert1?world=alert&level=alert0`

**Дата:** 2026-03-25  
**Окружение:** хост Windows, стек ARGUS (`d:\Developer\Pentest_test\ARGUS`)

---

## Краткое резюме (executive summary)

- **Критический дефект логирования:** колбэк `va_raw_log` в `run_vuln_analysis` передаёт в `logger.info(..., extra=…)` ключ **`message`**, который в Python `logging` зарезервирован для `LogRecord`. Это вызывает `KeyError: Attempt to overwrite 'message' in LogRecord`, фаза active scan падает, срабатывает `va_active_scan_failed_fallback_to_llm` — **dalfox / xsstrike / ffuf фактически не отрабатывают** при первом же вызове `va_raw_log` на проблемном пути.
- **Пустая поверхность в зафиксированном прогоне:** в логах worker перед падением есть `xsstrike_targets_skipped` (причина `no_params_or_forms_inventory`) — у бандла не было строк в `params_inventory` и `forms_inventory`. Типично это значит, что в скан **не передали полный URL с query** (`world`, `level`), либо извлечение не дошло до VA с заполненным инвентарём.
- **Инструменты в sandbox установлены:** образ `argus-sandbox` собирается из `kalilinux/kali-rolling` (не отдельный тег `argus/kali-base:latest` в compose); в контейнере доступны `dalfox version` → v2.12.0, `ffuf`, `xsstrike`.

---

## 1. Docker / окружение worker

| Действие | Результат |
|----------|-----------|
| `docker ps` | Контейнеры: `argus-worker`, `argus-backend`, `argus-sandbox`, `argus-postgres`, `argus-redis`, `argus-minio`, `argus-nginx` — все в статусе Up (healthy). |
| Имя worker | `argus-worker` (image `argus-worker`). |

**Переменные внутри `argus-worker` (только факт наличия, без значений):**

| Переменная | Статус |
|------------|--------|
| `SANDBOX_ENABLED` | задана (`true` в прогоне проверки) |
| `VA_AI_PLAN_ENABLED` | задана (`true`) |
| `OPENAI_API_KEY` | **задана** (значение в отчёт не включать; при аудите через `docker exec` ключ попадает в stdout — рекомендуется ротация при утечке в общий лог) |
| `OPENROUTER_API_KEY` | **задана** (аналогично, только masked/set) |
| `VA_EXPLOIT_AGGRESSIVE_ENABLED` | задана (`true`) |
| `SQLMAP_VA_ENABLED` | задана (`true`) |

**Ошибки команд:** при фильтрации `env` ошибок нет.

---

## 2. Логи worker (`docker logs argus-worker`)

Поиск по строкам: `va_active_scan`, `dalfox`, `xsstrike`, `vuln_analysis_active_scan`, `sandbox_disabled`, `docker_daemon`, `Phase`, `LLM`.

**Наблюдения по реальному прогону (scan_id в логе: `76c7297d-f9bb-4fcf-832c-b6b900d8814f`):**

- `Phase started` / `Phase completed` — фазы state machine отрабатывают.
- `LLM adapter failed` — на этапах recon/threat/VA LLM-адаптер сообщал о сбоях (отдельная тема, не единственная причина отсутствия XSS от инструментов).
- `va_active_scan_phase_start` — вход в фазу active scan выполнен.
- `xsstrike_targets_skipped` с причиной **`no_params_or_forms_inventory`** — пустые инвентари параметров/форм.
- Сразу после этого: **`va_active_scan_failed_fallback_to_llm`** с трассировкой:

```text
KeyError: "Attempt to overwrite 'message' in LogRecord"
```

Стек указывает на вызов `va_raw_log("va_active_scan_skipped no_targets")` внутри `run_va_active_scan_phase` (в смонтированном образе номер строки может отличаться от текущего репозитория).

**Вывод:** даже при непустом плане первый же вызов `va_raw_log` с текущей реализацией в `handlers.py` способен уронить фазу из‑за ключа `message` в `extra`.

Упоминаний **`sandbox_disabled`**, **`docker_daemon`** в выборке логов не найдено (sandbox включён; доступ к Docker из worker идёт через сокет, см. п. 6).

---

## 3. Образ sandbox и наличие инструментов

**Источник правды — `infra/docker-compose.yml`:**

- Сервис `sandbox`: `build: context: ../sandbox`, `dockerfile: Dockerfile`, **`image: argus-sandbox`**, контейнер `argus-sandbox`.
- Образ **`argus/kali-base:latest` в compose не используется**; базовый слой в `sandbox/Dockerfile`: `FROM kalilinux/kali-rolling:latest`.

**Проверка внутри одноразового контейнера:**

```text
docker compose -f infra/docker-compose.yml run --rm sandbox sh -c "dalfox version; ffuf -V; which xsstrike; xsstrike -h"
```

| Команда | Результат |
|---------|-----------|
| `dalfox version` | Dalfox **v2.12.0** (успех) |
| `dalfox --version` | Ошибка: `unknown flag: --version` (ожидаемо; у dalfox подкоманда `version`) |
| `ffuf -V` | **2.1.0-dev** |
| `which xsstrike` | `/usr/local/bin/xsstrike` |
| `xsstrike -h` | XSStrike **v3.1.5**, справка выводится |

**Побочный эффект:** при `docker compose run` пересоздавался контейнер MinIO (ожидаемо для зависимостей compose); на диагностику инструментов не влияет.

---

## 4. Трассировка кода (handlers → VA phase → planner)

### 4.1 `state_machine` вызывает `run_vuln_analysis` с целевым URL

```472:474:d:\Developer\Pentest_test\ARGUS\backend\src\orchestration\state_machine.py
                    vuln_out = await run_vuln_analysis(
                        tm, assets, target=target, tenant_id=tenant_id, scan_id=scan_id
                    )
```

### 4.2 `run_vuln_analysis` — условие active scan и вызов фазы

При `settings.sandbox_enabled` и непустом `target` вызываются `_extract_url_params_and_forms`, сборка `VulnerabilityAnalysisInputBundle` и **`run_va_active_scan_phase`**:

```740:772:d:\Developer\Pentest_test\ARGUS\backend\src\orchestration\handlers.py
    if settings.sandbox_enabled and target:
        try:
            params_inv, forms_inv = await _extract_url_params_and_forms(target)
            bundle = VulnerabilityAnalysisInputBundle(
                ...
                params_inventory=params_inv,
                forms_inventory=forms_inv,
                ...
            )
            ...
            result_bundle = await run_va_active_scan_phase(
                bundle,
                tenant_id_raw=tenant_id,
                scan_id_raw=scan_id or "",
                va_raw_log=lambda msg: logger.info(
                    "va_active_scan",
                    extra={"message": msg, "scan_id": scan_id},
                ),
            )
```

**Проблема:** ключ **`message` в `extra` недопустим** для стандартного `logging` → `KeyError` при записи лога.

### 4.3 Ранний выход при отключённом sandbox

```101:103:d:\Developer\Pentest_test\ARGUS\backend\src\recon\vulnerability_analysis\active_scan\va_active_scan_phase.py
    if not settings.sandbox_enabled:
        va_raw_log("va_active_scan_skipped sandbox_disabled")
        return bundle
```

При отключённом sandbox тот же `va_raw_log` вызовет тот же `KeyError`, если до него дошли (при включённом sandbox этот блок не берётся).

### 4.4 Пустой план → `no_targets`

```142:144:d:\Developer\Pentest_test\ARGUS\backend\src\recon\vulnerability_analysis\active_scan\va_active_scan_phase.py
    if not plan:
        va_raw_log("va_active_scan_skipped no_targets")
        return bundle
```

### 4.5 `VA_AI_PLAN_ENABLED=false` и планировщик

В `active_scan_planner.py` явно задокументировано: при `va_ai_plan_enabled` false возвращается `[]`, детерминированный план из `build_va_active_scan_plan` сохраняется; AI не «выталкивает» базовые шаги XSS.

```10:12:d:\Developer\Pentest_test\ARGUS\backend\src\recon\vulnerability_analysis\active_scan_planner.py
XSS-003: ``plan_active_scan_with_ai`` returns ``[]`` immediately when ``va_ai_plan_enabled`` is
false (no LLM client work). The executor merges base plan + AI rows, then
``ensure_minimum_xss_surface_plan`` appends the XSS trio for query URLs.
```

### 4.6 Минимальная XSS-тройка (dalfox / xsstrike / ffuf)

В `planner.py` тройка `_MINIMUM_XSS_TOOL_TRIO` добавляется только если у бандла есть **признак query-surface** (`_bundle_has_query_string_surface`) и удаётся разрешить полный URL с непустым query (`ensure_minimum_xss_surface_plan`).

```195:208:d:\Developer\Pentest_test\ARGUS\backend\src\recon\vulnerability_analysis\active_scan\planner.py
def ensure_minimum_xss_surface_plan(
    bundle: VulnerabilityAnalysisInputBundle,
    base_plan: list[ActiveScanPlanStep],
) -> list[ActiveScanPlanStep]:
    ...
    if not _bundle_has_query_string_surface(bundle):
        return list(base_plan)

    target_url = _resolve_minimum_xss_target_url(bundle)
    if not target_url or not _http_url_with_non_empty_query(target_url):
        return list(base_plan)
```

### 4.7 `_extract_url_params_and_forms` в `handlers.py` (не в `active_scan.py`)

Статическое извлечение query **без сети** — функция `_extract_url_query_params`:

```152:167:d:\Developer\Pentest_test\ARGUS\backend\src\orchestration\handlers.py
def _extract_url_query_params(target: str) -> list[dict[str, Any]]:
    """Extract query parameters from a target URL string (no network call)."""
    parsed = urlparse(target)
    if not parsed.query:
        return []

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else target.split("?")[0]
    params_inventory: list[dict[str, Any]] = []
    for param_name, values in parse_qs(parsed.query, keep_blank_values=True).items():
        params_inventory.append({
            "url": base_url,
            "param": param_name,
            "value": values[0] if values else "",
            "method": "GET",
        })
    return params_inventory
```

Для URL вида `https://alf.nu/alert1?world=alert&level=alert0` при передаче **именно этой строки** в `target` ожидаются две записи: параметры **`world`** и **`level`** с `url` = `https://alf.nu/alert1` (без query в поле `url`).

Если в скан передан только `https://alf.nu/alert1` или голый хост без `?world=…&level=…`, `_extract_url_query_params` вернёт `[]`; тогда `collect_xsstrike_scan_jobs` логирует `xsstrike_targets_skipped` / `no_params_or_forms_inventory`, план остаётся пустым (если нет других источников query в `live_hosts` / `entry_points`).

---

## 5. Сводка по цели alf.nu и «почему нет XSS в отчёте»

1. **Баг `va_raw_log` + `extra["message"]`** — гарантированный срыв фазы при вызове колбэка; инструменты не выполняются, срабатывает fallback на LLM.
2. **Пустой `params_inventory` / `forms_inventory`** в залогированном прогоне — нет целей для `build_va_active_scan_plan` и для минимальной XSS-тройки; для alf.nu нужно убедиться, что **в `target` попадает полный URL с query**.
3. **Ложные отрицания сканеров** (dalfox/xsstrike не видят отражение/контекст) возможны уже после устранения п.1–2; на alf.nu это отдельная проверка руками/логами артефактов.

---

## 6. Docker socket на worker / backend

В `infra/docker-compose.yml` у **`worker`** и **`backend`** смонтировано **read-only**:

- `/var/run/docker.sock:/var/run/docker.sock:ro`

Это ожидаемый путь для **exec в `argus-sandbox`** с хоста. Риски: компрометация worker даёт контроль над Docker API; для продакшена обычно рассматривают изоляцию, отдельный раннер, политику образов.

---

## Таблица: Finding | Status | Evidence

| Finding | Status | Evidence |
|--------|--------|----------|
| Worker запущен | OK | `docker ps`: `argus-worker` Up healthy |
| Sandbox включён | OK | `SANDBOX_ENABLED=true` в env worker |
| Образ sandbox | OK | compose: `image: argus-sandbox`, build из `sandbox/Dockerfile`, база `kalilinux/kali-rolling` |
| dalfox / ffuf / xsstrike в sandbox | OK | `dalfox version` v2.12.0; `ffuf -V`; `xsstrike` v3.1.5 |
| Вызов `run_va_active_scan_phase` из `run_vuln_analysis` | OK | `handlers.py` ~740–772 |
| Извлечение `world`/`level` из полного URL | OK (логика) | `_extract_url_query_params` `handlers.py` 152–167 |
| Логирование `va_raw_log` | **FAIL** | `KeyError` reserved `message` в `extra`; `handlers.py` 768–770 |
| План active scan в прогоне | **FAIL (пусто)** | `xsstrike_targets_skipped` / `no_params_or_forms_inventory` в логах |
| LLM как замена инструментов при сбое VA | Degraded | `va_active_scan_failed_fallback_to_llm`; `LLM adapter failed` в том же прогоне |

---

## Конкретные шаги исправления (remediation)

1. **Исправить колбэк `va_raw_log`:** заменить ключ `message` в `extra` на нейтральный (например `va_message` или `va_log_text`), чтобы не пересекаться с [`LogRecord`](https://docs.python.org/3/library/logging.html#logrecord-attributes). Прогнать smoke: запуск VA с непустым планом и проверка отсутствия `KeyError` в логах worker.
2. **Проверить передачу `target` в скан:** для alf.nu в UI/API/CLI должна уходить строка **`https://alf.nu/alert1?world=alert&level=alert0`** (или эквивалент с обоими параметрами), иначе инвентарь пустой и XSS-тройка не строится по параметрам.
3. **После правки:** пересобрать и задеплоить образ **`argus-worker`** (и при необходимости backend, если тот же паттерн используется elsewhere).
4. **Наблюдаемость:** включить поиск по `va_active_scan_tool_start`, `tool_va_active_scan_plan` в MinIO/сырых артефактах, чтобы подтвердить реальные argv dalfox/xsstrike.
5. **Секреты:** не использовать `docker exec … env` в общих логах; при уже показанных ключах в консоли — **ротация** `OPENAI_API_KEY` / `OPENROUTER_API_KEY`.
6. **Опционально:** поднять таймаут `VA_ACTIVE_SCAN_TOOL_TIMEOUT_SEC`, если цель медленная; это вторично относительно п.1–2.

---

**Абсолютный путь отчёта:** `d:\Developer\Pentest_test\ARGUS\docs\diagnostics\active_scan_diagnostic_2026-03-25.md`
