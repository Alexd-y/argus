# Проверка активного XSS-сканирования (alf.nu) — 2026-03-25

**Цель:** `https://alf.nu/alert1?world=alert&level=alert0`  
**API (nginx):** `http://127.0.0.1/api/v1/...`

---

## Краткое заключение

| Критерий | Результат |
|----------|-----------|
| Исправление `va_message` в worker | Да (после `--no-cache` rebuild backend/worker) |
| `KeyError` на `va_raw_log` | Нет в успешном прогоне |
| Инструменты dalfox / xsstrike / ffuf реально выполняются в sandbox | Да (после Docker CLI в образе + доступ к сокету) |
| Артефакты `*dalfox*`, `*xsstrike*`, `*ffuf*` в MinIO | Да (stdout/stderr/meta) |
| Finding CWE-79, severity ≥ 7.0, PoC с `alert(1)` в отчёте / API | **Нет** в этом прогоне |

**Вывод:** цепочка active scan **работоспособна** (фаза стартует, `docker exec` в `argus-sandbox` выполняется, артефакты пишутся). **Автоматически зафиксированной XSS (CWE-79) с требуемым PoC в Valhalla/midgard в этом запуске нет:** Dalfox завершил скан с `issues: 0`; XSStrike сообщил «No reflection found» для `world` и `level`. В отчёте доминируют эвристики/LLM (в т.ч. ложноположительный акцент на CWE-78 для тех же параметров).

---

## 1. Развёртывание `va_message`

- До пересборки: `docker exec argus-worker grep va_message /app/src/orchestration/handlers.py` → пусто (старый слой `COPY src/`).
- После `docker compose ... build --no-cache backend` и пересборки worker: строка с `extra={"va_message": msg, ...}` присутствует.

---

## 2. Дополнительные исправления инфраструктуры (обнаружены при проверке)

### 2.1 Отсутствие бинарника `docker` в worker

Код VA вызывает `subprocess.Popen(["docker", "exec", ...])`. В образе не было `docker` → `va_active_scan_exec_os_error` (ENOENT).

**Исправление:** в `infra/backend/Dockerfile` добавлено:

`COPY --from=docker:26-cli /usr/local/bin/docker /usr/local/bin/docker`

### 2.2 Permission denied на `/var/run/docker.sock` (Docker Desktop)

Проверка сокета с хоста: `660 root root`. Пользователь `appuser` в контейнере не мог открыть сокет.

**Исправление:** в `infra/docker-compose.yml` для сервиса `worker` задано `user: "0:0"` с комментарием (для прод-Linux предпочтительнее `group_add` с GID группы `docker` на хосте вместо root).

---

## 3. Сканы

### 3.1 Первый прогон (до исправления Docker CLI / root)

- **scan_id:** `d559c41b-b2fe-4ed2-b816-e4727bb0ab06`
- **target:** полный URL с query — да.
- **Логи:** массовые `va_active_scan_exec_os_error`, `va_active_scan_exec_skip`, пустые stderr-артефакты — инструменты не запускались в sandbox.

### 3.2 Финальный прогон (после всех исправлений)

- **scan_id:** `09c25592-9b20-4b46-882c-9253f47cb7ba`
- **Создание:** `POST /api/v1/scans` с телом  
  `{"target":"https://alf.nu/alert1?world=alert&level=alert0","email":"xss-verify2@argus.local","options":{}}`
- **Статус:** `completed`, фазы дошли до `reporting` / `complete`.

---

## 4. Логи worker (фрагменты, scan `09c25592-…`)

- `va_active_scan_phase_start` — **есть** (04:16:09 UTC в контейнере).
- `KeyError` / `Attempt to overwrite 'message'` — **нет**.
- `xsstrike_targets_skipped` — **не наблюдалось** для этого скана.
- Имена событий в коде: **`va_active_scan_tool_start`** / `va_active_scan_tool_done` (в задании фигурировало `tool_va_active_scan_start` — такого префикса в логах нет).
- Предупреждения `Failed to parse headers` при обращении к MinIO (urllib) — **есть**, на загрузку артефактов не смотрели блокирующе; объекты в бакете присутствуют.

---

## 5. Артефакты MinIO (`GET /api/v1/scans/{id}/artifacts?phase=vuln_analysis&raw=true`)

Примеры ключей (неполный список):

| Инструмент | Пример объекта | Размер stdout (из API) |
|------------|----------------|-------------------------|
| ffuf | `..._tool_ffuf_scan_alf_nu_24_ffuf_minimum_xss_query_surface_stdout.txt` | 6712 |
| xsstrike | `..._tool_xsstrike_scan_alf_nu_23_xsstrike_minimum_xss_query_surface_stdout.txt` | 242 |
| dalfox | `..._tool_dalfox_scan_alf_nu_22_dalfox_minimum_xss_query_surface_stdout.txt` | 0 |

**Содержимое XSStrike (minimum XSS job), выдержка:**

```text
[!] Testing parameter: level
[-] No reflection found
[!] Testing parameter: world
[-] No reflection found
```

**Содержимое Dalfox stderr (minimum XSS job), выдержка:**

- Target: `https://alf.nu/alert1?level=alert0&world=alert`
- Строки вида «Reflected level param =>» / «Reflected world param =>» без полезной нагрузки в выводе
- Итог: `[issues: 0] Finish Scan!`

---

## 6. Findings и отчёты

- **GET** `/api/v1/scans/09c25592-9b20-4b46-882c-9253f47cb7ba/findings` — записей с **CWE-79** нет.
- **GET** `/api/v1/reports?target=<URL-encoded full alf.nu URL>` — первая запись `report_id=66796672-3135-445b-9a9f-182fd385bf9f`, tier `midgard`, `generation_status=ready`, 8 findings; среди них **нет** XSS с `alert(1)`; есть **CWE-78** (command injection) high / CVSS 8.0 — трактовать как **эвристику/LLM**, не как подтверждённый XSS.

**Ссылка на отчёт (API):**  
`http://127.0.0.1/api/v1/reports/66796672-3135-445b-9a9f-182fd385bf9f`  
(скачивание PDF/HTML — через `GET .../download` по контракту reports router, при необходимости.)

---

## 7. Автотесты плана (не E2E детекции)

```text
pytest tests/test_alf_nu_xss.py -q
# 2 passed, 1 skipped — проверяется наличие dalfox/xsstrike/ffuf в плане, не факт XSS в отчёте.
```

---

## 8. Рекомендации, если нужен именно CWE-79 в отчёте

1. Увеличить `VA_ACTIVE_SCAN_TOOL_TIMEOUT_SEC` и/или тонко настроить argv Dalfox (mining, blind, delay) под поведение alf.nu.
2. Добавить пост-обработку вывода Dalfox, когда есть «Reflected … param» но `issues: 0`, чтобы поднимать **информационный** finding или триаж.
3. На Linux вместо `user: "0:0"` у worker использовать `group_add: ["<GID docker на хосте>"]` и оставить непривилегированного пользователя.
4. Разобрать предупреждения клиента S3/urllib про `MissingHeaderBodySeparatorDefect` при пустых ответах MinIO (косметика/совместимость).

---

## 9. Чеклист из запроса

- [x] В логах worker нет `KeyError` при `va_raw_log` (успешный прогон).
- [x] В артефактах есть выводы dalfox/xsstrike/ffuf (часть stdout у dalfox пустая, stderr содержит полный лог).
- [ ] В отчёте (Valhalla/midgard) есть XSS CWE-79, high/critical, PoC с `alert(1)` — **не выполнено** в данном прогоне.
- [x] Итоговый документ создан (этот файл).
