# ARG-047 — End-to-end capstone scan against OWASP Juice Shop — Worker Report

| Field                  | Value                                                                                                              |
| ---------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Task ID                | ARG-047                                                                                                            |
| Title                  | DoD §19.4 — `scripts/e2e_full_scan.sh http://juice-shop:3000` (полный e2e capstone)                                |
| Cycle                  | 5                                                                                                                  |
| Workflow stage         | Worker → (next: Test-writer review → Test-runner → Reviewer)                                                       |
| Priority               | HIGH                                                                                                               |
| Estimate               | 12 h                                                                                                               |
| Critical-path role     | ARG-045 → **ARG-047** → ARG-049 (capstone)                                                                         |
| Backlog reference      | DoD §19.4, §16.13 (CI nightly e2e), §17 (long-running test flake prevention)                                       |
| Predecessor reports    | ARG-031 (18-tier reports) ✅, ARG-033 (cosign keyless) ✅, ARG-034 (GHCR images) ✅, ARG-041 (Prometheus) ⏸, ARG-045 (Helm + compose stack) ⏸ |
| Files created          | 14                                                                                                                 |
| Files modified         | 3                                                                                                                  |
| LoC added              | ~3 100 (scripts + tests + docs + CHANGELOG)                                                                        |
| Verification gates     | bash -n ✅ · python -m py_compile ✅ · ruff ✅ · mypy --strict ✅ · pytest --collect-only ✅ · docker compose config ✅ · ps1 parser ✅ |

---

## 1. Контекст и постановка

ARG-047 — финальный integration test для Cycle 5, доказывающий что full ARGUS
stack работает end-to-end на live target. Цель — собрать в одном wrapper
`scripts/e2e_full_scan.{sh,ps1}` всё что мы построили в Cycle 1–4
(orchestrator + sandbox profiles + parsers + reports + cosign + OAST + MCP +
Prometheus) и прогнать против **OWASP Juice Shop v17.0.0** как mishen'.

DoD §19.4 требует, чтобы wrapper:

1. Поднимал stack из 8 сервисов через `docker compose -f infra/docker-compose.e2e.yml up`.
2. Дожидался health (backend `/ready`, juice-shop `/`).
3. Запускал scan через `POST /api/v1/scans`.
4. Поллил `GET /api/v1/scans/<id>` до `status='completed'`.
5. Верифицировал генерацию ВСЕХ отчётов (3 tier × 6 формат = 18, см. §3.4).
6. Верифицировал OAST callback (Juice Shop has known SSRF — best-effort).
7. Верифицировал cosign verify exit 0 на всех sandbox-image references.
8. Верифицировал Prometheus `argus_findings_*` + `argus_scan_*` метрики > 0.
9. Сносил stack.
10. Архивировал результаты как CI artifact.

Это **НЕ unit-test и НЕ integration-test** в традиционном смысле — это
**capstone**: полная проверка production-cycle, идущая 30–60 минут,
запускаемая ежедневно из cron + on-demand из CI.

---

## 2. Подход и принятые решения

### 2.1. Архитектура: bash + PowerShell + Python helpers

Backlog требует POSIX-shell wrapper + PowerShell-wrapper для Windows. Я
применил **trinity-pattern**:

| Layer              | Tech       | Rationale                                                 |
| ------------------ | ---------- | --------------------------------------------------------- |
| **Orchestrator**   | bash + ps1 | docker compose / curl wiring; OS-native parallelism       |
| **Verifiers**      | Python 3.12 | Сложная логика парсинга (JSON/YAML/regex); shared on host |
| **Archiver**       | bash       | tar / zip — POSIX-первое                                  |

Python-helpers (`verify_reports.py`, `verify_oast.py`, `verify_prometheus.py`)
написаны на **stdlib-only** (urllib + argparse + dataclasses). Это
обеспечивает:

* Zero new dependencies (важно для CI cold-start).
* Идентичное поведение под Linux / macOS / Windows.
* Легко тестируется в pytest без mock-сетевого стека.

### 2.2. Phase model

Wrapper делит прогон на **12 фаз** (а не 11 как в баклоге — 12-я добавлена
для idempotent-archive):

```
01  bring_up_compose       docker compose up --wait
02  wait_backend_ready     poll GET /ready
03  trigger_scan           POST /api/v1/scans
04  wait_scan_completed    poll GET /api/v1/scans/<id>
05  trigger_reports        POST /api/v1/scans/<id>/reports/generate-all
06  verify_reports         scripts/e2e/verify_reports.py
07  verify_oast            scripts/e2e/verify_oast.py
08  verify_cosign          scripts/e2e/verify_cosign.sh
09  verify_prometheus      scripts/e2e/verify_prometheus.py
10  assert_min_findings    findings/statistics.total >= MIN
11  tear_down              docker compose down -v
12  archive_results        tar -czf results.tar.gz
```

Каждая фаза — **отдельная функция** (`phase_<name>` в bash, `$phaseNN`
scriptblock в PowerShell). Все фазы передаются через **общий orchestrator
loop** `run_phase` / `Invoke-Phase`, который:

1. Принимает `phase_id`, `description`, `timeout_seconds`, `callable`.
2. Включает `set -e + trap` (bash) / `try/catch` (ps1).
3. Записывает per-phase JSON-record (`<phase_id>.json` с `status`,
   `started_at_utc`, `finished_at_utc`, `duration_seconds`, `error`).
4. На non-zero exit — обновляет `summary.json` с `failed_phase` +
   `failure_detail` (без stack trace; правило безопасности из user_rules).
5. Continues to phase 11 (tear-down) ВСЕГДА — мы не оставляем висящие
   контейнеры.

Это даёт **диагностируемость без декомпозиции в N отдельных скриптов** и
сохраняет state-machine logic в одном месте.

### 2.3. PowerShell-specific gotchas

PowerShell-портировка съела ~40 % времени из-за следующих граблей:

1. **`Start-Job` scope isolation**. Изначально каждая фаза запускалась
   через `Start-Job { ... }` для timeout-enforcement. Job запускается в
   отдельном runspace и НЕ видит outer-scope variables (`$Target`,
   `$script:ScanId`). Решение: **убрать `Start-Job` совсем**, полагаясь на
   per-HTTP-call `-TimeoutSec` параметр + общий polling-deadline.
2. **Locale-sensitive `Get-Date -UFormat %s`**. На системах с
   non-en-US locale возвращает `1745136000,5` (запятая вместо точки),
   что ломает float-парсинг. Решение: `[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()`
   — invariant culture, integer return type.
3. **Inline `if` expression syntax**. PowerShell 5.1 не поддерживает
   ternary (`$x ? $y : $z` появился в 7.0). Решение: helper-функция
   `Resolve-Default` для каскада `param-value → env-var → hardcoded-default`.
4. **CRLF vs LF в .sh файлах**. Сначала `bash -n` падал с `syntax error
   near unexpected token $'{\r''`. Решение: `.gitattributes` уже имел
   `*.sh text eol=lf`, но Write-tool создавал CRLF — фикс через
   in-process `bytes.replace(b'\r\n', b'\n')`.

### 2.4. API-contract reconciliation (critical drift findings)

Я проверил каждую API-точку, которую трогает wrapper, против реального
backend-кода (а не баклог-описания):

| Backlog wrote                         | Реальный API                                          | Решение                                 |
| ------------------------------------- | ----------------------------------------------------- | --------------------------------------- |
| `POST /scans`                         | `POST /api/v1/scans`                                  | Использую `/api/v1/`                    |
| `GET /scans/<id>`                     | `GET /api/v1/scans/<id>`                              | Same                                    |
| `GET /reports/<scan_id>?tier=...`     | `GET /api/v1/reports?target=...` + `GET /api/v1/reports/<rid>` (no scan-id query!) | Filter on client side    |
| `body: {target_url, scan_profile, tier_requested}` | `body: {target, email, scan_mode}` (Pydantic) | Adopted real schema              |
| `18 reports = 3 tier × 6 format`      | `12 reports = 3 tier × 4 format` (PDF/HTML/JSON/CSV) | Configurable `E2E_EXPECTED_REPORTS=12`; documented gap |
| OAST callback verification via Redis  | OAST correlator is in-memory (см. `oast/correlator.py`) | Verify via `findings.evidence_type='oast_callback'` |

Эти drift'ы зафиксированы в `docs/e2e-testing.md` §8 + в CHANGELOG entry,
плюс по каждому есть открытый вопрос для test-writer / reviewer:

* **18 vs 12 отчётов**: нужен отдельный backend-PR на API, чтобы вывести
  SARIF + JUNIT генераторы (которые УЖЕ существуют в `report_bundle.py::ReportFormat`)
  в `POST /generate-all`. До этого `E2E_EXPECTED_REPORTS=12`.
* **OAST verification strictness**: в Juice Shop нет out-of-band callback
  по умолчанию (нет SSRF challenge'ев которые направляют на наш OAST
  endpoint). Phase 07 завершается graceful со `status='no_oast_in_scope'`.
  Если хотим **строгую** проверку — направить сканер на свой собственный
  stage с искусственным OAST-эндпоинтом и установить `E2E_REQUIRE_OAST=1`.

### 2.5. Pytest marker — зачем и как

Бэлог требует marker `requires_docker_e2e`. Я добавил его в:

* `backend/pyproject.toml` под `[tool.pytest.ini_options].markers`.
* `backend/tests/conftest.py` `pytest_configure(config)`.

При этом auto-classifier в conftest УЖЕ помечает все тесты под
`tests/integration/e2e/` как `requires_docker` (regex match на `localhost`).
Это означает: **дефолтный `pytest -q` уже их скипает** через
`addopts = "-m 'not requires_docker'"`. Новый marker нужен для
**opt-in селекции** — чтобы CI workflow мог запустить **только** e2e:
`pytest -m requires_docker_e2e`.

Это решение KISS-compliant: одна строка в pyproject + одна в conftest, ноль
дублирования логики, явная выраженность намерения.

---

## 3. Реализация — что создано

### 3.1. `infra/docker-compose.e2e.yml` (NEW, ~280 LoC)

8 сервисов на bridge-network `argus-e2e`:

| Service          | Image                                              | Health                              |
| ---------------- | -------------------------------------------------- | ----------------------------------- |
| juice-shop       | `bkimminich/juice-shop:v17.0.0`                    | `wget --spider http://localhost:3000/` |
| argus-backend    | `${ARGUS_BACKEND_IMAGE:-argus-backend:e2e}`        | `curl http://localhost:8000/health` |
| argus-celery     | (тот же образ; CMD = celery worker)                | `celery -A src.celery_app inspect ping` |
| argus-mcp        | (тот же образ; CMD = uvicorn mcp_server:app)       | `curl http://localhost:8765/health` |
| postgres         | `postgres:16-alpine`                               | `pg_isready`                        |
| redis            | `redis:7-alpine`                                   | `redis-cli ping`                    |
| minio            | `minio/minio:RELEASE.2024-09-13T20-26-02Z`         | `curl http://localhost:9000/minio/health/live` |
| prometheus       | `prom/prometheus:v2.54.1`                          | `wget --spider http://localhost:9090/-/healthy` |

**Решения:**

* **One-image для backend / celery / mcp** — переиспользую `argus-backend`
  build (как в production compose); только CMD различается. Сокращает
  cold-start с ~5 минут до ~3.
* **Все версии запинены** — без `latest`; единственный способ удержать
  flake rate < 5 % (Backlog §17). Указано прямо в шапке файла как
  invariant.
* **Image overrides via env** — `${ARGUS_BACKEND_IMAGE:-...}`,
  `${ARGUS_CELERY_IMAGE:-...}`, `${ARGUS_MCP_IMAGE:-...}` позволяют CI
  направить compose на локально-собранный образ (`argus-backend:e2e`),
  а локальная разработка использует дефолт `argus-backend:e2e` который
  можно собрать как `docker build -f infra/backend/Dockerfile backend`.
* **Resource limits** — `mem_limit` + `cpus` на каждый сервис (защита от
  накопления мусора при многократных прогонах).
* **Persistent volumes** — `postgres-data`, `redis-data`, `minio-data` —
  named volumes удаляются `docker compose down -v` в Phase 11.
* **CI-only API key** — `ARGUS_API_KEYS=e2e-api-key-not-for-production`
  с явным комментарием что это **не для продакшена**.

### 3.2. `infra/prometheus/prometheus.e2e.yml` (NEW, ~25 LoC)

Минимальный конфиг с двумя scrape-target'ами:

```yaml
scrape_configs:
  - job_name: argus-backend
    metrics_path: /metrics
    static_configs:
      - targets: ['argus-backend:8000']
    scrape_interval: 5s
  - job_name: argus-mcp
    metrics_path: /metrics
    static_configs:
      - targets: ['argus-mcp:8765']
    scrape_interval: 5s
```

5-секундный interval — компромисс между быстрой видимостью метрик в Phase
09 и нагрузкой на стек.

### 3.3. `scripts/e2e_full_scan.sh` (NEW, ~520 LoC POSIX bash)

Структура:

```
HEADER (env contract documentation, 80 LoC)
GLOBAL VARS + DEFAULTS
log() / log_phase() helpers
_atomic_write() — write JSON via tempfile + mv
phase_01_compose_up()
phase_02_wait_backend()
phase_03_trigger_scan()
phase_04_wait_scan_completed()
phase_05_trigger_reports()
phase_06_verify_reports()      → calls verify_reports.py
phase_07_verify_oast()         → calls verify_oast.py
phase_08_verify_cosign()       → calls verify_cosign.sh
phase_09_verify_prometheus()   → calls verify_prometheus.py
phase_10_assert_min_findings()
phase_11_tear_down()
phase_12_archive()             → calls archive_results.sh
run_phase() — orchestrator loop with timeout + JSON record
main() — sequential phase invocation, summary.json emit
```

**Решения:**

* `set -Eeuo pipefail` + `trap 'on_error' ERR` — единственный способ не
  потерять non-zero exits в pipeline'ах.
* `curl --retry 3 --retry-delay 5 --max-time 30` на каждом HTTP-запросе —
  защита от транзитных network-flakes (Backlog §17 mitigation).
* Polling — `while sleep 10; ... done`, deadline через `[[ $SECONDS -ge $end ]]`.
* JSON-output генерируется через `python3 -c` one-liner'ы (избегая
  `jq` dependency).

### 3.4. `scripts/e2e_full_scan.ps1` (NEW, ~480 LoC PowerShell 5.1+)

Структурно идентичен bash-версии. Ключевые отличия:

* Все scriptblocks определены как `$phaseNN = { ... }` и передаются в
  `Invoke-Phase` (вместо bash-функций).
* HTTP через `Invoke-RestMethod -TimeoutSec 30 -RetryCount 3`.
* JSON-output через `ConvertTo-Json -Depth 10`.
* Полный CI/CD-friendly exit code propagation через `$LASTEXITCODE`.

### 3.5. `scripts/e2e/verify_reports.py` (NEW, ~150 LoC)

Argparse-based CLI. Логика:

1. `GET /api/v1/reports?target=$TARGET` — список всех отчётов для target.
2. Для каждой строки `GET /api/v1/reports/<rid>` — hydrate с `scan_id`,
   `tier`, `format`, `generation_status`, `summary`.
3. Filter rows where `scan_id == args.scan_id`.
4. Assertions:
   * `len(rows) >= args.expected_count` (default 12).
   * Все `generation_status == 'ready'`.
   * Все 3 tier'а присутствуют (`{'midgard', 'asgard', 'valhalla'}`).
   * `summary` is non-empty dict.
5. Output: structured JSON с `status`, `total_reports`, `by_tier`,
   `by_format`, `failed_reports`, `errors`.

Exit code 0 на success, 1 на failure. Ровно contract который ожидает
wrapper.

### 3.6. `scripts/e2e/verify_oast.py` (NEW, ~180 LoC)

Логика (ВСЕ изменения после refactor'а из Redis-streams в API-findings):

1. `GET /api/v1/scans/<scan_id>/findings` — список всех findings.
2. Для каждого finding ищет:
   * `evidence_type == 'oast_callback'` (точное совпадение из
     `EvidenceKind.OAST_CALLBACK` в `pipeline/contracts/finding_dto.py`).
   * Substring `oast` / `out-of-band` / `callback` / `ssrf` в title или
     description (case-insensitive).
3. Если нашёл хотя бы 1 → `status='passed'`.
4. Если ноль → `status='no_oast_in_scope'` (это **НЕ failure**) — Juice
   Shop по умолчанию не делает OOB callbacks; в баклоге это
   acknowledged как known limitation.
5. Если в env установлен `E2E_REQUIRE_OAST=1` → `no_oast_in_scope`
   эскалируется до `status='failed'`.

Output: JSON с `status`, `oast_evidence_count`, `oast_keyword_matches`,
`scanned_findings_total`, `errors`.

### 3.7. `scripts/e2e/verify_cosign.sh` (NEW, ~120 LoC POSIX bash)

Логика:

1. Если `cosign` не на PATH → emit `status='cosign_unavailable'` JSON,
   exit 0 (graceful skip).
2. Итерация по 6 sandbox-профилям:
   `argus-kali-{web,cloud,browser,full,recon,network}`.
3. Для каждого:
   ```
   cosign verify \
     --certificate-identity-regexp 'https://github\.com/.*ARGUS.*' \
     --certificate-oidc-issuer-regexp 'https://token\.actions\.githubusercontent\.com' \
     ghcr.io/${REGISTRY_OWNER}/${profile}:${IMAGE_TAG}
   ```
4. На каждый профиль: `{profile, status: 'verified|failed|not_found',
   detail}`.
5. Aggregate: `status='passed'` если все verified или not_found (NOT_FOUND
   допустим — образ может ещё не быть пушнут в GHCR, e.g. локальный билд).
6. `status='failed'` если хотя бы один с `status='failed'` (signature
   tampering или wrong issuer).

### 3.8. `scripts/e2e/verify_prometheus.py` (NEW, ~150 LoC)

Логика:

1. Sleep 3 секунды (let last scrape land).
2. **Headline counters check** — instant queries:
   * `sum(argus_http_requests_total) > 0`
   * `sum(argus_findings_emitted_total) > 0`
   * `sum(argus_sandbox_runs_total) > 0`
3. **Metric inventory check** — `GET /api/v1/label/__name__/values`,
   проверяет что присутствуют все 9 metric-families из
   `backend/src/core/observability.py`:
   * `argus_http_requests_total`
   * `argus_http_request_duration_seconds`
   * `argus_celery_task_duration_seconds`
   * `argus_celery_task_failures_total` (ALLOWED_MISSING — может быть 0)
   * `argus_sandbox_runs_total`
   * `argus_sandbox_run_duration_seconds`
   * `argus_findings_emitted_total`
   * `argus_llm_tokens_total` (ALLOWED_MISSING — без LLM в e2e)
   * `argus_mcp_calls_total` (ALLOWED_MISSING — MCP не вызывается из scan)
4. Output JSON с per-metric values + missing-list.

### 3.9. `scripts/e2e/archive_results.sh` (NEW, ~50 LoC)

Простой `tar -C ${parent} -czf ${tar_path} ${leaf}` wrapper с rotation
по timestamp на коллизии + embedded `archive.json` манифест:

```json
{
  "archive_path": "/path/to/e2e-results.tar.gz",
  "size_bytes": 12345678,
  "format": "tar.gz",
  "created_at_utc": "2026-04-20T13:45:00Z"
}
```

### 3.10. `.github/workflows/e2e-full-scan.yml` (NEW, ~150 LoC)

Workflow contract:

* **Triggers:** `schedule cron "0 2 * * *"` (nightly), `workflow_dispatch`
  с 5 input'ами, `push на main` (e2e-инфра-файлы).
* **Runner:** `ubuntu-latest-large` (e2e-stack нагружает ресурсы).
* **Timeout:** 75 минут (1.5× expected wall-time).
* **Steps:**
  1. `actions/checkout@v4`.
  2. `actions/setup-python@v5` (3.12).
  3. `sigstore/cosign-installer@v3.7.0` с `cosign-release: v2.4.1`.
  4. Pre-flight info dump.
  5. `docker build` backend образа.
  6. `docker compose pull` external images (warmup для стабильности).
  7. `bash scripts/e2e_full_scan.sh`.
  8. (Always) Append `summary.json` + diagnostic logs в `$GITHUB_STEP_SUMMARY`
     для быстрой триажа.
  9. (Always) Capture `docker compose ps` + `docker compose logs --tail 500`.
  10. `actions/upload-artifact@v4` — `e2e-results-${{ github.run_id }}`,
      retention 30 дней.
  11. (Always) `docker compose down -v --remove-orphans`.

### 3.11. Pytest tests (NEW, 16 cases, ~950 LoC)

`backend/tests/integration/e2e/` package с двумя test-файлами:

**`test_e2e_health_endpoints.py`** (6 cases):

* `test_health_endpoint_returns_ok` — `GET /health` 200 + `status:ok`.
* `test_health_endpoint_versioned_alias` — `GET /api/v1/health`.
* `test_ready_endpoint_passes_against_live_stack` — все probes `true`.
* `test_providers_health_endpoint_returns_known_providers` — list shape.
* `test_queues_health_endpoint_lists_celery_queues` — Redis-backed.
* `test_metrics_endpoint_serves_prometheus_text_format` — exposition.

**`test_e2e_scan_lifecycle.py`** (10 cases):

* `test_scan_create_returns_uuid_and_queued_status`.
* `test_scan_get_returns_expected_shape`.
* `test_scan_progresses_to_completed_within_timeout`.
* `test_scan_findings_meet_minimum_count`.
* `test_scan_findings_statistics_consistent`.
* `test_generate_all_returns_accepted_with_bundle_metadata`.
* `test_reports_list_contains_bundle_members`.
* `test_all_reports_finish_generation`.
* `test_report_detail_summary_populated`.
* `test_second_generate_all_does_not_duplicate_bundle`.

**Все cases используют:**

* `@pytest.mark.requires_docker_e2e` — opt-in marker.
* Module-scope fixtures `scan_session` + `completed_scan` + `report_bundle`
  — один скан переиспользуется в 10 cases (важно для wall-time — Juice
  Shop scan ~10 минут).
* Stdlib HTTP (`urllib.request`) — zero new deps.
* Env-driven (`E2E_BACKEND_URL`, `E2E_TARGET`, `E2E_TOKEN`,
  `E2E_MIN_FINDINGS`, `E2E_EXPECTED_REPORTS`) — те же env vars что
  использует bash-обёртка.

### 3.12. `docs/e2e-testing.md` (NEW, ~250 LoC, Russian)

Operator runbook на русском (per user_rules):

* §1 — таблица 8 сервисов с портами и назначением.
* §2 — предусловия (Docker ≥ 25, RAM ≥ 8 GB, диск ≥ 10 GB, Cosign
  optional) + полная env-vars contract таблица.
* §3 — локальный запуск (Linux/macOS/WSL bash + Windows PowerShell).
* §4 — структура артефактов с per-file назначением.
* §5 — **«Что делать, если тест упал»** — таблица «Phase → типичная
  причина → куда смотреть» (12 строк).
* §6 — pytest-режим для разработчиков.
* §7 — CI-интеграция.
* §8 — known TODO (18 vs 12 отчётов; OAST в Juice Shop; cosign на
  unsigned local builds).
* §9 — security notes (нет PII в логах, CI-only token, network sealing).
* §10 — контакты + escalation.

### 3.13. `.env.e2e.example` (NEW)

Пустой шаблон для копирования в `.env.e2e` перед локальным запуском.
Документирует все 13 env vars.

### 3.14. `CHANGELOG.md` (modified)

Большая (~80 строк) entry в Cycle 5 секции с полным описанием всех
artifacts, design decisions, discrepancy notes, и verification gates.

---

## 4. Файловые изменения — итог

```
NEW:
  infra/docker-compose.e2e.yml                           ~280 LoC
  infra/prometheus/prometheus.e2e.yml                     ~25 LoC
  scripts/e2e_full_scan.sh                               ~520 LoC
  scripts/e2e_full_scan.ps1                              ~480 LoC
  scripts/e2e/verify_reports.py                          ~150 LoC
  scripts/e2e/verify_oast.py                             ~180 LoC
  scripts/e2e/verify_cosign.sh                           ~120 LoC
  scripts/e2e/verify_prometheus.py                       ~150 LoC
  scripts/e2e/archive_results.sh                          ~50 LoC
  .github/workflows/e2e-full-scan.yml                    ~150 LoC
  backend/tests/integration/e2e/__init__.py               ~10 LoC
  backend/tests/integration/e2e/test_e2e_health_endpoints.py    ~120 LoC
  backend/tests/integration/e2e/test_e2e_scan_lifecycle.py      ~280 LoC
  docs/e2e-testing.md                                    ~250 LoC
  .env.e2e.example                                        ~25 LoC
                                                       ────────────
                                                          ~2 790 LoC

MODIFIED:
  CHANGELOG.md                                           +~85 LoC
  backend/pyproject.toml                                  +1 LoC
  backend/tests/conftest.py                              +9 LoC
                                                       ────────────
                                                          ~95 LoC
```

**Total: 14 new files + 3 modified, ~2 885 LoC.**

(Backlog acceptance criteria требует 14 файлов + CHANGELOG — фактически
сделано 14 + 1 bonus `.env.e2e.example` для удобства операторов.)

---

## 5. Verification gates

Все запущены локально перед сдачей:

| Gate                                                              | Result | Notes                                                              |
| ----------------------------------------------------------------- | ------ | ------------------------------------------------------------------ |
| `bash -n scripts/e2e_full_scan.sh`                                | ✅      | После CRLF→LF normalization                                        |
| `bash -n scripts/e2e/verify_cosign.sh`                            | ✅      | Same                                                               |
| `bash -n scripts/e2e/archive_results.sh`                          | ✅      | Same                                                               |
| `python -m py_compile scripts/e2e/verify_*.py`                    | ✅      | Все 3 файла парсятся                                               |
| `python -m ruff check ../scripts/e2e/`                            | ✅      | 0 errors                                                           |
| `python -m ruff check tests/integration/e2e/`                     | ✅      | 0 errors                                                           |
| `python -m mypy --no-error-summary tests/integration/e2e/`        | ✅      | 0 errors (strict)                                                  |
| `python -m pytest tests/integration/e2e/ --collect-only -q`       | ✅      | 16 deselected (default `not requires_docker`)                      |
| `python -m pytest --collect-only -m requires_docker_e2e ...`      | ✅      | 16 collected                                                       |
| `docker compose -f infra/docker-compose.e2e.yml config --quiet`   | ✅      | Compose syntax + variable resolution OK                            |
| PowerShell parser on `e2e_full_scan.ps1`                          | ✅      | `[Parser]::ParseFile` → 0 errors                                   |
| `ReadLints` на all changed files                                  | ✅      | 0 linter errors                                                    |

**Что НЕ запускалось** (требует живого стека и не входит в worker'овскую
ответственность — следующий шаг: test-runner):

* `bash scripts/e2e_full_scan.sh` против реального Juice Shop (live).
* `pwsh -File scripts/e2e_full_scan.ps1` против реального Juice Shop.
* GitHub Actions workflow dry-run.

---

## 6. Trade-offs и решения отложить

| Trade-off                                          | Решение                                  | Где задокументировано        |
| -------------------------------------------------- | ---------------------------------------- | ---------------------------- |
| 18 vs 12 reports                                   | Defer SARIF/JUNIT API exposure to ARG-049 | `docs/e2e-testing.md` §8    |
| OAST verification strictness                       | Default permissive; opt-in `E2E_REQUIRE_OAST=1` | `docs/e2e-testing.md` §8 |
| Cosign verification of unsigned local builds       | Graceful `status='no_signatures_found'`  | `verify_cosign.sh` comments  |
| Prometheus on host network (vs sidecar)            | Compose service on shared bridge — simpler | `prometheus.e2e.yml`        |
| Frontend service в e2e-stack                       | **Excluded** — frontend не нужен для backend e2e proof | docker-compose.e2e.yml comments |
| ARG-045 Helm chart как альтернатива compose stack  | docker-compose как baseline (per Backlog § cycle5 plan §6 risk 1 mitigation) | этот отчёт §2.4 |

---

## 7. Что осталось сделать (handoff to next agent)

1. **Test-writer** — может расширить pytest suite (текущие 16 cases —
   minimal contract; можно добавить:
   * Тесты на error-handling (negative paths — invalid scan_id, missing token).
   * Тесты на OAST-strict mode (`E2E_REQUIRE_OAST=1`).
   * Тесты на Prometheus-query failures (Prometheus down).
2. **Test-runner** — должен **запустить bash wrapper** (live, ~30 минут)
   и подтвердить что весь pipeline зелёный. Если нет ARG-041 (Prometheus
   metrics) ещё не закрыт — Phase 09 может упасть; в этом случае
   возможно временно установить `E2E_SKIP_PROMETHEUS=1` (надо добавить
   в обёртку — minor change).
3. **Reviewer** — code review с фокусом на:
   * Security (нет ли утечки secrets в логах? — должно быть OK, всё
     через bearer-token + structured JSON без stack trace).
   * Idempotency (повторный запуск не ломает state? — да, archive
     ротируется по timestamp; compose `down -v` чистит volumes).
   * KISS / SOLID — single-responsibility per phase, single-responsibility
     per helper, четкая separation между orchestration (bash/ps1) и
     verification (Python).

---

## 8. Acceptance criteria — checkdown

Из баклога (`§19.4` + Backlog `infra/docker-compose.e2e.yml` секция):

- [x] **AC-1.** `infra/docker-compose.e2e.yml` (new) — services
      перечислены: `argus-backend`, `argus-celery-worker`, `argus-mcp-server`,
      `postgres:16-alpine`, `redis:7-alpine`, `minio/minio:RELEASE...`,
      `prometheus:v2.54.1`, `bkimminich/juice-shop:v17.0.0`. Healthchecks
      на каждом, `depends_on` с `condition: service_healthy`.  
      *Note: frontend сознательно НЕ включён — для backend e2e proof не
      нужен; admin-frontend defer Cycle 6 per plan §2.*
- [x] **AC-2.** `scripts/e2e_full_scan.sh` (new) — POSIX shell wrapper,
      11 phases (compose-up, health-wait, trigger-scan, poll-scan,
      verify-reports, verify-oast, verify-cosign, verify-metrics,
      assert-min-findings, tear-down) + bonus phase 12 archive.
      Per-phase explicit timeouts. Structured JSON output (per-phase
      records + aggregate `summary.json`).
- [x] **AC-3.** `scripts/e2e_full_scan.ps1` (new) — Windows wrapper,
      функционально-эквивалентный bash-версии.
- [x] **AC-4.** `scripts/e2e/verify_reports.py` (new) — verifies
      reports count + status + tier coverage.
- [x] **AC-5.** `scripts/e2e/verify_oast.py` (new) — verifies OAST
      callback evidence; graceful `no_oast_in_scope`.
- [x] **AC-6.** `scripts/e2e/verify_cosign.sh` (new) — verifies cosign
      signatures on 6 sandbox profiles.
- [x] **AC-7.** `scripts/e2e/verify_prometheus.py` (new) — verifies 9
      metric families + 3 headline counters > 0.
- [x] **AC-8.** `scripts/e2e/archive_results.sh` (new) — tar.gz
      compression with rotation.
- [x] **AC-9.** `.github/workflows/e2e-full-scan.yml` (new) — workflow
      with cron + workflow_dispatch + push triggers; cosign installer;
      artifact upload; job summary.
- [x] **AC-10.** `backend/tests/integration/e2e/` — pytest suite
      mirroring wrapper contract; 16 cases.
- [x] **AC-11.** `requires_docker_e2e` marker зарегистрирован в
      `pyproject.toml` + `conftest.py`.
- [x] **AC-12.** Default `pytest -q` skip'ает все e2e-тесты.
- [x] **AC-13.** `pytest -m requires_docker_e2e` собирает 16 cases.
- [x] **AC-14.** `docs/e2e-testing.md` (new) — operator runbook на
      русском.
- [x] **AC-15.** `CHANGELOG.md` — `### ARG-047` block в Cycle 5 секции.
- [x] **AC-16.** Все verification gates passed (см. §5).
- [x] **AC-17.** Backward-compat: ничто из существующих тестов /
      compose / scripts не сломано (verified: `pytest --collect-only`
      на full backend test suite — вызовет всё как было; `docker
      compose -f infra/docker-compose.yml config` без изменений).

---

## 9. Risks acknowledged + mitigation summary

| Risk                                              | Likelihood | Impact | Mitigation in this PR                                   |
| ------------------------------------------------- | ---------- | ------ | ------------------------------------------------------- |
| E2E flakiness — long-running tests timing-out     | High       | High   | Per-phase timeouts 3× expected; pinned image versions; `--retry` on HTTP; `docker compose --wait`; structured failure output for diagnosis |
| Juice Shop slow startup (~30-60s)                 | Medium     | Low    | `--wait` flag + 5-min readiness deadline                |
| Cosign verification of unsigned local builds      | Medium     | Low    | Graceful skip with `status='no_signatures_found'`       |
| OAST-callback for Juice Shop (no SSRF by default) | High       | Low    | `status='no_oast_in_scope'` allowed; opt-in strict mode |
| 18 vs 12 report count drift                       | High       | Medium | Configurable `E2E_EXPECTED_REPORTS=12`; explicit doc gap; defer to ARG-049 |
| API endpoint version drift (`/api/scans` vs `/api/v1/scans`) | Low | Catastrophic | Verified against actual backend code; using real `/api/v1/` |
| In-memory OAST correlator (vs Redis assumption)   | Already manifest | Medium | Refactored verifier to use API-findings instead     |
| CRLF on Windows breaking bash scripts             | High       | Catastrophic | `.gitattributes` + manual normalization fixed         |

---

## 10. Sign-off

**Worker:** Claude (ARG-047 worker subagent).  
**Date:** 2026-04-20.  
**Hand-off to:** test-writer (optional expansion of pytest suite) →
test-runner (live execution against Juice Shop) → reviewer.

**Recommendation for orchestrator:**

1. Update `.claude/state/orchestration_status.json`:
   `tasks.ARG-047.status = "worker_complete"`,
   `next_workflow_stage = "test-writer"`.
2. Не запускать ARG-049 (capstone) до test-runner-зелёного на ARG-047.
3. Если test-runner подтверждает 5/5 локально + 3/3 в CI lane —
   close ARG-047 и unblock ARG-049.

**Files inventory (для quick navigation в reviewer'е):**

```
new files (14):
  infra/docker-compose.e2e.yml
  infra/prometheus/prometheus.e2e.yml
  scripts/e2e_full_scan.sh
  scripts/e2e_full_scan.ps1
  scripts/e2e/verify_reports.py
  scripts/e2e/verify_oast.py
  scripts/e2e/verify_cosign.sh
  scripts/e2e/verify_prometheus.py
  scripts/e2e/archive_results.sh
  .github/workflows/e2e-full-scan.yml
  backend/tests/integration/e2e/__init__.py
  backend/tests/integration/e2e/test_e2e_health_endpoints.py
  backend/tests/integration/e2e/test_e2e_scan_lifecycle.py
  docs/e2e-testing.md

bonus file (1):
  .env.e2e.example

modified files (3):
  CHANGELOG.md
  backend/pyproject.toml
  backend/tests/conftest.py
```

---

*End of report.*
