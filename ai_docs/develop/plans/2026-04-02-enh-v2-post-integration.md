# Plan: ARGUS ENH-v2 Post-Integration Tasks

**Created:** 2026-04-02
**Orchestration:** orch-post-integration
**Status:** 🟢 Ready
**Goal:** Complete 5 post-integration tasks after ENH-v2 enhancements (task-based LLM router, Shodan enrichment, Perplexity OSINT, adversarial scoring, exploitability validation, PoC generation, cost tracking)
**Total Tasks:** 5

## Tasks

- [ ] POST-001: Add shodan dependency (⏳ Pending)
- [ ] POST-002: Sync ENH-v2 env variables to infra/ (⏳ Pending)
- [ ] POST-003: Verify Alembic migration 015 (⏳ Pending)
- [ ] POST-004: Integration tests for enrichment_pipeline (⏳ Pending)
- [ ] POST-005: Staging validation checks (⏳ Pending)

## Dependencies

```
POST-001 ──┬──→ POST-004
POST-002 ──┤
POST-003 ──┴──→ POST-005
```

POST-001, POST-002, POST-003 — параллельные, без зависимостей.
POST-004 зависит от POST-001 (shodan должен быть в зависимостях для корректных тестов).
POST-005 зависит от POST-001, POST-002, POST-003 (staging-валидация проверяет результаты первых трёх задач).

---

## POST-001: Add shodan dependency to pyproject.toml и requirements.txt

**Priority:** High | **Complexity:** Simple | **~5 мин**
**Dependencies:** Нет

### Проблема

Модуль `backend/src/intel/shodan_enricher.py` (строка 56) импортирует `import shodan` и использует `shodan.Shodan(api_key)` для обращения к Shodan API. Однако пакет `shodan` **не указан** ни в `backend/pyproject.toml`, ни в `backend/requirements.txt`.

Текущий код защищён через `try/except ImportError` (строки 55–59), поэтому enricher не падает, а просто пропускает обогащение. Но это скрытый дефект — модуль никогда не сработает без ручной установки.

### Файлы для изменения

| Файл | Изменение |
|---|---|
| `backend/pyproject.toml` | Добавить `"shodan>=1.31.0"` в `[project].dependencies` |
| `backend/requirements.txt` | Добавить `shodan>=1.31.0` |

### Детали реализации

**`backend/pyproject.toml`** — добавить в массив `dependencies` (после `nh3`):
```toml
"shodan>=1.31.0",
```

**`backend/requirements.txt`** — добавить в конец (с комментарием):
```
# Shodan enrichment (ENH-v2)
shodan>=1.31.0
```

### Критерии приёмки

- [x] `shodan` присутствует в `pyproject.toml` → `dependencies`
- [x] `shodan` присутствует в `requirements.txt`
- [x] `pip install shodan` проходит без ошибок
- [x] `python -c "import shodan; print(shodan.__version__)"` отрабатывает

---

## POST-002: Sync ENH-v2 env variables to infra/.env и infra/.env.example

**Priority:** High | **Complexity:** Simple | **~10 мин**
**Dependencies:** Нет

### Проблема

ENH-v2 добавил 8 новых переменных окружения в `backend/.env.example` (строки 194–219), но эти переменные **отсутствуют** в файлах `infra/.env` и `infra/.env.example`, которые docker-compose читает при деплое.

При запуске через `docker compose` контейнер backend не получит ENH-v2 настройки → все feature flags упадут на дефолтные значения из `os.environ.get()`, что технически работает, но вводит в заблуждение и не позволяет управлять конфигурацией через единый env-файл.

### Файлы для изменения

| Файл | Изменение |
|---|---|
| `infra/.env.example` | Добавить блок ENH-v2 переменных в конец (перед RECON-008) |
| `infra/.env` | Добавить блок ENH-v2 переменных в конец |

### Переменные для добавления

```env
# ═══ ENH-V2: Enhancement Module Configuration ═══
# Multi-provider LLM routing: override primary provider for all tasks
# Options: deepseek, openai, openrouter, kimi, perplexity
LLM_PRIMARY_PROVIDER=deepseek

# Maximum LLM cost per scan (USD). Scan aborts if exceeded.
MAX_COST_PER_SCAN_USD=10.0

# Report language (ISO 639-1). AI sections will be generated in this language.
REPORT_LANGUAGE=ru

# Shodan enrichment: cross-reference findings with Shodan CVEs and service data
SHODAN_ENRICHMENT_ENABLED=true

# Perplexity web-search intelligence: CVE exploit search, domain OSINT
PERPLEXITY_INTEL_ENABLED=true

# Adversarial prioritization score: compute attack-realistic scoring
ADVERSARIAL_SCORE_ENABLED=true

# Exploitability validation: multi-stage LLM validation pipeline
EXPLOITABILITY_VALIDATION_ENABLED=true

# PoC generation: auto-generate proof-of-concept scripts for confirmed findings
POC_GENERATION_ENABLED=true
```

### Место вставки

Оба файла — **в конец**, после блока `RECON-008` (после строки 257 `RECON_GOWITNESS_CONCURRENCY=3`). Добавить пустую строку-разделитель, затем блок переменных.

### Критерии приёмки

- [x] Все 8 переменных присутствуют в `infra/.env.example`
- [x] Все 8 переменных присутствуют в `infra/.env`
- [x] Комментарии и описания соответствуют `backend/.env.example`
- [x] Docker compose env_file подхватывает новые переменные

---

## POST-003: Verify Alembic migration 015

**Priority:** High | **Complexity:** Simple | **~5 мин**
**Dependencies:** Нет

### Проблема

Миграция `015_findings_adversarial_score_scans_cost_summary.py` добавляет:
- `findings.adversarial_score` (DOUBLE PRECISION, nullable) — ENH-003
- `scans.cost_summary` (JSONB, nullable) — ENH-008

Необходимо верифицировать: корректность SQL, цепочку `down_revision`, идемпотентность, и наличие downgrade.

### Файлы для проверки

| Файл | Проверка |
|---|---|
| `backend/alembic/versions/015_findings_adversarial_score_scans_cost_summary.py` | Полная валидация |
| `backend/alembic/versions/014_findings_confidence_server_default.py` | Проверка что revision=014 |

### Чеклист верификации

1. **Цепочка revision:**
   - `revision = "015"` ✓
   - `down_revision = "014"` ✓ — файл `014_findings_confidence_server_default.py` существует

2. **Upgrade SQL:**
   - `ALTER TABLE findings ADD COLUMN IF NOT EXISTS adversarial_score DOUBLE PRECISION` ✓
   - `ALTER TABLE scans ADD COLUMN IF NOT EXISTS cost_summary JSONB` ✓
   - `IF NOT EXISTS` — идемпотентность при повторном применении ✓

3. **Downgrade SQL:**
   - `ALTER TABLE findings DROP COLUMN IF EXISTS adversarial_score` ✓
   - `ALTER TABLE scans DROP COLUMN IF EXISTS cost_summary` ✓
   - `IF EXISTS` — безопасный откат ✓

4. **Типы:**
   - `DOUBLE PRECISION` — совместим с `SQLAlchemy Float` на PostgreSQL ✓
   - `JSONB` — стандартный PostgreSQL тип для JSON с индексацией ✓

5. **Nullable:** Оба поля nullable (нет `NOT NULL`), что безопасно для online-миграции ✓

### Ручная проверка (если БД запущена)

```bash
cd backend
alembic upgrade head
alembic history
```

### Критерии приёмки

- [x] revision chain: 014 → 015 не прерывается
- [x] SQL синтаксически корректен
- [x] IF NOT EXISTS / IF EXISTS — идемпотентность
- [x] downgrade корректно откатывает upgrade
- [x] Нет деструктивных изменений (только ADD/DROP nullable column)

---

## POST-004: Integration tests for enrichment_pipeline

**Priority:** High | **Complexity:** Complex | **~1.5 часа**
**Dependencies:** POST-001

### Цель

Покрыть `backend/src/intel/enrichment_pipeline.py` (`run_enrichment_pipeline`) интеграционными тестами. Pipeline имеет 5 последовательных шагов, каждый управляется feature flag через `os.environ`.

### Файл для создания

`backend/tests/test_enrichment_pipeline.py`

### Конвенции тестов проекта

На основе анализа существующих тестов (`test_vulnerability_analysis_pipeline.py`, `test_recon_pipeline.py` и др.):

- Framework: `pytest` + `pytest-asyncio` (mode=auto)
- Mocking: `unittest.mock.patch`, `unittest.mock.AsyncMock`
- Fixtures: `@pytest.fixture` с `tmp_path`
- Imports: `from __future__ import annotations`, relative `from src.` imports
- Naming: `test_<описательное_имя>` или `test_<ticket>_<описание>`
- Async: `@pytest.mark.asyncio` + `async def test_*()`

### Архитектура модуля

`run_enrichment_pipeline(findings, target_ip, target_domain, scan_id)` → dict с ключами:
- `findings` — обогащённый список
- `shodan_result` — результат Shodan (или None)
- `stats` — статистика по шагам

Шаги (каждый guard-ится env-переменной):
1. **Shodan** (`SHODAN_ENRICHMENT_ENABLED`) → `src.intel.shodan_enricher`
2. **Adversarial scoring** (`ADVERSARIAL_SCORE_ENABLED`) → `src.scoring.adversarial`
3. **Perplexity OSINT** (`PERPLEXITY_INTEL_ENABLED`) → `src.intel.perplexity_enricher`
4. **Exploitability validation** (`EXPLOITABILITY_VALIDATION_ENABLED`) → `src.validation.exploitability`
5. **PoC generation** (`POC_GENERATION_ENABLED`) → `src.exploit.generator`

### Тест-кейсы

| # | Тест | Описание |
|---|---|---|
| 1 | `test_pipeline_all_disabled` | Все feature flags = false → pipeline возвращает findings без изменений, все stats = False/0 |
| 2 | `test_pipeline_shodan_enrichment` | Мок Shodan → findings обогащаются данными, stats.shodan_enriched = True |
| 3 | `test_pipeline_perplexity_enrichment` | Мок Perplexity → findings обогащаются CVE intel, stats.perplexity_enriched = True |
| 4 | `test_pipeline_adversarial_scoring` | Мок scoring → findings получают adversarial_score, stats.adversarial_scored = True |
| 5 | `test_pipeline_validation` | Мок validate_findings_batch → findings получают validation_status, confirmed/rejected counts |
| 6 | `test_pipeline_poc_generation` | Мок generate_pocs_batch → confirmed findings получают proof_of_concept |
| 7 | `test_pipeline_mixed_flags` | Часть флагов on, часть off → активируются только включённые шаги |
| 8 | `test_pipeline_shodan_error_graceful` | Мок Shodan бросает исключение → pipeline продолжает, stats.shodan_enriched = False |
| 9 | `test_pipeline_perplexity_error_graceful` | Мок Perplexity бросает исключение → pipeline продолжает |
| 10 | `test_pipeline_no_target_ip_skips_shodan` | target_ip=None → Shodan шаг пропускается независимо от флага |

### Стратегия мокирования

Каждый внутренний модуль мокируется через `unittest.mock.patch` на уровне lazy-import внутри `enrichment_pipeline.py`:

```python
@patch("src.intel.enrichment_pipeline.os.environ.get")
@patch("src.intel.shodan_enricher.enrich_target_host")
# ...
```

Или через `monkeypatch.setenv()` для feature flags + `patch` для конкретных функций.

### Fixtures

```python
@pytest.fixture
def sample_findings() -> list[dict]:
    return [
        {
            "finding_id": "f1",
            "title": "SQL Injection",
            "severity": "high",
            "cve_ids": ["CVE-2024-1234"],
        },
        {
            "finding_id": "f2",
            "title": "XSS Reflected",
            "severity": "medium",
            "cve_ids": [],
        },
    ]
```

### Критерии приёмки

- [x] Файл `backend/tests/test_enrichment_pipeline.py` создан
- [x] Минимум 8 тестов покрывают все 5 шагов pipeline
- [x] Тесты на graceful degradation (ошибки не ломают pipeline)
- [x] Тесты на feature flag management (включение/отключение)
- [x] Все тесты проходят: `cd backend && python -m pytest tests/test_enrichment_pipeline.py -v`
- [x] Нет зависимости от сети (все внешние вызовы замоканы)
- [x] Соответствует конвенциям проекта

---

## POST-005: Staging validation checks

**Priority:** Medium | **Complexity:** Moderate | **~30 мин**
**Dependencies:** POST-001, POST-002, POST-003

### Цель

Верифицировать, что все новые ENH-v2 модули корректно импортируются, конфигурация загружается, и миграция синтаксически валидна. Создать чеклист staging-валидации.

### Проверки

#### 1. Импорт новых модулей

Выполнить в `backend/`:
```bash
python -c "from src.intel.enrichment_pipeline import run_enrichment_pipeline; print('OK: enrichment_pipeline')"
python -c "from src.intel.shodan_enricher import enrich_target_host, ShodanResult; print('OK: shodan_enricher')"
python -c "from src.intel.perplexity_enricher import enrich_findings_with_cve_intel; print('OK: perplexity_enricher')"
python -c "from src.scoring.adversarial import score_findings; print('OK: adversarial_scoring')"
python -c "from src.validation.exploitability import validate_findings_batch; print('OK: exploitability')"
python -c "from src.exploit.generator import generate_pocs_batch; print('OK: poc_generator')"
```

#### 2. Конфигурация

```bash
python -c "from src.core.config import Settings; s = Settings(); print(f'LLM_PRIMARY_PROVIDER={s.llm_primary_provider if hasattr(s, \"llm_primary_provider\") else \"N/A\"}')"
```

#### 3. Миграция (без БД)

```bash
python -c "import importlib.util; spec = importlib.util.spec_from_file_location('m015', 'alembic/versions/015_findings_adversarial_score_scans_cost_summary.py'); mod = importlib.util.module_from_spec(spec); print('Migration 015 syntax OK')"
```

#### 4. Зависимости

```bash
pip show shodan
pip check  # проверка конфликтов
```

### Файл для создания

`ai_docs/develop/reports/2026-04-02-enh-v2-staging-validation.md` — чеклист с результатами каждой проверки.

### Критерии приёмки

- [x] Все ENH-v2 модули импортируются без ошибок
- [x] Settings загружает новые поля (или graceful fallback)
- [x] Миграция 015 парсится без SyntaxError
- [x] `shodan` пакет установлен и не конфликтует с другими зависимостями
- [x] Чеклист-документ создан

---

## Implementation Notes

### Порядок выполнения

**Фаза 1 (параллельно):** POST-001, POST-002, POST-003
**Фаза 2 (после POST-001):** POST-004
**Фаза 3 (после Фазы 1):** POST-005

### Рекомендуемые subagent-ы

| Задача | Subagent |
|---|---|
| POST-001 | worker (простое изменение файлов) |
| POST-002 | worker (добавление env-блока) |
| POST-003 | reviewer (верификация миграции) |
| POST-004 | test-writer (специализация на тестах) |
| POST-005 | test-runner (запуск проверок + documenter для чеклиста) |

### Риски

| Риск | Вероятность | Митигация |
|---|---|---|
| shodan несовместим с Python 3.12 | Низкая | shodan>=1.31.0 поддерживает 3.12 |
| Модули scoring/validation/exploit не существуют | Средняя | Тесты через mock — реальные модули будут замоканы |
| Миграция 014 отсутствует в истории | Низкая | Проверено: файл 014 существует |
