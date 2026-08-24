# Design — ARGUS Profile & Orchestration Rework

## 1. Текущая архитектура (as-is)

### 1.1 Scan create
- `POST /api/v1/scans` (`backend/src/api/routers/scans.py:398`) принимает `ScanCreateRequest`
  (`backend/src/api/schemas.py:209`) с полями `scan_mode` (depth) и `execution_mode` (immutable).
- Логика: `parse_requested_execution_mode` + `assert_execution_mode_payload` (`backend/src/quick/create.py`).
  При `execution_mode=quick` форсится `scan_mode=quick`, резолвится `quick_profile`.
- Колонки `Scan` (`backend/src/db/models.py:173`): `scan_mode`, `execution_mode`, `deadline_at`,
  `quick_profile`. `engagement_id`, `lab_lease_id`, `nuclei_profile` — только в `options` JSONB.
- LAB lease/scope: `execution_mode/` пакет + таблицы `lab_scope_manifests`, `lab_execution_leases`,
  `engagement_execution_modes`. Runtime resolution: `orchestration/execution_mode_context.py`.
- Alembic head: `058`.

### 1.2 Reports
- Нет канонического snapshot. Двухслойно: `ScanReportData` (сбор, `reports/data_collector.py`)
  и `ReportData` (рендер, `reports/generators.py`).
- Форматы: PDF/HTML/JSON/CSV/MD (`generators.py`), SARIF/JUnit отдельно. Нет generic XML.
- Тиры Asgard/Midgard/Valhalla: `reports/tier_classifier.py`.
- Хранилище: MinIO bucket `argus-reports`. Таблица `report_objects (report_id, format, object_key, size_bytes)`.

### 1.3 Frontend
- Главная `/` (`Frontend/src/app/page.tsx`) → `POST /api/scans` (Next route) → `Frontend/src/lib/scans.ts`
  (in-memory Map + `setTimeout` + hardcoded findings из `scan-results.ts`/`live-findings.ts`).
- Параллельно есть реальный клиент `Frontend/src/lib/api.ts` + `labApi.ts` для `/api/v1`, но он
  не подключён к главному потоку.
- UI-тиры: `free`/`standard`/`premium` (billing), не `quick`/`light`/`deep`.

## 2. Целевая архитектура (to-be)

```
UI (quick|light|deep)
   → Next route /api/scans (proxy, tenant/correlation/idempotency headers)
      → backend POST /api/v1/scans { scan_profile, engagement_id?, lab_lease_id? }
         → ProfileResolver.resolve(scan_profile, ...) → ResolvedScanProfile (frozen)
            → LAB lease preflight (deep only)
            → persist Scan(scan_profile, resolved_scan_mode, execution_mode, quick_profile,
                            nuclei_profile, engagement_id?, lab_lease_id?, profile_version)
            → queue
   → State machine (phases/tools/budgets driven by ResolvedScanProfile, durable checkpoints)
      → LLM intent → deterministic compiler → tool job → parser → evidence store → verifier
      → coverage engine
   → reporting: ReportDocumentV1 snapshot → JSON/MD/XML/PDF renderers (parity)
```

## 3. API contracts

### 3.1 POST /api/v1/scans (расширение, backward compatible)

Request (новое каноническое поле + legacy):
```jsonc
{
  "target": "https://example.com",
  "email": "operator@example.com",
  "scan_profile": "quick",              // NEW canonical: quick|light|deep
  "quick": { "profile": "balanced" },   // quick sub-options (deep/light ignore)
  "engagement_id": "engagement-uuid",   // NEW (required for deep)
  "lab_lease_id": "lease-uuid",         // NEW (required for deep)
  // legacy (deprecated, backward compat):
  "scan_mode": "standard",
  "execution_mode": null,
  "options": { "scanType": "quick" }
}
```

Правила разрешения:
1. Если `scan_profile` задан — он источник истины; внутренние mode вычисляет ProfileResolver.
2. Если задан `scan_profile` и legacy `scan_mode`/`execution_mode`, которые конфликтуют с
   разрешёнными профилем значениями → `422 conflicting_profile_fields`.
3. Если `scan_profile` не задан — работает legacy-путь (обратная совместимость):
   `scan_mode`/`execution_mode` как раньше. `scan_mode=deep` остаётся production-deep.
4. Неизвестный `scan_profile` → `422 invalid_scan_profile`.
5. `deep` без `engagement_id` → `lab_engagement_required`; без `lab_lease_id` → `lab_lease_required`.

### 3.2 Scan response (расширение)
Добавляются поля (nullable для legacy scans):
`scan_profile`, `resolved_scan_mode`, `execution_mode`, `quick_profile`, `nuclei_profile`,
`engagement_id`, `lab_lease_id`, `profile_version`, `report_snapshot_version`.

### 3.3 Единый error contract
```jsonc
{ "error": { "code": "lab_lease_required", "message": "...", "details": {}, "correlation_id": "..." } }
```
Коды: `invalid_scan_profile`, `conflicting_profile_fields`, `lab_engagement_required`,
`lab_scope_required`, `lab_lease_required`, `lab_lease_expired`, `lab_lease_revoked`,
`lab_lease_tenant_mismatch`, `target_out_of_lab_scope`, `profile_capability_denied`,
`payload_family_denied`, `tool_unavailable`, `parser_unavailable`, `budget_exhausted`,
`report_snapshot_unavailable`, `report_generation_failed`.

## 4. Модели данных

### 4.1 Scan (новые колонки, миграция 059)
| Колонка | Тип | Null | Назначение |
|---------|-----|------|------------|
| `scan_profile` | VARCHAR(16) | Y | quick\|light\|deep (external canonical); null для legacy scans |
| `resolved_scan_mode` | VARCHAR(20) | Y | зеркало resolved scan_mode (для аналитики/idempotent resume) |
| `nuclei_profile` | VARCHAR(64) | Y | resolved nuclei profile id |
| `engagement_id` | VARCHAR(36) | Y | для deep |
| `lab_lease_id` | VARCHAR(36) | Y | для deep |
| `profile_version` | VARCHAR(16) | Y | версия резолвера (`v1`) |
| `report_snapshot_version` | VARCHAR(16) | Y | версия snapshot схемы (`v1`) |

`scan_mode`, `execution_mode`, `deadline_at`, `quick_profile` — уже существуют (058).
Миграция аддитивная (все новые колонки nullable) → сохранённые старые scans не меняют семантику (P6).

### 4.2 ReportDocumentV1 (in-memory canonical snapshot + persisted JSON)
Хранится как канонический JSON-артефакт в MinIO (`.../reports/_snapshot/{report_id}.snapshot.json`)
и/или в `report_objects` c format=`snapshot`. Поля — см. раздел 7.

## 5. Profile Resolver

Новый модуль `backend/src/profiles/` — единая точка резолва.

```python
class ScanProfile(StrEnum):          # external canonical
    QUICK = "quick"; LIGHT = "light"; DEEP = "deep"

@dataclass(frozen=True)
class ResolvedScanProfile:
    external_profile: ScanProfile
    scan_mode: str                   # quick|standard|lab
    execution_mode: ExecutionMode    # quick|production|lab_unrestricted
    quick_profile: str | None        # balanced|compact|extended (quick only)
    nuclei_profile: str              # quick-default|vuln_default|lab_unrestricted
    requires_lab_lease: bool
    tool_capability_set: str         # production_safe|production_active|lab_unrestricted
    payload_risk_ceiling: str        # low|medium|high
    approval_policy: str             # auto|gated|lease_bound
    budget_class: str                # quick_bounded|production_bounded|lab_unbounded
    report_policy: str               # partial_ok|standard|full_evidence
    profile_version: str = "v1"
```

Mapping:
| external | scan_mode | execution_mode | quick_profile | nuclei_profile | lease | capability_set | risk_ceiling | approval | budget | report |
|----------|-----------|----------------|---------------|----------------|-------|----------------|--------------|----------|--------|--------|
| quick | quick | quick | balanced* | quick-default | нет | production_safe | low | auto | quick_bounded | partial_ok |
| light | standard | production | — | vuln_default | нет | production_active | medium | gated | production_bounded | standard |
| deep | lab | lab_unrestricted | — | lab_unrestricted | да | lab_unrestricted | high | lease_bound | lab_unbounded | full_evidence |

*Quick `quick_profile` берётся из `quick.profile` (compact/balanced/extended), по умолчанию `balanced`.

Функция `detect_legacy_conflict(scan_profile, legacy_scan_mode, legacy_execution_mode)` возвращает
список конфликтующих полей для `422 conflicting_profile_fields`.

## 6. Workflow Quick / Light / Deep

- **Quick:** ProfileResolver→quick; переиспользуется существующий `resolve_quick_runtime`
  (budget/deadline/quick rows). Phase skipping разрешён, exploitation — только safe validation,
  всегда partial report.
- **Light:** production-safe полный web workflow, bounded active checks, approval gates сохраняются.
- **Deep:** lease preflight (см. §8) до старта и перед destructive-фазами; capture_full evidence;
  lease expiry → останов опасных действий.

## 7. LAB lease validation

Preflight-функция `preflight_lab_lease(session, tenant_id, engagement_id, lab_lease_id, target)`:
1. `engagement_id` пуст → `lab_engagement_required`.
2. `lab_lease_id` пуст → `lab_lease_required` (+ engagement_id, required_action).
3. lease не найден → `lab_lease_required`.
4. lease.tenant_id != tenant → `lab_lease_tenant_mismatch`.
5. lease.engagement_id != engagement_id → `lab_engagement_required`.
6. lease.status == revoked → `lab_lease_revoked`.
7. lease.expires_at < now → `lab_lease_expired`.
8. scope manifest отсутствует → `lab_scope_required`.
9. target вне scope allowlist → `target_out_of_lab_scope`.
Иначе — allow, возвращает proof-ссылку для checkpoint.

Реализация опирается на существующие модели `execution_mode/models.py` и `lab_lease.py`.

## 8. Tool / payload / prompt registries

- **Tools:** `backend/config/tools/*.yaml` (signed) — единый source of truth. Генерация каталога,
  MCP-дефиниций, manifest, presets, healthchecks, parser mapping, risk/approval из descriptor.
  Регистрация MCP tool только при наличии executable+compiler+parser+healthcheck и разрешении profile.
- **Parser fallback:** не создаёт INFO finding; создаёт raw artifact + `parser_status=unparsed`
  + coverage reason=`parser_unavailable`.
- **Payloads:** signed registry source of truth; taxonomy-based mapping; PayloadBuilder —
  bounded deterministic expansion + dedup + stable hash + provenance.
- **Prompts:** `backend/config/prompts/*.yaml` + `backend/app/prompts/*.md`. Санитизация legacy
  инструкций; добавление untrusted-data guardrails и разрешения abstain.

## 9. LLM orchestration

Цепочка: Evidence/context → Planner → typed ValidationPlan → Critic → Policy/Capability Compiler
→ Tool Job → Parser/Normalizer → Evidence Store → Verifier → Finding lifecycle → Coverage → next/stop → Reporter.

LLM возвращает только typed intent (schema из раздела 8 задания). Deterministic compiler
валидирует schema/scope/profile/lease/approvals/budget, резолвит tool/payload id, строит argv
без `shell=True`, создаёт job. Все вызовы — через единый facade (`backend/src/llm/facade.py`) с
redaction/policy/budget/versions/trace.

## 10. Report pipeline

`ReportDocumentV1` (Pydantic, `backend/src/reports/report_document.py`) — канонический snapshot:
`schema_version`, `scan_id`, `tenant_id`, `target`, `scan_profile`, `resolved_scan_mode`,
`execution_mode`, `quick_profile`, `nuclei_profile`, `started_at`, `completed_at`, `scope_summary`,
`profile_limits`, `tool_runs`, `tested_capabilities`, `not_assessed_capabilities`, `coverage`,
`findings[]` (с `finding_id`, `evidence_ids`, `tool_run_id`, `confidence`, `verification_status`),
`evidence_references`, `oast_references`, `failures`, `skipped_reasons`, `budget_usage`,
`limitations`, `prompt_model_versions`, `registry_versions`, `generated_at`, `snapshot_hash`.

`snapshot_hash` = SHA-256 канонического JSON (без самого поля hash и без generated_at).

Рендереры (`backend/src/reports/renderers/`): `render_json`, `render_markdown`, `render_xml`,
`render_html` (→ PDF через существующий `pdf_backend`). Все читают только snapshot.

Evidence gate: finding со статусом confirmed/exploitable без `evidence_ids` → downgrade в
`insufficient_evidence` + validation error (P5). AI narrative без evidence refs → отклонение секции.

## 11. State machine

Стадии не меняются. Выбор стадий/tools/budgets — из `ResolvedScanProfile`. Durable checkpoint
(`orchestration/checkpoints`) хранит resolved profile (frozen), phase, remaining budget, scope hash,
lease state, registry versions, report snapshot status. Resume читает immutable profile context.

## 12. Обработка ошибок

Единый helper `backend/src/api/errors.py` (`ArgusError`, `error_response`) формирует
`{ "error": { code, message, details, correlation_id } }`; FastAPI exception handler
маппит внутренние исключения; stack trace/secrets не попадают в тело.

## 13. Тестовая стратегия

- Unit: ProfileResolver (все маппинги/конфликты/legacy), LAB preflight (все ветки), report
  snapshot+parity, prompt integrity, payload taxonomy/dedup/replay, tool registry drift.
- Integration/e2e: Quick/Light против локальных vulnerable targets, Deep с lease и без, report
  generation per profile, cancel/resume.
- Frontend: vitest (createScan real fetch, profile mapping, errors), lint, build, Playwright.

## 14. Совместимость и rollout

- Все изменения БД аддитивны (nullable columns) → безопасный rollback.
- `scan_profile` опционален; отсутствие → legacy-путь.
- Legacy `scan_mode=deep` без `scan_profile` = production-deep (deprecated), не LAB.
- Feature flags: `quick_mode_enabled` (существует). Новый резолвер активируется наличием `scan_profile`.
- Frontend proxy имеет graceful degradation: при недоступном backend — понятная ошибка в UI,
  без падения рендера.
