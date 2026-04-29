# Plan: Valhalla / reporting pipeline closeout

**Created:** 2026-04-27  
**Orchestration:** `orch-2026-04-27-rpt-valhalla-closeout`  
**Trigger:** `/orchestrate` без явного текста — область **выведена** из текущего working tree (изменения вокруг Valhalla, отчётов, FE report, infra).  
**Total tasks:** 6 (≤10; при расползании snapshot/интеграций — вынести фазу 2 отдельной оркестрацией).

## Goal

Довести до согласованного состояния цепочку **генерации/экспорта отчётов Valhalla**: backend pipeline и quality gate, шаблоны и PDF/CSS, контракт API с Frontend, UI отчёта, автотесты и снапшоты, инфраструктурная прокладка API — без расширения объёма за пределы уже затронутых в репозитории файлов.

## Inferred scope (git / paths)

- `backend/src/reports/*`, `backend/src/api/routers/reports.py`, `backend/src/services/reporting.py`, промпты/VA по необходимости только если блокируют отчёт.
- `Frontend/src/app/report/page.tsx`, `Frontend/src/lib/reports.ts` (+ tests).
- `infra/docker-compose.yml`, `infra/nginx/conf.d/api.conf` при необходимости маршрутизации.

## Dependencies (high level)

```
RPT-001 ─┬─► RPT-002 ───┐
         ├─► RPT-003 ─► RPT-004 ─┬─► RPT-005
         │                        │
         └─ (RPT-003) ───────────► RPT-006
```

После **RPT-001** задачи **RPT-002** и **RPT-003** можно выполнять **параллельно** разными воркерами. **RPT-005** — после **RPT-002** и **RPT-004**. **RPT-006** — после **RPT-003** (можно параллельно с RPT-002/RPT-004 до merge, если нет конфликтов файлов).

## Tasks

### RPT-001 — Backend report pipeline (Critical)

- **Priority:** Critical  
- **Complexity:** Complex  
- **Areas:** `backend/src/reports/` (pipeline, quality gate, dedup, collectors, valhalla context/normalization), связанные изменения в `report_service`, `generators`.  
- **Acceptance:** Quality gate и сбор данных для Valhalla работают предсказуемо; нет регрессий в существующих unit-тестах отчётов; логи структурированные, без утечки секретов.

### RPT-002 — Valhalla templates & renderer (High)

- **Priority:** High  
- **Complexity:** Moderate  
- **Depends on:** RPT-001  
- **Areas:** `backend/src/reports/templates/reports/partials/valhalla/*`, `valhalla.html.j2`, `valhalla_tier_renderer.py`, `templates/reports/valhalla/pdf_styles.css`.  
- **Acceptance:** Рендер обязательных секций согласован с pipeline; PDF стили не ломают печать; при необходимости обновлены снапшоты в **RPT-005**.

### RPT-003 — Reports API & schemas ↔ contract (Critical)

- **Priority:** Critical  
- **Complexity:** Moderate  
- **Depends on:** RPT-001  
- **Areas:** `docs/api-contracts.md` (если меняется контракт), `backend/src/api/routers/reports.py`, `backend/src/api/schemas.py`.  
- **Acceptance:** Поведение соответствует **Frontend как источнику истины** per workspace rule; ошибки API не раскрывают стеки клиенту.

### RPT-004 — Frontend report UI & lib (High)

- **Priority:** High  
- **Complexity:** Moderate  
- **Depends on:** RPT-003  
- **Areas:** `Frontend/src/app/report/page.tsx`, `Frontend/src/lib/reports.ts`, `Frontend/src/app/page.tsx` только если задело отчёт.  
- **Acceptance:** Типы и вызовы совпадают с контрактом; состояния загрузки/ошибок без утечки внутренних деталей.

### RPT-005 — Tests & snapshots (High)

- **Priority:** High  
- **Complexity:** Moderate  
- **Depends on:** RPT-002, RPT-004  
- **Areas:** `backend/tests/reports/*`, `backend/tests/test_report_*.py`, снапшоты `backend/tests/snapshots/reports/*`, `Frontend/src/lib/reports.test.ts`.  
- **Acceptance:** Целевые pytest/vitest зелёные; снапшоты обновлены осознанно при смене эталона.

### RPT-006 — Infra routing (Medium)

- **Priority:** Medium  
- **Complexity:** Simple  
- **Depends on:** RPT-003  
- **Areas:** `infra/docker-compose.yml`, `infra/nginx/conf.d/api.conf`.  
- **Acceptance:** Маршруты к API отчётов согласованы с тем, как FE ходит в backend в целевом деплое; секреты только через env.

## Phase 2 (optional split)

Если **RPT-005** раздувается (полный E2E, все tier снапшоты): остановить оркестрацию после RPT-004; завести `orch-*-rpt-testing-wave2` только для тестов и CI.

## Progress (orchestrator)

| ID | Task | Status |
|----|------|--------|
| RPT-001 | Backend pipeline | ⏳ Pending |
| RPT-002 | Templates/renderer | ⏳ Pending |
| RPT-003 | API contract | ⏳ Pending |
| RPT-004 | Frontend | ⏳ Pending |
| RPT-005 | Tests/snapshots | ⏳ Pending |
| RPT-006 | Infra | ⏳ Pending |

## Verification (global)

- Backend: targeted `pytest` для изменённых модулей отчётов + при необходимости полный `backend/tests/reports`.  
- Frontend: `npm test` / project script для `reports.test.ts`.  
- Ревью: соответствие api-contract и отсутствие утечек в ответах ошибок.
