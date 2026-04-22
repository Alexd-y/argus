# Отчёт: ARGUS Cycle 6 — Batch 5 (Webhook DLQ + Kyverno admission)

**Дата:** 2026-04-22  
**Оркестрация:** `orch-2026-04-22-argus-cycle6-b5`  
**Status:** ✅ **COMPLETED** — все 9 задач (T37–T45): персистентная DLQ, admin API, Celery replay, UI, Kyverno/Helm/CI, operator runbooks  

**Backlog:** ARG-053 (webhook DLQ), ARG-054 (Sigstore/Kyverno supply-chain gate)

---

## TL;DR

Batch 5 закрыл **операторскую DLQ для webhook-доставок** и **кластерный admission-gate для подписанных образов**. Код T37–T44 был внедрён в репозитории до финального закрытия батча; финальный шаг оркестрации — **T45**: runbooks `docs/admission-policy.md` (EN) и `docs/webhook-dlq.md` (RU), правка формулировок по ревью, верификация pytest/tsc. Отклонение от roadmap: миграция DLQ — **`027_webhook_dlq.py`** (цепочка после `026_scan_schedules`), а не «025» в тексте roadmap.

---

## Задачи T37–T45 (сводка)

| ID | Тема | Артефакты |
|----|------|-----------|
| T37 | Alembic DLQ | `backend/alembic/versions/027_webhook_dlq.py` |
| T38 | Persistence | `backend/src/mcp/services/notifications/webhook_dlq_persistence.py` |
| T39 | Admin API | `backend/src/api/routers/admin_webhook_dlq.py`, `main.py` |
| T40 | Celery replay | `backend/src/celery/tasks/webhook_dlq_replay.py`, `beat_schedule.py` |
| T41 | Frontend | `Frontend/src/app/admin/webhooks/dlq/*`, `Frontend/src/lib/adminWebhookDlq.ts`, навигация, E2E mock |
| T42 | Kyverno SoT | `infra/kyverno/cluster-policy-require-signed-images.yaml` |
| T43 | Helm | `infra/helm/argus/templates/kyverno-cluster-policy.yaml`, `policy.enabled` |
| T44 | CI | `.github/workflows/admission-policy-kind.yml`, `helm-validation.yml` (policy gate) |
| T45 | Docs | `docs/admission-policy.md`, `docs/webhook-dlq.md` |

---

## Верификация

- **Backend:** целевые pytest по DLQ (admin API, persistence, Celery, migration, RLS) — зелёные; RLS-изоляция на Postgres — skip на SQLite (ожидаемо).
- **Frontend:** `npx tsc --noEmit` в `Frontend/` — OK.
- **CI:** полный прогон `admission-policy-kind` в этом закрытии не дублировался; локальная сверка workflow с документацией выполнена на ревью.

---

## Production / pre-launch (не закрыто этим батчем)

- **ISS-T20-003** — JWT/session вместо cookie-shim для публичного admin.
- **ISS-T26-001** — контраст / axe для новых admin-поверхностей (в т.ч. при добавлении сценариев для `/admin/webhooks/dlq`).

---

## Что разблокирует Batch 6

По roadmap: PDF/A, KEV-aware HPA, прочие T46–T53.

---

## Ссылки

- План: `ai_docs/develop/plans/2026-04-22-argus-cycle6-b5.md`
- Roadmap: `Backlog/dev1_finalization_roadmap.md` §Batch 5
- Carry-over: `ai_docs/develop/issues/ISS-cycle6-batch5-carry-over.md`
