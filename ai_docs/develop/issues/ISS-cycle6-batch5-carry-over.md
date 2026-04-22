# Cycle 6 Batch 5 — carry-over

**Дата:** 2026-04-22  
**Статус:** краткий список follow-up после закрытия T37–T45  

---

## Открытые темы (наследие, не блокеры батча)

1. **ISS-T26-001** — при расширении axe Playwright на `/admin/webhooks/dlq` и диалоги replay/abandon убедиться, что контраст и роли соответствуют WCAG AA (или зафиксировать `test.fail` до polish PR).
2. **ISS-T20-003** — до production launch заменить admin identity shim на JWT/session (см. Batch 3/4 отчёты).
3. **CI** — периодически пинить версию Kyverno chart при обновлении kind/K8s matrix (см. `admission-policy-kind.yml` env).

## Пусто / нет новых отложенных фич из scope Batch 5

Rate-limit Redis для DLQ replay (roadmap risk R4) остаётся опциональным усилением, не входил в обязательный scope T40.
