# ARGUS — Полная стабилизация (TASK)

owner для всех задач: **Cursor**. Статусы обновляются ТОЛЬКО после фактической
проверки командой и её exit code.

Легенда: `[ ]` не начато · `[~]` частично/в работе · `[x]` подтверждено.

---

## T1. Изолированный контейнерный стенд зависимостей — `[x]`
Result: `infra/docker-compose.validation.yml` + `infra/.env.validation.example`;
проект `argus-validation` поднят, pg/redis/minio `healthy`.
Subtasks:
- [x] Compose-файл (отдельные имена/тома/порты; disposable volumes).
- [x] `docker compose ... config` exit 0.
- [x] pg `accepting connections`, redis `PONG`, minio `healthy`.
_Requirements: R1._

## T2. Alembic upgrade/downgrade round-trip — `[x]`
Result: `alembic upgrade head` (→059) и `alembic downgrade base` — exit 0 после
фикса 031.downgrade.
Subtasks:
- [x] Реальный баг миграции 031 (PK ordering) исправлен.
- [x] Полный `head↔base` проходит на чистой БД.
- [~] Single-head инвариант в тесте (ранее исправлен в 737c3b9: `len(heads)==1`).
_Requirements: R2._

## T3. PostgreSQL/RLS тесты реально исполняются — `[~]`
Result: Layer B миграций запускается против живого PG; setup-errors 23→0.
Subtasks:
- [x] psycopg2-binary (sync introspection driver) установлен.
- [x] `::regclass` синтаксис исправлен (3 файла).
- [ ] RLS-изоляция под NOSUPERUSER-ролью (класс C1 в test-failures.md).
_Requirements: R3._

## T4. Изоляция состояния между тестами — `[~]`
Result: 031-фикс восстановил корректный `downgrade base` в teardown (устранил
каскад). Остаются: стале-хопы `downgrade -N` (C2) и sandbox-parser registry
order-dependence (C4).
Subtasks:
- [x] Teardown downgrade-base снова детерминирован.
- [ ] Стале-хопы `downgrade -N from head` → явный target revision (C2).
- [ ] Parser-registry reset/lifecycle (C4).
_Requirements: R4._

## T5. Повторная проверка 7 фиксов + regression tests — `[~]`
- [x] Ранее (737c3b9) добавлены regression-тесты для 7 фиксов; unit-набор
  (10497) зелёный.
- [ ] Расширенные негативные LAB-authorization тесты (DNS suffix, CIDR, IDNA,
  expired/revoked lease, wrong tenant, Quick+lease) — план в Requirements R5.
- [ ] usage_ledger no-loop durability (очередь/flush) — усиление.
_Requirements: R5._

## T6. Контракты ARGUS — `[~]`
- [x] Quick/Light/Deep mapping и conflict→422 покрыты (resolver + unit).
- [ ] Полная report-parity (PDF/JSON/MD/XML) под контейнерным прогоном.
_Requirements: R6._

## T7. AWS-переносимость (без развёртывания) — `[~]`
- [x] Валидационный стенд подтверждает env-конфигурируемость pg/redis/minio.
- [ ] `docs/aws-readiness.md` + production env-template (без секретов).
_Requirements: R7._

## T8. Отсутствие секретов в коммите — `[~]`
- [x] `.env.validation` gitignored; в индекс не попадает.
- [ ] Финальный staged-diff secret scan перед push.
_Requirements: R8._

---

## Ссылки
- [Requirements.md](./Requirements.md)
- [Design.md](./Design.md)
- [test-failures.md](./test-failures.md)
- Связанная: [../argus-profile-orchestration-rework/](../argus-profile-orchestration-rework/)
