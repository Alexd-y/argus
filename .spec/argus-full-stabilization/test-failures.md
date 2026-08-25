# ARGUS — Диагностика падений тестов (stabilization)

Окружение прогонов: Windows + `backend/.venv`, изолированный стенд
`argus-validation` (pgvector:pg15 :55432, redis :56379, minio :59000).
`DATABASE_URL=postgresql+asyncpg://argus:argus_validation@localhost:55432/argus_test`,
`ADMIN_SESSION_PEPPER=test-pepper-...`.

Команда прогона:
```
docker compose -p argus-validation -f infra/docker-compose.validation.yml --env-file infra/.env.validation up -d
docker exec argus-validation-pg psql -U argus -d argus_test -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
cd backend && python -m pytest tests/integration/migrations -q
```

Прогресс: без стенда 12f/59p/23e → после подъёма PG 12f/59p/23e →
+psycopg2 20f/70p/23e → +фикс 031.downgrade 20f/70p/**4e** →
+test_053 path/+test_028 subset/+scan_schedules CAST 19f/75p/**0e**.

Все `E`(errors) устранены. Ниже — root cause по классам оставшихся `F`.

---

## Устранённые дефекты (с проверкой)

### D1 — `031_drop_legacy_admin_session_id.downgrade` (реальный баг миграции) ✅
- **Symptom**: `asyncpg InvalidTableDefinitionError: column "session_token_hash"
  is in a primary key` при `downgrade base`; каскадом — 23 setup-error во всём
  наборе (teardown каждого pg-теста делает `downgrade base`).
- **Root cause**: downgrade выполнял `ALTER COLUMN session_token_hash DROP NOT
  NULL` до снятия PK, которому колонка принадлежит.
- **Fix**: `alembic/versions/031_...py` — `DROP CONSTRAINT ... pk_admin_sessions`
  перенесён ПЕРЕД демоцией колонки в nullable.
- **Verification**: `alembic upgrade head` + `alembic downgrade base` — exit 0
  (цепочка 059↔base проходит, `Running downgrade 031 -> 030` без ошибок).

### D2 — отсутствовал sync-драйвер psycopg2 ✅
- **Symptom**: `ModuleNotFoundError: No module named 'psycopg2'` в тестах,
  использующих sync-engine для интроспекции.
- **Root cause**: `psycopg2-binary` объявлен dev-only в `pyproject.toml`, но не
  установлен в venv.
- **Fix**: `uv pip install "psycopg2-binary>=2.9"` (зависимость уже в
  pyproject — правки репозитория не требуется).

### D3 — `test_053_force_rls_login` неверный `script_location` ✅
- **Symptom**: `CommandError: Path doesn't exist: backend\tests\alembic`.
- **Root cause**: `_BACKEND_ROOT = parents[2]` → `backend/tests` (off-by-one;
  соседний test_031 использует `parents[3]`).
- **Fix**: `parents[2]` → `parents[3]`.

### D4 — `test_028` сверял точный набор колонок 028-эры после `upgrade head` ✅
- **Symptom**: `admin_users/admin_sessions columns differ from spec` — head
  содержит колонки, добавленные 030/032.
- **Root cause**: устаревший `==` set-assert против 028-era набора при апгрейде
  до head (последующие миграции легитимно добавляют колонки; каждая покрыта
  своим тестом).
- **Fix**: `==` → проверка присутствия 028-era колонок (subset), per-column
  nullable-проверки сохранены.

### D5 — `:table::regclass` ломался на psycopg2 ✅
- **Symptom**: `psycopg2 SyntaxError: syntax error at or near ":"`.
- **Root cause**: смешение bind `:table` и `::regclass` shorthand → paramstyle
  psycopg2 отдавал лишний `:`.
- **Fix**: `CAST(:table AS regclass)` в `test_scan_schedules_migration.py`,
  `test_028_admin_sessions_migration.py`, `tests/db/test_webhook_dlq_migration.py`.

---

## Оставшиеся падения — root cause по классам (план доработки)

### C1 — RLS-изоляция под суперпользователем (5+ тестов)
- Тесты: `test_053::test_tenant_scoped_session_is_isolated`,
  `test_053::test_write_still_requires_matching_tenant`,
  `test_scan_schedules::test_026_rls_isolation_on_select/on_update`.
- **Root cause**: пользователь `argus` (POSTGRES_USER) — **суперпользователь**,
  а суперпользователь ОБХОДИТ RLS даже при `FORCE ROW LEVEL SECURITY`
  (`assert 2 == 1`, `DID NOT RAISE DBAPIError`). Дефект тестовой инфраструктуры:
  RLS-изоляцию нельзя проверить из-под суперпользователя.
- **Remediation (не хак)**: в стенде создать NOSUPERUSER-роль (напр. `argus_app`
  с `GRANT SELECT/INSERT/... ON ALL TABLES`), миграции гнать owner-ролью, а
  сессии проверки изоляции открывать через `argus_app`. Требуется conftest-
  фикстура non-superuser URL + правки RLS-тестов на её использование. Отдельный,
  аккуратный подшаг (не ослаблять assertions).

### C2 — устаревшие `downgrade -N from head` (5+ тестов)
- Тесты: `test_028::..downgrade_drops_tables_idempotently` (`-1 from 028`),
  `test_029::..downgrade_drops_column`, `test_030::grace-window`/`token_hash
  index`, `test_031::pg_downgrade_restores_legacy_pk` (`-2 from head`),
  `test_032::pg_downgrade_drops_mfa_columns` (`-1 from head`).
- **Root cause**: тесты писались, когда их ревизия была близка к head, и делают
  относительные `downgrade -1/-2 from head`, ожидая отката ИМЕННО своей
  миграции. Сейчас head=059, поэтому `-N from head` не доходит до 028..032
  (напр. `-2 from head` = 059→057, а не 032→030), плюс общая тестовая БД
  оставляет head-схему между тестами.
- **Remediation (не хак)**: заменить относительные хопы на явный целевой
  revision (`command.downgrade(cfg, "<down_revision>")`) и/или изолировать БД
  на тест (отдельная схема/БД на тест-модуль). Не менять ожидаемые значения ради
  зелёного — менять НАВИГАЦИЮ по ревизиям.

### C3 — `alembic_smoke` subprocess `scripts.dump_alembic_schema` (4 теста)
- Тесты: `test_alembic_smoke::test_upgrade_head_creates_arg045_tables`,
  `..full_round_trip_is_no_op`, `..partial_rollback_round_trip_is_no_op`,
  `..report_bundles_columns_match_arg045_spec`.
- **Root cause**: `subprocess.CalledProcessError: python -m
  scripts.dump_alembic_schema returned non-zero` — вспомогательный скрипт дампа
  схемы падает в текущем окружении (нужно снять его точный stderr; кандидаты:
  требует sqlite/aiosqlite конфигурацию или переменные окружения).
- **Remediation**: воспроизвести `python -m scripts.dump_alembic_schema`
  напрямую, устранить причину non-zero exit (окружение/конфиг скрипта), не
  подавляя ошибку.

---

## Соответствие исходным «28»
Исходные 28 (миграции ~16 + sandbox-parser order-dependent 12) на стенде
разложились так: 23 setup-error устранены (D1..D5); из оставшихся `F` —
классы C1 (RLS-superuser), C2 (стале-хопы), C3 (dump-schema subprocess);
sandbox-parser order-dependent (проходят в изоляции 529/529) — отдельный класс
C4 (утечка глобального состояния parser-registry), диагностируется в §7 Design.
