# Migration 052 — FORCE ROW LEVEL SECURITY apply checklist (SEC-002)

Operational checklist for applying `backend/alembic/versions/052_force_rls_core_tables.py`.

**Status: written, reviewed, NOT applied.** This document is the gate that must be
cleared before `alembic upgrade head` reaches revision `052` in any shared
environment. Nothing here has been executed against a database.

---

## 1. What the migration changes

`052` runs `ALTER TABLE … FORCE ROW LEVEL SECURITY` on 60 tenant-scoped core
tables that were created with `ENABLE ROW LEVEL SECURITY` only.

ARGUS connects to PostgreSQL as the table owner (`argus`). A table owner
**bypasses** `ENABLE`-only RLS, so today tenant isolation on those tables rests
entirely on application-layer `WHERE tenant_id` filters. `FORCE` makes the
database enforce isolation for the owner too.

The upgrade is idempotent and guarded — a table is forced only when it exists,
already has RLS enabled, and has at least one policy. On SQLite it is a no-op.

## 2. Why this is not auto-applied

The policy created in `002_rls_and_audit_immutable.py` is:

```sql
CREATE POLICY tenant_isolation ON "<table>"
USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
```

`current_setting(..., true)` returns `NULL` when the GUC is unset, so
`tenant_id = NULL` is `NULL` — never true. Under `FORCE`, any connection that
has not run `SET LOCAL app.current_tenant_id`:

- sees **zero rows** on `SELECT`
- fails `WITH CHECK` on `INSERT` / `UPDATE`

and does so **silently** for reads. Every code path touching these tables must
therefore set the tenant context first, via
`src.db.session.set_session_tenant(session, tenant_id)`.

## 3. Blocking preconditions

### 3.1 P0 — login breaks as written

`src/api/routers/auth.py` authenticates with:

```python
select(User).where(User.email == req.mail, User.is_active == True)
```

on a session that never calls `set_session_tenant`. `users` is in the FORCE list.
Under `FORCE` this query returns no rows for every user, so **all logins fail**
with "invalid credentials" and no error is logged.

The tenant is not known before authentication, so this cannot be fixed by simply
setting the GUC. Pick one before applying `052`:

- [ ] Exempt `users` from the FORCE set and keep tenant scoping in the query, **or**
- [ ] Add a policy allowing lookup by email/id without a tenant context, **or**
- [ ] Move authentication to a dedicated role marked `BYPASSRLS`.

Same question applies to `src/auth/admin_users.py` (`bootstrap_admin_user_if_configured`,
runs at app startup) and `src/auth/admin_dependencies.py`.

### 3.2 Modules that open a session and never set a tenant

Evidence — modules under `backend/src/` that construct a session
(`async_session_factory(` / `task_session_factory(`) with no `set_session_tenant`
call anywhere in the file. Each must be confirmed as either (a) not touching a
forced table, or (b) intentionally cross-tenant and therefore needing an explicit
`BYPASSRLS` role rather than an unset GUC.

| Module | Triage |
|--------|--------|
| `src/api/routers/auth.py` | P0 — see 3.1, touches `users` |
| `src/auth/admin_users.py` | P0 — startup bootstrap, touches `users` |
| `src/auth/admin_dependencies.py` | P0 — admin session resolution |
| `src/api/routers/admin_emergency.py` | Cross-tenant admin — needs `BYPASSRLS` decision |
| `src/api/routers/admin_schedules.py` | Cross-tenant admin — needs `BYPASSRLS` decision |
| `src/api/routers/admin_webhook_dlq.py` | Cross-tenant admin — needs `BYPASSRLS` decision |
| `src/api/routers/cache.py` | Confirm target tables |
| `src/llm_gateway/usage_ledger.py` | Writes usage rows — confirm `tenant_id` + context |
| `src/tools/executor.py` | Writes `tool_runs` — confirm context |
| `src/recon/cli/commands/export.py` | CLI, out-of-band — confirm |
| `src/recon/cli/commands/status.py` | CLI, out-of-band — confirm |
| `src/recon/cli/commands/threat_modeling.py` | CLI, out-of-band — confirm |
| `src/recon/cli/commands/vulnerability_analysis.py` | CLI, out-of-band — confirm |

Regenerate this list after any refactor:

```powershell
cd backend
.venv\Scripts\python.exe -c "
import pathlib, re
sess = re.compile(r'async_session_factory\(|task_session_factory\(')
for p in sorted(pathlib.Path('src').rglob('*.py')):
    t = p.read_text(encoding='utf-8', errors='replace')
    if sess.search(t) and 'set_session_tenant' not in t:
        print(p.as_posix())
"
```

### 3.3 Celery worker, beat, and data-migration paths

- [ ] Every task in `src/tasks/` that touches a forced table sets the tenant context.
- [ ] Beat-scheduled jobs (daily EPSS/KEV refresh, DLQ sweep) are confirmed to write
      only to non-tenant tables, or run under an explicitly tenant-scoped session.
- [ ] Any future data migration that backfills a forced table sets
      `app.current_tenant_id` per tenant, or runs as a `BYPASSRLS` role.

## 4. Staging validation (run before prod)

- [ ] Restore a production-shaped dump into staging.
- [ ] Apply: `cd backend && alembic upgrade head`.
- [ ] Confirm the forced set matches expectations:

```sql
SELECT relname, relrowsecurity, relforcerowsecurity
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = current_schema() AND c.relkind = 'r' AND c.relrowsecurity
ORDER BY relforcerowsecurity DESC, relname;
```

- [ ] Confirm no forced table lacks a policy (this would deny all access):

```sql
SELECT c.relname
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = current_schema() AND c.relforcerowsecurity
  AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid);
```

- [ ] Prove isolation actually bites (expect 0 rows, not an error):

```sql
BEGIN;
SET LOCAL app.current_tenant_id = '00000000-0000-0000-0000-0000000000ff';
SELECT count(*) FROM scans;
ROLLBACK;
```

- [ ] Run the full e2e lane against staging:
      `docker compose -f infra/docker-compose.e2e.yml up -d` then
      `cd backend && python -m pytest -m requires_docker_e2e tests/`.
- [ ] Smoke the paths RLS most easily breaks silently: login, scan create,
      findings list, report generate + download, admin cross-tenant views,
      webhook DLQ replay.
- [ ] Check worker logs for empty result sets and `WITH CHECK` violations —
      reads fail silently, so absence of errors is **not** sufficient evidence.

## 5. Apply to production

- [ ] Take a database backup and verify it restores.
- [ ] Schedule a maintenance window; `ALTER TABLE` takes a brief `ACCESS EXCLUSIVE`
      lock per table.
- [ ] Announce rollback criteria up front (see section 6).
- [ ] `cd backend && alembic upgrade head`.
- [ ] Re-run the section 4 verification queries against production.
- [ ] Watch error rates, login success rate, and scan throughput for one full
      scan cycle.

## 6. Rollback

`downgrade()` is safe and reverses only what `upgrade()` set:

```bash
cd backend && alembic downgrade 051
```

Roll back if login success rate drops, any tenant-scoped list endpoint starts
returning empty results, or workers begin failing `WITH CHECK`.

## 7. Sign-off

- [ ] 3.1 resolved (login path has a decided, implemented strategy)
- [ ] 3.2 table fully triaged
- [ ] 3.3 worker/beat/migration paths confirmed
- [ ] Section 4 staging validation passed
- [ ] Backup verified, window scheduled, rollback criteria agreed

Approver: ______________________  Date: ____________
