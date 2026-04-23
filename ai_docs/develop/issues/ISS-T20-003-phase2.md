# ISS-T20-003 Phase 2 — MFA + runbook + grace-window cleanup

**Issue ID:** ISS-T20-003-phase2
**Parent:** ISS-T20-003 (full session-based admin auth)
**Owner:** Backend / Auth + Frontend / Admin console + Ops
**Source task:** Phase 1 completed in Cycle 6 Batch 6 (B6-T08, B6-T09, +crit-hash)
**Status:** **PARTIAL** — Phase 2a (MFA, C7-T01/T03) and Phase 2c (grace-window cleanup, C7-T07) shipped Cycle 7; Phase 2b (operator runbook) shipped Cycle 7 / C7-T05.
**Priority:** HIGH (completes the admin auth refactor; Phase 1 is production-safe but partial)
**Date filed:** 2026-04-22
**Last updated:** 2026-04-23 (Phase 2c marked DONE — see §Phase 2c below)

---

## Context

Cycle 6 Batch 6 shipped **ISS-T20-003 Phase 1**:

- ✅ `admin_sessions` table (Alembic 028) — keys: `session_id String(64) PK`, `subject String(255)`, `role String(32)`, `tenant_id UUID nullable`, `created_at`, `expires_at`, `last_used_at`, `revoked_at`, `ip_hash`, `user_agent_hash`.
- ✅ `admin_users` table (same revision 028) with bcrypt-12 verification.
- ✅ `POST /auth/admin/login {subject, password}` → HttpOnly Secure SameSite=Strict cookie `argus.admin.session=<token>`. Per-IP token-bucket limiter (default `ADMIN_LOGIN_RATE_LIMIT_PER_MINUTE=10`), constant-time `_burn_dummy_cycle` failure-path equaliser.
- ✅ `POST /auth/admin/logout` (idempotent, tombstones `revoked_at`).
- ✅ `GET /auth/admin/whoami` → `{subject, role, tenant_id, expires_at}` or 401.
- ✅ Dual-mode `require_admin` in `backend/src/api/routers/admin.py` — `cookie | session | both`, default `both` for backward compat.
- ✅ Frontend `Frontend/middleware.ts` redirect to `/admin/login` when session-mode + no cookie.
- ✅ Frontend `getServerAdminSession()` resolves via `cookie | session | auto` modes (`Frontend/src/services/admin/serverSession.ts`).
- ✅ E2E `Frontend/tests/e2e/admin-auth.spec.ts` covers cookie tampering / role tampering / session tampering.

**Critical follow-up shipped in the same batch (`crit-hash`):**

- ✅ Alembic 030 — `admin_sessions.session_token_hash VARCHAR(64) UNIQUE INDEX`.
- ✅ `session_token_hash = HMAC-SHA256(ADMIN_SESSION_PEPPER, raw_token)` — keyed hash, length-extension safe.
- ✅ `create_session` writes the hash; legacy raw `session_id` is mirrored only when `ADMIN_SESSION_LEGACY_RAW_WRITE=true` (default for the grace window).
- ✅ Resolver looks up by `session_token_hash` first; falls back to `session_id` when `ADMIN_SESSION_LEGACY_RAW_FALLBACK=true` AND opportunistically backfills the hash on hit.
- ✅ `hmac.compare_digest` defence-in-depth on every comparison; full session id never logged (`redact_session_id` keeps the first 6 chars).
- ✅ Boot-time guards (BE `Settings._enforce_production_admin_auth` + FE `instrumentation.ts::register`) reject `cookie`/`auto` mode in production.

**Phase 1 acceptance against `ISS-T20-003.md`:**

- (a) ✅ Unique CSPRNG subject per operator session (`subject` column populated from authenticated identity, not from a header).
- (b) ✅ Audit rows carry the operator subject (handlers read `SessionPrincipal.subject`, not the X-Operator headers).
- (c) ✅ Cookie tampering in browser DevTools no longer changes backend-observed identity (server-side DAO is the only source of truth).
- (d) ❌ MFA enforcement — **deferred to this Phase 2 issue**.
- (e) ❌ Operator runbook — **deferred to this Phase 2 issue**.
- (f) ❌ Legacy `session_id` PK drop (Alembic 031) — **deferred until grace window closes**.

---

## Problem

Three independent work streams remain after Phase 1:

1. **MFA layer (criterion d).** The login flow today is single-factor (subject + password). Super-admin actions need a second factor.
2. **Operator runbook (criterion e).** Ops needs a stable, versioned doc for session lifecycle, rotation, revocation, and audit-trail queries.
3. **Grace-window cleanup (criterion f).** The legacy `session_id` column and the two `ADMIN_SESSION_LEGACY_RAW_*` compatibility flags are explicitly temporary; once production has fully drained them, Alembic 031 drops the column and the flags die with the migration.

These three are **orthogonal** — each can ship independently in Cycle 7 without blocking the others.

---

## Proposal

### Phase 2a — MFA layer (pick exactly one option)

#### Option 1: Backend-managed TOTP (recommended for self-contained shops)

**Schema (Alembic 032 — distinct from the 031 cleanup migration):**

| Column | Type | Notes |
|---|---|---|
| `admin_users.mfa_enabled` | `bool default false` | Per-operator toggle. Super-admin role → enrollment is forced. |
| `admin_users.mfa_secret_encrypted` | `bytea nullable` | TOTP secret encrypted with `cryptography.Fernet`; key sourced from `ADMIN_MFA_KEYRING` env. |
| `admin_users.mfa_backup_codes_hash` | `text[] nullable` | bcrypt-hashed one-time recovery codes; set/used flag tracked via deletion from the array. |
| `admin_sessions.mfa_passed_at` | `timestamptz nullable` | When the second factor was accepted; resolver requires non-NULL for super-admin endpoints. |

**Endpoints (added to `backend/src/api/routers/admin_auth.py`):**

- `POST /auth/admin/mfa/enroll` → returns provisioning URI + base32 secret + QR SVG (in-memory; never stored as plaintext).
- `POST /auth/admin/mfa/enroll/confirm {totp_code}` → validates TOTP, persists encrypted secret, generates and returns 10 backup codes (one-time display).
- `POST /auth/admin/mfa/verify {mfa_token, totp_code | backup_code}` → invoked after `/login` returns `{status:"mfa_required", mfa_token}` instead of a session cookie. On success the session cookie is set and `mfa_passed_at` populated.
- `POST /auth/admin/mfa/disable {password, totp_code}` → re-auth + clear secret + clear backup codes.

**Resolver:** `require_admin` (super-admin endpoints) checks `SessionPrincipal.mfa_passed_at is not None and now() - mfa_passed_at < ADMIN_MFA_REAUTH_WINDOW_SECONDS` (default 12h, reset on logout).

**Tests:** ≥10 backend pytest cases (enroll happy-path, enroll TOTP mismatch, verify with backup code, verify with replay-protected backup code, MFA-required for super-admin, MFA-not-required for plain admin, disable, key-rotation under Fernet keyring).

#### Option 2: IdP-delegated MFA (recommended if enterprise SSO is already on the roadmap)

OIDC integration with Azure AD / Auth0 / Google Workspace / Keycloak. Backend trusts `amr=mfa` (or `acr` level) claim from the IdP; no MFA storage in `admin_users`. Phase 1 session table stays as-is. Out of scope of this issue beyond a one-paragraph design note.

**Trade-off:** Option 1 is implementable in Cycle 7 (estimated 3–4 days). Option 2 needs IdP procurement (out of engineering's hands) — defer to the cycle in which procurement closes.

### Phase 2b — Operator runbook

**Location:** `docs/operations/admin-sessions.md` (new file; mirror the format of existing `docs/admission-policy.md` and `docs/webhook-dlq.md`).

**Sections:**

1. **Session lifecycle**
   - Default TTL: 12h (`ADMIN_SESSION_TTL_SECONDS=43200`).
   - Sliding window: every authenticated request bumps `last_used_at` and `expires_at` to `now() + ADMIN_SESSION_TTL_SECONDS`.
   - Token shape: 48 CSPRNG bytes → URL-safe base64, ~64 chars. The raw token is the cookie; `HMAC-SHA256(pepper, token)` is the DB key.
   - HttpOnly + Secure + SameSite=Strict; `Secure` is relaxed only when `DEBUG=true` AND the connection is plain HTTP (local dev).
2. **Login procedure**
   - `POST /auth/admin/login {subject, password}` (subject is the operator login, not necessarily an email).
   - bcrypt cost 12; `_burn_dummy_cycle` runs on every failure path so timing leaks do not differentiate `unknown subject` / `disabled` / `wrong password`.
   - Per-IP token-bucket: `ADMIN_LOGIN_RATE_LIMIT_PER_MINUTE` (default 10). Response on burst: 429 + `Retry-After`.
   - Trust `X-Forwarded-For` ONLY when running behind a reverse proxy that overwrites the header (uvicorn `--proxy-headers`, nginx `proxy_set_header`). Document the deployment requirement.
3. **MFA (Phase 2a; tracked separately)** — placeholder until Option 1/2 ships.
4. **Logout & revocation**
   - Operator self: `POST /auth/admin/logout` clears the cookie + tombstones the row (`revoked_at = now()`).
   - Super-admin force-revoke: `DELETE /admin/auth/sessions/{session_id_prefix}` (new endpoint; super-admin only; matches the row by `session_id` startswith for safety against full-token leak in the URL).
   - Beat-prune: cron task deletes rows older than `ADMIN_SESSION_TTL_SECONDS * 2` AND `revoked_at IS NOT NULL` to keep the table bounded.
   - Audit emit: `argus.auth.admin.logout`, `argus.auth.admin_session.revoked`, `argus.auth.admin_session.expired`.
5. **Audit-trail queries**
   - `SELECT * FROM audit_log WHERE actor_subject = $1 AND created_at >= $2;` — operator activity since timestamp.
   - `SELECT subject, ip_hash, user_agent_hash, created_at, last_used_at FROM admin_sessions WHERE revoked_at IS NULL AND expires_at > now();` — all currently active sessions.
   - Use `ip_hash` / `user_agent_hash` purely for forensic correlation: same hash across two sessions = same client.
6. **Pepper rotation procedure** (mirrors the comment block in `backend/.env.example`)
   - Confirm both `ADMIN_SESSION_LEGACY_RAW_*` flags are ON.
   - Deploy new `ADMIN_SESSION_PEPPER`. Live sessions resolve via legacy raw column; opportunistic backfill rewrites `session_token_hash` under the new pepper on first hit.
   - Wait one TTL window. Force-revoke any rows that did not get backfilled (`UPDATE admin_sessions SET revoked_at = NOW() WHERE session_token_hash IS NULL AND revoked_at IS NULL;`).
   - Emergency rotation: accept downtime; revoke all rows; force re-login.

### Phase 2c — Grace-window cleanup (Alembic 031)

> **STATUS — DONE (Cycle 7 / C7-T07, 2026-04-23).**
>
> Single-stage delete decision (audit in the C7-T07 Wave 2 commit message): ARGUS is pre-production, no live deploy holds raw `session_id` rows worth a 2-stage rollout. Deliverables shipped:
>
> - ✅ Alembic 031 — `backend/alembic/versions/031_drop_legacy_admin_session_id.py` — backfills straggler `session_token_hash` rows when the pepper is configured, purges unhashable orphans (best-effort; the resolver had already stopped serving them), drops the `admin_sessions.session_id` column and its supporting index, promotes `session_token_hash` to PK NOT NULL. Forward-only — `downgrade()` is a no-op (raw token material cannot be reconstructed from the hash; rollback procedure for emergencies remains the §Phase 2c block below).
> - ✅ Code cleanup — `backend/src/auth/admin_sessions.py` lost the `legacy_raw_value` branch in `create_session`, the legacy-fallback branch in `revoke_session` / `_lookup_session_row`, and the opportunistic backfill. `backend/src/db/models.py::AdminSession` declares `session_token_hash` as `primary_key=True, nullable=False` and no longer carries a `session_id` column.
> - ✅ Config + env cleanup — `backend/src/core/config.py` lost both `admin_session_legacy_raw_*` settings and their `coerce_admin_session_legacy_bool` validator. `backend/.env.example` replaced the two flag lines with a removal note pointing back to this issue.
> - ✅ Test cleanup — `backend/tests/auth/test_admin_sessions_hash_at_rest.py` dropped the four legacy-fallback cases. New `backend/tests/auth/test_admin_sessions_no_legacy_path.py` proves the branch is structurally absent (no `session_id` column on the model, no flag on Settings, hash-only resolver, no raw fallback when pepper is missing). New `backend/tests/integration/migrations/test_031_drop_legacy_admin_session_id_migration.py` covers schema drop + PK promotion + straggler backfill + unhashable purge + 030-precondition refusal.
> - ✅ Runbook — `docs/operations/admin-sessions.md` §3 / §4.2 / §5.1 / §8 updated; the Configuration table no longer lists the flags; the migration tracker flips them to **Removed**.
>
> Pre-flight signals from the table below are preserved for archival / future audits, but no longer block deployment — the schema and code state they were guarding has already been collapsed.

This is the **concrete acceptance work** for criterion (f). Phase 2c is independent of Phase 2a/2b and can ship in any Cycle ≥ 7 once production has soaked.

**Pre-flight signals (operator MUST verify before running 031):**

| Signal | How to verify | Pass criterion |
|---|---|---|
| All live sessions hashed | `SELECT count(*) FROM admin_sessions WHERE session_token_hash IS NULL AND revoked_at IS NULL;` | Returns 0 across two consecutive observation windows of length `ADMIN_SESSION_TTL_SECONDS` (default 24h total). |
| No fallback hits in logs | `argus.auth.admin_session.resolved` events with `extra.matched_via == "legacy"` over the last 24h | Returns 0. |
| Both compat flags off | `ADMIN_SESSION_LEGACY_RAW_WRITE=false` AND `ADMIN_SESSION_LEGACY_RAW_FALLBACK=false` deployed for at least one TTL window | Confirmed in the env source-of-truth (Vault / SOPS / Helm values). |

**Recommended deploy sequence (each step waits one full TTL window before the next):**

1. **T+0**: Both flags ON (Phase 1 default state).
2. **T+1× TTL** (~12h after 030 deploy): Flip `ADMIN_SESSION_LEGACY_RAW_WRITE=false`. New sessions stop populating `session_id` → existing sessions still hit the legacy fallback.
3. **T+2× TTL**: Verify the three pre-flight signals. Flip `ADMIN_SESSION_LEGACY_RAW_FALLBACK=false`. Resolver now refuses any row that lacks `session_token_hash`.
4. **T+3× TTL**: Run `alembic upgrade 031`.

**Migration `031_drop_legacy_admin_session_id.py` shape:**

```python
revision = "031"
down_revision = "030"

def upgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"
    with op.batch_alter_table("admin_sessions", recreate="auto") if is_sqlite \
            else nullcontext():
        # Promote `session_token_hash` to PK; drop legacy `session_id`.
        op.alter_column(
            "admin_sessions", "session_token_hash",
            existing_type=sa.String(64),
            nullable=False,
        )
        op.execute(
            "ALTER TABLE admin_sessions DROP CONSTRAINT admin_sessions_pkey",
        )
        op.execute(
            "ALTER TABLE admin_sessions ADD PRIMARY KEY (session_token_hash)",
        )
        op.drop_column("admin_sessions", "session_id")

def downgrade() -> None:
    # Strictly forward-only — Phase 2c's pre-flight checks ensure 031 is
    # safe to run; downgrade would re-introduce a security regression.
    raise RuntimeError(
        "031 is forward-only — see ISS-T20-003-phase2 §Phase 2c rollback.",
    )
```

**Code cleanup that lands in the same release as 031:**

- `backend/src/auth/admin_sessions.py` — drop the `legacy_raw_value` branch in `create_session`, drop the legacy-fallback branch in `revoke_session` and `resolve_session`, drop the opportunistic backfill, drop `is_session_pepper_configured` short-circuits whose only job was to keep the legacy path alive.
- `backend/src/db/models.py` — drop the `session_id` column declaration, promote `session_token_hash` to `primary_key=True, nullable=False`.
- `backend/src/core/config.py` — remove `admin_session_legacy_raw_write` and `admin_session_legacy_raw_fallback` settings + their validators.
- `backend/.env.example` — remove the two flag lines + their comment block.
- `backend/tests/auth/test_admin_sessions_hash_at_rest.py` — drop the four tests covering the legacy fallback path; the contract no longer applies.

**Rollback procedure (if 031 breaks the smoke environment):**

1. `alembic downgrade 030` — restores `session_id` as a nullable column (NOT a PK; full PK restoration is impossible because the column has been NULL for production rows since `ADMIN_SESSION_LEGACY_RAW_WRITE=false`).
2. Force-revoke all sessions: `UPDATE admin_sessions SET revoked_at = NOW();`.
3. Re-deploy a build that pins `session_id` back to `primary_key=True` AND re-enables `ADMIN_SESSION_LEGACY_RAW_WRITE=true`.
4. Operators re-login; new sessions populate both columns; the failure root cause is investigated offline.

This rollback path **deliberately costs all live sessions** — better than running a half-migrated schema.

---

## Acceptance criteria

- (d) ✅ MFA enforcement — Phase 2a Option 1 (or 2) shipped; super-admin endpoints require a second factor; ≥10 unit/integration tests cover enroll / verify / replay-block / disable. **DONE — Cycle 7 / C7-T01 + C7-T03.**
- (e) ✅ Runbook — `docs/operations/admin-sessions.md` published, linked from `README.md` Operations section, reviewed by Ops. **DONE — Cycle 7 / C7-T05.**
- (f) ✅ Alembic 031 — runs cleanly against staging snapshot; pre-flight signal table all green; legacy code paths fully removed; full pytest+vitest+E2E suites green post-cleanup. **DONE — Cycle 7 / C7-T07 (2026-04-23).**
- (g) ✅ No new pre-existing test failures attributable to Phase 2 work (regression-free).

---

## Dependencies

- Phase 1 + crit-hash deployed to production for at least one TTL window (verified via `last_used_at` distribution in `admin_sessions`).
- Pre-flight signal automation: small Grafana panel + alert on the three signals listed above so operators do not have to remember to check them manually.
- (Option 2 only) IdP procurement closed.

---

## Cross-links

- Phase 1 implementation: `ai_docs/develop/reports/2026-04-22-cycle6-batch6-implementation.md`.
- Parent issue: `ai_docs/develop/issues/ISS-T20-003.md`.
- Cycle 7 backlog: `ai_docs/develop/issues/ISS-cycle7-carry-over.md`.
- Pepper rotation comment: `backend/.env.example` (`ADMIN_SESSION_PEPPER` block).
- Resolver invariants: `backend/src/auth/admin_sessions.py` module docstring.
