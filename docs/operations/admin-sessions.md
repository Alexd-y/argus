# Admin Sessions — Operator Runbook

> Owner: SRE on-call. Last reviewed: 2026-04-22.

Self-sufficient runbook for the admin-session subsystem (ISS-T20-003 Phase 1, shipped Cycle 6 / Batch 6). Audience: on-call SRE with shell access to a backend pod and the primary Postgres, no familiarity with the auth code assumed. Every cited path, function, and column has been verified against `main` at the date above; if `main` and this file disagree, the repository wins — patch this file in the same commit.

---

## 1. Overview & threat model summary

The admin-session subsystem authenticates operator/admin/super-admin humans for the ARGUS admin surface. Login mints a CSPRNG-opaque token (`secrets.token_urlsafe(48)`, ~64 chars), hands it to the browser as the `argus.admin.session` cookie (HttpOnly, Secure, SameSite=Strict, path=`/`), and stores its keyed at-rest hash in `admin_sessions.session_token_hash`. Every subsequent admin request resolves the cookie back to a row, validates expiry/revocation, and slides the TTL forward.

**Trust boundary.** The raw token never leaves the browser cookie jar (HttpOnly blocks JS reads; SameSite=Strict blocks cross-site send). The server only ever stores `HMAC-SHA256(ADMIN_SESSION_PEPPER, raw_token)`. A Postgres-only compromise (DB dump, replica leak, backup theft) yields hashes that are forgery-useless without the application-side pepper. Conversely, a pepper-only leak does not by itself reveal session tokens — the attacker must also carry a live cookie from a victim browser. Both halves must leak together for a session to be replayable. The pepper rotation in §5 is the kill-switch for the second case.

Design history: [`ai_docs/develop/issues/ISS-T20-003.md`](../../ai_docs/develop/issues/ISS-T20-003.md) (Phase 1 — what shipped) and [`ai_docs/develop/issues/ISS-T20-003-phase2.md`](../../ai_docs/develop/issues/ISS-T20-003-phase2.md) (Phase 2 — MFA, dual-pepper rotation, Alembic 031 cleanup).

---

## 2. Architecture at a glance

### 2.1 Login → cookie → request → renew → logout sequence

```mermaid
sequenceDiagram
    autonumber
    participant U as Operator (browser)
    participant FE as Next.js (Frontend/instrumentation.ts, serverSession.ts)
    participant API as FastAPI router (admin_auth.py)
    participant DAO as admin_sessions.py (DAO)
    participant DB as Postgres (admin_sessions, admin_users)

    U->>FE: POST /admin/login (subject, password)
    FE->>API: POST /auth/admin/login
    API->>API: _LoginRateLimiter.acquire(client_ip)
    API->>DB: SELECT admin_users WHERE subject=...
    API->>API: bcrypt.checkpw(password, password_hash)
    API->>DAO: create_session(subject, role, tenant_id, ip, ua)
    DAO->>DAO: token = secrets.token_urlsafe(48); hash = HMAC-SHA256(pepper, token)
    DAO->>DB: INSERT INTO admin_sessions (session_token_hash, ..., expires_at)
    API-->>U: Set-Cookie: argus.admin.session=<token>; HttpOnly; Secure; SameSite=Strict
    Note over U,API: Subsequent admin request

    U->>FE: GET /admin/...  (Cookie: argus.admin.session=<token>)
    FE->>API: GET /auth/admin/whoami (cookie forwarded)
    API->>DAO: resolve_session(session_id=cookie)
    DAO->>DAO: hash = HMAC-SHA256(pepper, cookie); hmac.compare_digest
    DAO->>DB: SELECT * FROM admin_sessions WHERE session_token_hash = :hash
    DAO->>DB: UPDATE last_used_at=now(), expires_at=now()+ttl  (sliding TTL)
    API-->>U: 200 {subject, role, tenant_id, expires_at}

    U->>FE: POST /admin/logout
    FE->>API: POST /auth/admin/logout (cookie)
    API->>DAO: revoke_session(session_id=cookie)
    DAO->>DB: UPDATE admin_sessions SET revoked_at=now() WHERE session_token_hash=:hash
    API-->>U: Set-Cookie: argus.admin.session=; Max-Age=0
```

### 2.2 Component map (verified paths)

| Layer | File | Responsibility |
| ----- | ---- | -------------- |
| Backend DAO | `backend/src/auth/admin_sessions.py` | Token mint (`generate_session_id`, line 124), at-rest hash (`hash_session_token`, line 134), `create_session` (line 188), `revoke_session` (line 256), `resolve_session` (line 321), redaction helper `redact_session_id` (line 113), grace-window dispatcher `_lookup_session_row` (line 429). |
| Backend HTTP | `backend/src/api/routers/admin_auth.py` | `POST /auth/admin/login` (`admin_login`, line 322), `POST /auth/admin/logout` (`admin_logout`, line 415), `GET /auth/admin/whoami` (`admin_whoami`, line 462), cookie helpers `_set_session_cookie` (line 236) / `_clear_session_cookie` (line 263), per-IP token-bucket `_LoginRateLimiter` (line 121). |
| Backend credentials | `backend/src/auth/admin_users.py` | `verify_credentials` (line 180) — bcrypt + constant-time burn cycle (`_burn_dummy_cycle`, line 124); bootstrap `bootstrap_admin_user_if_configured` (line 266). |
| Backend config | `backend/src/core/config.py` | All `admin_*` settings (lines 224–349) and the production `model_validator` `_enforce_production_admin_auth` (line 848). |
| Frontend resolver | `Frontend/src/services/admin/serverSession.ts` | `getServerAdminSession` (line 237) — cookie/session/auto modes; lazy production guard `assertProductionAdminAuthModeOnce` (line 71). |
| Frontend boot guard | `Frontend/instrumentation.ts` | `register` hook (line 34) — refuses to start the FE if `NEXT_PUBLIC_ADMIN_AUTH_MODE != session` and `NODE_ENV=production`. |
| DB schema | `backend/src/db/models.py` | `AdminUser` (line 713), `AdminSession` (line 782). |
| Migration | `backend/alembic/versions/030_hash_admin_session_ids.py` | Added `session_token_hash` column, backfilled `HMAC-SHA256(ADMIN_SESSION_PEPPER, session_id)` for live rows, indexed UNIQUE. |
| Cleanup migration | `backend/alembic/versions/031_drop_legacy_admin_session_id.py` | **NOT YET PRESENT — planned in C7-T07** (drops the raw `session_id` column, promotes `session_token_hash` to PK). |

### 2.3 Database tables (current shape)

`admin_users` — operator credentials (`backend/src/db/models.py:713`):

| Column | Type | Notes |
| ------ | ---- | ----- |
| `id` | uuid PK | |
| `subject` | varchar(255) UNIQUE | Login identifier (email or stable handle). |
| `password_hash` | varchar(255) | bcrypt. |
| `role` | varchar(32) | `operator` \| `admin` \| `super-admin`. |
| `tenant_id` | varchar(36) NULL | NULL for super-admin. |
| `mfa_enabled` | bool | Phase 2 (C7-T01). |
| `mfa_secret_encrypted` | bytea NULL | Fernet-encrypted TOTP secret (Phase 2). |
| `mfa_backup_codes_hash` | jsonb NULL | bcrypt list (Phase 2). |
| `disabled_at` | timestamptz NULL | Soft-disable tombstone. |
| `created_at` / `updated_at` | timestamptz | |

`admin_sessions` — issued sessions (`backend/src/db/models.py:782`):

| Column | Type | Notes |
| ------ | ---- | ----- |
| `session_id` | varchar(64) PK | **Legacy raw token** during 030→031 grace window. After C7-T07 drops out. |
| `session_token_hash` | varchar(64) UNIQUE INDEX NULL | `HMAC-SHA256(pepper, raw_token)` hex. Primary lookup column. |
| `subject` | varchar(255) | Denormalized from `admin_users` so revocation joins are unnecessary. |
| `role` | varchar(32) | |
| `tenant_id` | varchar(36) NULL | |
| `created_at` | timestamptz | |
| `expires_at` | timestamptz | Slid forward by `resolve_session`. |
| `last_used_at` | timestamptz | Slid forward by `resolve_session`. |
| `ip_hash` | varchar(64) | SHA-256 of source IP (forensic, not enforcement). |
| `user_agent_hash` | varchar(64) | SHA-256 of UA (forensic, not enforcement). |
| `revoked_at` | timestamptz NULL | Tombstone — once set, row is permanently invalid. |
| `mfa_passed_at` | timestamptz NULL | Phase 2 (C7-T01) — last successful TOTP/backup-code re-auth. |

Indexes: `ix_admin_sessions_subject_revoked (subject, revoked_at)`, `ix_admin_sessions_expires_at (expires_at)`, plus the unique on `session_token_hash`.

---

## 3. Configuration reference

All variables are loaded by `Settings` in `backend/src/core/config.py`. The production guard `_enforce_production_admin_auth` (line 848) refuses to boot if any production-required value is wrong.

| Variable | Required | Default | Validated by | Notes |
| -------- | -------- | ------- | ------------ | ----- |
| `ADMIN_AUTH_MODE` | **prod: `session`** | `session` | `normalize_admin_auth_mode` (line 429) + `_enforce_production_admin_auth` (line 848) | Allowed: `cookie` \| `session` \| `both`. Production refuses anything ≠ `session`. The FE boot guard `Frontend/instrumentation.ts:34` enforces the same on the FE side via `NEXT_PUBLIC_ADMIN_AUTH_MODE`. |
| `ADMIN_SESSION_TTL_SECONDS` | yes | `43200` (12 h) | Field constraint `gt=0` (line 234) | Sliding window — every successful `resolve_session` extends the row to `now() + this`. Treat as "max idle gap before a re-login is required". |
| `ADMIN_LOGIN_RATE_LIMIT_PER_MINUTE` | yes | `5` | Field constraint `ge=1` (line 242) | Per-source-IP token bucket; bucket size = burst = `per_minute`; refill = `per_minute / 60` tok/s. LRU-capped at 4096 IPs (`backend/src/api/routers/admin_auth.py:87`). |
| `ADMIN_SESSION_PEPPER` | **prod: required, ≥32 chars** | `""` (empty) | `_enforce_production_admin_auth` (line 848 → 893) | Secret-grade. Hashes session tokens at rest. Empty value disables session auth at runtime (`is_session_pepper_configured`, line 129). Rotation procedure in §5. |
| `ADMIN_SESSION_LEGACY_RAW_WRITE` | no | `true` | `coerce_admin_session_legacy_bool` (line 443) | Grace-window flag (Alembic 030). When `true`, `create_session` mirrors the raw token in `admin_sessions.session_id` so a deploy rollback to pre-030 code can still resolve. **Set `false`** ≥ 24 h (= 2 × TTL window) before C7-T07 / Alembic 031 ships. |
| `ADMIN_SESSION_LEGACY_RAW_FALLBACK` | no | `true` | `coerce_admin_session_legacy_bool` (line 443) | Grace-window flag. When `true`, `_lookup_session_row` falls back to a raw `session_id` lookup if the hash misses. Same drain procedure as `_WRITE`. |
| `ADMIN_MFA_KEYRING` | Phase 2 (C7-T01) | `""` | `validate_admin_mfa_keyring` (line 351) | CSV of base64 Fernet keys, **newest first**. Encrypts `admin_users.mfa_secret_encrypted`. |
| `ADMIN_MFA_REAUTH_WINDOW_SECONDS` | Phase 2 | `43200` | Field constraint `gt=0` (line 329) | How long a recent MFA challenge counts as "fresh" before sensitive admin actions re-prompt. |
| `ADMIN_MFA_ENFORCE_ROLES` | Phase 2 | `["super-admin", "admin"]` | `parse_admin_mfa_enforce_roles` (line 396) | CSV. Roles in this list MUST complete MFA on login. |

> **Naming note.** Earlier drafts of C7-T05 referenced `ADMIN_SESSION_LEGACY_RAW_LOOKUP` and `ADMIN_SESSION_LEGACY_RAW_DEADLINE`. The flags actually shipped are `ADMIN_SESSION_LEGACY_RAW_WRITE` and `ADMIN_SESSION_LEGACY_RAW_FALLBACK` (above). The "deadline" is a calendar date, not an env var: **2026-06-21** (60 days after Phase 1 deploy, per `ai_docs/develop/issues/ISS-T20-003.md:11`). Cleanup is tracked in §8.

Production self-check from a backend pod:

```powershell
# Windows PowerShell on a jump host (or `kubectl exec ...`)
$envs = @(
  "ADMIN_AUTH_MODE", "ADMIN_SESSION_PEPPER", "ADMIN_SESSION_TTL_SECONDS",
  "ADMIN_SESSION_LEGACY_RAW_WRITE", "ADMIN_SESSION_LEGACY_RAW_FALLBACK",
  "ADMIN_LOGIN_RATE_LIMIT_PER_MINUTE"
)
foreach ($e in $envs) {
  $v = [System.Environment]::GetEnvironmentVariable($e)
  if ($e -eq "ADMIN_SESSION_PEPPER" -and $v) { $v = "<set, len=$($v.Length)>" }
  "{0,-40} = {1}" -f $e, $v
}
```

```bash
# Linux equivalent
for v in ADMIN_AUTH_MODE ADMIN_SESSION_PEPPER ADMIN_SESSION_TTL_SECONDS \
         ADMIN_SESSION_LEGACY_RAW_WRITE ADMIN_SESSION_LEGACY_RAW_FALLBACK \
         ADMIN_LOGIN_RATE_LIMIT_PER_MINUTE; do
  if [ "$v" = "ADMIN_SESSION_PEPPER" ] && [ -n "${!v}" ]; then
    printf '%-40s = <set, len=%d>\n' "$v" "${#!v}"
  else
    printf '%-40s = %s\n' "$v" "${!v}"
  fi
done
```

---

## 4. Lifecycle operations

### 4.1 Issuing a session (login)

`POST /auth/admin/login` → `admin_login` (`backend/src/api/routers/admin_auth.py:322`):

1. Per-IP rate limit (`_LoginRateLimiter.acquire`, line 337). 429 + `Retry-After` if exhausted; logs `argus.auth.admin_login.rate_limited`.
2. `verify_credentials` (`backend/src/auth/admin_users.py:180`) — bcrypt comparison, constant-time burn cycle on miss (line 124).
3. `create_session` (`backend/src/auth/admin_sessions.py:188`):
   - `session_id = secrets.token_urlsafe(48)` (`generate_session_id`, line 124).
   - `token_hash = HMAC-SHA256(ADMIN_SESSION_PEPPER, session_id)` (`hash_session_token`, line 134) — refuses to mint a session if the pepper is empty.
   - INSERT into `admin_sessions` with `expires_at = now() + ADMIN_SESSION_TTL_SECONDS`, `ip_hash` / `user_agent_hash` SHA-256 fingerprints.
4. `_set_session_cookie` (line 236) attaches `argus.admin.session=<raw_token>; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=<ttl>`.
5. Logs `argus.auth.admin_session.created` (DAO, line 245) and `argus.auth.admin_login.session_issued` (router, line 397).

### 4.2 Reading a session (every authenticated request)

`resolve_session` (`backend/src/auth/admin_sessions.py:321`) is the single resolver:

1. Recompute `token_hash = HMAC-SHA256(pepper, cookie_value)`.
2. `_lookup_session_row` (line 429) — `SELECT … WHERE session_token_hash = :hash`, then re-validate equality with `hmac.compare_digest` to defeat any ORM/dialect timing oracle. Falls back to a raw `session_id` lookup only when the hash misses **and** `ADMIN_SESSION_LEGACY_RAW_FALLBACK=true` (grace window for pre-030 rows).
3. Reject if `revoked_at IS NOT NULL` — logs `argus.auth.admin_session.resolve_miss` with `reason="revoked"` (line 367).
4. Reject if `expires_at <= now()` — logs `reason="expired"` (line 379).
5. UPDATE `last_used_at = now()`, `expires_at = now() + ttl` (sliding window — see 4.3). Returns a `SessionPrincipal` (subject, role, tenant_id, expires_at, created_at, last_used_at).
6. Logs `argus.auth.admin_session.resolved` at DEBUG (line 410).

The handler MUST treat `None` as "unauthenticated" and issue a single canonical 401 — the failure reason fans out into the `argus.auth.admin_session.resolve_miss` log surface, never into the HTTP body.

### 4.3 Renewing a session

**Sliding TTL is implemented**, contrary to a common assumption that admin sessions are absolute. Every successful `resolve_session` writes:

```python
update_values = {
    "last_used_at": now,
    "expires_at": now + timedelta(seconds=ttl),
}
```

(`backend/src/auth/admin_sessions.py:387–390`). This means an idle gap > `ADMIN_SESSION_TTL_SECONDS` between two requests forces re-login; an active operator never logs out mid-flow.

There is **no separate refresh endpoint** and **no rotation of the raw token** during the lifetime of a session — the same cookie value is reused until logout, revoke, or expiry. Token rotation on every request was rejected in Phase 1 to keep the cookie-set surface narrow; it is on the Phase 2 backlog (`ISS-T20-003-phase2.md`).

`last_used_at` cadence: written on **every** successful resolve. Treat divergence between `last_used_at` and the live `expires_at` as a Postgres-side bug (the resolver always writes both in the same UPDATE).

### 4.4 Revoking a single session

**HTTP path — operator-initiated (logout):** `POST /auth/admin/logout` → `admin_logout` (`backend/src/api/routers/admin_auth.py:415`). Idempotent: returns `revoked=false` and still wipes the cookie if the row is already gone.

**SQL path — SRE-initiated (revoke a specific user, no token in hand):**

```sql
-- Tombstone every live session for one operator. Idempotent; re-running
-- this query against an already-revoked row updates 0 rows.
UPDATE admin_sessions
SET    revoked_at = now()
WHERE  subject = '<operator-subject>'
  AND  revoked_at IS NULL
  AND  expires_at > now()
RETURNING session_token_hash, created_at, expires_at;
```

Replace `<operator-subject>` with the value from `admin_users.subject`. The `expires_at > now()` clause skips already-expired rows so the row count returned is the live-session count you actually killed (useful for the audit-log entry).

### 4.5 Mass revocation (kill-switch)

**SQL** — wipe every live admin session globally:

```sql
-- Single statement; safe to run inside a normal transaction. Returns the
-- number of sessions tombstoned for the audit trail.
UPDATE admin_sessions
SET    revoked_at = now()
WHERE  revoked_at IS NULL
  AND  expires_at > now()
RETURNING subject, role, created_at;
```

**Python REPL** (preferred for production — uses the DAO, hits the same code path as `/logout`, and gives you per-row logging):

```bash
# From a backend pod with the app environment loaded:
kubectl exec -n argus deploy/argus-backend -- \
  python -m asyncio
```

```python
import asyncio
from sqlalchemy import select, update
from src.db.session import async_session_factory
from src.db.models import AdminSession
from src.auth.admin_sessions import _utcnow

async def mass_revoke():
    async with async_session_factory() as db:
        stmt = (
            update(AdminSession)
            .where(
                AdminSession.revoked_at.is_(None),
                AdminSession.expires_at > _utcnow(),
            )
            .values(revoked_at=_utcnow())
        )
        result = await db.execute(stmt)
        await db.commit()
        return result.rowcount

print(asyncio.run(mass_revoke()))
```

After mass revoke: open the audit-log channel (§5), drop a one-line entry referencing the incident ticket, and re-run the verification query in §6 to confirm zero live rows remain.

> **No HTTP admin-revoke endpoint exists yet.** A `DELETE /auth/admin/sessions/{subject}` surface is planned for Phase 2 (`ISS-T20-003-phase2.md`); until then, SQL or the Python one-liner is the only mass-revoke path. Do not extend `/auth/admin/logout` to take a `subject` parameter — that path explicitly accepts only the bearer's own cookie.

---

## 5. Pepper rotation procedure

### 5.1 Why rotate

`ADMIN_SESSION_PEPPER` is the keying material for `HMAC-SHA256` over every admin session token. **A pepper leak is a forge primitive**: an attacker who steals the pepper and a copy of `admin_sessions.session_token_hash` can compute a raw token whose hash matches a live row, then plant it in a victim cookie jar (or just use the corresponding `session_id` raw column during the 030→031 grace window). Rotate immediately on any of:

- Suspected secrets-store compromise (Vault, sealed secret, env-var leak).
- Departure of an operator who held production env-var read access.
- Routine 90-day rotation (recommended; not yet automated).
- Forensic discovery that a hash leaked (DB dump exfiltration, replica-snapshot loss).

Today's mechanism is **invalidating rotation**: changing the pepper turns every existing `session_token_hash` into a forgery-useless string, all live admin sessions die at the next request, and operators must re-login. A dual-pepper rolling rotation (`ADMIN_SESSION_PEPPER_NEXT`) is on the Phase 2 roadmap (`ISS-T20-003-phase2.md`); it does **not** exist in `core/config.py` today — verified.

### 5.2 Pre-rotation checklist

1. Open the incident channel and the audit log: `ai_docs/operations/incident-log.md` (create if absent — see §5.5 template).
2. Schedule a maintenance window. Every active admin gets logged out on the next request after the new pepper takes effect.
3. Confirm at least one super-admin can log in via the bootstrap flow (`bootstrap_admin_user_if_configured`, `backend/src/auth/admin_users.py:266`) in case the rotation locks everyone out.
4. Note the **previous** `ADMIN_SESSION_PEPPER` value somewhere only you can read for the rollback window (encrypted secrets store, NOT a paste in the incident channel).
5. Verify backend pod count and rollout strategy — a rolling restart will briefly serve from old + new pods simultaneously; that is expected and safe (an old-pod resolve fails closed to "unauthenticated").

### 5.3 Step-by-step rotation

**Step 1 — generate a new pepper** (≥48 bytes of entropy; keep base64 for readability):

```powershell
# Windows PowerShell (preferred on operator workstations):
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

```bash
# Linux / macOS:
openssl rand -base64 64 | tr -d '\n'; echo
# or, identical entropy, no shell quoting traps:
python -c "import secrets; print(secrets.token_urlsafe(64))"
```

The result is an 80-ish-char URL-safe string. Treat it as a credential — handle in the secrets manager, never in chat.

**Step 2 — stage in the secrets store.** Write the new value into the secret backing `ADMIN_SESSION_PEPPER` (Vault path / Kubernetes secret / sealed secret). Do **not** roll the deployment yet.

> *Dual-pepper note.* `ADMIN_SESSION_PEPPER_NEXT` does **not** exist in `backend/src/core/config.py` as of 2026-04-22 — this is invalidating-rotation only. When Phase 2 lands the dual-pepper accepter (planned in `ISS-T20-003-phase2.md`), update this section. Do not paste a `_NEXT` value into the env hoping it works; the resolver ignores unknown vars.

**Step 3 — drain in-flight admin work.** Announce in the operator channel that everyone is about to be logged out. Optionally pre-emptively mass-revoke (§4.5) so the cutover is instantaneous instead of staggered.

**Step 4 — roll the backend.**

```bash
kubectl -n argus rollout restart deploy/argus-backend
kubectl -n argus rollout status   deploy/argus-backend --timeout=5m
```

The new pods boot with the new pepper. The production `model_validator` `_enforce_production_admin_auth` (`backend/src/core/config.py:848`) refuses to start if the pepper is missing or `< 32` chars — a botched rotation surfaces as a `CrashLoopBackOff`, not a quietly-broken auth surface.

**Step 5 — verify.** Log into the admin UI with a known account, then from the DB:

```sql
-- Newest session row should belong to the operator you just used and its
-- session_token_hash should validate against the new pepper from a Python REPL.
SELECT subject, role, created_at, expires_at, session_token_hash
FROM   admin_sessions
WHERE  subject = '<your-subject>'
ORDER  BY created_at DESC
LIMIT  1;
```

```python
# In a backend pod REPL — confirm the hash matches what the new pepper produces.
from src.auth.admin_sessions import hash_session_token
# Paste the raw cookie value from the browser DevTools (Application → Cookies →
# argus.admin.session). Verify it hashes to the value from the SQL query above.
print(hash_session_token("<raw-cookie-value>"))
```

If the two strings match, rotation succeeded. If they don't, you are still on the old pepper — re-check the secret-store value and the pod env (`kubectl exec ... env | rg ADMIN_SESSION_PEPPER`).

### 5.4 Rollback

For the duration of the maintenance window, the **previous** pepper remains a valid rollback target:

1. Restore the previous value in the secrets store.
2. `kubectl -n argus rollout restart deploy/argus-backend`.
3. Pre-rotation sessions become valid again; **post-rotation sessions become invalid** (their hashes no longer match). Operators who logged in during the rotation window must log in again.
4. Annotate the incident-log entry with the rollback timestamp and the reason.

After the maintenance window closes, drop the previous pepper from the secrets store so a future rollback cannot resurrect it.

### 5.5 Audit-log entry template

Append to `ai_docs/operations/incident-log.md` (create the file with the heading `# Operations Incident Log` if it does not exist):

```markdown
## YYYY-MM-DD — ADMIN_SESSION_PEPPER rotation

- **Operator:** <your handle>
- **Reason:** <90-day routine | suspected leak | personnel change | forensic finding>
- **Pre-rotation:** mass-revoke run? <yes/no>; live session count: <N>
- **Generated by:** `python -c "import secrets; print(secrets.token_urlsafe(64))"`
- **Rolled at:** <ISO-8601 UTC>; pods restarted: <count>
- **Verification:** <hash-match / SQL row id>
- **Rollback window closes:** <ISO-8601 UTC>
- **Linked ticket:** <Jira / ARG-xxx>
```

### 5.6 Worked example

A fully-commented worked example for the env-var lifecycle (generation, staging, drain, restart, verification) lives inline in [`backend/.env.example`](../../backend/.env.example) under the `ADMIN_SESSION_PEPPER` block — read it before your first rotation. Do **not** copy the rotation prose from `.env.example` into this runbook; treat `.env.example` as the source of truth for the env-var grammar and this runbook as the source of truth for the operational procedure.

---

## 6. Audit & forensics

### 6.1 Events emitted today

Structured logs (logger name = module name; format = `extra.event` JSON field). Verified at `backend/src/auth/admin_users.py` and `backend/src/auth/admin_sessions.py`:

| Event | Emitter | When |
| ----- | ------- | ---- |
| `argus.auth.admin_login.failed` | `admin_users.py:203, 224, 235, 245` | Subject missing / disabled / wrong password / DB error. Same canonical 401 to the client. |
| `argus.auth.admin_login.succeeded` | `admin_users.py:254` | bcrypt match accepted. |
| `argus.auth.admin_login.rate_limited` | `admin_auth.py:342` | Per-IP token bucket exhausted; includes `retry_after_seconds`. |
| `argus.auth.admin_login.session_issued` | `admin_auth.py:397` | Cookie set, row inserted. Carries `session_id_prefix` (first 6 chars + `...`). |
| `argus.auth.admin_session.created` | `admin_sessions.py:245` | DAO-level mint event. |
| `argus.auth.admin_session.resolved` | `admin_sessions.py:410` (DEBUG) | Successful resolve + slide. |
| `argus.auth.admin_session.resolve_miss` | `admin_sessions.py:356, 367, 379` | `reason ∈ {not_found, revoked, expired}`. |
| `argus.auth.admin_session.resolve_mismatch` | `admin_sessions.py:460, 476` | Constant-time re-check rejected an apparent hit (defence-in-depth — should be 0 in healthy operation). |
| `argus.auth.admin_session.resolve_db_error` | `backend/src/api/routers/admin.py:403` | Resolver caught a `SQLAlchemyError`. |
| `argus.auth.admin_session.revoked` | `admin_sessions.py:313` | Tombstone applied. |
| `argus.auth.admin_logout` | `admin_auth.py:449` | Endpoint hit (whether or not a row was tombstoned — see `revoked` field). |
| `argus.auth.admin_logout.db_error` | `admin_auth.py:441` | Logout caught a DB error; cookie still cleared. |

> The `audit_logs` Postgres table (`backend/src/db/models.py:551`) is for **tenant** audit events and does **not** receive admin-auth events today. Admin-auth audit lives entirely in the structured app-log stream.

### 6.2 Recommended queries

Assumes JSON logs piped through `jq` (substitute Loki / Datadog / Elastic syntax as needed). All filters key off the `event` field.

**All login attempts for one operator over the last 24 h:**

```bash
kubectl -n argus logs --since=24h deploy/argus-backend \
  | jq -c 'select(.event | startswith("argus.auth.admin_login."))
           | select(.subject == "<operator-subject>"
                  or .extra.subject == "<operator-subject>")'
```

> The `failed` event redacts the subject before logging; failure rows must be correlated by source IP + timestamp + the `succeeded` rows surrounding them. This is intentional (no enumeration oracle) — see `admin_users.py:203`.

**All sessions revoked in the last 7 days (DB):**

```sql
SELECT subject, role, tenant_id, created_at, revoked_at,
       expires_at AS would_have_expired
FROM   admin_sessions
WHERE  revoked_at >= now() - interval '7 days'
ORDER  BY revoked_at DESC;
```

**Mass-revocation log events in the last 7 days (logs):**

```bash
kubectl -n argus logs --since=168h deploy/argus-backend \
  | jq -c 'select(.event == "argus.auth.admin_session.revoked")'
```

**Orphan detector — rows past TTL but never tombstoned** (should be zero; non-zero = a resolver path is silently failing to tombstone, file an incident):

```sql
SELECT subject, role, created_at, expires_at, last_used_at
FROM   admin_sessions
WHERE  revoked_at IS NULL
  AND  expires_at < now() - interval '1 hour'  -- grace for clock skew
ORDER  BY expires_at ASC
LIMIT  100;
```

> **Note.** No periodic prune job for `admin_sessions` exists in `backend/src/celery/beat_schedule.py` today (verified). Expired rows accumulate until cleanup is added (planned post-Phase 2). The orphan query above is the manual SRE-side check; row growth ≈ `logins/day × retention_days` and is not yet a capacity concern.

**Hash forensics — recompute one row's hash from a captured cookie:**

```python
# Backend pod REPL. Confirms whether a captured cookie value resolves to a
# specific stored row — useful for "did this token actually hit our DB?"
from src.auth.admin_sessions import hash_session_token
print(hash_session_token("<raw-cookie>"))
# Compare the hex output with admin_sessions.session_token_hash.
```

---

## 7. Incident playbooks

### 7.1 Suspected admin-account compromise

**Trigger.** Anomalous login (off-hours, unfamiliar IP geo, repeated failed attempts followed by a success), tip from the operator, or detection from external SOC.

**Action.**

1. Mass-revoke every live session for the subject (§4.4 SQL block).
2. Force a password reset by NULLing `password_hash` on the operator and re-running `bootstrap_admin_user_if_configured` with a fresh value (or use the team's admin-user reset doc if one exists).
3. Pull the last 30 days of `argus.auth.admin_login.*` and `argus.auth.admin_session.resolved` for the subject (§6.2 query) and walk the source IPs.
4. If the compromise plausibly involved the pepper (e.g., the operator had secrets-store read access), proceed to §7.2 in the same change window.
5. Record in `ai_docs/operations/incident-log.md`.

### 7.2 Pepper compromise / leak

**Trigger.** Vault audit shows the secret was accessed by a non-allow-listed identity, the secret appears in a paste, or the operator who owned it leaves the team.

**Action.** Execute §5 end-to-end (rotate). After verification (§5.3 step 5), additionally mass-revoke (§4.5) so any session minted in the last few minutes against the old pepper is also tombstoned. File the incident.

### 7.3 Mass session anomaly (suspected bot)

**Trigger.** Sudden spike in `argus.auth.admin_login.session_issued` rate, `admin_sessions` row growth, or 429s from `argus.auth.admin_login.rate_limited`.

**Action.**

1. Identify the source — group `argus.auth.admin_login.*` by `extra.client_ip` over the last hour:

   ```bash
   kubectl -n argus logs --since=1h deploy/argus-backend \
     | jq -r 'select(.event | startswith("argus.auth.admin_login.")) | .client_ip' \
     | sort | uniq -c | sort -rn | head -20
   ```

2. If a single IP / /24 dominates, block at the load balancer / WAF layer first (the per-IP token bucket already throttles to `ADMIN_LOGIN_RATE_LIMIT_PER_MINUTE = 5/min`, but a botnet rotates IPs).
3. Notify the security on-call channel; do **not** lower `ADMIN_LOGIN_RATE_LIMIT_PER_MINUTE` without a rollback plan — legitimate operators on a shared NAT will hit the same bucket.
4. Mass-revoke (§4.5) only if there is evidence sessions were actually issued (i.e., `session_issued` events, not just `failed`).

### 7.4 Cookie configuration drift

**Trigger.** Browser DevTools shows `argus.admin.session` missing `Secure` or `HttpOnly`, or `SameSite` is set to `Lax`/`None`.

**Diagnose.** Hit the login endpoint directly and inspect the `Set-Cookie` header:

```bash
curl -i -s -X POST https://<host>/api/auth/admin/login \
  -H 'content-type: application/json' \
  -d '{"subject":"<known-test-subject>","password":"<test-password>"}' \
  | sed -n '1,/^\r$/p' | rg -i '^set-cookie'
```

Expected (production): `Set-Cookie: argus.admin.session=...; HttpOnly; Secure; SameSite=Strict; Path=/`. The `Secure` flag is unconditional in production; it is relaxed only if `DEBUG=true` **and** the request itself was not HTTPS (`backend/src/api/routers/admin_auth.py:249–251`). The `HttpOnly` and `SameSite=Strict` flags are unconditional (lines 256–258).

**Roll forward.** The cookie attributes are hard-coded in `_set_session_cookie` — drift means either someone has shipped a code change or `DEBUG=true` slipped into a production deploy. Check `kubectl -n argus exec deploy/argus-backend -- env | rg '^DEBUG='` first; if `true`, that is your bug and a config rollback fixes it. Otherwise, `git log -p -- backend/src/api/routers/admin_auth.py` to find the offending change and revert.

### 7.5 `ADMIN_AUTH_MODE` reverted to legacy in production

**Symptom.** Backend pods refuse to start; pod log shows:

```text
admin_auth_mode_unsafe_for_production
event=argus.config.admin_auth_mode_unsafe_for_production
```

This is the production guard `_enforce_production_admin_auth` (`backend/src/core/config.py:848, 876`) doing its job. Production refuses any value other than `ADMIN_AUTH_MODE=session`.

**Recover.**

1. Don't try to override the guard — it exists because `cookie` and `both` modes accept a legacy header path and bypass HMAC at-rest hashing.
2. Set `ADMIN_AUTH_MODE=session` in the secrets store / config map.
3. `kubectl -n argus rollout restart deploy/argus-backend`.
4. The frontend has the symmetric guard (`Frontend/instrumentation.ts:34`); if that crash-loops the FE pod, set `NEXT_PUBLIC_ADMIN_AUTH_MODE=session` and roll the FE.
5. File the incident — the change set that introduced the bad config must be reverted regardless of whether the recovery succeeded.

---

## 8. Migration & cleanup tracking

| Item | Status | Reference |
| ---- | ------ | --------- |
| Alembic 030 — add `session_token_hash`, backfill HMAC, index UNIQUE | **Shipped** (Cycle 6 / Batch 6) | `backend/alembic/versions/030_hash_admin_session_ids.py` |
| Grace-window flag `ADMIN_SESSION_LEGACY_RAW_WRITE` | **Live**, default `true` | `backend/src/core/config.py:271` |
| Grace-window flag `ADMIN_SESSION_LEGACY_RAW_FALLBACK` | **Live**, default `true` | `backend/src/core/config.py:278` |
| Grace-window deadline | **2026-06-21** (60 days post Phase 1) | `ai_docs/develop/issues/ISS-T20-003.md:11` |
| Pre-flight gate: flip both `_WRITE` and `_FALLBACK` to `false` ≥ 24 h before C7-T07 | **Pending** | `ai_docs/develop/plans/2026-04-22-argus-cycle7.md:73` |
| Alembic 031 — drop `session_id` raw column, promote `session_token_hash` to PK, remove both flags | **Planned** (C7-T07) | `ai_docs/develop/plans/2026-04-22-argus-cycle7.md:721` |
| Periodic prune job for tombstoned + expired rows | **Not implemented**; manual cleanup or future Celery beat task | `backend/src/celery/beat_schedule.py` (verified — no admin-session task) |

The C7-T07 PR cannot merge without (a) a screenshot of the pre-flight signal table from staging Prometheus, all green, (b) a link to this runbook, and (c) confirmation that `ADMIN_SESSION_LEGACY_RAW_FALLBACK=false` has been deployed in staging for at least one TTL window. SREs running the rollout: do not flip the flag and immediately call C7-T07 done — wait the full TTL window so live sessions drain.

---

## 9. Quick reference appendix

The five commands you reach for most often. Copy-paste, substitute the obvious placeholders.

**1. Revoke one operator's sessions (no token needed):**

```sql
UPDATE admin_sessions SET revoked_at = now()
WHERE subject = '<operator-subject>' AND revoked_at IS NULL AND expires_at > now()
RETURNING session_token_hash, created_at, expires_at;
```

**2. Mass revoke (all live admin sessions):**

```sql
UPDATE admin_sessions SET revoked_at = now()
WHERE revoked_at IS NULL AND expires_at > now()
RETURNING subject, role, created_at;
```

**3. Rotate the pepper (full procedure: §5):**

```powershell
# 1. Generate
python -c "import secrets; print(secrets.token_urlsafe(64))"
# 2. Stage in secrets store, then:
kubectl -n argus rollout restart deploy/argus-backend
kubectl -n argus rollout status   deploy/argus-backend --timeout=5m
# 3. Verify in browser + DB (see §5.3 step 5).
```

**4. List currently active admin sessions:**

```sql
SELECT subject, role, tenant_id, created_at, last_used_at, expires_at
FROM   admin_sessions
WHERE  revoked_at IS NULL AND expires_at > now()
ORDER  BY last_used_at DESC;
```

**5. Tail the admin-auth event stream (live):**

```bash
kubectl -n argus logs -f deploy/argus-backend \
  | jq -c 'select(.event | startswith("argus.auth.admin_"))'
```

```powershell
# PowerShell-equivalent without jq (rg + Select-String):
kubectl -n argus logs -f deploy/argus-backend `
  | Select-String -Pattern '"event":"argus\.auth\.admin_'
```

---

## 10. MFA enrollment & enforcement (C7-T03)

> Cycle 7 deliverable, mounted at `/api/v1/auth/admin/mfa/*` (matches the
> sibling `admin_auth.py` router prefix `"/auth/admin"` — auth-domain
> first, admin-namespace nested). Foundation (DAO + Fernet keyring +
> Alembic 032) ships with C7-T01; the HTTP surface and the super-admin
> policy gate ship with C7-T03. Audience: SRE on-call + admin operators
> rolling out MFA to a fresh deployment.

### 10.1 Endpoint reference

All endpoints sit under `/api/v1/auth/admin/mfa/*`, return JSON, and require an authenticated admin session (the existing `require_admin` gate — same auth modes as the rest of the admin surface). Successful proofs additionally stamp `admin_sessions.mfa_passed_at` so the new `require_admin_mfa_passed` gate (§10.3) accepts the same session for sensitive routes.

| Method | Path | Body / params | Success (2xx) | Failure surface |
| ------ | ---- | ------------- | ------------- | --------------- |
| `POST` | `/auth/admin/mfa/enroll` | _none_ | `200 MFAEnrollResponse` — `secret_uri` (otpauth://), `qr_data_uri=null`, `backup_codes` (returned ONCE) | `409 mfa_already_enabled`, `429` (per-user+IP burst) |
| `POST` | `/auth/admin/mfa/confirm` | `{ "totp_code": "NNNNNN" }` | `200 MFAConfirmResponse` — `enabled=true`, `enabled_at`. Atomically calls `mark_session_mfa_passed` so the operator does not need a separate verify hop after enrolling. | `400 invalid_totp` / `400 no_pending_enrollment`, `409 mfa_already_enabled`, `429` |
| `POST` | `/auth/admin/mfa/verify` | `{ "totp_code": "NNNNNN" }` **or** `{ "backup_code": "..." }` (XOR enforced by Pydantic) | `200 MFAVerifyResponse` — `verified=true`, `mfa_passed_at`, `remaining_backup_codes` | `401 mfa_verify_failed` (single detail across both paths so a brute-forcer cannot tell TOTP-typo vs backup-code-typo apart), `409 mfa_not_enabled`, `429` |
| `POST` | `/auth/admin/mfa/disable` | Same XOR proof as `/verify` | `200 MFADisableResponse` — `disabled=true`, `disabled_at` | `401 mfa_verify_failed`, `409 mfa_not_enabled`, `429` |
| `GET` | `/auth/admin/mfa/status` | _none_ | `200 MFAStatusResponse` — `enabled`, `enrolled_at`, `remaining_backup_codes`, `mfa_passed_for_session` | `401` (unauthenticated) |
| `POST` | `/auth/admin/mfa/backup-codes/regenerate` | Same XOR proof as `/verify` | `200 BackupCodesRegenerateResponse` — fresh `backup_codes` (ONCE) + `generated_at` | `401 mfa_verify_failed`, `409 mfa_not_enabled`, `429` |

Curl walk-through (replace `<HOST>` and `<COOKIE>`):

```bash
# 1. Enroll — captures the otpauth URI + first 10 backup codes (last time you see them).
curl -sS -X POST "https://<HOST>/api/v1/auth/admin/mfa/enroll" \
  -b "argus.admin.session=<COOKIE>" \
  -H "Accept: application/json"
# {
#   "secret_uri": "otpauth://totp/ARGUS:operator-1?secret=...&issuer=ARGUS",
#   "qr_data_uri": null,
#   "backup_codes": ["1a2b-3c4d-5e6f", ...]
# }

# 2. Confirm — paste the 6-digit code from your authenticator app.
curl -sS -X POST "https://<HOST>/api/v1/auth/admin/mfa/confirm" \
  -b "argus.admin.session=<COOKIE>" \
  -H "content-type: application/json" \
  -d '{"totp_code":"123456"}'

# 3. Re-verify on subsequent sessions (TOTP).
curl -sS -X POST "https://<HOST>/api/v1/auth/admin/mfa/verify" \
  -b "argus.admin.session=<COOKIE>" \
  -H "content-type: application/json" \
  -d '{"totp_code":"123456"}'

# 4. Re-verify with a backup code (consumed on success — single use).
curl -sS -X POST "https://<HOST>/api/v1/auth/admin/mfa/verify" \
  -b "argus.admin.session=<COOKIE>" \
  -H "content-type: application/json" \
  -d '{"backup_code":"1a2b-3c4d-5e6f"}'

# 5. Snapshot.
curl -sS "https://<HOST>/api/v1/auth/admin/mfa/status" \
  -b "argus.admin.session=<COOKIE>"
# {"enabled":true,"enrolled_at":"...","remaining_backup_codes":9,"mfa_passed_for_session":true}

# 6. Mint a fresh batch of backup codes (prior batch is invalidated server-side).
curl -sS -X POST "https://<HOST>/api/v1/auth/admin/mfa/backup-codes/regenerate" \
  -b "argus.admin.session=<COOKIE>" \
  -H "content-type: application/json" \
  -d '{"totp_code":"123456"}'

# 7. Disable (requires a fresh proof; same XOR shape as /verify).
curl -sS -X POST "https://<HOST>/api/v1/auth/admin/mfa/disable" \
  -b "argus.admin.session=<COOKIE>" \
  -H "content-type: application/json" \
  -d '{"totp_code":"123456"}'
```

> **No `qr_data_uri` payload yet.** The backend deliberately returns `null` because no QR generator (`qrcode`, `segno`, …) is pinned in `backend/requirements.txt`. The frontend (C7-T04) renders the `secret_uri` itself with `qrcode.react` so the server bundle stays slim. Operators using curl can paste the otpauth URI into any TOTP app supporting URI import, or transcribe the `secret=` parameter into manual-entry mode.

### 10.2 Bounded error taxonomy

The endpoints emit a small, deliberately bounded set of `detail` codes so the SIEM, the FE, and the runbook agree on a single vocabulary. None of them carry PII, role names, or secret material.

| HTTP | `detail` | Meaning | Operator response |
| ---- | -------- | ------- | ----------------- |
| 400 | `invalid_totp` | `/confirm` received a code that did not match the pending seed (or was outside the ±1 step skew window). | Re-check device clock skew; retry. |
| 400 | `no_pending_enrollment` | `/confirm` was called but there is no pending TOTP secret to confirm. | Call `/enroll` first. |
| 401 | `Authentication required` | Underlying admin gate denied the request (no cookie / expired / revoked). | Log in again. |
| 401 | `mfa_verify_failed` | `/verify`, `/disable`, or `/backup-codes/regenerate` got a wrong TOTP **or** wrong backup code. Single detail across both paths so a brute-forcer cannot fingerprint which proof type they typed wrong. | Retry with a fresh code; if you exhausted backup codes, file an incident (§10.5). |
| 409 | `mfa_already_enabled` | `/enroll` or `/confirm` called on an account that is already enrolled. | Use `/verify` instead, or `/disable` first if you want a fresh enrolment. |
| 409 | `mfa_not_enabled` | `/verify`, `/disable`, or `/backup-codes/regenerate` called on an account without MFA enrolled. State mismatch — distinct from `401 mfa_verify_failed` which signals a wrong proof on an enrolled account. | Call `/enroll` + `/confirm` to enrol the account first; for `/disable`, no action — the row is already in the desired state. |
| 429 | _Too Many Requests_ | Per-user-and-IP token bucket exhausted (5 req/min/user/IP). `Retry-After` header set. | Honour `Retry-After`; do not loop. |
| 500 | `Internal Server Error` | Unhandled exception path (DB error, etc.). Stack trace stays in the structured app log; the response body carries no detail. | Pull the matching `argus.auth.admin_mfa.*_failed` log line for triage. |

### 10.3 Super-admin enforcement gate (`require_admin_mfa_passed`)

Sensitive admin routes (mutating tenant / target / provider / cache / DR state — full table in `ai_docs/changelog/CHANGELOG.md` C7-T03 entry) hang off `require_admin_mfa_passed` instead of `require_admin`. The gate runs **after** `require_admin` succeeds and adds two checks:

1. **Enrolment gate.** If the operator's role is in `settings.admin_mfa_enforce_roles` (env-driven, default `super-admin`) and `admin_users.mfa_enabled = false`, the gate raises:

   ```http
   HTTP/1.1 403 Forbidden
   X-MFA-Enrollment-Required: true
   Content-Type: application/json

   {"detail": "mfa_enrollment_required"}
   ```

   The frontend reads `X-MFA-Enrollment-Required` to decide whether to show an enrolment wizard vs. a re-auth prompt.

2. **Re-authentication freshness gate.** If the operator IS enrolled but `admin_sessions.mfa_passed_at` is NULL or older than `ADMIN_MFA_REAUTH_WINDOW_SECONDS` (default 12 h, matches `ADMIN_SESSION_TTL_SECONDS` so MFA is re-prompted at most once per session), the gate raises:

   ```http
   HTTP/1.1 401 Unauthorized
   X-MFA-Required: true
   Content-Type: application/json

   {"detail": "mfa_required"}
   ```

The gate intentionally degrades to a no-op on **two** paths:

- The `ADMIN_MFA_ENFORCE_ROLES` CSV is empty. A one-shot WARNING is logged at process start (`argus.auth.admin_mfa.enforcement_disabled` via `log_mfa_enforcement_state`) so an operator-induced misconfiguration cannot silently disable the control.
- The request authenticated via the legacy `X-Admin-Key` shim (no `SessionPrincipal` on `request.state` — therefore no `mfa_passed_at` to consult). Switch `ADMIN_AUTH_MODE` away from `both` to close this bypass once the FE is fully on session-mode.

### 10.4 Tuning the enforcement set

`ADMIN_MFA_ENFORCE_ROLES` is a CSV of role names (canonical hyphen form, e.g. `super-admin,admin`). The parser also accepts the underscore form (`super_admin` → `super-admin`). Examples:

| Value | Effect |
| ----- | ------ |
| `super-admin` (default) | Only super-admins are forced into MFA; tenant-scoped admins keep their existing surface. |
| `super-admin,admin` | Both super-admins and tenant admins must enrol + reauth. Recommended endpoint state once admins have walked through enrolment. |
| `` (empty) | Gate disabled. Logged as WARNING at startup. **Do not ship to production with this value.** |

Roll-out guidance:

1. Start with `ADMIN_MFA_ENFORCE_ROLES=super-admin` and announce a 2-week enrolment window in the operator channel.
2. Once every super-admin is enrolled (verify via `SELECT subject FROM admin_users WHERE role='super-admin' AND mfa_enabled=true`), broaden to `super-admin,admin` and repeat.
3. Per-pod restart picks up the new value (`Settings` parses on boot via `parse_admin_mfa_enforce_roles` in `backend/src/core/config.py:396`); a `kubectl -n argus rollout restart deploy/argus-backend` is sufficient.
4. Confirm post-deploy:

   ```bash
   kubectl -n argus logs --since=2m deploy/argus-backend \
     | jq -c 'select(.event == "argus.auth.admin_mfa.enforcement_enabled")'
   # {"event":"argus.auth.admin_mfa.enforcement_enabled","enforced_roles":["super-admin"], ...}
   ```

For the Fernet keyring used to encrypt TOTP seeds at rest, follow the rotation cookbook inline in [`backend/.env.example`](../../backend/.env.example) under the `ADMIN_MFA_KEYRING` block (do **not** duplicate the procedure here — `.env.example` is the source of truth; this runbook only points at it).

### 10.5 Incident playbook — super-admin lost MFA device

**Trigger.** Super-admin reports loss / theft / wipe of their TOTP authenticator and they have already exhausted their backup codes.

**Goal.** Restore the operator to a usable login state without disabling MFA across the fleet, in a way that is fully audit-trailed.

**Preferred path — DBA-assisted backup-code regeneration.**

1. Out-of-band identity check (Slack DM + a control question only the human operator could answer; do NOT accept request via the operator's email if the lost device is a phone — assume the email account is also lost).
2. Open a change ticket; link this runbook section.
3. From a backend pod REPL, mint a fresh batch of backup codes for the operator without holding their TOTP. This bypasses the verify-proof requirement of `/backup-codes/regenerate` and is the reason the path is DBA-only:

   ```python
   import asyncio
   from src.db.session import async_session_factory
   from src.auth.admin_mfa import regenerate_backup_codes

   async def issue():
       async with async_session_factory() as db:
           plaintext = await regenerate_backup_codes(db, subject="<lost-device-operator>")
           await db.commit()
           return plaintext

   for code in asyncio.run(issue()):
       print(code)
   ```

4. Hand the printed codes back to the operator over the same out-of-band channel (the `regenerate_backup_codes` DAO returns plaintext exactly once; the call commits bcrypt hashes server-side — there is no second chance to read them).
5. Operator uses one of the new codes to call `/auth/admin/mfa/verify`, then `/auth/admin/mfa/disable` (proof body), then `/auth/admin/mfa/enroll` against the new device.
6. Record the chain (ticket, who minted, who consumed) in `ai_docs/operations/incident-log.md`.

**Fallback path — temporary `mfa_enabled=false` toggle (DO NOT prefer).**

Only acceptable when the DAO bypass above also fails (e.g. the operator's row is missing or corrupt). Trade-off: the operator is unauthenticated against the MFA gate for the whole window between SQL flip and re-enrolment, so any concurrent compromise of their cookie can move freely through the sensitive surface.

```sql
-- 1. Capture pre-flip state for the audit trail.
SELECT subject, role, mfa_enabled, updated_at
FROM   admin_users
WHERE  subject = '<lost-device-operator>';

-- 2. Disable MFA for the operator. Wrap in a transaction so the AuditLog
--    INSERT below is in the same unit of work.
BEGIN;
UPDATE admin_users
SET    mfa_enabled = false,
       mfa_secret_encrypted = NULL,
       mfa_backup_codes_hash = NULL,
       updated_at = NOW()
WHERE  subject = '<lost-device-operator>'
RETURNING subject, mfa_enabled;

-- 3. Tombstone every active session for the operator so the next request
--    forces a fresh login (the gate would otherwise still see a stale
--    mfa_passed_at row from before the flip).
UPDATE admin_sessions
SET    revoked_at = NOW()
WHERE  subject     = '<lost-device-operator>'
  AND  revoked_at  IS NULL;
COMMIT;
```

After the SQL flip:
- Notify the operator out-of-band; they MUST log in fresh and immediately walk through `/auth/admin/mfa/enroll` + `/confirm`.
- Append to `ai_docs/operations/incident-log.md`: who flipped, the change-ticket link, expected re-enrolment deadline (≤ 24 h).
- Add a follow-up calendar reminder to verify `mfa_enabled = true` on the operator within 24 h. If they have not re-enrolled, mass-revoke their sessions again (§4.4) until they do.

**Why backup-code regeneration is preferred.** It keeps `mfa_enabled = true` for the operator at all times, so the policy gate never lets the account through a sensitive route without a fresh proof. The SQL flip leaves a window where the operator is effectively non-MFA — exactly the surface the gate exists to close.
