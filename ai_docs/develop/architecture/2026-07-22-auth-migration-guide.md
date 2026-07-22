# Multi-Principal Auth Migration Guide (P3-AUTH-003)

**Status:** additive, fully backward compatible (SI-7)
**Date:** 2026-07-22
**Scope:** `TargetConfig` / `AuthConfig`, `SessionStore`, Playwright session reuse,
exploitation auth propagation.

This guide explains how the existing single-principal authentication config maps
onto the new multi-principal model, how to declare several principals, when to use
`secret_ref` vs. inline secrets, and the hard rule that secrets never reach the LLM,
logs, or evidence.

---

## 1. What changed

Three security gaps were closed:

| Gap | Before | After |
|-----|--------|-------|
| **G-1** | Playwright login produced cookies that were **dropped** — `execute_exploitation` ran unauthenticated. | The owner session's cookies/headers are propagated into tool argv (`nuclei`/`ffuf`/`sqlmap`/`dalfox`). |
| **G-2** | Exactly one identity (single `authentication` block). | N principals (`owner`, `attacker`, tenant users, …) with **isolated** cookie jars. |
| **G-7** | Every login started a fresh browser; no reusable session. | Playwright `storageState` can be seeded and is always exported for reuse. |

All new fields are `Optional` / additive. **Existing YAML/JSON configs and the
existing `resolve_placeholders()` behaviour are unchanged.**

---

## 2. Legacy single-auth → `owner` principal

The legacy shape still works verbatim:

```yaml
authentication:
  login_type: form
  login_url: "https://app.example.com/login"
  credentials:
    username: "user"
    password: "pass"
  login_flow:
    - instruction: "Type $username into the email field"
    - instruction: "Type $password into the password field"
    - instruction: "Click Sign In"
  success_condition:
    type: url_contains
    value: "/dashboard"
```

Downstream code should call `TargetConfig.resolved_principals()`, which normalises
this into a single principal:

```python
cfg = TargetConfig.from_yaml(yaml_text)
principals = cfg.resolved_principals()
# -> [PrincipalConfig(principal_id="owner", role=PrincipalRole.OWNER,
#                     credentials=<AuthCredentials>, login=<AuthConfig>)]
```

Resolution order in `resolved_principals()`:

1. `principals` (new field) if present — returned as-is.
2. else legacy `authentication` → one `owner` principal.
3. else `[]` (anonymous / no auth).

> **Aliases:** `owner` == `user_a`, `attacker` == `user_b`. Use `owner`/`attacker`
> in config; the aliases are documentation only.

---

## 3. Declaring multiple principals

```yaml
principals:
  - principal_id: owner
    role: owner
    tenant_id: tenant_a
    login:
      login_type: form
      login_url: "https://app.example.com/login"
      credentials:
        username: "owner@example.com"
        password: "$password"        # placeholder, see §5
      login_flow:
        - instruction: "Type $username into the email field"
        - instruction: "Type $password into the password field"
        - instruction: "Click Sign In"
      success_condition:
        type: url_contains
        value: "/dashboard"

  - principal_id: attacker
    role: attacker
    tenant_id: tenant_b
    bearer_token_ref: "ATTACKER_BEARER"   # split-plane handle, see §4

  - principal_id: anon
    role: anonymous
```

`principal_id` must match `^[a-z][a-z0-9_]{0,63}$` (e.g. `owner`, `attacker`, `anon`,
`tenant_a_user`).

### Session isolation (G-2)

Each principal gets its own `PrincipalSession` in the `SessionStore` with an
**isolated cookie jar**. Cookies set on `owner` are never visible on `attacker`:

```python
store = SessionStore()
owner = store.create_session("owner", PrincipalRole.OWNER)
attacker = store.create_session("attacker", PrincipalRole.ATTACKER)

owner.set_cookie("session", "OWNER-COOKIE")
assert attacker.get_cookie("session") is None   # isolation guaranteed
```

---

## 4. `secret_ref` (split-plane) vs. inline secrets (SI-3)

There are two ways to supply secrets. **Both are supported**; pick per environment.

### Inline (back-compat)

Secret values live directly in the config (`credentials.password`,
`credentials.totp_secret`, …). Fine for local/dev fixtures. **Do not** commit real
production secrets this way.

### Split-plane via `*_ref` handles (recommended for CI/prod)

The config carries only **opaque identifiers**, never values:

| Field | Resolves to |
|-------|-------------|
| `secret_ref` | a password / generic secret |
| `bearer_token_ref` | an `Authorization: Bearer <token>` header |
| `api_key_ref` | an `X-API-Key: <value>` header |

A `SecretRef` is a plain string matching `^[A-Za-z0-9_.:\-/]+$`. It is safe to keep
in configs, task plans, prompts, and logs because it is **not** the secret.

Resolution happens **only on the execution layer**, inside `SessionStore`:

```python
store = SessionStore(secrets={"ATTACKER_BEARER": "eyJ..."} )  # or falls back to os.environ
attacker_cfg = cfg.resolved_principals()[1]
session = store.create_session_for_principal(attacker_cfg)
# store.resolve_secret("ATTACKER_BEARER") -> "eyJ..."  (never logged)
# session.headers()["Authorization"] == "Bearer eyJ..."
```

`resolve_secret()` checks the injected `secrets` map first, then `os.environ`.
An unresolvable handle raises `SecretResolutionError` (fail loud, never run
silently unauthenticated). The error message contains only the **handle**.

---

## 5. Placeholders (unchanged)

`$username`, `$password`, `$totp`, `$email_address`, `$email_password`,
`$email_totp` continue to resolve from `credentials` at runtime via
`resolve_placeholders()` (per-`TargetConfig`) and `PrincipalConfig.resolve_placeholders()`
(per-principal). TOTP codes are generated with `pyotp` when installed; otherwise the
`$totp` token is left intact.

---

## 6. Secrets never reach the LLM / logs / evidence (SI-3)

Hard invariants enforced by this change:

- **Planning layer** (prompts, task descriptions, config snapshots) sees only
  `secret_ref` handles and placeholder tokens — never resolved values.
- **Execution layer** (`SessionStore`, `PrincipalSession.as_exploitation_auth()`,
  tool argv) is the *only* place real secret values exist.
- **Serialisation for logs/evidence** must go through
  `PrincipalSession.to_redacted_dict()` / `src.auth.redaction`, which redact cookie
  values, `Authorization`, tokens, passwords, OTPs, and `storageState` blobs.
- `PrincipalSession.__repr__` / `SessionStore.__repr__` expose **names and counts
  only**, never values.
- Tool argv is assembled as a **list** (`argv`-only, SI-4) — no shell strings — and
  secret-bearing argv is never logged.

Redaction reuses the P2 primitives in `src.playbooks.evidence` (`redact_headers`,
`redact_body`, `redact`); `src.auth.redaction` adds only the session-shaped helpers
(cookie jars + `storageState`) that the generic secret-key heuristics don't cover.

---

## 7. Playwright session reuse (G-7)

`PlaywrightAdapter.login_flow(..., storage_state=<prev>)` seeds the browser context
from a previously exported `storageState`, and the response always includes the new
`storage_state`. Persist it on the session:

```python
resp = await adapter.login_flow(url, steps, storage_state=prev_state)
ctx = export_auth_context(resp)          # {cookies, storage_state, ...}
session.set_cookies_from_playwright(ctx["cookies"])
session.storage_state = ctx["storage_state"]
```

---

## 8. Exploitation propagation (G-1)

`execute_exploitation(..., auth_context=session.as_exploitation_auth())` appends the
session to supported tool argv:

| Tool | Cookie flag | Header flag |
|------|-------------|-------------|
| `nuclei`, `ffuf` | `-H "Cookie: ..."` | `-H "<name>: <value>"` |
| `sqlmap` | `--cookie "..."` | `--headers "<name>: <value>"` |
| `dalfox` | `--cookie "..."` | `-H "<name>: <value>"` |

When `auth_context is None`, argv is identical to the pre-change behaviour (SI-7).
