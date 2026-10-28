---
name: graphql
description: GraphQL-specific security testing methodology
applicable_contexts: [api, web]
---

## GraphQL Security Testing

### Introspection Query

```graphql
{
  __schema {
    types {
      name
      fields {
        name
        type { name kind ofType { name } }
        args { name type { name } }
      }
    }
    mutationType { fields { name } }
    queryType { fields { name } }
  }
}
```

If introspection is disabled, use field suggestion enumeration:
```graphql
{ user { __typename } }
# Error message may reveal field names: "Did you mean 'users'?"
```

### Batch Query Attacks (DoS)

```graphql
# Query batching — multiple operations in one request
[
  {"query": "{ user(id: 1) { name } }"},
  {"query": "{ user(id: 2) { name } }"},
  {"query": "{ user(id: 3) { name } }"}
]
```

### Nested Query DoS (Query Depth Attack)

```graphql
{
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            friends { name }
          }
        }
      }
    }
  }
}
```

### Authorization Bypass via Mutations

```graphql
# Direct object access
mutation { updateUser(id: "OTHER_USER_ID", role: "admin") { id role } }

# Mass assignment through mutations
mutation { createUser(input: { name: "test", isAdmin: true }) { id } }
```

### IDOR Through GraphQL

```graphql
# Enumerate users
{ user(id: "1") { email ssn creditCard } }
{ user(id: "2") { email ssn creditCard } }

# Access other user's data
{ order(id: "OTHER_ORDER_ID") { items total shippingAddress } }
```

### SQL Injection in Arguments

```graphql
{ user(name: "admin' OR '1'='1") { id email } }
{ search(query: "'; DROP TABLE users; --") { results } }
```

### Tools

```bash
# InQL — GraphQL security scanner
inql -t https://target.com/graphql

# graphql-cop — compliance testing
graphql-cop -t https://target.com/graphql

# clairvoyance — field enumeration without introspection
clairvoyance -o /workspace/schema.json https://target.com/graphql
```

### Validation Requirements

- Document full schema if introspection is enabled
- Show unauthorized data access via query/mutation
- Demonstrate DoS potential with query depth/batching metrics
- Test all mutations for authorization checks

### Business Impact

- Full schema exposure reveals internal data model
- IDOR at scale through query enumeration
- Denial of service via expensive nested queries
- Data exfiltration through unauthorized field access

### Confirmation Phase

GraphQL is an attack surface, not a single arbiter class. Every GraphQL finding is adjudicated under the ARGUS confirmation class of its underlying bug — route each to the matching rule in `src/pipeline/contracts/confirmation_rules.py` and satisfy that class's bar. A GraphQL `200` or a populated `{"data": ...}` body is never, by itself, confirmation.

Seed vs finding:
- A payload/seed confidence (`suspected|likely|confirmed`) rates the SEED as a hint only. It NEVER raises a finding's EvidenceTier — tier comes from the evidence below.

General non-confirmation (all sub-vectors):
- A populated `data` with `errors: null` is not impact — it may be data you were already entitled to.
- Introspection enabled, schema dump, or field-suggestion ("Did you mean…?") enumeration is **informational recon only**; it never raises a tier. Report the consequence it unlocked, not the schema.
- A single response is never proof — each class below requires a negative control the finding must differ from.

Per-sub-vector bar (arbiter class → not-confirmation → negative control → impact proof EvidenceKind → repeats):

- **Node-ID / argument IDOR, field-level authz, cross-tenant read** → class `idor`/`bola`.
  - NOT confirmation: a field returned under your own role; a `{param}` that decodes to your own object.
  - Negative control: the same operation against your **own** object, and/or an unauthenticated session → `negative_control_result` (set `cross_owner_access`).
  - Impact proof: two-principal body-diff — attacker session reads victim-owned fields the baseline session cannot. EvidenceKind: **DIFF** (HAR may carry the paired request/response pairs).
  - Stability: ≥2 clean repeats; for enumeration, ≥2 distinct victim object IDs.

- **Unauth / low-priv-reachable sensitive mutation** (admin-create, role/runner mutation, unscoped mutation) → class `auth_bypass`.
  - NOT confirmation: HTTP 200 or a success-shaped body; the operation parsing without executing.
  - Negative control: the same operation with a valid low-priv/anon session showing denial → `negative_control_result` (set `protected_resource_reached`).
  - Impact proof: the protected side effect is reached without the required role, verified out-of-band (state re-read confirms it took effect). EvidenceKind: **DIFF** or **HAR**.
  - Stability: ≥2 clean repeats from a reset state.

- **SSRF via URL / resource argument** → class `ssrf` (**OAST-dependent**).
  - NOT confirmation: a 200 from the app; an error naming the host; reflection of the URL (not a server-side fetch).
  - Negative control: the same argument pointing at an inert/non-routable `{canary}` host that must NOT fire, plus a baseline arg that never dereferences.
  - Impact proof: a controlled interaction on `{oast_host}` carrying a unique `{canary}` subdomain bound to this operation. EvidenceKind: **OAST_CALLBACK**.
  - **Cap: without a confirmed OAST_CALLBACK the finding stays SUSPECTED.**
  - Stability: ≥2 distinct canaries fire.

- **Injection via string argument** (SQLi; downstream search/sort/template/DSL engine) → class `sqli` (blind → **OAST-dependent**).
  - NOT confirmation: a bare timing difference without a control; an error string alone.
  - Negative control: a benign argument value producing the baseline response → `negative_control_result`.
  - Impact proof: a boolean-control pair (true-branch vs false-branch responses differ deterministically) OR an identifiable DB/engine error signature; for blind, an OAST interaction from the sink. EvidenceKind: **RAW_OUTPUT** (both branches / error) or **OAST_CALLBACK** (blind).
  - Cap: blind/time-based without OAST stays SUSPECTED.
  - Stability: ≥2 repeats of the branch differential.

- **Downstream code/command execution at the sink** (arg → engine → exec) → class `rce`/`cmdi`.
  - NOT confirmation: a suspicious argument or a reflected marker.
  - Negative control: the benign-argument baseline.
  - Impact proof: a unique harmless marker in command/engine output, or an OAST interaction from the sink. EvidenceKind: **RAW_OUTPUT** or **OAST_CALLBACK**.
  - Stability: ≥2 repeats.

- **Alias / batch rate-limit bypass & query-cost abuse** → class `rate_limiting`.
  - NOT confirmation: absence of a 429; many aliases returning `success` (may be no-quota, not a race).
  - Negative control: the same operation one-per-request on the rate-limited path (alt-path check) → record `attempts` + `result`.
  - Impact proof: N operations executed under a single rate-limit increment (response carries N result keys; limiter counter moves by 1). EvidenceKind: **RAW_OUTPUT** (request + N-keyed response + limiter headers).
  - Stability: ≥2 repeats; state-changing targets also need the server-state check in Validation below.

- **Depth / complexity / alias-amplified DoS** → no dedicated arbiter class (nearest `rate_limiting`; `needs_class_rule`). Confirm only against a statistical baseline (e.g. depth-N vs depth-3 timing over ≥10 samples each), never a single slow response; a server 5xx/crash is the only CONFIRMED-grade impact. EvidenceKind: **DIFF** (timing vs baseline) or **RAW_OUTPUT** (crash).

OAST-dependent sub-vectors (SSRF-arg, blind injection): WITHOUT a confirmed OAST_CALLBACK, cap at SUSPECTED regardless of seed confidence.

### Validation Requirements (CONFIRMED vs EXPLOITED)

Minimum for **CONFIRMED** (the gap is proven to exist):
- Finding is routed to its arbiter class (idor/bola, auth_bypass, ssrf, sqli, rce/cmdi, rate_limiting) and meets that class rule — not filed as a generic "graphql" finding.
- A negative control is stored (`negative_control_result`/`negative_control_url`) and the proof **differs** from it.
- Exactly one impact-proof EvidenceKind is attached per the sub-vector table (DIFF / HAR / RAW_OUTPUT / OAST_CALLBACK).
- ≥2 clean repeats from a reset state (≥2 distinct canaries for OAST; ≥2 distinct victim IDs for enumeration).
- Two distinct principals for any authz/IDOR claim (attacker account + a victim-owned object you control) — a single-session body is not CONFIRMED.
- PII in captures is masked: use `{target_email}`; redact tokens, recovery/`backup_codes_hash`, routing/account numbers before storage.

Raises to **EXPLOITED** (concrete impact, not just the gap):
- Cross-tenant / field-authz: victim-owned sensitive data actually returned to the attacker session (DIFF/HAR showing the exfiltrated fields), not merely a reachable resolver.
- Auth-bypass mutation: the side effect is confirmed out-of-band (state read / second API shows the change persisted) — e.g. privilege persists after revocation, verified by re-query.
- SSRF: an attacker-chosen internal target is reached — OAST_CALLBACK from a unique `{canary}` plus the returned/diffed response content.
- Injection → sink: command/engine output carrying the harmless marker (RAW_OUTPUT), or OAST from the sink.
- Rate-limit / batch / money-movement: a real state change is shown (quota or balance/ledger before-vs-after via DIFF), deterministically reproduced ≥2× from a clean state — not a single success body. Alias batching ALONE is NOT EXPLOITED for a race claim; require the parallel-HTTP single-packet confirmation.
- Introspection: never EXPLOITED on its own; only as the recon step inside a chain whose downstream finding meets a bar above.
