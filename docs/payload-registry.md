# ARGUS Payload Registry

Comprehensive reference for all 54 payload families maintained under `backend/config/payloads/`. Each family is a signed YAML descriptor validated by `PayloadRegistry` and materialised by `PayloadBuilder` into deterministic `PayloadBundle`s for sandboxed validators.

---

## 1. Summary

| Metric | Value |
|--------|-------|
| **Total families** | 54 |
| **Unique CWE IDs covered** | 42 |
| **Vulnerability types** | SQLi, NoSQLi, CMDi, SSTI, LDAPi, XPathi, GraphQL, XSS (Reflected, DOM, Stored, Contextual), JWT, OAuth, JWT none-alg, CSRF, IDOR, Auth bypass, LFI, RFI, Path Traversal, SSRF, XXE, Deserialization, HTTP Smuggling, Protocol Smuggling, CORS, Race Condition, Mass Assignment, Cache Poisoning, Buffer Overflow, Format String, Integer Overflow, Type Juggling, Prototype Pollution, SMTP Injection, CRLF, Open Redirect, RCE |
| **Safe families** (`_safe` suffix) | 16 |
| **Offense-only families** (no `_safe` counterpart) | 22 |
| **Requires approval** | 5 |
| **OAST-dependent** | 21 |
| **Risk levels** | 19 low, 22 medium, 12 high, 1 critical |
| **Payload directory** | `backend/config/payloads/` |

---

## 2. Family Catalog

| Family ID | CWE IDs | Risk | Approval | OAST | Safe | Pld | Category |
|-----------|---------|------|----------|------|------|-----|----------|
| `auth_bypass` | 287, 290, 305, 798 | medium | No | No | — | 6 | Auth |
| `buffer_overflow` | 120 | critical | **Yes** | No | — | 4 | Memory/Logic |
| `cache_poisoning` | 444, 79, 524 | medium | No | Yes | — | 6 | Infrastructure |
| `command_injection_safe` | 78 | low | No | No | **Safe** | 2 | Injection |
| `cors_misconfig` | 942 | medium | No | Yes | — | 4 | Infrastructure |
| `crlf` | 93, 113 | medium | No | Yes | — | 6 | Email |
| `crlf_safe` | 93 | low | No | No | **Safe** | 2 | Email |
| `csrf_safe` | 352 | low | No | No | **Safe** | 3 | Auth |
| `csrf_token_bypass` | 352 | medium | No | Yes | — | 4 | Auth |
| `deserialization` | 502 | high | No | Yes | — | 4 | Server-Side |
| `format_string` | 134 | high | No | No | — | 4 | Memory/Logic |
| `graphql` | 863, 209, 400 | medium | No | No | — | 6 | Injection |
| `graphql_safe` | 20 | low | No | No | **Safe** | 2 | Injection |
| `http_smuggling` | 444 | high | **Yes** | Yes | — | 5 | Server-Side |
| `idor` | 639, 284 | low | No | No | — | 6 | Auth |
| `integer_overflow` | 190 | high | No | No | — | 4 | Memory/Logic |
| `jwt` | 347, 287, 290 | medium | No | No | — | 6 | Auth |
| `jwt_none_alg` | 347 | high | No | No | — | 4 | Auth |
| `jwt_safe` | 345 | low | No | No | **Safe** | 2 | Auth |
| `ldap_injection` | 90 | high | No | No | — | 4 | Injection |
| `ldapi` | 90 | medium | No | No | — | 6 | Injection |
| `ldapi_safe` | 90 | low | No | No | **Safe** | 2 | Injection |
| `lfi_rfi` | 22, 98 | medium | No | Yes | — | 6 | File/Path |
| `mass_assignment` | 915, 284 | medium | No | No | — | 6 | Infrastructure |
| `mass_assignment_safe` | 915 | low | No | No | **Safe** | 2 | Infrastructure |
| `nosqli` | 943, 89 | medium | No | No | — | 6 | Injection |
| `nosqli_safe` | 943 | low | No | No | **Safe** | 2 | Injection |
| `oauth` | 601, 602, 287 | medium | No | Yes | — | 6 | Auth |
| `oauth_misconfig` | 290 | high | No | Yes | — | 4 | Auth |
| `open_redirect` | 601 | low | No | Yes | — | 6 | Injection |
| `open_redirect_safe` | 601 | low | No | No | **Safe** | 2 | Injection |
| `path_traversal` | 22, 23, 35 | medium | No | No | — | 6 | File/Path |
| `proto_smuggle` | 444, 436 | high | **Yes** | Yes | — | 5 | Server-Side |
| `prototype_pollution` | 1321 | medium | No | No | — | 6 | Memory/Logic |
| `prototype_pollution_safe` | 1321 | low | No | No | **Safe** | 2 | Memory/Logic |
| `race_condition` | 362, 367 | high | **Yes** | No | — | 5 | Infrastructure |
| `rce` | 78, 77 | high | **Yes** | Yes | — | 7 | Injection |
| `smtp_injection` | 150 | medium | No | Yes | — | 4 | Email |
| `sqli` | 89 | medium | No | Yes | — | 6 | Injection |
| `sqli_safe` | 89 | low | No | No | **Safe** | 2 | Injection |
| `ssrf` | 918 | medium | No | Yes | — | 6 | Server-Side |
| `ssrf_oast_safe` | 918 | low | No | Yes | **Safe** | 2 | Server-Side |
| `ssti` | 1336, 94 | medium | No | No | — | 6 | Injection |
| `ssti_safe` | 1336 | low | No | No | **Safe** | 2 | Injection |
| `traversal_safe` | 22 | low | No | No | **Safe** | 2 | File/Path |
| `type_juggling` | 697 | high | No | No | — | 4 | Memory/Logic |
| `xpath_injection` | 643 | high | No | No | — | 4 | Injection |
| `xpathi_safe` | 643 | low | No | No | **Safe** | 2 | Injection |
| `xss` | 79 | medium | No | Yes | — | 6 | XSS |
| `xss_contextual` | 79 | low | No | No | — | 2 | XSS |
| `xss_dom` | 79 | medium | No | Yes | — | 4 | XSS |
| `xss_stored` | 79 | medium | No | Yes | — | 4 | XSS |
| `xxe` | 611, 776 | medium | No | Yes | — | 6 | Server-Side |
| `xxe_oast_safe` | 611 | low | No | Yes | **Safe** | 2 | Server-Side |

**Legend:** Safe = family ID ends in `_safe`; Pld = seed payload count; OAST = `oast_required: true`.

---

## 3. By Vulnerability Type

### Injection

Covers code/data injection through query languages, templates, and system commands.

| Family ID | CWE | Risk | Notes |
|-----------|-----|------|-------|
| `sqli` | 89 | medium | Boolean, error, time-based, UNION SQL injection |
| `sqli_safe` | 89 | low | Inert alphanumeric marker strings |
| `nosqli` | 943, 89 | medium | MongoDB `$ne`/`$gt`/`$where`/`$regex` operator injection |
| `nosqli_safe` | 943 | low | Inert ASCII markers |
| `rce` | 78, 77 | high | OS-command injection (`id`, `whoami`, `echo` probes); **requires approval** |
| `command_injection_safe` | 78 | low | Alphanumeric sentinels with no shell metacharacters |
| `ssti` | 1336, 94 | medium | Jinja2/Twig, Freemarker, ERB/Velocity, Thymeleaf probes (`{{7*7}}`, `${7*7}`) |
| `ssti_safe` | 1336 | low | Static text markers without template delimiters |
| `ldapi` | 90 | medium | LDAP filter injection (wildcard, OR-injection, DN traversal) |
| `ldapi_safe` | 90 | low | Alphanumeric literal placeholders |
| `ldap_injection` | 90 | high | Advanced LDAP injection (tautology, base DN traversal, attribute enumeration) |
| `xpath_injection` | 643 | high | Boolean-based, blind time-based XPath injection, auth bypass |
| `xpathi_safe` | 643 | low | Plain literal tokens |
| `graphql` | 863, 209, 400 | medium | Introspection queries, batched alias overload, field-suggestion oracles |
| `graphql_safe` | 20 | low | Whitespace-only / curriculum name markers |
| `open_redirect` | 601 | low | Scheme tricks, protocol-relative URLs, OAST-marked external destinations |
| `open_redirect_safe` | 601 | low | Relative-only path fragments and anchor-only markers |

### XSS

Cross-Site Scripting probes across four delivery contexts.

| Family ID | CWE | Risk | Notes |
|-----------|-----|------|-------|
| `xss` | 79 | medium | Reflected XSS — `<script>`, `<img onerror>`, `<svg onload>`, `<body onload>` |
| `xss_dom` | 79 | medium | DOM-based — `location.hash`, `document.write`, `innerHTML`, `postMessage` |
| `xss_stored` | 79 | medium | Stored XSS — polyglot break-outs, `img onerror`, `svg onload`, `details ontoggle` |
| `xss_contextual` | 79 | low | Inert custom elements and entity-encoded brackets for parser training |

### Auth

Authentication and authorisation bypass, token manipulation, and session attacks.

| Family ID | CWE | Risk | Notes |
|-----------|-----|------|-------|
| `jwt` | 347, 287, 290 | medium | alg=none, alg confusion, weak HMAC, kid traversal, JKU/X5U tampering |
| `jwt_safe` | 345 | low | Non-secret JWT fragment markers |
| `jwt_none_alg` | 347 | high | alg:none bypass, RS256→HS256 confusion, kid/jku/jwk header injection |
| `oauth` | 601, 602, 287 | medium | redirect_uri tampering, state reuse, PKCE downgrade markers |
| `oauth_misconfig` | 290 | high | redirect_uri bypass, state omission, PKCE downgrade, scope upgrade |
| `csrf_safe` | 352 | low | Missing/wrong/blank anti-CSRF token probes |
| `csrf_token_bypass` | 352 | medium | Null byte truncation, custom header, Referer validation, SameSite bypass |
| `idor` | 639, 284 | low | Sequential ID enumeration, UUID confusion, tenant-scope bypass |
| `auth_bypass` | 287, 290, 305, 798 | medium | X-Forwarded-For, X-Original-URL, Host override, verb tunnelling |

### File / Path

File-system traversal and inclusion attacks.

| Family ID | CWE | Risk | Notes |
|-----------|-----|------|-------|
| `lfi_rfi` | 22, 98 | medium | UNIX/Windows LFI (`/etc/passwd`, `win.ini`), PHP wrapper RFI vectors |
| `path_traversal` | 22, 23, 35 | medium | UNIX/Windows separators, encoded variants, absolute-path overrides |
| `traversal_safe` | 22 | low | Safe path segments without `..` sequences |

### Server-Side

Server-originated attacks targeting back-end infrastructure.

| Family ID | CWE | Risk | Notes |
|-----------|-----|------|-------|
| `ssrf` | 918 | medium | OAST HTTP/HTTPS probes, cloud metadata endpoints, DNS rebinding |
| `ssrf_oast_safe` | 918 | low | Inert URL-shaped tokens with non-routable TLDs |
| `xxe` | 611, 776 | medium | Classic file disclosure, OAST DNS exfiltration, parameter entities |
| `xxe_oast_safe` | 611 | low | Non-fetching XML fragment markers |
| `deserialization` | 502 | high | Java Jackson/XStream, PHP unserialize, .NET type-swap probes |
| `http_smuggling` | 444 | high | CL.TE, TE.CL, TE.TE markers; **requires approval** |
| `proto_smuggle` | 444, 436 | high | HTTP/2 downgrade markers, gRPC trailers, WebSocket upgrade smuggling; **requires approval** |

### Infrastructure

Configuration and architectural weaknesses.

| Family ID | CWE | Risk | Notes |
|-----------|-----|------|-------|
| `cors_misconfig` | 942 | medium | Origin: null, attacker-controlled Origin, subdomain prefix bypass, credential bypass |
| `race_condition` | 362, 367 | high | TOCTOU sinks, idempotency-key replay, burst-probe; **requires approval** |
| `mass_assignment` | 915, 284 | medium | `isAdmin`, `role`, `plan`, `verified` over-posting to JSON/form bodies |
| `mass_assignment_safe` | 915 | low | Benign camelCase field name markers |
| `cache_poisoning` | 444, 79, 524 | medium | Unkeyed headers (X-Forwarded-Host, X-Original-URL), param cloaking |

### Memory / Logic

Low-level memory corruption and language-specific logic flaws.

| Family ID | CWE | Risk | Notes |
|-----------|-----|------|-------|
| `buffer_overflow` | 120 | critical | Format string `%n` writes, 8192-byte overflow, canary leak, off-by-one null; **requires approval** |
| `format_string` | 134 | high | `%x`/`%n`/`%s` read/write probes, positional argument pointer leaks |
| `integer_overflow` | 190 | high | `INT_MAX+1`, `INT_MIN-1` boundary tests, allocation size underflow |
| `type_juggling` | 697 | high | PHP `0e`-hash collision, `strcmp` bypass, `in_array` loose compare, JSON decode overflow |
| `prototype_pollution` | 1321 | medium | `__proto__`, `constructor.prototype`, nested merge pollution via lodash/jQuery |
| `prototype_pollution_safe` | 1321 | low | Inert object-literal key names |

### Email

Header and protocol injection in email delivery paths.

| Family ID | CWE | Risk | Notes |
|-----------|-----|------|-------|
| `smtp_injection` | 150 | medium | Bcc header injection, CRLF response splitting, Content-Type boundary injection |
| `crlf` | 93, 113 | medium | HTTP header injection, response-splitting cookie injection, raw CR/LF bytes |
| `crlf_safe` | 93 | low | Verbalised CR/LF tokens (no raw bytes) |

---

## 4. Safe vs Offensive Families

### Safe Families (`_safe` suffix — 16 total)

These families contain no executable payloads. Seeds are inert markers, alphanumeric sentinels, or curriculum-safe labels that can be used without sandboxing.

| Family ID | Corresponding Offensive Family | Description |
|-----------|-------------------------------|-------------|
| `sqli_safe` | `sqli` | Alphanumeric marker strings |
| `nosqli_safe` | `nosqli` | Inert ASCII markers |
| `command_injection_safe` | `rce` (subset) | No shell metacharacters |
| `ssti_safe` | `ssti` | Static text without template delimiters |
| `ldapi_safe` | `ldapi` / `ldap_injection` | Alphanumeric literal placeholders |
| `xpathi_safe` | `xpath_injection` | Plain literal tokens |
| `graphql_safe` | `graphql` | Whitespace-only / curriculum name tokens |
| `jwt_safe` | `jwt` / `jwt_none_alg` | Non-secret JWT fragment markers |
| `open_redirect_safe` | `open_redirect` | Relative-only path fragments |
| `ssrf_oast_safe` | `ssrf` | Inert URLs with non-routable TLDs |
| `xxe_oast_safe` | `xxe` | Non-fetching XML fragment markers |
| `mass_assignment_safe` | `mass_assignment` | Benign field name markers |
| `prototype_pollution_safe` | `prototype_pollution` | Inert object-literal key names |
| `traversal_safe` | `path_traversal` / `lfi_rfi` | Safe path segments without `..` |
| `crlf_safe` | `crlf` | Verbalised CR/LF tokens (no raw bytes) |
| `csrf_safe` | `csrf_token_bypass` | Missing/wrong/blank token probes |

### Offense-Only Families (no `_safe` counterpart — 22 total)

These families contain potentially dangerous payloads or require active OAST callbacks. They must only be built with sandbox isolation or operator approval.

| Family ID | Risk | Reasoning |
|-----------|------|-----------|
| `auth_bypass` | medium | Header forgery may trigger side-effects in auth middleware |
| `cache_poisoning` | medium | Canary propagation through cache layers is inherently side-effectful |
| `cors_misconfig` | medium | Probing CORS produces observable cross-origin requests |
| `csrf_token_bypass` | medium | Token replay may create state changes |
| `deserialization` | high | Gadget chains reference live JNDI/XML parsing sinks |
| `format_string` | high | `%n` write probes are inherently dangerous |
| `http_smuggling` | high | Request smuggling can poison connection pools (approval-gated) |
| `idor` | low | Read-only by design but probes adjacent user data |
| `integer_overflow` | high | Large allocation values may crash handlers |
| `ldap_injection` | high | Advanced filter manipulation beyond read-only ldapi |
| `lfi_rfi` | medium | Remote file inclusion may trigger callbacks |
| `oauth_misconfig` | high | Flow bypass may trigger unintended redirects |
| `oauth` | medium | OAuth tampering targets live auth flows |
| `proto_smuggle` | high | Protocol confusion can destabilise proxy tiers (approval-gated) |
| `smtp_injection` | medium | Header injection generates real email traffic |
| `type_juggling` | high | PHP type confusion may trigger unintended code paths |
| `xpath_injection` | high | Boolean/blind XPath probing exercises live query engines |
| `xss` | medium | Active script execution in reflected context |
| `xss_contextual` | low | Inert by design; safe but not a `_safe` family |
| `xss_dom` | medium | DOM injection payloads execute in client context |
| `xss_stored` | medium | Polyglot payloads persist in storage sinks |
| `race_condition` | high | Concurrent send bursts create real TOCTOU windows (approval-gated) |

### Approval-Gated Families

These five families have `requires_approval: true` — `PayloadBuilder.build()` will raise `PayloadApprovalRequiredError` unless an `approval_id` is supplied:

1. **`buffer_overflow`** — critical risk; memory corruption probes
2. **`http_smuggling`** — high risk; connection-pool poisoning
3. **`proto_smuggle`** — high risk; protocol-confusion attacks
4. **`race_condition`** — high risk; concurrent TOCTOU sends
5. **`rce`** — high risk; remote command execution probes

The registry model enforces that any family with `risk_level: high` or `risk_level: critical` must also have `requires_approval: true`, or schema validation fails (`registry.py:218-223`). However, not all `high`-risk families are approval-gated — only those where the builder author explicitly deemed the blast radius too large for automated use (e.g., `format_string` and `integer_overflow` are `high` but not approval-gated).

---

## 5. Exploitation Executor Integration

The `exploitation_executor.py` module bridges payload families to sandbox tool execution via auto-detection.

### Family Map (`_build_payloads_for_finding`, lines 88–97)

```
xss              → xss                         sqli              → sqli
sql_injection    → sqli                        ssrf              → ssrf
lfi              → traversal_safe              rfi               → lfi_rfi
ssti             → ssti_safe                   nosqli            → nosqli_safe
graphql          → graphql_safe                prototype_pollution → prototype_pollution_safe
command_injection → command_injection_safe     xxe               → xxe_oast_safe
csrf             → csrf_safe                   idor              → idor
open_redirect    → open_redirect_safe          path_traversal    → traversal_safe
```

Key observations:
- **9 of 16 mapped vuln types** route to their `_safe` variant for curriculum-safe exploitation.
- **7 route to offensive families** (`xss`, `sqli`, `ssrf`, `lfi_rfi`, `idor`, `open_redirect` — though `open_redirect` maps to `open_redirect_safe`... wait, re-reading the map: `"open_redirect": "open_redirect_safe"` — so 8 to safe, 8 to offensive).
- The map covers only 16 of 54 families directly; the remaining 38 families are invoked through explicit family IDs from the `ValidationPlanV1`.

### Auto-Detection Blob Logic (lines 99–104)

```python
vuln_type = str(finding.get("vuln_type") or finding.get("type") or "").lower().strip()
title = str(finding.get("title") or "").lower()
description = str(finding.get("description") or "").lower()
blob = f"{vuln_type} {title} {description}"

family_id = None
for keyword, fid in family_map.items():
    if keyword in blob:
        family_id = fid
        break
```

The executor concatenates `vuln_type` + `title` + `description` into a `blob` string, then iterates the `family_map` in insertion order. The **first keyword** found in the blob wins. This means:
- Exact keyword order matters (e.g., `"xss"` before `"ssti"` in the dict may not apply here since they don't overlap, but `"sqli"` before more specific substrings could).
- If no keyword matches, falls back to the finding's raw `payload` or `poc` field.
- The same blob is used for tool selection (`_select_tools_for_finding`), matching against `_VULN_TOOL_MAP`.

### Payload Build Flow (lines 109–140)

```
Finding → family_map lookup → PayloadRegistry.load() → registry.get_family(family_id)
        → PayloadBuilder.build(request) → PayloadBundle → [rendered payloads]
```

The build request is constructed with:
- `encoding_pipeline: "url_only"` (hardcoded default)
- `parameters` extracted from finding fields (`url`, `param`, `user_input`)
- `max_payloads: 8`
- `correlation_key` derived from `scan_id:family_id:md5_hash`

### Sandbox Execution Flow (main `execute_exploitation`, lines 424–523)

```
For each finding (capped at 10):
  1. _build_payloads_for_finding() → concrete payload list
  2. _select_tools_for_finding()    → tool list (dalfox, sqlmap, commix, nuclei, ffuf)
  3. _execute_tool_in_sandbox()     → Docker exec into argus-sandbox container
  4. _assess_exploitability_wrb()   → LLM call to WhiteRabbitNeo for verdict
  5. Stop on first exploitable result (confidence > 0.7)
```

---

## 6. Using PayloadBuilder

### Core Classes

| Class | Module | Role |
|-------|--------|------|
| `PayloadRegistry` | `src.payloads.registry` | Loads, verifies, and indexes all signed YAML descriptors |
| `PayloadFamily` | `src.payloads.registry` | Pydantic model for a single family descriptor |
| `PayloadBuilder` | `src.payloads.builder` | Materialises seed templates into deterministic `PayloadBundle`s |
| `PayloadBuildRequest` | `src.payloads.builder` | Input contract specifying target family, params, encoding, and approval |
| `PayloadBundle` | `src.payloads.builder` | Fully rendered payload list with manifest hash |
| `RenderedPayload` | `src.payloads.builder` | One concrete payload string with provenance metadata |

### Example Usage

```python
from pathlib import Path
from src.payloads.registry import PayloadRegistry
from src.payloads.builder import PayloadBuilder, PayloadBuildRequest

# 1. Load registry
payloads_dir = Path("backend/config/payloads")
registry = PayloadRegistry(payloads_dir=payloads_dir)
summary = registry.load()
print(f"Loaded {summary.total} families")

# 2. Inspect a family
family = registry.get_family("sqli")
print(f"Risk: {family.risk_level.value}")
print(f"OAST required: {family.oast_required}")
print(f"Approval required: {family.requires_approval}")
print(f"Seeds: {len(family.payloads)}")
for entry in family.payloads:
    print(f"  {entry.id}: {entry.template[:60]}...")

# 3. List families requiring approval
approval_gated = registry.families_requiring_approval()
for fam in approval_gated:
    print(f"  {fam.family_id} ({fam.risk_level.value})")

# 4. Build a payload bundle
builder = PayloadBuilder(registry=registry)
request = PayloadBuildRequest(
    family_id="sqli_safe",
    correlation_key="scan-123:sqli_safe:a1b2c3d4",
    encoding_pipeline="url_only",       # Optional; defaults to first declared pipeline
    parameters={
        "url": "http://target.example.com/login",
        "param": "username",
        "user_input": "admin",
        "canary": "argus-canary-001",
    },
    max_payloads=4,
)

bundle = builder.build(request)
print(f"Manifest hash: {bundle.manifest_hash}")
print(f"Payload count: {len(bundle.payloads)}")
for rp in bundle.payloads:
    print(f"  [{rp.index}] {rp.id}: {rp.payload[:80]}")

# 5. Replay determinism — same correlation_key → same manifest_hash
bundle2 = builder.build(request)
assert bundle.manifest_hash == bundle2.manifest_hash

# 6. Build an approval-gated family
try:
    req2 = PayloadBuildRequest(
        family_id="rce",
        correlation_key="scan-123:rce:b2c3d4e5",
        parameters={"url": "http://target.example.com/cmd", "canary": "canary-002"},
        max_payloads=4,
    )
    builder.build(req2)  # Raises PayloadApprovalRequiredError
except PayloadApprovalRequiredError:
    pass

# With approval
req3 = PayloadBuildRequest(
    family_id="rce",
    correlation_key="scan-123:rce:b2c3d4e5",
    approval_id="op-approval-token-xyz",
    parameters={"url": "http://target.example.com/cmd", "canary": "canary-002"},
    max_payloads=4,
)
bundle3 = builder.build(req3)
print(f"Approval-gated build OK: {bundle3.family_id}")
```

### Build Pipeline Internals

Each `build()` call executes this pipeline per seed entry:

```
Seed template → _substitute(placeholders) → apply_mutations(declared mutations)
              → apply_pipeline(encoding stages) → RenderedPayload
```

- **Substitution**: `{param}` placeholders in templates are replaced from `request.parameters`. Missing placeholders raise `PayloadBuildError`.
- **Mutations**: Declared `MutationRule`s are applied (e.g., `case_flip`, `whitespace_alt`, `comment_injection`). Deterministic via `seed_base` derived from `correlation_key`.
- **Encoding**: The resolved `EncodingPipeline` (chosen by name or first declared) applies each stage in order (e.g., `["url", "base64"]`).
- **Manifest hash**: SHA-256 of the canonical JSON representation of all rendered payloads — used for evidence binding.

### Available Encoding Pipelines

Each family declares its own pipelines. Common ones:

| Pipeline Name | Stages | Description |
|---------------|--------|-------------|
| `identity` | `[]` | Raw payload pass-through |
| `url_only` | `[url]` | Single URL-encoding |
| `url_double` | `[url_double]` | Double URL-encoding (bypasses one-pass decoders) |
| `base64_only` | `[base64]` | Base64 encoding |
| `url_then_b64` | `[url, base64]` | URL-encode then Base64 |

### Determinism Guarantee

Given the same `correlation_key` + `family_id` + `encoding_pipeline`, the builder always produces the same `PayloadBundle` with an identical `manifest_hash`. This is guaranteed by:
- Seeded PRNG via `_derive_seed(correlation_key, family_id)` using SHA-256 of `"{correlation_key}|{family_id}"`.
- Deterministic mutation application by payload index.
- JSON canonicalisation with sorted keys for manifest hashing.

---

## 7. Adding New Families

### Step 1: Create the YAML Descriptor

Create `backend/config/payloads/<family_id>.yaml` with this structure:

```yaml
family_id: my_new_family        # Must match filename stem
description: >-
  Short description of what this family probes.
cwe_ids: [XXX, YYY]             # 1-16 unique positive integers
owasp_top10:
  - 'A03:2021'                  # Must start with 'A'
risk_level: low|medium|high|critical
requires_approval: false|true   # Must be true if high or critical
oast_required: false|true

payloads:
  - id: seed_one                 # Unique within family, pattern [a-z0-9_\-]+
    template: "payload template with {placeholders}"
    confidence: suspected|likely|confirmed   # From ConfidenceLevel enum
    notes: What this seed targets and how to confirm.

  - id: seed_two
    template: "another {canary} template"
    confidence: suspected
    notes: Companion probe for differential analysis.

mutations:                       # Optional; must reference MUTATION_NAMES
  - name: case_flip
    description: Flip case to evade substring filters.
    max_per_payload: 1           # 1-8, default 1

encodings:                       # Optional; must reference ENCODER_NAMES
  - name: identity
    stages: []
    description: Raw payload pass-through.
  - name: url_only
    stages: [url]
    description: URL-encoded for query parameters.
```

### Step 2: Sign the Descriptor

Generate an Ed25519 signature for the new file and add it to `backend/config/payloads/SIGNATURES`:

```bash
# Using the KeyManager infrastructure:
python -m src.sandbox.signing sign backend/config/payloads/my_new_family.yaml
```

The signature entry is keyed by the relative path `my_new_family.yaml`. Without a valid signature, `PayloadRegistry.load()` will raise `PayloadSignatureError` (fail-closed).

### Step 3: Add to Exploitation Executor (Optional)

If this family should be auto-detected, add a mapping to the `family_map` dictionary in `exploitation_executor.py:88-97`:

```python
family_map = {
    # ... existing entries ...
    "my_vuln_keyword": "my_new_family",      # Use _safe variant if available
}
```

Also add tool mappings to `_VULN_TOOL_MAP` if applicable (`exploitation_executor.py:27-61`):

```python
_VULN_TOOL_MAP: dict[str, list[str]] = {
    # ... existing entries ...
    "my_vuln_keyword": ["nuclei", "ffuf"],
}
```

### Step 4: Validate Locally

```bash
# Load the registry and verify the new family passes schema + signature checks
python -c "
from pathlib import Path
from src.payloads.registry import PayloadRegistry
r = PayloadRegistry(payloads_dir=Path('backend/config/payloads'))
summary = r.load()
f = r.get_family('my_new_family')
print(f'schema_version={f.risk_level}, payloads={len(f.payloads)}')
"
```

### Step 5: Test PayloadBuilder Integration

```python
from src.payloads.builder import PayloadBuilder, PayloadBuildRequest

builder = PayloadBuilder(registry=registry)
request = PayloadBuildRequest(
    family_id="my_new_family",
    correlation_key="test:my_new_family:0001",
    parameters={"canary": "test-canary"},
    max_payloads=4,
)
bundle = builder.build(request)
assert len(bundle.payloads) > 0
assert len(bundle.manifest_hash) == 64
```

### Design Rules

| Rule | Enforcement |
|------|-------------|
| `family_id` must match filename stem (minus `.yaml`) | `registry.py:329-332` |
| `cwe_ids` must be unique, positive integers | `PayableFamily._check_cwe_ids` |
| `owasp_top10` entries must start with `A` and be unique | `PayableFamily._check_owasp` |
| `payloads[].id` must be unique within the family | `PayableFamily._validate` -> `registry.py:206-208` |
| `risk_level: high \| critical` requires `requires_approval: true` | `PayableFamily._validate` -> `registry.py:218-223` |
| `mutations[].name` must be a registered key in `MUTATION_NAMES` | `MutationRule._check_name` |
| `encodings[].stages` entries must be in `ENCODER_NAMES` | `EncodingPipeline._check_stages` |
| `requires_approval: false` families must not receive `approval_id` in build request | `builder.py:240-244` |
| No duplicate `family_id` across YAML files | `registry.py:323-327` |

---

## Appendix: Quick Reference

### All 54 Family IDs

```
auth_bypass              buffer_overflow          cache_poisoning
command_injection_safe   cors_misconfig           crlf
crlf_safe                csrf_safe                csrf_token_bypass
deserialization          format_string            graphql
graphql_safe             http_smuggling           idor
integer_overflow         jwt                      jwt_none_alg
jwt_safe                 ldap_injection           ldapi
ldapi_safe               lfi_rfi                  mass_assignment
mass_assignment_safe     nosqli                   nosqli_safe
oauth                    oauth_misconfig          open_redirect
open_redirect_safe       path_traversal           proto_smuggle
prototype_pollution      prototype_pollution_safe race_condition
rce                      smtp_injection           sqli
sqli_safe                ssrf                     ssrf_oast_safe
ssti                     ssti_safe                traversal_safe
type_juggling            xpath_injection          xpathi_safe
xss                      xss_contextual           xss_dom
xss_stored               xxe                      xxe_oast_safe
```

### CWE Coverage

| CWE | Title | Families |
|-----|-------|----------|
| 20 | Improper Input Validation | `graphql_safe` |
| 22 | Path Traversal | `lfi_rfi`, `path_traversal`, `traversal_safe` |
| 23 | Relative Path Traversal | `path_traversal` |
| 35 | Path Traversal: '.../...//' | `path_traversal` |
| 77 | Command Injection (catastrophic) | `rce` |
| 78 | OS Command Injection | `command_injection_safe`, `rce` |
| 79 | XSS | `cache_poisoning`, `xss`, `xss_contextual`, `xss_dom`, `xss_stored` |
| 89 | SQL Injection | `nosqli`, `sqli`, `sqli_safe` |
| 90 | LDAP Injection | `ldap_injection`, `ldapi`, `ldapi_safe` |
| 93 | CRLF Injection | `crlf`, `crlf_safe` |
| 94 | Code Injection | `ssti` |
| 98 | Remote File Inclusion | `lfi_rfi` |
| 113 | HTTP Response Splitting | `crlf` |
| 120 | Buffer Overflow | `buffer_overflow` |
| 134 | Format String | `format_string` |
| 150 | SMTP Injection | `smtp_injection` |
| 190 | Integer Overflow | `integer_overflow` |
| 209 | Information Exposure Through Error Message | `graphql` |
| 284 | Improper Access Control | `idor`, `mass_assignment` |
| 287 | Improper Authentication | `auth_bypass`, `jwt`, `oauth` |
| 290 | Authentication Bypass by Spoofing | `auth_bypass`, `jwt`, `oauth_misconfig` |
| 305 | Authentication Bypass by Primary Weakness | `auth_bypass` |
| 345 | Insufficient Verification of Data Authenticity | `jwt_safe` |
| 347 | Improper Verification of Cryptographic Signature | `jwt`, `jwt_none_alg` |
| 352 | Cross-Site Request Forgery | `csrf_safe`, `csrf_token_bypass` |
| 362 | Concurrent Execution using Shared Resource (Race Condition) | `race_condition` |
| 367 | Time-of-check Time-of-use (TOCTOU) | `race_condition` |
| 400 | Uncontrolled Resource Consumption | `graphql` |
| 436 | Interpretation Conflict | `proto_smuggle` |
| 444 | HTTP Request/Response Smuggling | `cache_poisoning`, `http_smuggling`, `proto_smuggle` |
| 502 | Deserialization of Untrusted Data | `deserialization` |
| 524 | Caching of Sensitive Data | `cache_poisoning` |
| 601 | URL Redirection to Untrusted Site | `oauth`, `open_redirect`, `open_redirect_safe` |
| 602 | Client-Side Enforcement of Server-Side Security | `oauth` |
| 611 | Improper Restriction of XML External Entity Reference | `xxe`, `xxe_oast_safe` |
| 639 | Authorization Bypass Through User-Controlled Key | `idor` |
| 643 | XPath Injection | `xpath_injection`, `xpathi_safe` |
| 697 | Incorrect Comparison (PHP Type Juggling) | `type_juggling` |
| 776 | Improper Restriction of Recursive Entity References | `xxe` |
| 798 | Use of Hard-coded Credentials | `auth_bypass` |
| 863 | Incorrect Authorization | `graphql` |
| 915 | Improperly Controlled Modification of Dynamically-Determined Object Attributes | `mass_assignment`, `mass_assignment_safe` |
| 918 | Server-Side Request Forgery (SSRF) | `ssrf`, `ssrf_oast_safe` |
| 942 | Permissive Cross-domain Policy | `cors_misconfig` |
| 943 | Improper Neutralization of Special Elements in Data Query Logic (NoSQLi) | `nosqli`, `nosqli_safe` |
| 1321 | Improperly Controlled Modification of Object Prototype Attributes | `prototype_pollution`, `prototype_pollution_safe` |
| 1336 | Improper Neutralization of Special Elements Used in a Template Engine | `ssti`, `ssti_safe` |
