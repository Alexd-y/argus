---
name: prototype_pollution
description: Prototype pollution discovery and confirmation — client-side (__proto__/constructor into a DOM gadget) and server-side (recursive-merge pollution of Object.prototype), proven by a polluted property observably changing a separate object/code path against a negative-control baseline
applicable_contexts: [web, api]
---

## Prototype Pollution Testing Methodology

> A polluted property is the finding only when it is observed on an object/code path that never set it, and differs from a baseline without the key. A reflected `__proto__` key is not impact.

### Discovery Phase

**Entry points (recursive merge / deep-assign sinks):**
- JSON bodies merged into config/options bags: `merge` / `defaultsDeep` / `mergeWith` (lodash), `jQuery.extend(true, ...)`, `deepmerge`, `Hoek.applyToDefaults`, hand-rolled `Object.assign` / `for..in` copy loops.
- Query/body parsers that expand bracket notation into nested objects (`qs`, Express querystring, multipart → nested builders): `{param}[__proto__][x]=` style keys.
- Endpoints whose job is "merge settings / preferences / profile / filters / options".

**Pollution vectors (keys to probe):** `__proto__`, `constructor.prototype`, `constructor[prototype]` — delivered in JSON, query string, or bracketed form params.

**Client-side (DOM) sources:** `location.hash` / `location.search` / `window.name` / `postMessage` → `JSON.parse` → `$.extend(true,...)` / merge util / config object → a gadget (sanitizer allowlist, template-compiler option, a URL or `script.src` built from a polluted default).

**Server-side fingerprints:** `X-Powered-By: Express`, Node stack traces with `.js` paths, exposed `package-lock.json` listing a vulnerable merge library, settings/profile merge endpoints.

**Non-destructive signal probe:** send a benign canary property through a vector, then exercise a DIFFERENT code path that creates a fresh object and reads that key — surfacing where you never set it is the pollution signal.

### Exploitation Phase

- **Probe family (inert only):** inject a harmless canary key via each vector shape, carrying marker value `{canary}` — e.g. a JSON `__proto__` wrapper, a `constructor.prototype` wrapper, and a bracketed `{param}[__proto__][canaryKey]={canary}` query. No destructive values, no overwriting of real config.
- **Prove prototype-level, not instance-level:** trigger an operation that constructs a brand-new, unrelated object (or issue a second, independent request) and read `canaryKey`. Appearing on an object you never assigned to = write landed on `Object.prototype`.
- **Gadget reach (conceptual — no working exploit):** map the controllable property to a downstream consumer. Client-side: a sanitizer/allowlist flag, a template option, or a URL/`script.src` assembled from a polluted default → DOM-XSS or behavior change. Server-side: a polluted options key consumed by a template engine or a child-process/spawn options bag. Reference the gadget family only; the seed stops at "a polluted option reaches sink X." The weaponized chain and its out-of-band proof are a policy-gated exploitation task, not part of this seed.
- Seed confidence (`suspected|likely|confirmed`) rates the hint quality of this seed; it NEVER raises a finding's EvidenceTier.

### Confirmation Phase

**What does NOT constitute confirmation (arbiter idiom):**
- A reflected or echoed `__proto__` key in the response is not a prototype write — the app may simply mirror input (cf. "reflection of a string is not execution").
- An HTTP 200, or the server merely accepting the `__proto__` JSON, is not confirmation — acceptance is not a write (cf. "a 200 from the app is not a controlled OAST interaction").
- A property set as an OWN property on the request's own object is not pollution — it must land on `Object.prototype` and be observable on a different object.
- Client-side: a pollutable source that never reaches a gadget/sink, or mere string reflection, is not execution in a browser context.

**Negative control (required baseline that must differ):** the same request/flow WITHOUT the pollution key — or with an inert sibling key `{param}` in place of `__proto__` — captured against a freshly-created object / identical path. The baseline must NOT show the canary and must show normal app behavior. The polluted run must differ observably from it.

**Impact proof — exactly one EvidenceKind records each leg:**
- Prototype write observed on a separate object/code path → **DIFF** (polluted response/DOM vs the negative-control baseline), or **RAW_OUTPUT** (console / API read-back of the canary on an object it was never assigned to).
- Client-side gadget → DOM-XSS or render/behavior change → **SCREENSHOT** of the executed context / changed render, backed by the **DIFF** vs baseline.
- Gadget reaching an out-of-band sink (SSRF- or RCE-class chain) → **OAST_CALLBACK** from the controlled `{oast_host}` carrying `{canary}`. This leg is capped at SUSPECTED without a confirmed OAST_CALLBACK.

**Stability / repeats:** reproduce ≥3 times with the negative control interleaved. Server-side prototype state is process-global and may be per-worker or reset on restart — record worker affinity and show the canary surviving ≥2 independent requests so the DIFF is not request residue.

### Validation Requirements

**Minimum for CONFIRMED:**
1. Negative-control baseline captured (no pollution key; canary absent; normal behavior).
2. Polluted run where the canary surfaces on an object/response it was never assigned to.
3. A **DIFF** or **RAW_OUTPUT** artifact showing the delta against the baseline.
4. ≥3 stable repeats with the baseline interleaved (server-side: across ≥2 independent requests).

**Raises to EXPLOITED** — the polluted property demonstrably reaches a security-impacting gadget:
- DOM-XSS / client behavior change: **SCREENSHOT** of execution + the **DIFF**.
- Authorization / flag / ACL override that flips a decision: **DIFF** of allowed-vs-denied under identical identity.
- SSRF/RCE-class sink fired: **OAST_CALLBACK** proving the out-of-band interaction.

A reflected `__proto__` key, or a pollutable source with no observed downstream effect, stays below CONFIRMED (observed only). Mask real identifiers in all artifacts; use `{target_email}` / `{canary}` placeholders.
