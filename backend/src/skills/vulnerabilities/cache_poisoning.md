---
name: cache_poisoning
description: Unkeyed-input web cache poisoning and cache deception — discovery, cross-user confirmation, and blast-radius validation
applicable_contexts: [web, api]
---

## Cache Poisoning Testing Methodology

Scope: this skill owns the case where a response is stored in a SHARED cache and
served to OTHER users. Host / X-Forwarded-Host that only reaches app logic
(reset-link, routing SSRF, OAuth issuer) without being cached belongs to the
host-header skill. Core primitive here: an **unkeyed input** (header, scheme,
port, param, or path suffix) influences a response that the cache keys by URL
alone — so one request poisons every subsequent visitor of that key.

### Discovery Phase

- **Cache-layer fingerprint (response headers):** `Age:`, `X-Cache: HIT/MISS`,
  `X-Cache-Status`, `CF-Cache-Status`, `Via: ... varnish/cloudfront/fastly/ats`,
  `X-Served-By`, `X-Varnish`, `Surrogate-Control`, `Server: ATS/<ver>`. Map the
  CDN/proxy and version — cache-layer CVEs exist (Varnish VSV00013 HTTP/2, Apache
  Traffic Server CVE-2021-37150), not just app misconfig.
- **Cacheability signal:** `Cache-Control: public, max-age=...`; repeat the same
  GET — if `Age:` increments and `X-Cache`/`CF-Cache-Status` flip to HIT, the URL
  is cached.
- **Attack surface / entry points:**
  - CDN-fronted hosts: `cdn.`, `assets.`, `static.`, `updates.`, `downloads.`
  - Cacheable pages that reflect a request-derived value into a cached surface:
    canonical `<link>`, script `src`, redirect `Location`, CSP `report-uri`,
    `Access-Control-Allow-Origin`
  - Affiliate / link-tracking flows: `/link/`, `/go/`, `/ref/`, `/out/`
  - Authenticated, user-specific routes behind a CDN (`/account`, `/api/me`,
    `/dashboard`) — the Web Cache Deception (WCD) surface
- **Unkeyed-input candidates (not in the cache key):**
  - Headers: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`,
    `X-HTTP-Host-Override`, `Forwarded: host=...`, `X-Original-URL`,
    `X-Rewrite-URL`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`,
    `X-Forwarded-Port`, `Origin`, `True-Client-IP`
  - Params: unkeyed query params and HPP; params the cache normalizes away
    (e.g. `utm_*`) but the backend still reads
  - Path: static-extension append (`/account/profile.css`, `.js`, `.jpg`,
    `.ico`, `.avif`) and cache/origin normalization disagreement (`;`, `%2f`,
    `\`, encoded dot-segments)
- **Tooling:** Param Miner "guess headers/params" to enumerate unkeyed inputs
  systematically — a discovery hint, never proof of cross-user impact.

### Exploitation Phase

**Golden rule — probe under a throwaway key.** Always test with a unique
cache-buster (`?cb={canary}`) so you never store poison under the real,
victim-shared key while investigating. Client `Cache-Control: no-cache` does NOT
skip storage on most CDNs — rely on a fresh key, not a request header.

1. **Confirm cacheability.** Repeat GET to `{target_url}`; watch `Age:`
   increment and the cache-status header flip to HIT.
2. **Isolate the cache key.** Vary one candidate unkeyed input at a time with an
   inert marker (`{canary}`) under a fresh `?cb={canary}` key; note whether the
   marker reflects into body/headers while the keyed URL stays the throwaway one.
3. **Unkeyed-header reflection (conceptual).** Supply the reflecting candidate
   header with an inert marker or `{attacker_origin}`; if the origin echoes it
   into a cached surface (canonical link, script src, `Location`, ACAO), the
   stored entry now carries attacker-controlled bytes. Placeholder markers only —
   never a live payload host or script.
4. **Web Cache Deception (conceptual).** Request an authenticated route with an
   appended static suffix on a throwaway path; if the origin path-normalizes and
   serves the user-specific body while the CDN caches it as a static asset, a
   private response becomes publicly retrievable. Never use a real victim's
   session or real PII.
5. **Cache-DoS variant (conceptual).** An input the origin errors on (4xx/5xx)
   that the CDN stores replaces the asset for that edge. Demonstrate only with an
   inert marker under a throwaway key; never target production-critical assets.
6. **Blast-radius mapping.** Pin host resolution to a specific edge/PoP to
   determine single-edge vs regional vs global reach.

Payload families (reference by name only — no working exploit, CRLF, or smuggling
emitted): unkeyed host/scheme/port header reflection; unkeyed-param / HPP;
static-extension & path-normalization deception; ACAO reflection; cached-error
DoS.

### Confirmation Phase

A payload-seed confidence (`suspected | likely | confirmed`) rates the SEED as a
hint only. It describes how promising the probe looked — it NEVER raises a
finding's EvidenceTier. Tier is decided by the artifacts below, not by the seed.

**(a) What does NOT constitute confirmation for this class:**
- A 200 from the app, or your own request echoing the injected input, is
  "reflected-for-you" — not a shared-cache effect (same idiom as the arbiter's
  "a 200 from the app is not a controlled OAST interaction" / "reflection of a
  string is not execution").
- `X-Cache: HIT` or an incrementing `Age:` alone is not poisoning — a HIT only
  proves the URL is cached, and may be serving the clean, pre-poison entry.
- A `Vary`-keyed response returned on a MISS with `Age: 0` is reflected-for-you:
  it is keyed to your request and is never served to another client.
- Param Miner flagging an unkeyed header with no public cache storing the body is
  a header-reflection finding (possibly XSS), not cache poisoning.

**(b) Negative control for this class:** a fresh-egress request — incognito /
different IP / no attacker cookies — to the SAME URL and SAME cache-buster value
that **omits** the injected input. Its body is the clean, un-poisoned baseline.
Record it in `negative_control_url` / `negative_control_result`. Confirmation
requires the attacker-controlled bytes to appear in THIS fresh-egress response
that never sent the injected input.

**(c) What counts as impact proof, and which EvidenceKind records it:**
- **HAR** (primary) — captures both legs: the keyed poisoning request (injected
  header/suffix present) and the unkeyed fresh-egress retrieval, with
  cache-status headers (`Age`, `X-Cache`, `CF-Cache-Status`) showing the poisoned
  body served on a HIT to a request that omitted the input.
- **DIFF** — the keyed-vs-unkeyed differential: the negative-control clean body
  vs the poisoned cached body, isolating the attacker-controlled bytes present in
  the response that omitted the injected input.
- Chain-only: **SCREENSHOT**/**VIDEO** where the cached poison renders (WCD
  discloses another user's data in a browser, or poisoned script executes) —
  supplements, never replaces, HAR/DIFF.

**(d) Repeats for stability:** the poisoned entry must be served to >= 2
independent fresh-egress retrievals (distinct IP/incognito) within the observed
`Age`/`max-age` window, and reproduced after one cache-buster rotation. Record
the TTL window and the blast radius (pin a second edge via host resolution:
single-PoP = scoped, all-edge = global).

**OAST note:** base unkeyed-input poisoning is NOT OAST-dependent — proof is
HAR + DIFF from fresh egress. Where the poison vector is itself an out-of-band
beaconing payload (the cached response embeds an exfil probe to `{oast_host}`),
that specific chain is capped at SUSPECTED without a confirmed **OAST_CALLBACK**,
per the arbiter's OAST rule.

### Validation Requirements

**Minimum for CONFIRMED:**
- HAR with both legs plus the negative control (fresh-egress, injected input
  omitted) returning the attacker-controlled body on a cache HIT.
- DIFF isolating the poisoned bytes against the clean baseline.
- `negative_control_url` / `negative_control_result` populated (the arbiter's
  canonical keys).
- >= 2 fresh-egress retrievals within TTL; cache-status headers recorded; blast
  radius stated (edge vs global).
- Caveat: `cache_poisoning` is NOT yet in the arbiter `_CLASS_RULES`
  (xss, sqli, ssrf, rce, cmdi, idor, bola, auth_bypass, rate_limiting,
  cve_version, tls_headers). Until a `cache_poisoning` rule lands, a finding that
  resolves to no class is adjudicated by the generic path — do not assume an
  auto-upgrade; `needs_class_rule` is set.

**What raises to EXPLOITED:**
- Demonstrated cross-user impact to a non-attacker identity: another client
  receives the poisoned body with concrete harm — rendered XSS in victim context
  (SCREENSHOT/VIDEO), another user's PII/session material disclosed via WCD
  (HAR + masked DIFF), or a legitimate asset denied via a cached error (HAR
  showing a clean request served the poisoned error).
- Reproduced across TTL rotations and, for a global claim, confirmed on >= 2
  edges/PoPs.
- Mask all real PII in evidence (emails → `{target_email}`, tokens/cookies
  redacted).
