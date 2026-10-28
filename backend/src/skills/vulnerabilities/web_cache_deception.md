---
name: web_cache_deception
description: Path-confusion caching of authenticated pages under static-looking keys, leaking victim private content to a second unauthenticated client
applicable_contexts: [web]
---

## Web Cache Deception Testing Methodology

### Discovery Phase

- Cache-layer fingerprints (response headers): `CF-Cache-Status`, `X-Cache: HIT/MISS`, `Age:`, `Via: cloudfront/fastly/varnish/ats`, `X-Served-By`, `Surrogate-Control`, `Cache-Control: public, max-age=...`.
- Entry points: authenticated, user-specific dynamic endpoints — `/account`, `/account/profile`, `/api/me`, `/dashboard`, `/settings`, invoice/order views, anything returning PII or session-bound data.
- Precondition (two systems must disagree):
  - Origin uses permissive path routing (Rails / Express / FastAPI / .NET) — unknown trailing suffix segments fall through to the parent dynamic handler.
  - Cache has a static-extension rule ("cache `*.css` / `*.js` / images regardless of `Cache-Control`") that overrides `Cache-Control: private`.
- Normalization probe: does `{target_url}/account/profile` and `{target_url}/account/profile/{canary}.css` return the same dynamic body at the origin, while the cache treats the second as a static asset?
- Suffix / delimiter families to enumerate (conceptual): trailing static extension (`.css .js .jpg .png .ico .avif`), path-segment append (`/{canary}.css`), delimiter tricks (`;`, `%2f`, `%2e%2e`), and less-common extensions that slip a static allowlist / Cache Deception Armor gap.
- Early negative signal: if the endpoint sets `Cache-Control: private` AND the cache honors it, it is not a candidate — the bug lives only where a static-asset rule overrides `private`.

### Exploitation Phase

Conceptual payload family only — NO working exploit code; placeholders and inert canaries throughout; mask any real PII observed.

1. Prime (authed victim role): request the deceptive static-looking URL `{target_url}/account/profile/{canary}.css`. Observe the origin serving the victim's private/dynamic body under a cacheable-looking key.
2. Confirm store: look for the entry being written — `CF-Cache-Status: MISS`→stored, `Age:` begins to increment, `Cache-Control: public` on an authenticated body, `Content-Type: text/html` served under a `.css` key.
3. Retrieve cross-client: from a SEPARATE, fully unauthenticated client (no cookies, no attacker-only headers, different session / IP) request the identical URL `{target_url}/account/profile/{canary}.css`. The SHARED cache key — not any attacker-supplied header — is what makes this victim-facing.
4. Isolate safely: use a fresh per-test `{canary}` in the suffix so each probe lands on a throwaway key; do not prime the real victim-shared key during discovery.
5. Scope blast radius: note per-PoP vs global caches; pin host/edge to check whether a second edge serves the cached private content or only the primed PoP.
6. Redact: mask any real PII in the retrieved body; keep only inert, redacted markers for evidence.

### Confirmation Phase

Align to the ARGUS arbiter (`src/pipeline/contracts/confirmation_rules.py`). This class has NO per-class rule in `_CLASS_RULES` yet (`needs_class_rule`); state confirmation in the arbiter idiom so adjudication is unambiguous.

- Seed confidence is a HINT only: a suffix / payload seed rated `suspected | likely | confirmed` rates the SEED, never the finding's provenness, and must NEVER raise a finding's `EvidenceTier`.
- What does NOT constitute confirmation:
  - A 200 (or a cache HIT) on a `.css` / static suffix is not proof — a cacheable-looking response is not cross-user disclosure.
  - Your OWN second request returning your OWN session content is not deception — a same-session cache read is not a cross-client leak.
  - `Content-Type: text/css` on an HTML body, `Cache-Control: public`, or a nonzero `Age` are signals, not impact.
  - A scanner / Param-Miner verdict alone is not proof.
- NEGATIVE CONTROL (baseline that must differ): the identical static-looking URL fetched by a clean, unauthenticated client on an UNPRIMED key (or before priming) must return NO private content — login redirect / public page / 404 / empty body. Confirmation requires the post-prime unauthenticated fetch to return the victim's private content while this baseline does not. Also baseline the canonical no-suffix URL unauthenticated → it must be auth-gated, proving the content is genuinely private.
- Impact proof — EvidenceKind = HAR: one HAR capturing BOTH legs — (1) the authenticated victim client priming the cache (`MISS`→store), and (2) a separate unauthenticated client (no credentials) retrieving the SAME key and receiving the victim's private content from cache (`Age>0` / `X-Cache: HIT`). The masked private markers (victim email / token / PII) present in the unauthenticated leg are the impact. A DIFF may accompany it (unauth body == victim private body, and != the negative-control public body); HAR of both clients is the primary kind.
- NOT OAST-dependent: proof is cross-client cache retrieval, not an out-of-band callback — `OAST_CALLBACK` is not required and does not apply here. Without the cross-client HAR the finding is capped at SUSPECTED (a bare 200 on a `.css` suffix).
- Stability / repeats: re-fetch from the clean unauthenticated client ≥2–3 times within the cache TTL; the private body must be served repeatedly (rule out a one-off race) and must key on the shared URL with no attacker-only header present.

### Validation Requirements

- CONFIRMED (minimum artifacts):
  - HAR of both legs — authed prime (`MISS`/store) + unauthenticated cross-client retrieval of the SAME key returning the victim's auth-gated private content (`Age>0` / HIT).
  - Recorded negative control — same URL unauthenticated on an unprimed key returns no private content (login / public / 404), and the canonical no-suffix URL is auth-gated.
  - ≥2–3 stable repeats within TTL; blast radius noted (single-edge vs global).
  - All PII in evidence masked.
- Raises to EXPLOITED:
  - Demonstrated retrieval of another real user's session-bound secrets (session token / reset link / full PII record) from the cache by an unauthenticated client, or a chain (cached body yields a usable session indicator → account takeover), captured end-to-end in HAR with masked markers.
  - Cross-tenant or global-edge confirmation that materially widens the victim set.
