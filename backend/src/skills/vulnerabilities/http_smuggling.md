---
name: http_smuggling
description: HTTP request/response smuggling (desync) discovery, chains, and time-delay / OAST confirmation — CL.TE, TE.CL, TE.TE, CL.0, H2.CL, H2.TE.
applicable_contexts: [web, api]
---

## HTTP Request Smuggling Testing Methodology

Smuggling exists when two hops in a chain (front-end proxy / CDN and back-end origin, or an HTTP/2 front-end and an HTTP/1.1 origin) disagree on where one request ends and the next begins. The disagreement poisons every subsequent request on a reused keep-alive connection. This skill produces training-grade methodology only — payload families are referenced conceptually; smuggled content is an inert `{canary}` marker, never a live internal-path or credential-collector request.

### Discovery Phase

- **Topology prerequisite**: a proxy chain with connection reuse (keep-alive) and, usually, a CDN/LB in front of an origin. No chain, no desync.
- **Entry points**: any method/endpoint behind the proxy (POST most productive); HTTP/2-terminating front-ends (the dominant 2024-2026 surface).
- **Front-end fingerprint** (recon, read-only):
  - `curl -sI {target_url}` → read `Server:`, `Via:`, `X-Cache:`; note HTTP/2 support (`curl --http2 -I {target_url}`).
  - RFC-9112-strict proxies (modern nginx, Caddy, Envoy, recent HAProxy) reject competing `Content-Length` + `Transfer-Encoding` with **400** → classic HTTP/1.1 CL/TE is dead; pivot to the H2-downgrade path.
  - Legacy/quirky stacks (older HAProxy — CVE-2021-40346; Apache `mod_proxy_ajp`→Tomcat — CVE-2022-26377; older F5/NetScaler/Squid/ATS; custom Python/Go proxies) and CDN→origin (`awselb`, `Via: cloudfront`, Akamai/Fastly) are the live surface.
- **Signals**: differential timing on framing-ambiguous probes; inconsistent handling of obfuscated `Transfer-Encoding`; version banners mapping to known desync CVEs.
- **Tooling** (detection, not weaponization): Burp HTTP Request Smuggler, `smuggler.py`, `h2csmuggler`, raw-HTTP/2 clients. HTTP/1.1-only clients cannot test an H2 front-end — they send the wrong protocol.

### Exploitation Phase

Reference the payload family conceptually; draw concrete probes from the signed ARGUS payload catalog, not inline bytes.

- **CL.TE** — front honors `Content-Length`, back honors `Transfer-Encoding`; smuggled prefix hides behind the chunk terminator.
- **TE.CL** — inverted (front TE, back CL).
- **TE.TE** — both honor TE but one accepts an obfuscated header the other normalizes away (whitespace/casing/duplicate/custom-encoding variants).
- **CL.0** — back-end ignores the body entirely, treating it as the start of the next request.
- **H2.CL / H2.TE** — HTTP/2 front-end re-serializes to HTTP/1.1 for origin, re-introducing CL/TE ambiguity; test by injecting `content-length`/`transfer-encoding` inside the H2 message. Must be sent as H2 frames.
- **Smuggled content = inert `{canary}` only.** Do NOT seed live internal-path, admin, or token-collector requests.
- **Impact chains** (describe, do not weaponize; cross-reference ARGUS skills):
  - Cache poisoning → the smuggled response body is cached against a victim-facing path (→ `hunt-cache-poison`).
  - Cross-request / token capture → a reflecting "collector" gadget attributes the next client's `Cookie`/`Authorization`/`X-Access-Token` to the attacker (→ ATO).
  - ACL/auth bypass → smuggled request reaches internal-only routes/vhosts the front-end filters.
  - Hop-by-hop header stripping via `Connection:` abuse to drop a security header before the origin.

### Confirmation Phase

Confidence on a payload seed (`suspected`/`likely`/`confirmed`) rates the SEED as a hint only; it never raises a finding's EvidenceTier. The arbiter decides the tier from artifacts + gates.

- **What does NOT confirm this class**:
  - A latency *blip* alone is not a desync — jitter, GC, back-end load, or coincidental spikes produce the same thing.
  - The attacker's OWN follow-up request returning an admin/200 body is not proof (could be a front-end echo of smuggled bytes, or the attacker's own authenticated session). The effect MUST land on a *different* client/session.
  - A `400` on competing CL+TE is a hardened parser, not a bypass; a single `502` is parser disagreement, not impact.
  - A string reflected back in your own response is not cross-request execution/landing.
- **Negative control (baseline that must differ)**: re-issue the SAME endpoint/probe with unambiguous single-framing (no competing CL/TE; a valid, non-smuggling H2 downgrade). The control request must show baseline latency (~ms) and must NOT plant the `{canary}`. The *differential* between desync probe and control is the signal. Record it under the canonical `negative_control_result` / `negative_control_url` keys.
- **Impact proof and the EvidenceKind that records it** — exactly one path:
  - **CONFIRMED (desync proven)**: a saved raw exchange — **HAR** or **PCAP** — of the probe + follow-up pair capturing the **time-delay differential** (follow-up hangs ~ configured timeout while the control stays ~ms). Raw tool stdout (`RAW_OUTPUT`/`PARSED`/`DIFF`) does not satisfy this.
  - **EXPLOITED (effect landed off-session)**: additionally one impact-proof kind — a controlled **OAST_CALLBACK** to `{oast_host}` carrying a unique `{canary}` subdomain (smuggled reach / collector gadget echoing the canary OOB), **or** a **SCREENSHOT**/**VIDEO** of a separate, clean client receiving the planted `{canary}` (cache-poison landing, cross-session prepend).
  - A controlled `OAST_CALLBACK` with a unique `{canary}` is the strongest proof; a 200 from the app is not a controlled interaction.
- **Stability / repeats**: re-run the differential ≥ 2 times with all runs matching (arbiter minimum). Operator practice: ~10 repeats — the configured hang must appear reliably and the baseline never; vary the smuggled timeout (10/30/60s) and confirm follow-up latency tracks linearly. Divergence across runs, or a tripped WAF / rate-limit / fingerprint change (interference), caps the tier at SUSPECTED.

### Validation Requirements

- **Minimum for CONFIRMED**:
  - Saved **HAR** or **PCAP** of the desync probe and its **negative control** showing the time-delay differential (or the planted-`{canary}` cross-request landing).
  - Negative control present and demonstrably different from the probe.
  - ≥ 2 matching repeats; no interference signal (WAF/rate-limit/target-unreachable untripped).
  - Front-end and back-end fingerprints recorded; desync variant named (CL.TE / TE.CL / TE.TE / CL.0 / H2.CL / H2.TE).
  - Mask any captured victim PII (cookies/tokens/`{target_email}`) — show structure only, never live secrets.
- **Raises to EXPLOITED**: add one impact-proof kind landing on a *different* client/session than the attacker's —
  - **OAST_CALLBACK** to `{oast_host}` with a unique `{canary}`, or
  - **SCREENSHOT**/**VIDEO** of a clean separate client served the planted `{canary}` (cache-poison landing / cross-session token capture).
- **Note**: ARGUS has no per-class arbiter rule for `http_smuggling` yet, so class confirmation records as "not checked" and the finding is adjudicated via the generic artifact + wave-3-gate path — flag for a dedicated rule.
