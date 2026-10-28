---
name: cors
description: CORS misconfiguration — reflected-origin + ACAC credentialed read, null-origin trust, trusted-regex/prefix/suffix bypass, pre-flight gating
applicable_contexts: [web, api]
---

## CORS Misconfiguration Testing Methodology

### Discovery Phase

Signals / entry points (prioritise session-gated endpoints returning PII, tokens, CSRF tokens, or financial data):

- Any response emitting `Access-Control-Allow-*` headers.
- API surface: `/api/*`, `/v1/*`, `/graphql`.
- Identity/secret bodies: `/api/me`, `/api/profile`, `/api/session`, `/api/tokens`, `/api/keys`, `/api/csrf`, `/api/account/*`.
- Financial / admin / internal: `/api/balance`, `/api/transactions`, `/api/admin/*`, `/internal/*`.
- Probe with GET carrying a crafted `Origin` and the victim session cookie — some servers emit CORS only on GET, not HEAD.

Two hard browser rules to fingerprint first (they kill most false positives):

- `Access-Control-Allow-Origin: *` cannot combine with credentials — the browser refuses to expose a `credentials:include` response. Wildcard-only is not credential-exploitable (interesting only if the data is sensitive *without* a session — usually Low/Info).
- `Access-Control-Allow-Credentials: true` means nothing on its own — it matters only when ACAO reflects/allows *your* attacker origin AND a cross-origin credentialed read returns a body.

Triage automation (lead, never proof): `corsy`, nuclei CORS misconfiguration templates, Burp passive origin-reflection flags. Every hit is re-confirmed in a real browser (curl does not enforce CORS).

### Exploitation Phase

Reference the origin-reflection probe family and the null-origin emitter family conceptually; all payload values use placeholders — no live infrastructure.

- **Reflected-origin + credentials** — send `Origin: {attacker_origin}` with the victim session; look for `ACAO: {attacker_origin}` + `ACAC: true`. This is the classic credentialed-read case.
- **Null-origin trust** — send `Origin: null`; look for `ACAO: null` + `ACAC: true`. Null is emitted by a sandboxed iframe (no `allow-same-origin`), a `data:`/`blob:` document, or a cross-scheme redirect chain.
- **Trusted-origin regex / prefix / suffix bypass** — match the candidate origin to the *specific* flaw class, then confirm the server reflects your **registerable** origin:
  - Missing end-anchor (`$`) → `{attacker_origin}` shaped `https://x.{target_host}.<attacker-domain>`.
  - Unescaped dot (`.` = any char) → origin where the separator char is substituted.
  - Missing dot-separator (prefix merge) → attacker registers `<prefix>{target_host}`.
  - Prefix-only, unanchored → `{target_url}`-prefixed origin with attacker-controlled suffix.
  - In-scope `*.{target_host}` reflecting is NOT a bug unless you actually control that host (see subdomain-takeover / stored-XSS chains).
- **Trusted insecure (http) origin** — ACAC:true against an `http://` in-scope origin lets a network attacker on that cleartext host read the authed body (pair with TLS/network class).
- **Pre-flight (OPTIONS) gating** — probe whether `Access-Control-Allow-Methods` / `-Headers` reflect arbitrary method/headers for `{attacker_origin}`; if so, a malicious origin can drive cross-origin state-changing writes (chain to CSRF-style actions SameSite would otherwise block).
- **postMessage origin check** — separate DOM-side class: flag handlers using `event.data` without a strict `event.origin` allowlist (`indexOf`/`endsWith`/`startsWith` checks are weak). Impact is DOM XSS / client auth bypass, not HTTP read.

Build the actual credentialed cross-origin read in a browser context from a host you control ({attacker_origin}); the read is proof, the header reflection is only a lead.

### Confirmation Phase

Align to the ARGUS arbiter (`src/pipeline/contracts/confirmation_rules.py`). Seed confidence (`suspected|likely|confirmed`) rates the origin-reflection seed as a hint only — it NEVER raises a finding EvidenceTier.

- **What does NOT constitute confirmation for `cors`:**
  - A curl/scanner-reflected `ACAO` header is not confirmation — curl does not enforce CORS; reflection is a hint, not a browser-enforced read.
  - `ACAO: *` + credentials is not a finding — the browser blocks the credentialed read.
  - `ACAC: true` alone proves nothing — it must pair with your reflected origin AND a readable sensitive body.
  - ACAO reflection *without* a credentialed cross-origin read of sensitive data is lower (capped at SUSPECTED/observed), not CONFIRMED.
  - `evil.{target_host}` reflecting is in-scope by design unless you control that host.
- **Negative control (baseline that must differ):** repeat the identical request with (a) a benign control `Origin` unrelated to the trust logic and (b) the same cross-origin fetch *without* `credentials:include`. The control must NOT reflect / must NOT return the sensitive body. The delta between {`{attacker_origin}` → ACAO reflect + ACAC:true + readable victim body} and {control → no reflection / empty / 401} is the discriminator.
- **Impact proof + EvidenceKind (exactly one):** `HAR` capturing the cross-origin credentialed fetch from `{attacker_origin}` — the request carrying the victim session, the response with `ACAO: {attacker_origin}` + `ACAC: true`, and a sensitive body actually read. Corroborate with `SCREENSHOT`/`VIDEO` of the browser console rendering the authed body; `OAST_CALLBACK` only records optional out-of-band exfil of the read body in blind/headless contexts (`{oast_host}`); `DIFF` records the negative-control delta.
- **Stability:** re-run the credentialed read >=2–3 times with a fresh victim session each run; it must succeed every time and the control must fail every time. Intermittent reflection (cache/CDN artifact) is not stable.

Not OAST-dependent: absence of an OAST_CALLBACK does NOT cap a CORS finding — the HAR is the primary record. Absence of the credentialed read (HAR + DIFF) does cap it at SUSPECTED.

### Validation Requirements

**Minimum artifacts for CONFIRMED:**

- HAR of the browser-context credentialed cross-origin read showing `ACAO` reflecting `{attacker_origin}` + `ACAC: true` + a sensitive response body.
- Negative-control DIFF: control-origin request and/or uncredentialed fetch that fails to reflect or returns no sensitive body.
- Stability repeats (>=2–3) with fresh sessions; browser console SCREENSHOT/VIDEO corroborating the read.
- The read is tied to sensitive data (PII, session/CSRF tokens, secrets, financial) — a readable `/api/health` is not CONFIRMED.

**Raises to EXPLOITED:**

- Demonstrated extraction of concrete sensitive data cross-origin (e.g. `/api/me`, `/api/tokens`, `/api/csrf`) turned into account impact.
- Chain proven: stolen CSRF token → forged state change; or pre-flight authorising an attacker-origin state-changing write; or trusted-subdomain takeover / stored-XSS used to host the read from a legitimately-served origin.
- Mask any real PII in captured bodies ({target_email} / {attacker_email}); retain only the minimum snippet needed to prove the read.
