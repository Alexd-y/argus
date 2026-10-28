---
name: account_takeover
description: Account takeover via auth-factor mutation flaws — password-reset poisoning, reset-token predictability/reuse, MFA/OTP bypass & response-manip, OTP race/TOCTOU, pre-auth session fixation (not brute-force)
applicable_contexts: [web, api]
---

## Account Takeover Testing Methodology

> ATO is a destination class, not a single bug. Each path below is a primitive that only becomes a finding when you demonstrate an authenticated session or action under a SECOND test account `{victim_account}` you do not legitimately control, from attacker A's session. A path that only locks you out of your own account, or only works when you already hold the victim's credential + session, is not standalone ATO. Brute-force / credential-stuffing is out of scope here (hydra/ncrack adapter). Use test accounts only; mask any real PII.

### Discovery Phase

Signals, entry points, fingerprints (from reference taxonomy):

- **Map every auth-factor mutation endpoint**: `/forgot-password`, `/reset-password`, `/account/email`, `/account/password`, `/mfa/verify`, `/otp/verify`, passwordless / magic-link, OAuth account-link & callback. For each, note whether it re-verifies the *current* factor and re-verifies the *new* identifier — ATO almost always lives in a missing check on one side.
- **Reset-link construction fingerprint**: does the mailer build the reset URL from a request-controlled host header (`Host`, `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Host`, dual-Host)? A reflected host value is a *signal*, not proof (link domain may be server-pinned).
- **Reset-token shape**: length, charset, entropy. Legitimately request several tokens for an account you own and inspect for sequential / timestamp-derived structure. Probe expiry window, single-use semantics, and invalidation-on-new-request.
- **MFA/OTP verify envelope**: diff success vs failure response — status, body length, redirect target, session/token issuance. Flag client-trusted success flags (e.g. `{"verified": true}`), skippable steps, and surfaces where a captured success body could be substituted for a failure body (response-manip).
- **OTP concurrency**: is there a check-then-consume gap (TOCTOU) between validating the code and marking it spent?
- **Session issuance timing**: is a session identifier set *before* authentication and retained afterward (fixation signal)? Does successful login rotate the session id?
- Cover both web forms and JSON APIs; check mobile API parity.

### Exploitation Phase

Conceptual steps; reference payload families, no working exploit code. Placeholders only: `{target_email}` `{victim_account}` `{oast_host}` `{canary}` `{attacker_origin}` `{param}` `{target_url}`.

- **Password-reset poisoning**: request a reset for `{target_email}` with the host-routing header pointed at `{oast_host}/{canary}` (host-header override payload family — inert placeholder). A mailer that builds the link from the request host routes the token off-origin. Blind: the token must *arrive* at the controlled host.
- **Reset-token predictability / reuse**: sample tokens you legitimately own and analyse entropy/monotonicity offline (no brute-force against the victim). Separately, replay a previously-used or expired token to test reuse / no-expiry / no-invalidation-on-reissue.
- **MFA / OTP bypass & response-manip**: on the verify step test (i) step-skip directly to the post-MFA state, (ii) flip of a client-trusted success flag, (iii) substitution of a captured success response for a failure response, (iv) acceptance of null/empty/format-variant codes. Confidence of the seed is a hint only.
- **OTP race / TOCTOU**: submit N concurrent verify requests with one candidate inside the validity window to exercise a check-then-consume gap (parallel / single-batch submission concept) — targets one code validating more than once or during a cleanup window.
- **Pre-auth session fixation**: plant a known session identifier pre-auth from `{attacker_origin}`, have the victim authenticate on it, then confirm the pre-auth identifier survives the privilege transition.
- **Chains** (reference other skills, keep placeholders): IDOR / mass-assignment on the email-change factor → trigger reset → token lands at attacker mailbox (see `idor`, `mass_assignment`); JWT-identity forgery to the victim endpoint (see `authentication_jwt`). Chained email-change → reset is the most reliable low-interaction path.
- All steps run against `{victim_account}` (B) from attacker A's session; never real infrastructure or PII.

### Confirmation Phase

Provability idiom — align to the ARGUS arbiter (`src/pipeline/contracts/confirmation_rules.py`). A seed's confidence (`suspected|likely|confirmed`) rates the **seed as a hint only** and must NEVER raise a finding's EvidenceTier.

**(a) What does NOT constitute confirmation for this class**
- A `200` / `"success"` / `{"verified":true}` from a reset, MFA, or OTP endpoint is not takeover — the app returning OK is not an authenticated session under the victim.
- Reflection of an attacker `Host` value in the reset email body is not poisoning — the delivered link domain may be server-pinned; a reflected string is not a delivered, redeemable token.
- Decoding, forging, or altering a token, or an OTP "accepted" message, is not impact unless it yields an authenticated action under the victim identity.
- A reset token present at the attacker host but not redeemable into a session is not ATO.
- Self-account lockout, or a flow that only works once you already hold the victim's password + session, is not standalone ATO.

**(b) Negative control (baseline that must differ)** — write to canonical keys `negative_control_url` / `negative_control_result`:
- Session/MFA/OTP/fixation paths: the SAME request/state WITHOUT the manipulation must be rejected — clean-client access to `{victim_account}` carrying no legitimately-issued victim credential returns 401/403 or lands in attacker A's own account. Manipulated vs clean states must diverge.
- Reset-poisoning: a baseline reset with the native host must deliver to the legitimate domain, not `{oast_host}`; only the manipulated request routes the token off-origin.
- OTP race: a single sequential submission must fail / consume-once; only the concurrent burst double-consumes.

**(c) Impact proof + EvidenceKind (exactly one primary per sub-path)**
- Session-fixation / MFA-OTP response-manip / token-reuse → **HAR** capturing an authenticated action under `{victim_account}` from a clean client that holds no legitimately-issued victim credential (request + response proving cross-identity access).
- Host-header reset poisoning / blind token-leak → **OAST_CALLBACK**: the token/code must actually arrive at the controlled `{oast_host}` on a unique `{canary}` subdomain and be redeemable (the _rule_ssrf shape: OAST interaction + canary, not a 200 from the app).
- Directly-read token predictability/reuse → **RAW_OUTPUT** of the sampled token set plus a **DIFF** of own-token vs victim-path response, with the redemption HAR.

**(d) Repeats for stability**
- Re-run the full takeover ≥2 independent times (fresh browser/session each) with the negative control interleaved. OTP-race is probabilistic — report the success ratio (k of n), never a single fluke.

**OAST dependency (cap rule)**: host-header reset poisoning and any blind token-leak sub-path are OAST-dependent — WITHOUT a confirmed `OAST_CALLBACK` (unique canary at the controlled host) the finding is **capped at SUSPECTED**, regardless of a 200 or a reflected `Host` value. Session-fixation, MFA/OTP response-manip, and directly-read token-reuse sub-paths confirm on the HAR negative-control pair without OAST.

### Validation Requirements

**Minimum artifacts for CONFIRMED**
1. Manipulated-vs-clean negative-control pair recorded (`negative_control_url` / `negative_control_result`) with states that diverge.
2. The class EvidenceKind present — HAR of cross-identity authenticated access to `{victim_account}`, OR OAST_CALLBACK with a unique canary for poisoning/blind-leak paths, OR RAW_OUTPUT + DIFF + redemption HAR for directly-read token flaws.
3. ≥2 stable repeats from fresh clients (OTP-race: k-of-n ratio).
4. Test account `{victim_account}` only; no real PII in evidence.

**Caps (never CONFIRMED)**
- OAST sub-path without OAST_CALLBACK → SUSPECTED.
- A 200 / success-flag / reflected-host / decoded-token with no cross-identity session → SUSPECTED (observed).
- Self-account-only impact → not a standalone ATO finding.

**Raises to EXPLOITED**
- End-to-end demonstrated seizure of `{victim_account}` — attacker sets a new credential or holds a durable session from a clean device, victim access displaced — captured as **VIDEO** or **SCREENSHOT** walkthrough plus the redemption HAR; i.e. authenticated control persists beyond the single request.
