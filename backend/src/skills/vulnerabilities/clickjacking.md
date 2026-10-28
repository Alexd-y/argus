---
name: clickjacking
description: UI redressing via missing/weak X-Frame-Options or CSP frame-ancestors; header-absence only screens, a rendered browser PoC completing a state-changing action proves.
applicable_contexts: [web]
---

## Clickjacking Testing Methodology

### Discovery Phase

Header-absence is the trigger for investigation, **not** the finding.

- **Screening signal (candidate only):** fetch the target response and inspect frame protection.
  - `X-Frame-Options: DENY | SAMEORIGIN` absent or permissive, AND
  - CSP `frame-ancestors 'none' | 'self'` absent or permissive.
  - Both missing/weak → candidate for UI redressing. Either present and restrictive → protected, stop.
- **High-value entry points** (authenticated, state-changing — severity scales with the redressed action):
  - Login / auth flows (login-CSRF via frame).
  - Money transfer / checkout / confirm-payment.
  - Account settings: email change, password change, 2FA disable.
  - OAuth / social-login "Authorize app" consent.
  - Admin actions: delete, role change, promote.
- **Fingerprints that DEFEAT it (check early, downgrade candidate):**
  - Framebusting JS (`top !== self` breakout, redirect, blank-on-frame).
  - Session cookie `SameSite=Lax | Strict` (modern default) → not sent on the cross-site framed request → clickjack fails.
  - Re-authentication / step-up prompt on the sensitive action.
  - Non-HTML endpoints (JSON/API/images) — not redressable.

### Exploitation Phase

- **Payload family (conceptual):** UI-redress overlay — target page loaded in a low-opacity / transparent cross-origin iframe from `{attacker_origin}`, with decoy UI positioned over the hidden sensitive control. No JavaScript on the target is required.
- **Inert PoC skeleton (placeholders only, no weaponized decoy):**
  - `{attacker_origin}` page frames `{target_url}`.
  - iframe styled low-opacity + absolute-positioned over the viewport.
  - decoy element ("click to continue") aligned over the hidden state-changing control.
  - no auto-trigger, no live infrastructure, inert markers only.
- **Steps:**
  1. Load `{target_url}` in the frame from `{attacker_origin}` in a real browser; confirm it actually renders (no framebusting).
  2. Confirm the victim's authenticated state carries into the cross-site frame (observe SameSite behaviour).
  3. Align the decoy over the sensitive control; drive a victim-style click.
  4. Confirm the state-changing action completes while framed cross-site.
- Target the most sensitive action first — consequence of the framed action IS the severity.

### Confirmation Phase

- **What does NOT constitute confirmation for this class:**
  - A missing `X-Frame-Options` / `frame-ancestors` header is a screening signal, not a finding.
  - A page that merely renders inside the frame is not proof — reachability is not a redressed, completed action.
  - A `200` from the endpoint is not a victim click landing on a state-changing control.
  - A read-only / non-HTML page framed has no impact to redress.
- **Negative control (baseline that must differ):** the same cross-site framed action must **fail to complete** when the redress/authenticated-click is removed — e.g. overlay absent, a session where `SameSite` blocks the cookie, or with `XFO`/`frame-ancestors` enforced (frame blanks / action does not fire). Record `negative_control_url` / `negative_control_result`. Prove the victim's authenticated session cookie actually travels into the cross-site frame; a same-origin / same-site success is not cross-site proof.
- **Impact proof + EvidenceKind:** the rendered browser PoC where the state-changing action **completes** via a framed click. Recorded as **SCREENSHOT** (decoy overlay + rendered cross-origin frame + resulting state change) or **VIDEO** (the full click-through sequence). VIDEO preferred — the class is interaction-dependent. Server-side before/after of the changed resource may corroborate as DIFF, but the canonical EvidenceKind here is SCREENSHOT/VIDEO.
- **Seed confidence vs tier:** a payload-seed confidence (`suspected|likely|confirmed`) rates the overlay seed as a hint only; it never raises a finding EvidenceTier. Tier derives from the rendered PoC artifact, not the seed.
- **Stability:** reproduce the framed click-through on **>=2 distinct runs** with a fresh victim session; a single render is not stability.
- Not OAST-dependent — no `OAST_CALLBACK` is involved in this class.

### Validation Requirements

- **CONFIRMED (minimum artifacts):**
  - SCREENSHOT or VIDEO of `{target_url}` rendered inside an `{attacker_origin}` iframe with the decoy overlay.
  - Evidence the sensitive state-changing action completed via the framed click while authenticated (cookie survived the cross-site context).
  - Negative control showing the action does NOT complete absent the redress / with frame protection present.
  - >=2 reproductions.
- **Raises to EXPLOITED:**
  - VIDEO of the end-to-end victim-perspective click-through completing a consequential action (ATO-grade: email change to `{target_email}`, password change, 2FA disable, funds transfer, OAuth grant), plus a DIFF / recorded before-after state of the affected resource.
- **Downgrade to observed/suspected:**
  - Header-absence only, no rendered PoC.
  - Frame renders but the action is blocked by SameSite, framebusting, or a re-auth step.
  - Read-only or non-HTML target.
