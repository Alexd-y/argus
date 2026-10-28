---
name: host_header_injection
description: Host header injection — reset/verification-link poisoning to ATO, unkeyed Host/X-Forwarded-Host cache poisoning, routing-based SSRF, X-Original-URL path override, and OAuth/OIDC poisoning.
applicable_contexts: [web, api]
---

## Host Header Injection Testing Methodology

Mostly a **blind** class: the server trusts a client-supplied host to build a link,
pick an upstream, or key a cache. Impact lands out-of-band (victim inbox, shared
cache, internal network), so reflection in your own response is a lead, not a proof.

### Discovery Phase

**Entry points / attack surface**
- Forgot-password, email-verification, invite, and set-password flows (absolute links built from the request host).
- Any transactional/notification email sender that embeds a link.
- Apps behind a CDN or reverse proxy (Cloudflare, Fastly, Varnish, Akamai, nginx, HAProxy, k8s ingress, service mesh, forward proxies).
- OAuth/OIDC `authorize` endpoints and `/.well-known/openid-configuration` (discovery) documents.
- Reverse proxies that select the upstream from the Host header (routing-based SSRF surface).

**Dangerous (often unkeyed / over-trusted) headers**
- `Host`, `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `Forwarded: host=…`, `X-Forwarded-Scheme`.
- Path-override family (different layer): `X-Original-URL`, `X-Rewrite-URL`, `X-Override-URL`.

**Fingerprints / signals**
- Injected host echoed into an absolute URL, `Location`, `<link rel=canonical>`, `<base href>`, or `og:url`.
- Cache indicators: `X-Cache`/`CF-Cache-Status: HIT`, nonzero `Age`, `Via: varnish/fastly/cloudfront`.
- `Vary` **does not** list `Host`/`X-Forwarded-Host` → candidate unkeyed input (poisonable).
- Framework tells: Django `USE_X_FORWARDED_HOST`, Rails/Express `request.host`-style helpers with no allowlist.

### Exploitation Phase

> Test only against your **own** registered test account and a canary/OAST host you control. Never request another user's reset. Use placeholders, never live third-party infra.

Reference the payload families conceptually (see the signed `payloads/` catalogs); no working exploit code here.

- **Reset / verification-link poisoning (→ ATO):** drive the forgot-password flow for `{target_email}` while supplying an attacker host via the header family above — direct `Host`, trusted `X-Forwarded-Host`, dual-`Host`, subdomain-append (`{target_host}.{oast_host}`), or parser-confusion (`{target_host}:{target_port}@{oast_host}`). Use `{oast_host}`/`{canary}` as the injected host so a click/preview exfiltrates the token out-of-band.
- **Cache poisoning via unkeyed Host/X-Forwarded-Host:** inject a unique `{canary}` that reflects into an absolute URL/`Location`/canonical on a **cacheable** response, then target a cache key you do not control. Reflection-based, not OAST — keep the marker inert.
- **Routing-based SSRF:** set `Host` to an internal name or metadata endpoint so the front-end forwards upstream; the path stays on the request line. Do **not** compose this with `X-Original-URL` (different layers). Blind case: point `Host` at a unique `{canary}.{oast_host}` subdomain.
- **Path override / edge-ACL bypass:** keep the real `Host`; use `X-Original-URL`/`X-Rewrite-URL` to steer the routed path toward an edge-blocked endpoint.
- **OAuth/OIDC poisoning:** where `redirect_uri`, `issuer`, or discovery endpoints are built from the host, re-point the flow at `{attacker_origin}` to steal the auth code/token.

### Confirmation Phase

Align to the ARGUS arbiter: a seed's confidence (`suspected|likely|confirmed`) rates the
**hint**, never the finding's EvidenceTier. Each facet below states what does NOT confirm,
the negative control, the one impact-proof EvidenceKind, and the repeat count.

- **Reset / verification poisoning** — *Not confirmation:* the injected host echoed in the HTTP response, or a `200`, or a reflected link in the response body; many mailers rewrite to a fixed `SITE_URL` regardless of Host. *Negative control:* the same flow with the genuine `Host` (no injected header) yields a link under the canonical host — the attack email's link host must **differ**. *Impact proof:* **OAST_CALLBACK** on `{oast_host}` carrying the reset/verification token (inbound hit when the link is clicked/previewed). *OAST-dependent — without a confirmed OAST_CALLBACK the finding is capped at SUSPECTED.* *Repeats:* ≥2 token-bearing callbacks.
- **Cache poisoning (unkeyed Host/X-Forwarded-Host)** — *Not confirmation:* a reflection that only appears for **your** request (keyed input, in `Vary`, or Host-in-key), or a `MISS`/`Age: 0` with no shared entry. *Negative control:* a request that **omits** the injected header, from a fresh egress IP/incognito, on the same cache key — it must still return the attacker-controlled absolute URL to count; clean canonical content = not poisoned (demote to self-only if Vary-keyed). *Impact proof:* **HAR** of the header-omitted request returning the attacker content with `X-Cache: HIT`. *Repeats:* ≥2 across distinct egress.
- **Routing-based SSRF** — *Not confirmation:* a `200` echoing your Host string is not SSRF. *Negative control:* the genuine-`Host` request returns the app's own content; the Host-steered request must return internal-origin bytes or fire the OAST. *Impact proof:* **OAST_CALLBACK** from the front-end's outbound resolution of the unique `{canary}.{oast_host}` (blind case). *OAST-dependent — without a confirmed OAST_CALLBACK the finding is capped at SUSPECTED.* *Repeats:* ≥2.
- **Path override / edge-ACL bypass** — *Not confirmation:* a `200` for `/`, or the same status/body as the baseline. *Negative control:* the edge-blocked direct request to the protected path (403/404) — statuses/bodies must **differ** from the override request. *Impact proof:* **DIFF** of override response vs edge-blocked baseline showing the protected content was reached. *Repeats:* ≥2.
- **OAuth/OIDC poisoning** — *Not confirmation:* a reflected `redirect_uri`/`issuer`/discovery string is not code/token theft. *Negative control:* the genuine-`Host` flow delivers the code to the canonical callback; the poisoned flow must deliver to `{attacker_origin}`. *Impact proof:* **OAST_CALLBACK** capturing the auth code/token at `{attacker_origin}`. *OAST-dependent — without a confirmed OAST_CALLBACK the finding is capped at SUSPECTED.* *Repeats:* ≥2.

### Validation Requirements

**Minimum for CONFIRMED (EvidenceTier=3)**
- The facet's negative control recorded, demonstrably **differing** from the attack response.
- The facet's single impact-proof EvidenceKind captured and reproduced **≥2×**:
  - reset/verification, routing SSRF, OAuth/OIDC → **OAST_CALLBACK** (else capped at SUSPECTED=2);
  - cache poisoning → **HAR** (header-omitted fetch returns attacker content, `X-Cache: HIT`);
  - path override → **DIFF** (override vs edge-blocked baseline).
- Cache findings proven on a key you do not control; demote to self-only/Informational if Vary-keyed or `MISS`/`Age: 0` only.

**Raises to EXPLOITED (EvidenceTier=4)** — downstream impact demonstrated, not just the primitive:
- Reset/verification: token captured **and used** to reach the account — **SCREENSHOT**/HAR of the authenticated session (ATO).
- Routing SSRF: internal/metadata response retrieved; if cloud creds, validated — **RAW_OUTPUT** of the internal-origin bytes.
- Cache poisoning: the poisoned entry served to a victim and the injected absolute URL/content **executing** in a browser context — **SCREENSHOT** or **VIDEO**.
- OAuth/OIDC: the stolen code/token exchanged and used — **SCREENSHOT**/HAR of the attacker-held session.
- Path override: the protected endpoint's sensitive content actually returned under the override.

Mask any real PII in evidence. Reflected ≠ cached; cached-for-you ≠ cached-for-others; a reflected header ≠ a poisoned email (verify the email body).
