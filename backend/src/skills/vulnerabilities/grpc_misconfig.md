---
name: grpc_misconfig
description: gRPC misconfiguration — server-reflection enumeration, unauthenticated RPC calls, proxy-trusted metadata spoofing, -bin metadata smuggling, and message-size hardening
applicable_contexts: [api]
---

## gRPC Misconfiguration Testing Methodology

### Discovery Phase

Signals, entry points, fingerprints:
- Ports: 50051 (native), 443/8443 (TLS+ALPN h2), 9090/8080 (h2c). ALPN must negotiate `h2` — gRPC never runs on HTTP/1.1.
- Transport fingerprint: an HTTP/2 POST to a bogus `pkg.Service/Method` on `{target_host}:{target_port}` returns a `grpc-status` trailer (`UNIMPLEMENTED`=12) even on a wrong path → confirms a gRPC server / transcoder is present. This is transport only, not a finding.
- Content-types to recognize: `application/grpc`, `application/grpc-web+proto`, `application/grpc-web+json`, Connect (`connect-protocol-version`).
- Fronting translators = the realistic external surface: Envoy `grpc_web` / `grpc_json_transcoder`, grpc-gateway (REST↔gRPC), Connect (buf).
- Reflection services: `grpc.reflection.v1.ServerReflection` / `v1alpha`, plus `grpc.health.v1.Health`.
- Schema-leak entry points: descriptor / swagger paths on the proxy; `.proto` files in source or registries — these let you rebuild a descriptor set and drive a reflection-off target.

Server-reflection enumeration (conceptual):
- Use a reflection-capable client (`grpcurl list` / `list <svc>` / `describe`) against `{target_host}:{target_port}` to pull the full service/method/message catalog without source. `-plaintext` for h2c, `-insecure` for self-signed TLS.
- Triage the catalog for sensitive surfaces (admin / internal / debug / secret / impersonate / exec / migrate / reset / delete).
- Reflection-off is a hardening control, not a boundary — a leaked `.proto` rebuilt into a descriptor set (`-protoset`) reaches the same methods.

### Exploitation Phase

Conceptual steps only — reference the payload family, no working exploit code or shellcode.
- Unauthenticated RPC calls: invoke a sensitive method with NO auth metadata and read the `grpc-status`, not the byte count. `OK (0)` + populated message on a privileged method = candidate. `Unauthenticated (16)` / `PermissionDenied (7)` = authz works (close it). `Unimplemented (12)` = wrong method. `InvalidArgument (3)` = reached and parsed (fix the `{param}` shape, retry).
- Enumerable id fields → IDOR candidate; hand the owner-delta proof to the `idor` class.
- Proxy-trusted metadata spoofing (gRPC-specific crown jewel): backends that authenticate at the edge often re-trust proxy-injected identity metadata (`x-user-id`, `x-tenant-id`, `x-forwarded-*`, `x-envoy-internal`). If the edge does not STRIP these, spoofing them impersonates any caller. Test the spoof BOTH directly against the backend port AND through the public proxy — only a proxy that forwards the spoofed key unchanged makes it exploitable for real users.
- `-bin` metadata smuggling: keys ending `-bin` are base64-decoded server-side; some auth middleware inspects only text metadata and misses `-bin` keys. Carry an identity/auth assertion in a `-bin` key the text-only filter ignores (placeholder value, never a live token).
- Transcoder re-exposure: grpc-gateway / gRPC-Web / Connect routes frequently re-expose internal methods over plain HTTP/JSON to the browser. Confirm each transcoded route returns OK with sensitive data AND is reachable as an unauth / low-priv user, not just inside the mesh.
- Message-size hardening: assess the server's max-receive-message posture from config/version (e.g. an unbounded or very large `grpc.max_receive_message_length`). Report the hardening gap conceptually. Do NOT send an oversized or flood payload — resource exhaustion / Rapid-Reset-style DoS is authorization-gated, out of scope without explicit written permission, and must be version/config-matched, never exercised.
- Payload family: `grpc_misconfig` seeds are inert probe messages with placeholder fields (`{param}`, `{canary}`) and placeholder identity metadata — never live tokens or infrastructure. A seed's confidence (`suspected` | `likely` | `confirmed`) rates the SEED as a hint only; it never raises a finding's EvidenceTier.

### Confirmation Phase

Align to the ARGUS arbiter (`src/pipeline/contracts/confirmation_rules.py`). `grpc_misconfig` has no `_CLASS_RULES` entry yet (needs_class_rule=true) — shape its PoC like `auth_bypass`/`idor` (`protected_resource_reached` + negative control) so an added rule confirms it.

- What does NOT constitute confirmation for this class:
  - A `grpc-status` trailer merely being present (`UNIMPLEMENTED` on a bogus path) is transport fingerprint, not a vuln.
  - Reachable reflection or `grpc.health.v1.Health` is info-disclosure at most — not "missing auth" (many servers ship reflection on by design).
  - Returned bytes are not success: an error frame can carry a body. Only `grpc-status: 0 (OK)` is success.
  - `OK` on a legitimately anonymous method (health, public catalog read) is not an authz bug.
  - A seed tagged `confidence=confirmed` is a hint about the seed, never the finding's tier.
- Negative control (the baseline that must differ): the SAME RPC with the SAME arguments issued WITH a valid authed session / correct auth metadata, captured alongside the no-auth (or spoofed-metadata / `-bin`-smuggled) call and written to `negative_control_result`. The two must differ:
  - unauth / spoofed → `grpc-status: 0` + privileged or cross-owner data;
  - authed baseline → shows the control is real (or returns a different owner's data).
  - Metadata spoofing: baseline = the proxy-stripped request (no injected identity) vs. the spoofed `x-user-id` / `x-tenant-id` request — the two must return different owners' data.
  - `-bin` smuggling: baseline = the text-metadata equivalent that is REJECTED vs. the `-bin` key that is ACCEPTED.
- Impact proof and EvidenceKind: **RAW_OUTPUT** — the captured `grpc-status: 0` trailer plus the response message carrying privileged/cross-owner data for the no-auth / spoofed / `-bin` call, PAIRED with the authed-baseline RAW_OUTPUT showing the state delta. For a mutating RPC, add RAW_OUTPUT of a re-read proving the side effect. A DIFF of the two RAW_OUTPUTs may accompany it, but RAW_OUTPUT is the canonical kind.
- Repeats for stability: re-run the paired (no-auth vs authed-baseline) calls at least 2–3 times; identical OK-status + data across repeats rules out a transient or race.
- OAST dependency: `grpc_misconfig` is NOT OAST-dependent — its proof is RAW_OUTPUT. The one exception is a called RPC that takes a URL/host argument (webhook / import / render): that is a blind-SSRF candidate, OAST-dependent, and WITHOUT a confirmed `OAST_CALLBACK` (a unique `{canary}` subdomain under `{oast_host}`) it is capped at SUSPECTED — hand it to the `ssrf` class rule.

### Validation Requirements

Minimum artifacts for CONFIRMED:
- Paired RAW_OUTPUT: (1) the no-auth / spoofed-metadata / `-bin`-smuggled call with `grpc-status: 0` + sensitive data, and (2) the authed-baseline negative control showing the state delta.
- Stability across ≥2 repeats.
- An explicit external-reachability statement (exposed port vs. public-proxy passthrough vs. SSRF egress). A bug reachable only on an internal `:50051` found by port-scan is real, but its severity tracks reachability.
- Without the authed-baseline negative control, cap at SUSPECTED / OBSERVED — never confirmed.

What raises to EXPLOITED:
- A mutating admin RPC executed and its side effect proven by re-reading the changed state (RAW_OUTPUT), OR
- Cross-tenant impersonation demonstrated end-to-end THROUGH the public proxy (the proxy forwards the spoofed `x-user-id` / `x-tenant-id` unchanged), OR
- Chained mass exfiltration of another tenant's / owner's records via an enumerable RPC.

Severity posture (after the gates above pass):
- Sensitive/admin RPC callable with no auth + side-effect proven → Critical.
- Proxy-forwarded metadata spoofing → cross-tenant impersonation → Critical.
- IDOR / mass-PII via enumerable RPC → High.
- Internal service externally reachable (transcoder or open port) → High.
- Reflection exposing a non-public catalog → Medium (enabler).
- Proto/descriptor leak with no callable sensitive method → Low.
