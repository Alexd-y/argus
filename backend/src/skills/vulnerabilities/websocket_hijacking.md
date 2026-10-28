---
name: websocket_hijacking
description: CSWSH (foreign-Origin handshake), handshake-only vs per-message auth, in-flight frame tampering, and socket.io privileged-namespace/room authz bypass
applicable_contexts: [web, api]
---

## WebSocket Hijacking Testing Methodology

### Discovery Phase

Signals / entry points:
- JS references: `new WebSocket`, `io(`, `io.connect`, `socket.io`, `SockJS`, SignalR, `Phoenix.Socket`, `ws://` / `wss://`
- URL / path hints: `/ws`, `/socket.io/`, `/signalr`, `/cable`, `stream`, `realtime`, `live`, `chat`, `events`, `notifications`
- Realtime features: chat, live dashboards, notifications, trading / checkout, collab editors
- Non-standard ports: 3000, 3001, 8080, 8443, 8888, 9000

Fingerprints:
- Handshake probe to `{target_url}`: a `101 Switching Protocols` only proves upgrade support — a candidate, never a finding.
- socket.io polling handshake (`/socket.io/?EIO=4&transport=polling`) leaks the Engine.IO version + initial `sid`; also fingerprint the client lib version from JS bundles, then map to that release's advisories.
- Enumerate live sockets + frame schemas from proxy WS history; flag which frames carry auth-sensitive data (tokens, PII, balances, `userId`).

Auth-model triage (decides exploitability):
- (a) handshake authenticates via an ambient credential (cookie attached automatically by the browser), (b) no unpredictable per-connection token in the handshake (no `?token=`, no bearer sub-protocol, no first-frame nonce), (c) server does not enforce Origin. All three present → CSWSH candidate. A unique per-connection token riding the handshake breaks cross-site exploitation — downgrade or drop.

### Exploitation Phase

Reference the payload families conceptually; no working exploit/shellcode, inert markers only.

- CSWSH (foreign-Origin handshake): host a page on `{attacker_origin}` that opens a socket to `{target_url}` relying on the browser-attached victim cookie, subscribes with a unique `WSHJ-{canary}` marker, and forwards any received frame to `{oast_host}`. Cross-origin JS cannot forge Origin/Cookie — the browser attaches them, which is exactly the threat model.
- Handshake-only vs per-message auth: after a valid handshake, replay privileged app frames (e.g. an admin `{param}` action) under a no-/low-privilege session — many stacks authorize the socket once and then trust every later frame.
- In-flight tamper: alter server-trusted client values in frames (price / qty / `userId` / amount → `{param}`) on trading / checkout / game flows — the "frame-tamper" payload family.
- socket.io privileged namespace / room join: emit a socket.io CONNECT control packet targeting a privileged namespace (Engine.IO MESSAGE + socket.io CONNECT opcode — NOT a `?nsp=` query param, which is silently ignored and lands you in the root namespace), then emit an EVENT to join another user's room. SignalR analogue: `negotiate` then invoke hub methods (method-level authz). Phoenix: `phx_join` to `topic:subtopic`.
- Signed-frame replay: replay a captured signed frame across a time window (freshness) and across a second session (session binding).

Keep probes inert and link-safe: unique markers, `{canary}` / `{oast_host}` beacons, read-only subscribes. No destructive frames.

### Confirmation Phase

Align every claim to the arbiter (`src/pipeline/contracts/confirmation_rules.py`). This class is **not yet in `_CLASS_RULES`** — propose a rule (see below); until then it has no per-class gate.

What does NOT constitute confirmation (arbiter idiom):
- A bare `101` from `Origin: {attacker_origin}` is not CSWSH — parallels "a 200 from the app is not a controlled OAST interaction". The server may accept the upgrade and stream nothing, or reject at the first authenticated frame.
- A completed cross-origin handshake is not victim-data receipt.
- An echo / reflection of your own frame is not a privileged action (self-echo is not a server-side state change).
- A `40/<namespace>` ACK is not receipt of another tenant's data (connected-but-empty namespace).
- An accepted-but-silently-ignored frame is not impact.

Negative control (the baseline that must differ — write `negative_control_url` / `negative_control_result`):
- Re-run the identical handshake + subscribe from a clean context — absent / scrubbed cookie, or a second untrusted account — the attacker-origin run must receive data the baseline run does NOT.
- For tamper / privileged-frame: capture pre-action server state via REST; the post-action REST state must differ from that baseline.

Impact proof + EvidenceKind (exactly ONE kind records the proof):
- CSWSH read-exfil → `OAST_CALLBACK`: the unique `WSHJ-{canary}` carrying another account's data is delivered out-of-band to `{oast_host}`. In-band alternative artifact: `HAR` of the cross-origin WS session capturing the victim-account frames.
- Per-message-auth / privileged-frame / tamper → `DIFF`: REST before-vs-after shows the privileged / tampered effect persisted server-side (or `RAW_OUTPUT` of the changed server state).
- Namespace / room authz bypass → `RAW_OUTPUT` (or `HAR`) of the `42` event frames carrying a different tenant's data.

Stability: confirm on >=2 independent connections with the marker varied, against a freshly re-authenticated victim session.

OAST dependence: the blind CSWSH exfil subpath and any handshake-layer Upgrade-smuggling tunnel are OAST-dependent — WITHOUT a confirmed `OAST_CALLBACK` they cap at **SUSPECTED**. The per-message-auth, tamper, and namespace-join subpaths confirm on REST-persistence `DIFF` and are not OAST-gated.

Seed-confidence note: a payload-seed confidence (`suspected|likely|confirmed`) rates the seed as a hint only; it NEVER raises a finding's EvidenceTier.

### Validation Requirements

Minimum for CONFIRMED:
- Handshake candidate (`101` from `{attacker_origin}`) PLUS cross-account data receipt (or a persisted privileged effect) proven by exactly one EvidenceKind above, PLUS a negative control that materially differs, PLUS >=2 stable repeats. Receipt must belong to a different account / tenant than the attacker (verified by a planted `{canary}` / distinct non-PII marker; mask any real `{target_email}` / PII).

Raises to EXPLOITED:
- A demonstrated privileged action with server-side persistence verified via REST (`DIFF`) — e.g. a session / refresh / CSRF token exfiltrated from victim frames enabling ATO, a tampered value that persists and changes financial / business state, or sustained cross-tenant data streaming. Receipt alone is CONFIRMED; proven downstream impact is EXPLOITED.

Caps:
- Bare 101 / self-echo / empty-namespace ACK / accepted-but-ignored frame → INFORMATIONAL or SUSPECTED only.
- OAST-dependent subpaths without a confirmed `OAST_CALLBACK` → SUSPECTED.

Proposed `_CLASS_RULES` entry (new class — `needs_class_rule`):
- `confirmed = (cross_account_receipt OR privileged_effect) AND (oast_callback+canary OR rest_persistence_diff) AND negative_control`
- `not_confirmation_reason = "a 101 Switching Protocols from a foreign Origin is not victim-data receipt"`
