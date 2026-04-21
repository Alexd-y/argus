# ISS-SEC-001 — Sanitize `infra/.env.example` (operator checklist)

**Severity:** CRITICAL  
**Status:** Example file sanitized in-tree; **credential rotation, history rewrite, and verification remain human operator actions** — there is no automated `gitHistoryPurged` or “rotation complete” flag in-repo without evidence from your org’s process.

## Assumption

Any provider material that ever appeared in the repository or in forks/clones must be treated as **compromised**. Rotating keys is mandatory regardless of whether the example file is fixed.

---

## 1. Operator checklist — rotate, invalidate, verify

Do **not** record new secrets in tickets, chat logs, or commit messages. Use each provider’s console to **revoke or rotate** credentials and ensure **old tokens stop working** (revocation, not only “create new key and forget the old one”).

### 1.1 Providers aligned with `infra/.env.example`

Work through every integration your deployment actually uses (skip unused rows, but document “N/A” internally).

| Area | Variables (examples) | Notes |
|------|----------------------|--------|
| LLM / AI | `OPENROUTER_API_KEY`, `KIMI_API_KEY`, `PERPLEXITY_API_KEY`, `OPENAI_API_KEY`, `DEEPSEEK_API_KEY`, `GOOGLE_API_KEY` | At least one often required for AI features. |
| Intel / recon | `SHODAN_API_KEY`, `GITHUB_TOKEN`, `CENSYS_API_KEY` / `CENSYS_API_SECRET`, `NVD_API_KEY`, `EXPLOITDB_API_KEY`, `SECURITYTRAILS_API_KEY`, `VIRUSTOTAL_API_KEY`, `URLSCAN_API_KEY`, `ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY`, `OTX_API_KEY` | Optional per deployment; rotate any that were ever live in git. |
| Infra secrets (self-hosted) | `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `REDIS_URL`, `CELERY_BROKER_URL`, `MINIO_ACCESS_KEY`, `MINIO_SECRET_KEY`, `DATABASE_URL`, `JWT_SECRET`, `ADMIN_API_KEY`, `ARGUS_API_KEYS`, `ARGUS_GATEWAY_API_KEY`, `METRICS_TOKEN` | Treat as compromised if real values leaked; reissue and update secret stores / `.env` (never commit). |
| Edge / tunnel | `CLOUDFLARE_TUNNEL_TOKEN` | Revoke tunnel token in Cloudflare Zero Trust if exposed. |
| MCP | `MCP_AUTH_TOKEN` | Rotate if HTTP/SSE MCP was deployed with a leaked token. |

**Console entry points (verify URLs in vendor docs if they change):**

- OpenRouter — `https://openrouter.ai/keys`
- Kimi (Moonshot) — `https://platform.moonshot.cn/console/api-keys`
- Perplexity — `https://www.perplexity.ai/settings/api`
- OpenAI — `https://platform.openai.com/api-keys`
- DeepSeek — `https://platform.deepseek.com/api_keys`
- Google AI / Gemini — Google AI Studio / Cloud console per your setup
- Shodan — `https://account.shodan.io/`
- GitHub — Fine-grained or classic PAT management under GitHub Settings
- Censys, VirusTotal, urlscan.io, AbuseIPDB, GreyNoise, OTX — respective account API key pages

### 1.2 Invalidate old tokens

After issuing new credentials:

1. In each provider UI, **delete or revoke** the previous key/token (not only disable in your app).
2. Update **CI/CD secrets**, **Kubernetes SealedSecrets / external secrets**, and **team `.env` files** from a password manager or vault — not from chat.
3. Confirm no service still references the old value (grep in **private** runbooks only; never paste secrets into the repo).

### 1.3 Verify staging and production

For **each** environment (staging, then production), after deploy:

1. **Health:** backend `/health`, `/ready`, and any configured `/metrics` (with `METRICS_TOKEN` if used) respond as expected.
2. **Auth:** API key / JWT paths still work with **new** secrets only (smoke: one authenticated request).
3. **LLM / intel:** if enabled, run a minimal allowed operation (e.g. one low-cost inference or one passive intel call) to confirm new API keys.
4. **Workers:** Celery/Redis connectivity with rotated `REDIS_*` passwords.
5. **Object storage:** MinIO/S3 operations (report export, artifact upload) with new keys.

If staging and prod share a provider account, rotation still applies once; re-validate both endpoints and URLs.

Store new values only in a local `.env`, secret manager, or CI secrets — **never** in tracked example files with real material.

---

## 2. Purge secrets from git history (`git filter-repo` / BFG)

Removing strings from the current commit does **not** remove them from prior commits. This section is **procedural only** — it does **not** assert that history was rewritten.

### 2.1 Backup and legal / coordination

1. **Backup:** Take a full bare mirror or filesystem backup of the repository **before** any rewrite. Rewrites are destructive for all clones.
2. **Policy:** Confirm with **legal / security / management** whether rewriting public or private history is allowed in your jurisdiction and contracts (e.g. customer agreements, retention).
3. **Team:** Schedule the operation; **every** contributor must re-clone or hard-reset to the new default branch tip after a force-push. Old commit hashes must be treated as invalid.

### 2.2 Tools

- **`git filter-repo`** (recommended) — follow the official documentation for path/revision filtering.
- **BFG Repo-Cleaner** — alternative for large repositories; follow upstream usage.

**Do not** paste real secrets into shell history, scripts checked into git, or this document. **Do not** copy-paste example commands that embed literal key material: construct filters using **paths** (e.g. the path to `infra/.env.example`) and generic placeholders only, per the tool’s docs.

### 2.3 After a rewrite

1. Force-push updated protected branches per your git host’s rules.
2. Invalidate **CI cache**, **forks**, and **mirrors**; open a security advisory if the repo was public.
3. Optional housekeeping: expire **GitHub/GitLab OAuth tokens** or deploy keys if exposure scope is unclear.

**In-repo tracking:** Do not set any `gitHistoryPurged: true` (or equivalent) flag unless your process has verifiable evidence the rewrite completed.

---

## 3. Prevent recurrence (pre-commit / CI)

### 3.1 Local and pre-commit

- [Gitleaks](https://github.com/gitleaks/gitleaks) — secret scanning on commits and CI.
- [detect-secrets](https://github.com/Yelp/detect-secrets) — baseline-based hooks (optional complement).

Install and wire per team standards (`.pre-commit-config.yaml` if the repo adopts it).

### 3.2 Platform / CI

- Enable **GitHub secret scanning** (and partner alerts) or the equivalent on your forge.
- Align with org **SCA** policy (e.g. Mend, Dependabot) for dependency risk; secret scanning is complementary.

### 3.3 In-repo regression test

- `backend/tests/security/test_env_example_no_high_entropy_secrets.py` — blocks high-entropy provider-like patterns in `infra/.env.example`.

---

## 4. Cross-links

- Batch 1 closeout (summary pointer): [`ai_docs/develop/reports/2026-04-21-argus-batch1-orchestration-closeout.md`](../reports/2026-04-21-argus-batch1-orchestration-closeout.md) — section “CRITICAL — SEC-001”.
- Cycle 6 carry-over index: [`ai_docs/develop/issues/ISS-cycle6-carry-over.md`](ISS-cycle6-carry-over.md) — operational pointer.
- Historical workspace note: `.cursor/workspace/active/orch-argus-20260420-1430/notes/T06-followups.md` (SEC-001 context).

## 5. In-repo remediation tracking

- Do **not** paste live key material into issues, commits, or logs.
- **Rotation and history purge are human-only**; this checklist documents *what* to do, not automated completion.
