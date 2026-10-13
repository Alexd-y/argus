# ARGUS Security Guide

## Authentication

All API endpoints (except `/health` and `/metrics`) require authentication via:
- **JWT Bearer token** — for interactive users
- **X-API-Key header** — for MCP/service accounts

Tenant isolation enforced via JWT `tenant_id` claim. `X-Tenant-ID` header override
is only permitted for API-key authenticated service accounts.

## SAST — Bandit baseline

Run the scan with the project config so the documented baseline applies:

```bash
cd backend && bandit -c pyproject.toml -r src/   # exit 0 == gate clean
```

The config lives in `backend/pyproject.toml` `[tool.bandit]`. Policy:

- **Dangerous classes are FIXED in code and kept live (never skipped)** so a new
  occurrence re-triggers the gate:
  - `B324` — `hashlib.md5(..., usedforsecurity=False)` for non-crypto binary IDs.
  - `B314` — nmap/XML output parsed via `defusedxml` (XXE-safe), not stdlib `ET.fromstring`.
  - `B306` — generated sandbox scripts use `NamedTemporaryFile`, not `tempfile.mktemp`.
  - `B310` — wordlist fetch validates an `https://` scheme before `urlopen` (inline `# nosec`).
  - `B704` — report Markdown passes through `nh3.clean()` allowlist before `Markup()` (inline `# nosec`).
- **Inherent-to-domain classes are skipped with rationale** (see the commented
  `skips` list): `B501` (scanners must reach targets with invalid/self-signed TLS),
  `B603`/`B607` (the engine orchestrates external tools via list-form argv, broker-gated),
  `B404`/`B405`/`B406` (subprocess / xml imports; XML parsing is defused), `B311`
  (non-crypto randomness), `B101`/`B110`/`B112` (asserts / best-effort try blocks),
  `B108`/`B104` (container tmp paths / bind-all), and `B105`/`B106` (all current hits are
  enum/constant/wordlist NAMES, not credentials — real secrets are covered by gitleaks).

A bare `bandit -r src/` does **not** read the config and will re-report the baseline;
always pass `-c pyproject.toml`.

## MCP Server Security

- Auth: Bearer token via `MCP_AUTH_TOKEN` environment variable
- Binding: `127.0.0.1` when no token set; `0.0.0.0` permitted only with token
- Error responses sanitized — no internal details leaked to clients

## Docker Compose Secrets

- All secrets require explicit env vars (`${VAR:?required}` syntax in compose)
- See `infra/.env.example` for complete list with descriptions
- When `REDIS_PASSWORD` is set, `REDIS_URL` and `CELERY_BROKER_URL` must include it

## CORS

- Nginx: dynamic CORS via `envsubst` template (`ARGUS_CORS_ALLOWED_ORIGINS`)
- Backend: configurable via `CORS_ORIGINS` env var
- Wildcard `*` raises `ValueError` in production mode

## MinIO

- Credentials required (no defaults in production)
- Reports bucket separated from scan artifacts
- Access restricted to backend/worker services only

## Docker Socket Mount

The `backend`, `worker-scans`, `worker-general`, and `worker-cairn` services mount
`/var/run/docker.sock:ro` (4 mount points) to orchestrate the argus-sandbox container for
security tool execution. The `sandbox` service itself does **not** receive the socket.
See `docs/docker-socket-hardening.md` (F-H01) for the full analysis and the hardening overlay.

### Risk
The `:ro` flag applies to the socket *file*, not to the Docker API reachable through it:
`docker exec`, container creation, and image operations all still work over a read-only
mounted socket. Socket access therefore remains equivalent to host-level privilege — a
compromised container can enumerate, control, or create other containers. Treat `:ro` as
defence-in-depth (it blocks tampering with the socket inode), never as a capability limit.

### Mitigations (production)
- Use rootless Docker or Podman
- Run behind a Docker socket proxy (e.g., tecnativa/docker-socket-proxy)
- Use gVisor or Kata Containers for sandbox isolation
- Network-segment the sandbox from production databases
- Monitor Docker API calls with audit logging

### Why Not Remove It?
The socket is required for `docker exec` into argus-sandbox for VA active scan tool execution.
Without it, the vulnerability analysis pipeline cannot run security tools.

## Quick execution mode

`execution_mode=quick` is a third immutable profile next to `production` and `lab_unrestricted`. It is **fail-closed** and **does not inherit LAB**:

- Feature flag `ARGUS_QUICK_MODE_ENABLED` defaults to **false**. Flag off + `execution_mode=quick` → `400 quick_mode_disabled` (no silent fallback to a full scan).
- Tool approval uses `evaluate_tool_approval_policy(..., lab_lease_active=False)` and `production_evaluator`. Unknown mode raises; it must not fall through to `LAB_ALLOW_ALL`.
- Forbidden in Quick: `LAB_ALLOW_ALL`, Nuclei signature-gate skip, unsigned remote templates, `LAB_RESEARCH` RAG, destructive tools, password spray, clusterbomb, post-exploitation.
- `execution_mode=lab_unrestricted` combined with a `quick` payload → `400 conflicting_execution_mode`.
- Out-of-scope targets: zero network requests. Absence of a finding is not evidence that a vulnerability is absent.

See `docs/runbooks/quick-mode.md` and `ai_docs/develop/architecture/2026-08-16-adr-quick-execution-mode.md`.

## Cairn execution model

Cairn is a native port of the Cairn Fact–Intent blackboard search engine
(AGPL-3.0). It is a second, non-deterministic scan engine alongside the linear
8-phase pipeline. It is **off by default** (`CAIRN_ENABLED=false`); enabling it is
a deliberate action.

Security model and how the port differs from upstream:

- **No `--dangerously-*` flags.** Upstream launches CLI agents with
  `--dangerously-skip-permissions` / `--dangerously-bypass-approvals-and-sandbox`
  and a Kali container on `network_mode: host`. None of this is ported. Every tool
  the agent runs passes `CairnToolExecutor`'s fail-closed gate chain: task
  allowlist → `bash` only under `lab_unrestricted` → scope (`ScopeEngine`) →
  `assert_execution_allowed` (LAB lease / boundary) → approval policy for
  aggressive tools → budget → sandbox run → secret redaction → evidence.
- **Hardened sandbox.** `SandboxExecutionBackend` uses the existing
  `DockerLifecycleSandboxAdapter`: read-only rootfs, `cap_drop=ALL`,
  `no-new-privileges`, mem/cpu/pids limits, tmpfs workspace, and a **dedicated
  network — never host**.
- **CLI parity drivers (claude/codex/pi)** and the **local host-process backend**
  are fail-closed: only usable under `execution_mode=lab_unrestricted` AND their
  explicit flags (`CAIRN_CLI_DRIVERS_ENABLED`, `CAIRN_LOCAL_EXECUTION_ENABLED`),
  both default `false`. Local execution runs the agent with the current user's
  privileges without a sandbox — a LAB-only convenience.
- **Multitenancy + RLS.** Every `cairn_*` table carries `tenant_id` with FORCE
  row-level security; no endpoint returns another tenant's data.
- **WRB-only analysis.** All Cairn LLM tasks route to WhiteRabbitNeo with no cloud
  fallback (`LLMTask.CAIRN_*` are absent from `_CLOUD_FALLBACK_TASKS`).
- **Prompt-injection defense.** The graph is populated by external tool output and
  is a prompt-injection vector; all untrusted content is wrapped in
  `<untrusted_input>` before it reaches a model.
- **Config invariant.** `CAIRN_INTENT_TIMEOUT_SEC` / `CAIRN_REASON_TIMEOUT_SEC`
  must exceed `CAIRN_TICK_INTERVAL_SEC` (validated at startup, upstream D-02).

Deliberate deviations from upstream are tracked in `docs/cairn_port_deviations.md`.

## Evidence object integrity (wave 2, R-5.6.4)

Evidence objects in the `argus` / evidence bucket should be protected from
post-write overwrite for the tenant's retention period. Preferred mechanism:
MinIO **object lock** (requires bucket versioning + object-lock enabled at
bucket creation). Where the deployed MinIO/S3 does not support object lock,
prevention is unavailable and ARGUS falls back to **detection**:

- Each stored artifact has a SHA-256 recorded on its `evidence` row and folded
  into the per-scan manifest root hash (`evidence_manifests`), itself linked to
  the append-only, hash-chained `audit_logs`.
- `src.evidence.manifest.detect_overwrite` flags "an object with this key
  already exists and its hash differs" at write time.
- `scripts/verify_evidence_integrity.py` re-downloads every artifact, recomputes
  its SHA-256, re-derives the root hash, and replays the audit chain — exiting
  non-zero on any discrepancy. This is how an auditor confirms an evidence base
  was not edited after release, trusting only the data.

### Storage-growth bounds (wave 2 / 2a)

Capturing per-tool-run and per-producer evidence grows the object store, so each
producer is bounded by design rather than relying on an empirical cap. The
dominant per-scan figure is scan-size- and producer-dependent, but every path is
individually bounded:

- **Raw tool output** is truncated to a byte cap before upload (a truncation
  marker records that it was cut), so a chatty tool cannot write an unbounded
  object.
- **PCAP** is headers-only by default (`snaplen=96`, payload excluded) with a
  file-size cap (`tcpdump -C <MiB> -W 1`) and a wall-clock limit — so a capture
  can neither balloon nor leak payloads (`src/evidence/pcap_capture.py`).
- **HAR / HTTP evidence** stores capped request/response bodies (not full
  streams) and redacts secrets before persisting (`src/evidence/har_export.py`,
  `redaction.py`).
- **Browser video / screenshot** producers are opt-in and gated; absent an
  explicit capture they write nothing.
- **Manifest + audit rows** store only object keys and SHA-256 hashes, never a
  second copy of the artifact, so integrity metadata adds O(#artifacts) small
  rows, not bytes proportional to artifact size.

An empirical per-scan footprint should be measured against a representative scan
with the intended producer set enabled; the bounds above are the ceiling each
run is held under.
