# Docker socket hardening (F-H01)

**Finding:** `docker.sock` is bind-mounted into `backend`, `worker-scans`, and
`worker-general` so the sandbox tool runner can `docker exec` into the
`argus-sandbox` container. Mounting the socket — even `:ro` — grants those
processes the **full Docker Engine API**, which is equivalent to host root. A
compromised worker (e.g. via a malicious scan target that achieves code
execution inside a tool) can reach the daemon and escape to the host.

**CWE:** CWE-250 (Execution with Unnecessary Privileges).

This document explains why `:ro` is not a control, what the shipped hardening
overlay does and does not buy, and the stronger options that actually eliminate
the escape.

---

## 1. Why `:ro` on the socket is not a mitigation

`- /var/run/docker.sock:/var/run/docker.sock:ro` makes the **socket file**
read-only (you cannot `chmod`/`rm` it). It does nothing to the API served over
that socket. Every state-changing daemon call — `POST /containers/create`,
`POST /containers/{id}/start`, `POST /build`, `POST /images/create` — is still
accepted. The canonical escape is one API call:

```
docker -H unix:///var/run/docker.sock run -v /:/host --privileged alpine \
  chroot /host sh -c '<arbitrary host command>'
```

So the base stack's `:ro` mount and the previous documentation that treated it
as a security boundary were both misleading. The mount is host-level privilege.

---

## 2. Current runtime facts (what ARGUS actually calls)

ARGUS reaches the daemon **two** ways, not one: (a) the `docker` CLI via
`subprocess.run(..., shell=False)` and (b) the Python SDK via
`docker.from_env()`. The earlier claim that it "only" uses the CLI was wrong —
the SDK path (`docker.from_env()`) also honours `DOCKER_HOST`, but it is a
separate, easily-missed surface. Both are enumerated below (grep-verified
2026-09-29; re-grep before editing — the tree moves).

### 2a. `docker` CLI call sites (subprocess, argv, shell=False)

| Call site | Docker verbs | Purpose |
|-----------|--------------|---------|
| `backend/src/recon/sandbox_tool_runner.py` | `docker exec`, `which` | **Primary chokepoint**: run pentest tools in `argus-sandbox` |
| `backend/src/orchestration/exploitation_executor.py` | `docker exec` | Exploitation tools — **28** hardcoded `"argus-sandbox"` literals, exec ~L1054 (bypasses the chokepoint) |
| `backend/src/recon/vulnerability_analysis/active_scan/mcp_runner.py` | `docker exec` | Builds argv via the chokepoint, then runs its own `Popen` (~L351-365) to cap output volume |
| `backend/src/sandbox/playwright_adapter.py` | `docker exec` | Browser-driven checks (L131 default, L160, L405) |
| `backend/src/api/routers/sandbox.py` | `docker exec` | Sandbox admin/debug endpoints (L100, L234) |
| `backend/src/quick/cancellation.py` | `docker` (kill/cleanup) | Quick-mode cancellation (L139) |
| `backend/src/tools/wordlists/credential_bruteforce.py` | `docker exec` | Wordlist-driven brute force (L23, L76) |
| `backend/src/sandbox/validation/environment/container.py` | `docker run -d --rm`, `docker rm -f`, `docker commit`, `docker exec` | Ephemeral container for patch verification (L49, 94, 117, 148, 174) |
| `backend/src/sandbox/docker_adapter.py` | `docker exec` | Adapter-level exec (L441) |
| `backend/src/lab/runner.py` | `docker exec` | Isolated LAB runner (L31 guard `_PRODUCTION_SANDBOX_FORBIDDEN`) |

### 2b. Python SDK call sites (`docker.from_env()` — separate surface)

| Call site | Usage |
|-----------|-------|
| `backend/src/sandbox/docker_sandbox_adapter.py` | `docker.from_env()` client, built lazily (L112) |
| `backend/src/orchestration/ephemeral_worker.py` | `docker.from_env()` for ephemeral worker lifecycle (L188/236/276) |
| `backend/src/orchestration/exploit_verification_microvm.py` | `docker.from_env()` + `container.exec_run(...)` for exploit verification (L141) — also the shell-injection primitive, fact #4 |

The CLI and the SDK both honour `DOCKER_HOST`, so redirecting these services to
a TCP proxy requires **no code change** — but there is **no single chokepoint**
today, which is exactly why Stage 3 introduces `docker_gateway.py`.

Kubernetes deployments use `backend/src/sandbox/k8s_adapter.py` instead and need
**no socket mount at all** — prefer that in clusters.

---

## 3. Shipped overlay: `infra/docker-compose.hardened.yml`

```bash
docker compose -f infra/docker-compose.yml -f infra/docker-compose.hardened.yml up -d
```

Requires Docker Compose **v2.24.0+** (uses the `!override` merge tag to drop the
inherited socket bind mount).

What it changes:

1. Adds a `tecnativa/docker-socket-proxy` (`docker-socket-proxy`) that is the
   **only** component touching the real socket. It runs `no-new-privileges`,
   non-privileged, on an `internal: true` network (`docker-proxy`) with **no**
   published ports.
2. Removes the raw socket bind mount from `backend`, `worker-scans`,
   `worker-general` (`volumes: !override []`).
3. Points those services at the proxy with `DOCKER_HOST=tcp://docker-socket-proxy:2375`.

Allowlist (everything else defaults to denied):

| Var | Value | Why |
|-----|-------|-----|
| `POST` | 1 | Master switch; without it the API is read-only and `docker exec` fails |
| `CONTAINERS` | 1 | `/containers/*` — inspect, logs, stats, **exec-create**, create, rm |
| `EXEC` | 1 | `/exec/*` — exec start/resize (the `docker exec` stream) |
| `COMMIT` | 1 | `/commit` for patch-verification snapshots — set `0` if you do not use patch verification |
| `VERSION`, `PING` | 1 | docker CLI handshake |
| `IMAGES`, `BUILD`, `VOLUMES`, `NETWORKS`, `SWARM`, `SERVICES`, `TASKS`, `NODES`, `SECRETS`, `CONFIGS`, `PLUGINS`, `SYSTEM`, `EVENTS`, `AUTH`, `DISTRIBUTION`, `SESSION`, `INFO` | 0 | Denied |

### What this buys (defence-in-depth)

Relative to a raw socket, a compromised worker can **no longer**:

- Pull, build, save, load, or import images.
- Create/delete/mount volumes or manipulate networks.
- Touch Swarm, services, tasks, nodes, secrets, configs, or plugins.
- Make direct daemon `system`/`events`/`auth` calls or enumerate the host via `info`.
- Reach the daemon from anywhere except the internal `docker-proxy` network.

### Residual risk — READ THIS

`docker exec` requires `POST` + `CONTAINERS`, and that **same** combination
permits `POST /containers/create` + `/start`. The Tecnativa proxy filters by
endpoint *group*, not by method+path within a group, so it **cannot** allow
"exec into an existing container" while denying "create a new container". A
worker compromise can therefore still run:

```
docker run -v /:/host --privileged ... # create+start: still permitted
```

**Conclusion:** the overlay meaningfully shrinks the attack surface but does
**not** eliminate the container-escape primitive. Treat it as one layer, not the
fix. To actually block create, use §4 or §5.

---

## 4. Stricter variant — block container-create (breaks patch verification)

If you do **not** rely on the patch-verification sandbox (`container.py`), you
can front the daemon with a path-filtering reverse proxy that allowlists *only*:

- `POST /v*/containers/{id}/exec`
- `POST /v*/exec/{id}/start` and `/resize`
- `GET /v*/containers/{id}/json` (+ `/logs`, `/stats`)
- `GET /v*/version`, `GET /v*/_ping`

…and returns `403` for `POST /containers/create`, `/start`, `/build`, etc. This
removes the create-escape for the exec-only hot path.

Caveats:
- Docker's exec stream uses HTTP connection hijack/upgrade; the proxy must pass
  `Upgrade`/`Connection` through and disable buffering. Validate the exec stream
  end-to-end before relying on it.
- Enabling this **disables** patch verification (it needs `run`/`rm`/`commit`).
  Either turn patch verification off, or give it a separate, tightly-scoped
  broker credential.

Because this needs live validation of the hijacked exec stream, it is **not**
shipped as a default overlay — stand it up and verify in staging first.

---

## 5. True fixes (eliminate the escape)

In rough order of strength / effort:

1. **Kubernetes adapter** (`k8s_adapter.py`) — no socket mount at all; tools run
   as Jobs/Pods with their own RBAC and PodSecurity. Preferred for clusters.
2. **Rootless Docker / Podman** for the sandbox daemon — a socket compromise
   yields an unprivileged user on the host, not root.
3. **Sysbox runtime** — run the sandbox with `runtime: sysbox-runc` so nested
   containers are genuinely isolated; even `--privileged` inside cannot reach
   the host.
4. **gVisor (`runsc`)** — user-space kernel that contains syscall-level escapes
   from tools running inside the sandbox.
5. **Purpose-built exec broker** — a tiny authenticated service that accepts
   "run tool X with argv Y in argus-sandbox" and performs the `docker exec`
   itself, exposing zero raw Docker API. Highest assurance, most work.

### 5a. Sandbox container hardening & segmentation (Stage 2, validated Stage 8)

Applied to `sandbox`, `kali-runner` (base compose) and `lab-runner`
(`docker-compose.lab-runner.yml`):

- `user: "1000:1000"`, `cap_drop: [ALL]`, `cap_add: [NET_RAW]`,
  `deploy.resources.limits.pids: 512`. `NET_RAW` is required for `nmap -sS/-sU`
  and `masscan`; `NET_ADMIN` is **not** added — **validated**: `-sS`/`-sU` work
  with `NET_RAW` alone.

- **`no-new-privileges` is intentionally OMITTED (validated trade-off).** Live
  testing established that raw-socket tools run as the non-root `argus` user only
  via **file capabilities**, and that `no_new_privs` *disables* file-capability
  elevation on `execve`. Since ARGUS runs tools via `docker exec` as uid 1000
  (subject to the container's `no_new_privs`), the two are mutually exclusive.
  Chosen resolution: keep non-root + file caps, drop `no-new-privileges`.
  Residual risk is bounded — `cap_drop: ALL` leaves the capability **bounding
  set empty except `NET_RAW`**, so a setuid binary could reach uid 0 but gains
  **no** capabilities; combined with the non-root default, network segmentation,
  pids cap and no host mounts, this is the accepted cost of functional SYN/UDP
  scanning. (`docker-socket-proxy` and `argus-exec-broker` keep
  `no-new-privileges` — they run no raw-socket tools.)

- **File capabilities target the real ELF, not the wrapper.** Kali ships
  `/usr/bin/nmap` as a *shell script* that execs `/usr/lib/nmap/nmap --privileged`;
  the kernel ignores file caps on scripts. `Dockerfile.sandbox` installs
  `libcap2-bin` and `setcap cap_net_raw+eip` **only on ELF binaries** (magic
  `7f454c46`), explicitly including `/usr/lib/nmap/nmap`. Only `cap_net_raw` is
  set — a file cap for a capability outside the container bounding set (e.g.
  `cap_net_admin`) makes `execve` fail `EPERM`.

- **Validated live (Stage 8), uid 1000 + `cap_drop ALL` + `NET_RAW`, no
  `no-new-privileges`:**
  - `docker exec … nmap -sS -p80 127.0.0.1` → `80/tcp closed http` ✓
  - `docker exec … nmap -sU -p53 127.0.0.1` → `53/udp closed domain` ✓
  - `docker exec … nuclei -version` → `v3.3.7` ✓
  - `getent hosts postgres` / `redis` from inside the sandbox → both fail
    (segmentation holds) ✓
  - Proof that file caps are required: with the file cap present but
    `no-new-privileges:true`, `nmap -sS` fails `Couldn't open a raw socket:
    Operation not permitted`; removing `no-new-privileges` makes it succeed.
  - **NB:** the file caps are baked by the image build — run
    `docker compose build sandbox` after pulling this change so the running
    container carries them.

- **`read_only` rootfs is deferred, NOT skipped.** Confirmed at runtime that
  nuclei writes to `/home/argus/.config/nuclei` — so the standing sandbox needs
  a writable `$HOME`. Enabling `read_only` needs `read_only: true` +
  `tmpfs: [/tmp, /workspace]` + `$HOME` anchoring and a full end-to-end scan
  smoke run. Tracked as a staging-validated follow-up.

**Network segmentation:** `sandbox` and `kali-runner` moved off the `data`
bridge onto a dedicated `sandbox` bridge, so a compromised tool can no longer
reach `postgres`/`redis`/`minio`/`adminer` directly. Exec-capable services
(`backend`, `worker-scans`, `worker-general`, `worker-cairn`) also join
`sandbox`; `docker exec` itself goes via the daemon socket and is unaffected by
networking. `lab-runner` was already isolated on its own `lab` bridge. The
sandbox's `depends_on: minio` is now startup-ordering only — with the sandbox
off `data` it has no route to MinIO and needs none (artifacts are pulled out by
the worker via the shared `sandbox_tmp` volume, never pushed by the sandbox).

---

## 6. Verify

```bash
# 1. Bring up the hardened stack.
docker compose -f infra/docker-compose.yml -f infra/docker-compose.hardened.yml up -d

# 2. The workers no longer bind the raw socket (expect NO output).
docker inspect argus-worker-scans --format '{{json .Mounts}}' | grep -o docker.sock || echo "OK: no socket mount"

# 3. docker exec still works through the proxy (sandbox tool runner path).
docker compose -f infra/docker-compose.yml -f infra/docker-compose.hardened.yml \
  exec worker-scans docker version           # handshake via proxy → succeeds
docker compose -f infra/docker-compose.yml -f infra/docker-compose.hardened.yml \
  exec worker-scans docker exec argus-sandbox which nuclei   # tool exec → succeeds

# 4. Denied endpoints are refused (expect 403 / "not allowed").
docker compose -f infra/docker-compose.yml -f infra/docker-compose.hardened.yml \
  exec worker-scans docker images            # IMAGES=0 → HTTP 403
docker compose -f infra/docker-compose.yml -f infra/docker-compose.hardened.yml \
  exec worker-scans docker network ls        # NETWORKS=0 → HTTP 403

# 5. Run a real scan end-to-end and confirm sandbox tools execute (no
#    tool_not_found / DOCKER_HOST errors in worker logs).
docker compose logs worker-scans | grep -Ei 'docker_host|permission|denied|not allowed' || echo "OK"
```

## 7. Rollback

```bash
# Drop the overlay; the base stack restores the (documented-as-privileged)
# socket mount. No data migration involved.
docker compose -f infra/docker-compose.yml up -d
```

---

## 8. Status

Staged hardening (F-H01). Each stage ships independently, in order:

- **Stage 0 — overlay gap + docs (DONE):** `worker-cairn` added to
  `docker-compose.hardened.yml` (was the uncovered 4th socket mount); the
  misleading `:ro`-is-sufficient comments in the base compose rewritten to state
  host-root privilege; `ARGUS_DOCKER_SOCK` documented in `infra/.env.example` and
  `docs/env-vars.md`; §2 call-site table completed (CLI **and** SDK surfaces);
  `docs/security.md` corrected to 4 mount points; `!override []` footgun noted in
  the overlay header.
- **Stage 1 — shell-injection primitive (DONE):** `exploit_verification_microvm.py`
  `exec_run(f"sh -c '{payload}'")` → `exec_run(["sh", "-c", payload])` (both exec
  sites); the untrusted vulnerable-replica `containers.run` gained
  `network_mode="none"`, `cap_drop=[ALL]` + minimal LAMP `cap_add`,
  `no-new-privileges`, `pids_limit`, `mem_limit`, `nano_cpus`. `read_only=True`
  and a forced `user` are deliberately NOT applied — the third-party LAMP replica
  (DVWA/csrftester) needs a writable rootfs and root-initiated apache/mysql, so
  those flags would break its own init (unlike the trusted worker image in
  `ephemeral_worker.py`). Regression test:
  `tests/unit/orchestration/test_exploit_verification_argv_injection.py`.
- **Stage 2 — sandbox container + network segmentation (DONE):** `sandbox`,
  `kali-runner`, `lab-runner` gained `user`, `cap_drop:[ALL]`+`NET_RAW`,
  `no-new-privileges`, `pids:512`; `sandbox`/`kali-runner` moved to a dedicated
  `sandbox` bridge off `data`; exec-capable workers joined `sandbox`. `read_only`
  deferred with a documented reason (§5a). Raw-socket tool validation is a
  staging step (§5a). Verified via `docker compose config`: sandbox shares no
  network with postgres/redis/minio.
- **Stage 3 — single Docker chokepoint `docker_gateway.py` (foundation landed;
  full migration in Stage 7):**
  - New `backend/src/sandbox/docker_gateway.py`: the single module allowed to
    construct a Docker call. List-argv-only (shell string unrepresentable),
    transport-aware (`socket`/`proxy`/`broker`), validates container names,
    audits every call via `redact_argv_for_logging`.
  - `backend/src/core/config.py`: added `docker_transport`
    (`Literal[socket|proxy|broker]`) and `docker_host`; added a `field_validator`
    rejecting container names not matching `^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`
    at startup (covers `sandbox_container_name` + `lab_runner_container_name`).
  - Primary chokepoint `recon/sandbox_tool_runner.py` migrated: `build_sandbox_exec_argv`
    and the `check_tool_available` probe now delegate to the gateway; public API
    preserved (many tests monkeypatch these symbols).
  - AST guard `tests/test_audit_docker_gateway_ast.py`: fails if any module but
    the gateway imports the `docker` SDK or hands a subprocess call an argv whose
    first literal is `"docker"`; also fails on stale exempt entries.
  - **Migration COMPLETE — `_DOCKER_GATEWAY_EXEMPT` is now EMPTY (see Stage 7).**
    All former exempt modules route through the gateway; the AST guard passes with
    zero exemptions.
  - **Related finding — FIXED (see Stage 6):** the validation harnesses ran
    attacker-influenceable reproducer payloads on the host
    (`profiles.py` `CliHarness` via `create_subprocess_shell`, `LibraryHarness`
    via host `python3`). Now routed into the sandbox via the gateway, fail-closed.
- **Stage 4 — purpose-built exec broker (DONE):**
  - New `backend/src/exec_broker/app.py` — a FastAPI service (`argus-exec-broker`)
    that is the only socket holder. Single `POST /v1/exec` accepting
    `{container, argv[], workdir?, timeout, env?}`; `GET /health`. Server-side
    re-validation: container ∈ static allowlist (`argus-sandbox`,
    `argus-kali-runner`, `argus-lab-runner`), `argv` non-empty list of strings,
    `argv[0]` ∈ `ALLOWED_TOOLS`, timeout clamped, stdout/stderr truncated at a
    byte cap. **No create/start/commit/pull/build/volume/network endpoint exists**
    — the escape that survives the Tecnativa proxy is unreachable by construction.
  - The broker runs the exec through the single gateway (socket transport in the
    broker container), so the daemon/CLI handles the hijacked exec stream and
    stdout/stderr demux — the broker never proxies a raw upgraded socket, side-
    stepping the §4 stream-hijack problem.
  - Gateway `docker_transport="broker"` now POSTs to `EXEC_BROKER_URL/v1/exec`.
  - `infra/docker-compose.broker.yml`: `argus-exec-broker` (socket, internal
    `exec-broker` net, no published ports, `no-new-privileges`) + the four
    exec-capable services switched to `volumes: !override []` +
    `DOCKER_TRANSPORT=broker`. Apply EITHER this OR `docker-compose.hardened.yml`
    (never both); hardened.yml remains the weaker fallback.
  - Tests: `tests/unit/sandbox/test_exec_broker.py` (policy + no-create-surface,
    no daemon) and `tests/integration/test_exec_broker_docker.py`
    (`requires_docker`: real exec reaches a container; create/run endpoints 404).
- **Stage 5 — structural regression tests (DONE):** `test_audit4_docker_security.py`
  rewritten from substring-grep to structural checks (registers a YAML
  constructor for the `!override`/`!reset` merge tags so it parses the overlays
  without Docker): (1) every socket-mounting base service is covered by BOTH the
  hardened and broker overlays (the subset test that would have caught
  worker-cairn); (2) no service resolves to uid 0, including via the
  `${ARGUS_WORKER_USER:-...}` default; (3) sandbox/kali-runner/lab-runner declare
  `cap_drop:[ALL]` + `no-new-privileges` + a pids limit; (4) the sandbox shares no
  network with postgres/redis/minio; (5) `exploitation_executor.py` has no
  hardcoded `"argus-sandbox"` literal (its 28 literals migrated to
  `settings.sandbox_container_name`); (6) re-runs the Stage 3 AST gateway guard.
- **Stage 6 — validation-harness host-execution fix (DONE):** the validation
  harnesses no longer execute attacker-influenceable reproducer payloads on the
  host. `CliHarness` (`create_subprocess_shell(payload)`) and `LibraryHarness`
  (temp file + host `python3`) now run the payload inside the argus-sandbox via
  the gateway (`sh -c <command>` / `python3 -c <code>`, payload as one argv
  element so pipe/redirect semantics survive with no argv injection). Both fail
  closed when `SANDBOX_ENABLED` is off rather than falling back to the host shell.
  `BinaryHarness` keeps `file`/`strings` on a path via `create_subprocess_exec`
  (argv, read-only tools — not shell injection). Test:
  `tests/unit/sandbox/test_harness_sandbox_execution.py`.
- **Stage 7 — complete the gateway migration; `_DOCKER_GATEWAY_EXEMPT` = ∅ (DONE):**
  the gateway grew the surface the remaining callers needed —
  `docker_client()` / `docker_sdk_available()` (the single `import docker`),
  `inspect_format()` (docker inspect), `copy_to_container()` (docker cp),
  `exec_in_sync_bytes()` (binary capture for `head -c`), and a `build_exec_argv`
  `interactive` flag (`docker exec -i` for stdin). All seven previously-exempt
  modules migrated: the three SDK users (`ephemeral_worker`,
  `exploit_verification_microvm`, `docker_sandbox_adapter`) now obtain their
  client via `docker_client()` and catch `DockerGatewayError`; the four CLI
  callers (`lab/runner.py`, `api/routers/sandbox.py`, `quick/cancellation.py`,
  `recon/sandbox_artifact_io.py`) route through the gateway helpers. The AST
  guard now runs with an **empty** exempt list — no module but the gateway
  imports the docker SDK or builds a raw `docker` argv. Affected unit tests
  (cancellation, exploit-verification, gateway) updated to patch the gateway.
- **Stage 8 — live-stand validation of the sandbox hardening (DONE):** brought up
  the segmented sandbox and validated the §5a posture on a real daemon. Findings
  that changed the design: (1) raw-socket tools need **file caps on the real ELF**
  (`/usr/lib/nmap/nmap`, not the `/usr/bin/nmap` wrapper script) — added an
  ELF-aware `setcap cap_net_raw+eip` step to `Dockerfile.sandbox`; (2)
  `no-new-privileges` **disables** file-cap elevation on `execve` and is
  incompatible with non-root file-cap raw sockets, so it was **removed** from
  `sandbox`/`kali-runner`/`lab-runner` (kept on the proxy/broker) with a
  documented, bounded trade-off. Validated: `nmap -sS`/`-sU` and `nuclei` work as
  uid 1000; `postgres`/`redis` are unreachable from the sandbox (segmentation).
  Stage 5 test #3 updated to assert the new posture (cap_drop ALL + NET_RAW +
  non-root + pids, and that `no-new-privileges` is absent). `read_only` remains a
  documented staging follow-up (nuclei writes to `$HOME`, confirmed at runtime).
- **Overlay + runbook:** delivered (opt-in; no change to the default stack).
- **Residual:** container-create escape remains while `docker exec` is required
  (see §3). Full remediation is Stage 4 (exec broker) / §5 (k8s adapter /
  rootless / Sysbox / gVisor) for production deployments with untrusted targets.
