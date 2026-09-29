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
- **Stage 2 — sandbox container + network segmentation (pending).**
- **Stage 3 — single Docker chokepoint `docker_gateway.py` (pending).**
- **Stage 4 — purpose-built exec broker (pending).**
- **Stage 5 — structural regression tests (pending).**
- **Overlay + runbook:** delivered (opt-in; no change to the default stack).
- **Residual:** container-create escape remains while `docker exec` is required
  (see §3). Full remediation is Stage 4 (exec broker) / §5 (k8s adapter /
  rootless / Sysbox / gVisor) for production deployments with untrusted targets.
