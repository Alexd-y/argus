# WSL2 setup runbook for ARGUS developers

**Audience:** ARGUS developers on a Windows host who want a supported, low-friction dev environment.
**First filed:** 2026-04-21 (Cycle 6, T06).
**Pairs with:** [`ai_docs/develop/troubleshooting/mypy-windows-access-violation.md`](troubleshooting/mypy-windows-access-violation.md) — explains *why* WSL2 is the recommended path.

---

## 1. Why WSL2

Native-Windows Python development against the ARGUS backend hits two recurring pain points:

* **`mypy --strict` crashes** with `Windows fatal exception: access violation` (`0xC0000005`) — see the troubleshooting doc above. Linux (including WSL2) is unaffected.
* **Docker Desktop on Windows** is slower for ARGUS workloads than Docker on a native Linux kernel: bind-mounts under `/mnt/c/...` go through 9P and add tens of seconds to every `docker compose up` cycle; `pytest` discovery against a `\\?\C:\` path is materially slower than against `~/work/ARGUS/`.

WSL2 gives you a real Linux kernel, a native ext4 filesystem, and a Docker daemon that talks to that kernel through `vsock` instead of a SMB-style bridge. Everything that ARGUS CI exercises on `ubuntu-latest` runs identically inside WSL2 — so the dev box and CI agree, and "works on my machine" becomes "works on the runner".

> Use a native Linux or macOS host if you have one. WSL2 is the supported path for *Windows-only* developers.

---

## 2. Prerequisites

* **Windows version:** Windows 10 22H2+ or Windows 11 (any build). On Windows 10 ≤ 21H2, upgrade first — WSL2 networking and `wsl --install` were unstable on those builds.
* **Hardware:** ≥ 16 GB RAM (8 GB host + 8 GB headroom for the WSL2 VM + Docker), ≥ 50 GB free on the system drive (the WSL2 ext4 vhdx grows on demand).
* **Virtualization:** Hyper-V / WSL feature enabled in BIOS (`Intel VT-x` / `AMD-V`) and in Windows Features. `wsl --install` enables the OS-side feature automatically; the BIOS toggle is per-OEM and may need a reboot into firmware setup.
* **Docker:** Docker Desktop 4.30+ with the WSL2 backend ON and the Ubuntu-22.04 distro toggled in `Settings → Resources → WSL integration`.
* **Cursor / VS Code:** the `Remote - WSL` extension installed.

> Corporate-managed laptops: Hyper-V is sometimes blocked by the EDR / device-management policy. If `wsl --install` fails with a Hyper-V error, escalate to IT before proceeding — there is no clean workaround.

---

## 3. Step-by-step installation

### 3.1 Install WSL2 + Ubuntu 22.04

In an **elevated** PowerShell (Run as Administrator):

```powershell
wsl --install -d Ubuntu-22.04
wsl --set-default-version 2
wsl --update
```

The first command reboots the machine if the WSL feature is being installed for the first time. After reboot, Ubuntu finishes its first-run wizard automatically and asks you to set a UNIX username + password (these are local to the distro — pick anything; they are not your AD/SSO creds).

Verify:

```powershell
wsl --list --verbose
# expected: NAME=Ubuntu-22.04, STATE=Running, VERSION=2
wsl --status
# expected: Default Distribution: Ubuntu-22.04, Default Version: 2
```

### 3.2 Install the build chain inside WSL

Drop into the distro:

```powershell
wsl -d Ubuntu-22.04
```

Inside the distro (your prompt should be Linux now):

Ubuntu 22.04 ships with Python 3.10 by default. Add the deadsnakes PPA **first** so `python3.12` becomes available — a literal `apt install python3.12 ...` against the stock 22.04 repos fails with `E: Unable to locate package python3.12`.

```bash
sudo apt update
sudo apt upgrade -y
sudo apt install -y software-properties-common
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update
```

Then install the build chain:

```bash
sudo apt install -y python3.12 python3.12-venv python3.12-dev \
    build-essential pkg-config \
    git curl ca-certificates \
    libpq-dev \
    libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 libffi-dev shared-mime-info
```

> The `libcairo2` / `libpango-1.0-0` / `libgdk-pixbuf-2.0-0` group is needed by **WeasyPrint** (PDF backend) at runtime. `libpq-dev` is needed by `psycopg2-binary` (dev-only Postgres driver used by `tests/integration/migrations/test_alembic_smoke.py`). The other packages are standard build chain.

Verify:

```bash
python3.12 --version
# expected: Python 3.12.x  (matches backend/pyproject.toml requires-python = ">=3.12")
```

---

## 4. Clone the repo inside the Linux filesystem

**Clone into the Linux ext4 filesystem at `~/work/ARGUS`. Do NOT clone under `/mnt/d/...` or `/mnt/c/...`.**

```bash
mkdir -p ~/work
cd ~/work
git clone <your-fork-or-origin-url> ARGUS
cd ARGUS
```

### Why this matters

* **File IO performance.** WSL2 reaches `/mnt/<drive>` over a 9P-over-Hyper-V bridge. Every `os.stat()` and every `open()` pays a few-millisecond round-trip; pytest collection over the ARGUS backend tree (~12 000 tests) goes from ~10 s on ext4 to **2-5 minutes** on `/mnt/d/`. Docker bind-mounts compound this.
* **Filesystem semantics.** `/mnt/<drive>` honours Windows-side ACLs, case-insensitivity (depending on per-folder flag), and reserved filenames (`con`, `nul`, etc.). The repo contains files whose case-only differences and Linux-style permissions break under those rules. Symlinks created inside the repo from Linux tooling (`pip install -e .`, npm install, etc.) become useless under `/mnt/`.
* **`.git` race conditions.** `git` on `/mnt/` occasionally trips on Windows file-locking (especially with antivirus scanning the worktree), producing `index.lock`-related failures that never happen on ext4.

If you absolutely must access the worktree from Windows tools, use the network share `\\wsl$\Ubuntu-22.04\home\<user>\work\ARGUS\` — but only for read-only browsing. All builds, tests, and writes should happen from the Linux side.

---

## 5. Bring up the dev stack

ARGUS uses two compose files for local dev: the production-shape `infra/docker-compose.yml` and the dev-overrides `infra/docker-compose.dev.yml` that exposes service ports back to the host (Postgres, Redis, MinIO).

```bash
cd ~/work/ARGUS
cp infra/.env.example infra/.env
# edit infra/.env — at minimum set POSTGRES_PASSWORD, MINIO_SECRET_KEY, JWT_SECRET
# override POSTGRES_PASSWORD, MINIO_SECRET_KEY, JWT_SECRET for any non-throwaway dev box;
# the example defaults work for a one-off local sanity check but are obviously insecure.

docker compose -f infra/docker-compose.yml -f infra/docker-compose.dev.yml up -d
docker compose -f infra/docker-compose.yml ps
```

Wait until `postgres`, `redis`, `minio` show `healthy` status. The first `up` builds the backend image (1-2 minutes warm cache, 5-10 minutes cold) and pulls the pinned images; subsequent ups take ~10 s.

> `docker` is the Docker Desktop CLI exposed into WSL2. If `docker ps` returns "Cannot connect to the Docker daemon", open Docker Desktop → Settings → Resources → WSL Integration → enable for `Ubuntu-22.04`, then `wsl --shutdown` and re-open the distro.

---

## 6. Python venv + dependencies

```bash
cd ~/work/ARGUS/backend
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip wheel
pip install -r requirements.txt -r requirements-dev.txt
```

> `backend/requirements-dev.txt` is intentionally minimal (`pytest`, `pytest-asyncio`, `ruff`, `black`, `bandit`, `safety`). The broader dev surface (`pypdf`, `jinja2-latex`, `aiosqlite`, `psycopg2-binary`, `jsonschema`) is declared in `pyproject.toml` under `[project.optional-dependencies].dev`; install it via:
>
> ```bash
> pip install -e '.[dev]'
> ```
>
> **`mypy` is not in any of the above** — neither `requirements-dev.txt` nor the `[dev]` extras list it. The DoD §19 `mypy_capstone` gate in `scripts/argus_validate.py` calls `python -m mypy`, so install mypy explicitly when you intend to run the gate:
>
> ```bash
> pip install mypy
> ```

---

## 7. Run the test suite + mypy

```bash
cd ~/work/ARGUS/backend
source .venv/bin/activate

pytest -q
# expected: ~11 900+ PASS / ~165 SKIP / 0 FAIL  (no Postgres/Redis/Docker required for the default sweep)

python -m mypy --strict src/
# expected: "Success: no issues found in N source files" — exit 0
# this is the line that crashes on native Windows; under WSL2 it is boringly green.

cd ..
python scripts/argus_validate.py --only-gate mypy_capstone
# expected: gate.status = passed, exit 0
```

Run the full DoD §19 sweep when you want to mirror what CI checks:

```bash
python scripts/argus_validate.py
# 10 gates; the required ones (ruff_capstone, catalog_drift, coverage_matrix) MUST pass;
# advisory ones (mypy_capstone, frontend_lint, helm_lint, ...) skip cleanly when their
# binary is not on $PATH (e.g. helm, docker before Docker Desktop is up).
```

---

## 8. VS Code / Cursor integration

1. Make sure the `Remote - WSL` extension is installed in your editor.
2. From the Windows-side editor, open the command palette → **`WSL: Reopen Folder in WSL`** → select `Ubuntu-22.04` → navigate to `~/work/ARGUS`.
3. The editor restarts as a *remote-WSL* client; the Cursor agent, the language servers (Pyright / Pylance / ruff / TS server), and every terminal you open run **inside the distro**, against the Linux filesystem.
4. The first time you open the project, install the recommended extensions when prompted — they are installed into the *WSL* extension host, not the Windows host. This includes Python, Pylance, Ruff, ESLint, Tailwind, Prisma (whichever the project recommends).

> The Cursor / VS Code window itself runs on Windows, but everything compute-heavy (LSP, terminal, debugger, test runner, file watchers) runs in WSL2 against ext4. This is what gives you the "feels like Linux" performance with the Windows UI you are already used to.

---

## 9. Performance notes

* **Stay inside the Linux filesystem.** Anything under `~` is ext4 + native VHD; anything under `/mnt/` is 9P over Hyper-V. The performance gap is one to two orders of magnitude on metadata-heavy workloads (pytest collection, npm install, git status on a worktree with 50 k+ files).
* **Cap the WSL2 VM resources.** Without limits, WSL2 will happily eat all RAM. Drop a `~/.wslconfig` on the Windows side (`C:\Users\<you>\.wslconfig`) — it applies to all distros:

  ```ini
  [wsl2]
  memory=12GB
  processors=6
  swap=4GB
  localhostForwarding=true
  ```

  After editing, `wsl --shutdown` from PowerShell, then reopen the distro. Tune to your laptop.

* **Reach WSL2 from Windows tools.** When you need a Windows-side tool (browser, Postman, screen-recorder) to reach a service running in WSL2:

  * Services bound to `0.0.0.0` inside WSL2 are reachable on `localhost:<port>` from Windows out of the box (`localhostForwarding=true` above).
  * The ext4 worktree is reachable from Windows Explorer at `\\wsl$\Ubuntu-22.04\home\<user>\work\ARGUS\` — read-only browsing is fine; do not edit files from the Windows side.

* **Disable Defender on the WSL2 VM disk.** `%LOCALAPPDATA%\Packages\CanonicalGroupLimited.Ubuntu22.04LTS_*\LocalState\ext4.vhdx` is the WSL2 disk image. Add it to Defender's exclusion list — otherwise every read/write inside the distro is double-scanned (Linux and Windows side), which crushes IO throughput.

  ```powershell
  Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\Packages\CanonicalGroupLimited.Ubuntu22.04LTS_79rhkp1fndgsc\LocalState\ext4.vhdx"
  ```

  (Adjust the package name to match your installed Ubuntu — list with `Get-AppxPackage *Ubuntu*`.)

---

## 10. Common pitfalls

| Pitfall | Symptom | Fix |
|---------|---------|-----|
| Defender real-time scan over `\\wsl$\` | I/O inside the distro is 5-10× slower than expected; `pip install` takes minutes. | Add the WSL2 `ext4.vhdx` to Defender's exclusion list (see §9). |
| Corporate VPN MTU breaks `apt-get update` | `apt-get update` hangs at "Reading package lists" or fails with "Could not resolve archive.ubuntu.com". | Lower the MTU on the WSL2 NIC: `sudo ip link set eth0 mtu 1350` (matches a typical IPSec VPN ceiling); persist via `/etc/wsl.conf` `[boot] command = ip link set eth0 mtu 1350`. Test with `ping -M do -s 1300 archive.ubuntu.com`. |
| Docker Desktop "WSL Integration" toggle missing | `docker ps` inside WSL2 returns "command not found" or "Cannot connect to the Docker daemon". | Docker Desktop → Settings → Resources → WSL Integration → toggle ON for `Ubuntu-22.04`. Then `wsl --shutdown` from PowerShell and reopen the distro. |
| Clone landed under `/mnt/d/...` | `pytest` discovery is glacial; `git status` is slow; mypy / npm misbehave. | `mv /mnt/d/.../ARGUS ~/work/ARGUS` *via* `cp -a` + delete, or simply re-clone fresh into `~/work/ARGUS`. Never bind-mount ARGUS from `/mnt/`. |
| Line-ending drift (`CRLF` ↔ `LF`) | Pre-commit hooks reject files; CI fails on unexpected `\r`. | Inside the distro, set `git config --global core.autocrlf input`. Commit `.gitattributes` is already present in this repo and pins LF — so as long as you `git clone` from inside WSL2, you are safe. |
| WSL2 clock drift after suspend/resume | TLS to PyPI / GHCR fails with "certificate not yet valid". | `sudo hwclock -s` once, or install `systemd-timesyncd` and enable systemd in WSL2 (`/etc/wsl.conf` `[boot] systemd = true`). |
| Out-of-memory on `pip install` | `pip` is killed mid-install with no clear error. | Cap RAM via `~/.wslconfig` (see §9) and increase if you have headroom; default WSL2 takes up to 50 % of host RAM but Windows can still OOM-kill it. |
| Docker Desktop on a managed laptop refuses to enable WSL2 backend | Docker Desktop hangs on startup or shows "WSL2 is not supported on this build". | Confirm Hyper-V is allowed by your IT policy (`Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V` should be `Enabled`). If blocked, escalate — there is no end-user workaround. |

---

## 11. Quick-reference cheat sheet

```bash
# Inside WSL2, from ~/work/ARGUS:

# Bring stack up
docker compose -f infra/docker-compose.yml -f infra/docker-compose.dev.yml up -d

# Run the dev sweep
cd backend && source .venv/bin/activate
pytest -q                                       # no-Docker default sweep
python -m mypy --strict src/                    # the gate that crashes on native Windows
python -m ruff check src tests                  # lint
python -m bandit -r src -ll                     # SAST

# DoD §19 meta-runner (mirror CI)
cd .. && python scripts/argus_validate.py

# Tear down
docker compose -f infra/docker-compose.yml -f infra/docker-compose.dev.yml down
```

---

## 12. References

* [`ai_docs/develop/troubleshooting/mypy-windows-access-violation.md`](troubleshooting/mypy-windows-access-violation.md) — the mypy crash that motivated this runbook.
* `infra/docker-compose.yml` + `infra/docker-compose.dev.yml` — the dev stack composition.
* `backend/pyproject.toml` — single source of truth for backend Python deps; `requires-python = ">=3.12"`; dev extras under `[project.optional-dependencies].dev`.
* `backend/requirements-dev.txt` — minimal dev tools (`pytest`, `ruff`, `black`, `bandit`, `safety`). Install `[dev]` extras for the full set.
* `scripts/argus_validate.py` — DoD §19 meta-runner; the `mypy_capstone` gate is `required=False` for Windows-host parity.
* `docs/e2e-testing.md` — e2e capstone runbook; mentions WSL as a supported launch platform under §3 "Локальный запуск".
