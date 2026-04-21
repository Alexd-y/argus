# Troubleshooting — `mypy` Windows access-violation (`0xC0000005`)

**Audience:** ARGUS backend developers running on a Windows host.
**First filed:** 2026-04-21 (Cycle 6, T06).
**Closes:** carry-over item 1 in [`ai_docs/develop/issues/ISS-cycle6-carry-over.md`](../issues/ISS-cycle6-carry-over.md) §"Known limitations carry-over" (informally tagged ARG-058).
**See also:** [`ai_docs/develop/wsl2-setup.md`](../wsl2-setup.md) — recommended fix is to switch the Windows dev box to WSL2.

---

## TL;DR

* `python -m mypy --strict src/` (or `--strict tests/test_tool_catalog_coverage.py scripts/docs_tool_catalog.py`) sometimes crashes with **`Windows fatal exception: access violation`**, exit code **`0xC0000005`** (`STATUS_ACCESS_VIOLATION`), in the middle of type-checking. The traceback usually pins `typeshed/stdlib/zipimport.pyi:17`.
* This is a Windows-only, `mypy`-side native-extension bug. **The ARGUS code is fine** — Linux CI runs the same files cleanly.
* CI is unaffected: `scripts/argus_validate.py` Gate `mypy_capstone` is already `required=False` for exactly this reason.
* **Fix:** move the dev box to **WSL2**. Pure-Windows workarounds exist (clear cache, `--no-incremental`, Defender exclusion, enable long-path support) but only mask the symptom.

---

## Symptom

A typical crash looks like this (verbatim, taken from a Cycle 5 dev session — ARG-041 worker report and ARG-049 capstone notes):

```text
PS D:\Developer\Pentest_test\ARGUS\backend> python -m mypy --strict src\
Windows fatal exception: access violation

Current thread 0x00001f44 (most recent call first):
  File "C:\Python312\Lib\zipimport.py", line ...
  File "<frozen importlib._bootstrap>", line ...
  ...
  File "...\site-packages\mypy\stubs\typeshed\stdlib\zipimport.pyi", line 17
INTERNAL ERROR: mypy crashed
Process finished with exit code -1073741819 (0xC0000005)
```

Concrete properties of the crash, observed across multiple sessions:

* **Intermittent.** The same command, re-run minutes later, sometimes succeeds.
* **Triggered by the incremental cache.** Deleting `.mypy_cache/` or passing `--no-incremental` reliably makes the crash go away for one run.
* **Single-file invocation usually survives.** Splitting `mypy src/foo.py src/bar.py` into two sequential single-file invocations almost always passes.
* **`stdout`-redirected runs survive more often than TTY runs.** ARG-043 documented `python -m mypy ... > out.txt 2>&1` as a partial workaround (the analysis itself completes; the crash hits during interpreter shutdown after the report is already on disk).
* **CI never reproduces it.** `ubuntu-latest` runs the same `mypy --strict` invocations to completion every single time.

---

## Affected versions

Pinned from the repo state at the time of this filing (Cycle 5 close, 2026-04-21):

| Component                | Version / range observed crashing |
|--------------------------|-----------------------------------|
| Python                   | **3.12.x** (3.12.10 confirmed; project requires `>=3.12` per `backend/pyproject.toml`). |
| `mypy` (PyPI)            | **`1.10` … `1.20.x`** (1.20.1 explicitly logged in ARG-041 worker report). The project does not pin a `mypy` version — `pip install mypy` resolves the latest. |
| Windows                  | Windows 10 22H2 and Windows 11 (any build). |
| ARGUS commit-range       | Cycle 4 close (2026-04-20) onward. The crash was first formally documented in ARG-041 / ARG-043 worker reports and is now baked into `scripts/argus_validate.py` Gate `mypy_capstone` (`required=False`) since ARG-049. |

> ⚠️ Linux runs of the same `mypy` + Python combination are clean, so the bug is in `mypy`'s native code path on Windows, not in ARGUS or in a generic Python 3.12 issue.

---

## Root cause — best-current-understanding

`mypy` is shipped from PyPI as a **`mypyc`-compiled** native extension (since 0.940). On Windows, the typed-AST incremental cache (`.mypy_cache/3.12/...`) is read back through the compiled fast-path, and several upstream Windows-specific bugs (open as of mypy 1.13/1.14) interact poorly with the incremental cache and the typeshed `zipimport.pyi` lookup. The repeated `zipimport.pyi:17` location in our stack traces is a strong fingerprint for this class.

The exact memory fault is *not* deterministic from the project side. The three plausible candidates, ranked by how well they match the evidence in the repo, are:

### Hypothesis 1 — `mypyc`-compiled mypy + corrupt incremental-cache entry  *(most likely)*

The native fast-reader for `.mypy_cache/3.12/**/*.{data,meta}.json` mishandles a record written by a slightly different mypy build, and de-references freed memory while reading the typed-AST node. Matches:

* `--no-incremental` makes the crash disappear (forces the in-process slow-path).
* Deleting `.mypy_cache/` makes the crash disappear *for one run*, then it can come back.
* Single-file invocations survive (smaller cache surface, smaller race window).

**Diagnostic command:**

```powershell
Remove-Item -Recurse -Force backend\.mypy_cache
cd backend
python -m mypy --no-incremental --strict src\
```

If the crash is gone with `--no-incremental` and reproducible without, this hypothesis is confirmed.

### Hypothesis 2 — Windows Defender / antivirus racing with mypy's atomic write

mypy writes cache entries through a temp-file → rename pattern. If Defender real-time-scans the temp file between create and rename, mypy can read back a partially-flushed `.json`. Matches:

* Intermittent on otherwise idempotent commands.
* More frequent on systems with corporate/EDR endpoint protection (`Defender ATP`, `CrowdStrike`, `SentinelOne`).

**Diagnostic command** (run in elevated PowerShell):

```powershell
Add-MpPreference -ExclusionPath "D:\Developer\Pentest_test\ARGUS\backend\.mypy_cache"
Add-MpPreference -ExclusionPath "D:\Developer\Pentest_test\ARGUS\backend\src"
```

If the crash rate drops materially after exclusion, this hypothesis is at least a contributing factor.

### Hypothesis 3 — Win32 long-path support disabled + deep `.mypy_cache/` paths

The ARGUS codebase generates cache paths like
`backend\.mypy_cache\3.12\src\sandbox\parsers\openapi_scanner_parser.data.json`,
which can exceed the legacy 260-character `MAX_PATH` once expanded with the dev's working-directory prefix. On Windows builds with long-path support **disabled** (the default for Windows 10 / 11 unless explicitly enabled), some Win32 file APIs return ambiguous error codes that the mypy native reader does not handle and segfaults.

**Diagnostic command** (run in elevated PowerShell, then reboot):

```powershell
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
                 -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
```

If the crash disappears after enabling long-path support and rebooting, this hypothesis is at least a contributing factor.

> Less plausible candidates we ruled out: `typed-ast` native extension misbehaviour (`mypy` no longer uses `typed-ast` on 3.12+; it uses the stdlib `ast` plus its own typed AST), `fastparse` + Cython import order (does not match the `zipimport.pyi:17` stack frame), and a project-side Pydantic / SQLAlchemy plugin clash (no plugins are configured in `backend/pyproject.toml`).

---

## Fix / workaround

### Primary fix — move the dev box to WSL2

This is the supported developer environment for Windows hosts. Full step-by-step in [`ai_docs/develop/wsl2-setup.md`](../wsl2-setup.md). Once you are inside an Ubuntu 22.04 WSL2 distro with the repo cloned at `~/work/ARGUS` (Linux filesystem — **not** under `/mnt/d/...`), `python -m mypy --strict src/` is as boringly green as the Linux CI runner.

### Pure-Windows secondary workarounds (TODAY, no env change)

Apply in this order; each step is independently useful and can be combined.

1. **Clear the cache and re-run with `--no-incremental`.** Cures the crash for one run; rebuild the cache slowly afterwards on smaller batches.

   ```powershell
   Remove-Item -Recurse -Force backend\.mypy_cache
   cd backend
   python -m mypy --no-incremental --strict src\
   ```

2. **Exclude the mypy cache and `src/` tree from Windows Defender real-time scanning.** Requires an elevated PowerShell. Reverts on the next Defender policy push if you are on a managed laptop — re-apply as needed.

   Note: ARGUS bundles security-tool integrations and exploit payload fixtures — keep AV exclusions as narrow as possible. Start with `backend\.mypy_cache` + `backend\src`; only widen the scope if mypy still crashes.

   ```powershell
   # Narrow exclusions — start with the cache + src; only widen if mypy still crashes.
   # ARGUS bundles security-tool integrations and exploit payload fixtures —
   # keep AV exclusions as narrow as possible.
   Add-MpPreference -ExclusionPath "D:\Developer\Pentest_test\ARGUS\backend\.mypy_cache"
   Add-MpPreference -ExclusionPath "D:\Developer\Pentest_test\ARGUS\backend\src"
   ```

3. **Enable Win32 long-path support.** One-time, requires reboot. Useful well beyond mypy (npm, git on long pnpm trees, Helm chart `templates/`).

   ```powershell
   New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
                    -Name "LongPathsEnabled" -Value 1 -PropertyType DWORD -Force
   ```

4. **Run mypy file-by-file (last-resort scripted loop).** Slow, but every individual invocation survives. Useful when you need a strict pass to debug a specific PR before pushing.

   ```powershell
   Get-ChildItem backend\src -Recurse -Filter *.py |
       ForEach-Object { python -m mypy --strict --follow-imports=silent $_.FullName }
   ```

5. **Redirect stdout to a file.** Documented in ARG-043 — the analysis completes and writes its report; the crash sometimes only hits on shutdown, after the report is already on disk.

   ```powershell
   python -m mypy --strict src\ > mypy.log 2>&1
   Get-Content mypy.log -Tail 50
   ```

> If none of (1)–(5) work and you cannot move to WSL2, run mypy in CI only and rely on the per-file pass + ruff + pytest on the local Windows box. CI is the source of truth for full-strict typing — see "CI impact" below.

---

## Why we cannot easily fix this upstream

* The crash is in `mypy`'s **native (`mypyc`-compiled) code path**, not in our codebase. We cannot patch it without forking and re-compiling mypy.
* Upstream `python/mypy` has several open issues in this class with non-trivial repro steps (Windows + `mypyc` + incremental cache + native AST reader). Reproducing reliably requires a developer-time investment that does not match the value (CI Linux is the source of truth and never crashes).
* The recommended upstream remediation is "use WSL2 or run with `--no-incremental` on Windows", which is exactly what this document codifies.
* Filing a clean upstream report is still tracked as a Cycle 7 candidate (low priority — see closing note in `ISS-cycle6-carry-over.md`). A minimal repro that fits in a public bug tracker is a non-trivial extraction from this codebase.

For reference, the relevant upstream issue tracker is `https://github.com/python/mypy/issues` (search for `Windows`, `access violation`, `0xC0000005`, `STATUS_ACCESS_VIOLATION`, `zipimport.pyi`). Several open tickets at the time of writing match the fingerprint; none has a confirmed fix landed in the 1.10..1.20.x range we are using.

---

## Verification

You have proved the issue is fixed when, on the affected dev box:

```powershell
# inside WSL2 — the supported path
cd ~/work/ARGUS/backend
source .venv/bin/activate
python -m mypy --strict src/
# expected: "Success: no issues found in N source files" — exit 0, no crash
```

```powershell
# pure-Windows fallback — should also exit 0 after the workarounds above
cd D:\Developer\Pentest_test\ARGUS\backend
python -m mypy --strict --no-incremental tests\test_tool_catalog_coverage.py scripts\docs_tool_catalog.py
# expected: "Success: no issues found in 2 source files" — exit 0, no crash
```

The capstone gate, when you can run it cleanly:

```powershell
cd D:\Developer\Pentest_test\ARGUS
python scripts\argus_validate.py --only-gate mypy_capstone
# expected: gate.status = passed, exit 0
```

A single clean run is not sufficient evidence on its own (the crash is intermittent). A green run **three consecutive times** with a warm cache, against `src/` in full, is the criterion we use before declaring a workaround stable on a given machine.

---

## CI impact

**None.** All ARGUS CI runners are Linux (`ubuntu-latest` — see `.github/workflows/ci.yml`). The lint/test/security workflows there have never observed this crash. mypy itself does not currently run in CI; the `mypy_capstone` gate lives only in the local meta-runner `scripts/argus_validate.py`, where it is already marked `required=False` precisely so that this Windows-only flake cannot block a CI cycle close.

This document changes only developer-experience behaviour. No mypy / pyproject / CI configuration files are touched as part of T06.

---

## References

* `scripts/argus_validate.py` — Gate `mypy_capstone`, `required=False` declaration with inline rationale.
* `ai_docs/develop/issues/ISS-cycle6-carry-over.md` — §"Known limitations carry-over" item 1 (closed by this document).
* `ai_docs/develop/reports/2026-04-21-arg-041-observability-report.md` — first formal write-up of the crash with verbatim trace.
* `ai_docs/develop/reports/2026-04-20-argus-finalization-cycle5.md` — §"Testing & quality" lessons-learned entry.
* `ai_docs/develop/wsl2-setup.md` — full WSL2 onboarding runbook (primary fix).
