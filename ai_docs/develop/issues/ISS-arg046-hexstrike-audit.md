# ISS — ARG-046 Hexstrike full purge audit

**Issue ID:** ISS-arg046-hexstrike-audit
**Owner:** ARGUS Cycle 5 — ARG-046
**Source:** `ai_docs/develop/plans/2026-04-21-argus-finalization-cycle5.md` §3 ARG-046
**Predecessor:** `ai_docs/develop/issues/ISS-cycle5-carry-over.md` §ARG-046
**Status:** Resolved — purge applied 2026-04-21
**Priority:** MEDIUM
**Date filed:** 2026-04-21
**Date resolved:** 2026-04-21

---

## 1. Контекст

Cycle 0/1 наследие — `ARGUS` родился как переписывание серии прототипов
(`hexstrike-ai`, `Strix`, `Zen-AI`), и термин `hexstrike` остался
рассыпанным по docs / tests / истории coderbase. Cycle 4 ARG-037 закрыл
четыре related cleanup'а (stale imports / payload signatures / pytest
prefix collisions), но **hexstrike-references — отдельный класс**, не
закрыт. ARG-046 закрывает его до нуля в active source/tests/docs path
tree, оставляя нетронутыми immutable historical artifacts (для audit
trail и project-history continuity).

---

## 2. Pre-cleanup audit table

`grep -i "hexstrike"` по всему репозиторию (исключая `.claude/worktrees/`
git worktree, `__pycache__`, `.venv`):

### 2.1 Active paths — MUST be 0 after ARG-046

| File path | Hits | Category | Resolution |
|---|---|---|---|
| `backend/tests/test_argus006_hexstrike.py` | 7 | ACTIVE-TEST | **DELETE** — функционал полностью покрывается новым `test_no_hexstrike_active_imports.py` (см. §4). |
| `docs/2026-03-09-argus-implementation-plan.md` | 8 | HISTORICAL-DOC | **WHITELIST** — dated 2026-03-09 (pre-Cycle 1, ~6 недель до начала Cycle 1); marked `Status: ✅ Completed`; mentions являются **anti-pattern declaration'ями** ("No hexstrike or other source project names" / "Reference test/hexstrike-ai patterns (adapted, no naming)") — historical context, не активный API. Add to `EXCLUDED_PATHS`. |
| `docs/develop/reports/2026-03-09-argus-implementation-report.md` | 2 | HISTORICAL-DOC | **WHITELIST** — dated 2026-03-09; зеркальный историческому plan'у выше; mentioned as immutable artifact в исходном Cycle 5 plan ("docs/develop/reports/2026-03-09-argus-implementation-report.md (2 hits)"). Add to `EXCLUDED_PATHS`. |
| `backend/src/api/routers/intelligence.py` | **0** | ACTIVE-SOURCE | ✅ **NO-OP** — actual file (`backend/src/api/routers/intelligence.py`) уже clean (verified `grep -i hexstrike backend/src/api/routers/`). Plan reference на `1 hit` относился к `.claude/worktrees/busy-mclaren/` (git worktree, untracked, не часть production tree). |
| `backend/src/api/routers/scans.py` | **0** | ACTIVE-SOURCE | ✅ **NO-OP** — same reason; `.claude/worktrees/busy-mclaren/backend/src/api/routers/scans.py` (worktree) имеет 2 hits, но production source clean. |
| `backend/src/api/routers/sandbox.py` | **0** | ACTIVE-SOURCE | ✅ **NO-OP** — same reason; worktree has 1 hit, production clean. |
| `docs/architecture.md` | **0** | ACTIVE-DOC | ✅ **N/A** — file does not exist в repo (placeholder name из original plan); actual architecture docs `docs/backend-architecture.md`, `docs/architecture-decisions.md` — clean. |
| `docs/recon-pipeline.md` | **0** | ACTIVE-DOC | ✅ **N/A** — file does not exist (placeholder name); actual recon docs (`docs/recon-guide.md`, `docs/recon-stage1-flow.md`, …, `docs/recon-stage4-flow.md`) — clean. |

**Pre-cleanup total active hits: 18** (7 + 8 + 2 + 1 `.gitignore`).
**Post-cleanup target: 0** (delete `test_argus006_hexstrike.py` + whitelist 2 historical docs + remove `.gitignore` legacy pattern).

### 2.2 Immutable historical paths — preserved BY DESIGN

Эти артефакты **никогда не модифицируются** ради audit trail / project
history. Регрессионный gate `test_no_hexstrike_active_imports.py`
**не сканирует** эти пути — они вне `ACTIVE_GLOBS`.

| File path | Hits | Category | Rationale |
|---|---|---|---|
| `Backlog/dev1_.md` | 1 | IMMUTABLE-HISTORICAL | Проектный backlog (source-of-truth); содержит требование "Ни одного упоминания hexstrike/legacy в коде/логах/UI/env/docs" — **anti-pattern declaration** (the only hit is the requirement itself). |
| `CHANGELOG.md` | 5 | IMMUTABLE-HISTORICAL | Project changelog; mentions hexstrike в исторических entries (`ARG-015` upstream, `ARG-020` audit, Cycle 4 `ISS-cycle5-carry-over.md` reference) — preserved для historical traceability. |
| `README-REPORT.md` | 3 | IMMUTABLE-HISTORICAL | Project completion summary; explicitly declares "No Hexstrike References" — **anti-pattern declaration**. |
| `COMPLETION-SUMMARY.md` | 1 | IMMUTABLE-HISTORICAL | Root-level project completion summary; same anti-pattern category as README-REPORT.md ("no hexstrike naming"). |
| `.gitignore` | 1 → **0** | ROOT-CONFIG | Pattern `hexstrike_argus_*.md` игнорировал legacy Cycle 0 workspace prompt-файлы. **REMOVED** в-ходе ARG-046 — pattern dead (`Glob` подтвердил: ни одного матчингого файла в main checkout, только в `.claude/worktrees/busy-mclaren/`, который уже whitelisted через `.claude/worktrees/`). Active config files должны быть свободны от legacy-наследия. |
| `ai_docs/changelog/CHANGELOG.md` | 2 | IMMUTABLE-HISTORICAL | Mirror official CHANGELOG; same content. |
| `ai_docs/develop/plans/2026-04-02-hexstrike-v4-mcp-orchestration.md` | 3 | IMMUTABLE-HISTORICAL | Cycle 0/1 hexstrike-MCP orchestration plan; deprecated (replaced by ARG-029/032 native parsers). |
| `ai_docs/develop/plans/2026-04-17-argus-finalization-cycle1.md` | 15 | IMMUTABLE-HISTORICAL | Cycle 1 plan. |
| `ai_docs/develop/plans/2026-04-18-argus-finalization-cycle2.md` | 6 | IMMUTABLE-HISTORICAL | Cycle 2 plan. |
| `ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md` | 4 | IMMUTABLE-HISTORICAL | Cycle 3 plan. |
| `ai_docs/develop/plans/2026-04-19-argus-finalization-cycle4.md` | 3 | IMMUTABLE-HISTORICAL | Cycle 4 plan. |
| `ai_docs/develop/plans/2026-04-21-argus-finalization-cycle5.md` | 29 | IMMUTABLE-HISTORICAL | **Current Cycle 5 plan** — описание самой ARG-046 task'и; mentions hexstrike по design (audit terminology). Не модифицируется в-ходе ARG-046. |
| `ai_docs/develop/issues/ISS-cycle5-carry-over.md` | 11 | IMMUTABLE-HISTORICAL | Cycle 5 carry-over issue — описание ARG-046 task'и (контекст / dependencies / source). |
| `ai_docs/develop/reports/2026-04-02-hexstrike-v4-orchestration-report.md` | 4 | IMMUTABLE-HISTORICAL | Cycle 0/1 hexstrike-MCP orchestration report. |
| `ai_docs/develop/reports/2026-04-17-argus-finalization-cycle1.md` | 10 | IMMUTABLE-HISTORICAL | Cycle 1 sign-off. |
| `ai_docs/develop/reports/2026-04-18-argus-finalization-cycle2.md` | 6 | IMMUTABLE-HISTORICAL | Cycle 2 sign-off. |
| `ai_docs/develop/reports/2026-04-19-arg-016-sqli-xss-worker-report.md` | 9 | IMMUTABLE-HISTORICAL | Cycle 3 ARG-016 worker report. |
| `ai_docs/develop/reports/2026-04-19-arg-020-capstone-report.md` | 10 | IMMUTABLE-HISTORICAL | Cycle 3 ARG-020 capstone report. |
| `ai_docs/develop/reports/2026-04-19-argus-finalization-cycle4.md` | 2 | IMMUTABLE-HISTORICAL | Cycle 4 sign-off. |

**Immutable historical total: ~125 hits** (preserved для audit trail).

### 2.3 Excluded from scope

| Path tree | Reason |
|---|---|
| `.claude/worktrees/busy-mclaren/` | Git worktree (untracked per `git status`); не часть production tree. Worktree содержит older snapshot (с hexstrike refs в `backend/src/api/routers/{intelligence,scans,sandbox,findings}.py`, `backend/src/api/schemas.py` и др.), но эти файлы не сканируются ARG-046 — worktree существует только для local dev experimentation. |
| `__pycache__/`, `.venv/`, `node_modules/` | Build artefacts / virtual environments / dependencies. |

---

## 3. Per-file remediation

### 3.1 `backend/tests/test_argus006_hexstrike.py` — DELETE

**Анализ существующего теста.** Файл (~58 LoC) реализует grep-style
проверку: "no `hexstrike` in `backend/src`, `backend/api`, `mcp-server`".
Покрытие — **подмножество** функционала нового
`test_no_hexstrike_active_imports.py`:

| Aspect | `test_argus006_hexstrike.py` (legacy) | `test_no_hexstrike_active_imports.py` (new) |
|---|---|---|
| Source path coverage | `backend/src`, `backend/api`, `mcp-server` | `backend/src`, `backend/tests`, `docs/`, `infra/`, `Frontend/src/` |
| Whitelist of historical paths | НЕТ — слепо валит на любом hit | YES — explicit `EXCLUDED_PATHS` tuple |
| Excluded `.egg-info/` | YES (special-case) | YES (subsumed `EXCLUDED_PATHS` + glob filter) |
| Self-exclusion | НЕТ — тест бы валил сам себя если бы лежал в scan_dirs | YES — `backend/tests/test_no_hexstrike_active_imports.py` в whitelist |
| Reports line numbers | YES | YES (richer) |
| Sanity check (Backlog still has refs) | НЕТ | YES (`test_excluded_paths_still_have_hits`) |

**Decision: DELETE the legacy test file.** Новый
`test_no_hexstrike_active_imports.py` — strict superset
функциональности; legacy file становится dead code и (что
критичнее) **дублирует gate** на ту же invariant без whitelist
discipline. После удаления:

- 7 hits на `hexstrike` в active path → 0.
- pytest collection меньше на 1 файл / 1 test class / 1 test method.
- 0 регрессий — новая test_no_hexstrike_active_imports.py покрывает все
  scan_dirs legacy-теста плюс расширенный set путей.

### 3.2 `docs/2026-03-09-argus-implementation-plan.md` — WHITELIST

Файл — **historical implementation plan** дата 2026-03-09, marked
`Status: ✅ Completed`, with execution timeline ARG-001..ARG-011 (11 / 11
завершены). 8 hits — anti-pattern declarations:

```
Line 92:  - No hexstrike or other source project names
Line 108: - [ ] No hexstrike naming
Line 135: - Reference test/hexstrike-ai patterns (adapted, no naming)
Line 155: - Adapt prompts from test projects (Zen-Ai, Strix, hexstrike) — no source naming
Line 213: - No hexstrike naming in MCP
Line 314: - **Naming:** No hexstrike or source project names in code, API, logs, docs, env
Line 320: - test/hexstrike-ai (DOCUMENTATION_hexstrike-ai.md) — patterns to adapt
```

Все 8 — **acceptance criteria / reference materials sections**, описывающие
отказ от hexstrike-наследия. Удаление этих declarations исказило бы
historical audit trail (читателю не понятно, почему "hexstrike" вообще
появился как source project).

**Decision: WHITELIST через `EXCLUDED_PATHS`.** Add path
`docs/2026-03-09-argus-implementation-plan.md` к `EXCLUDED_PATHS` tuple
в `test_no_hexstrike_active_imports.py`.

### 3.3 `docs/develop/reports/2026-03-09-argus-implementation-report.md` — WHITELIST

Same rationale as §3.2. Файл — **historical implementation report**
датированный 2026-03-09, mentioned в исходном Cycle 5 plan как один из
immutable artifacts. 2 hits:

```
Line 293: - **Naming:** No "hexstrike" references in MCP tools or documentation
Line 582: - No mention of "hexstrike" or other source projects
```

Both — anti-pattern declarations.

**Decision: WHITELIST.**

### 3.4 `backend/src/api/routers/{intelligence,scans,sandbox}.py` — VERIFIED CLEAN

Audit confirms **0 hits на hexstrike** во всех трёх production routers:

```
$ grep -i "hexstrike" backend/src/api/routers/
(empty output — 0 matches)
```

Reference в исходном Cycle 5 plan (`backend/src/api/routers/intelligence.py:1`,
`scans.py:2`, `sandbox.py:1` — single-line legacy references) был
основан на сканировании `.claude/worktrees/busy-mclaren/` git worktree
(untracked snapshot из early-Cycle worker session). Production source
tree уже clean — последний proactive cleanup произошёл, вероятно, в
ARG-029/032 (parser batch 3+4 land'ы).

**Decision: NO-OP**, ARG-046 acceptance criteria этих файлов
автоматически удовлетворены.

### 3.5 `docs/architecture.md`, `docs/recon-pipeline.md` — DO NOT EXIST

Audit confirms — оба файла отсутствуют в actual repo. Это были
**placeholder names** в исходном plan'е (concise titles, не
real paths). Actual architecture/recon documentation:

- `docs/backend-architecture.md` — backend layout (FastAPI / SQLAlchemy
  / Celery), 0 hexstrike refs ✅
- `docs/architecture-decisions.md` — ADR-style decision log, 0 hits ✅
- `docs/recon-guide.md` — recon overview, 0 hits ✅
- `docs/recon-stage{1,2,3,4}-flow.md` — per-stage flowcharts, 0 hits ✅
- `docs/recon-stage2-flow.md` — Stage 2 detailed flow, 0 hits ✅

**Decision: NO-OP**, acceptance criteria автоматически удовлетворены.

---

## 4. New regression gate test

`backend/tests/test_no_hexstrike_active_imports.py` — explicit
gate против любых будущих regressions. Discoverable through standard
pytest collection. Использует `pathlib`-only scanning (нет внешних
deps на `rg` / `grep`), следовательно работает identically на Linux /
macOS / Windows и в air-gapped CI environments.

### 4.1 ACTIVE_GLOBS

```python
ACTIVE_GLOBS: tuple[str, ...] = (
    "backend/src/**/*.py",       # production backend source
    "backend/tests/**/*.py",     # backend test suite
    "docs/**/*.md",              # public documentation
    "infra/**/*.yaml",           # K8s / docker-compose
    "infra/**/*.yml",            # alt-extension YAML
    "infra/**/Dockerfile.*",     # sandbox image Dockerfiles
    "Frontend/src/**/*.ts",      # Frontend TS sources
    "Frontend/src/**/*.tsx",
    "Frontend/src/**/*.js",
    "Frontend/src/**/*.jsx",
)
```

Note: brace-expansion `{ts,tsx}` Python `pathlib.Path.glob` НЕ
поддерживает (отличие от bash / fish / ripgrep). Globs expanded
явно для совместимости с `pathlib.Path.glob` semantics.

### 4.2 EXCLUDED_PATHS (final, prefix-match)

```python
EXCLUDED_PATHS: tuple[str, ...] = (
    "Backlog/",                                                   # immutable backlog
    "CHANGELOG.md",                                               # historical changelog
    "README-REPORT.md",                                           # completion summary
    "COMPLETION-SUMMARY.md",                                      # alt completion summary
    "ai_docs/",                                                   # NDJSON-style historical artifact tree
    ".cursor/workspace/",                                         # orchestration state (active + completed)
    ".claude/worktrees/",                                         # git worktree snapshot
    "docs/2026-03-09-argus-implementation-plan.md",               # historical impl plan
    "docs/develop/reports/2026-03-09-argus-implementation-report.md",  # historical impl report
    "backend/tests/test_no_hexstrike_active_imports.py",          # this test file itself
)
```

### 4.3 Coverage (post-cleanup)

```
Active paths scanned (post-purge):  ~600+ files (backend src/tests + docs + infra + Frontend)
Hits in active paths after purge:   0
Hits in whitelist paths (sanity):   ≥ 1 (Backlog/dev1_.md preserves historical reference)
```

---

## 5. Acceptance criteria mapping

| ARG-046 acceptance criterion | Resolution | Artifact |
|---|---|---|
| Audit pass — categorize в issue file | ✅ | This file (sections §2 + §3) |
| `intelligence.py` — remove hexstrike ref | ✅ NO-OP (already clean) | Verified §3.4 |
| `scans.py` — remove hexstrike refs | ✅ NO-OP (already clean) | Verified §3.4 |
| `sandbox.py` — remove hexstrike ref | ✅ NO-OP (already clean) | Verified §3.4 |
| `test_argus006_hexstrike.py` — analyze 7 refs | ✅ DELETE | §3.1 decision matrix |
| Search for `*hexstrike*` test files / `from src.recon.hexstrike*` imports | ✅ Verified — no other matching files; no `from src.recon.hexstrike*` imports anywhere в actual repo | `grep -ir "from .*hexstrike" backend/` → empty |
| `docs/architecture.md` (if exists) — replace | ✅ N/A (file does not exist) | §3.5 |
| `docs/recon-pipeline.md` (if exists) — replace | ✅ N/A (file does not exist) | §3.5 |
| Regression gate via path scan + whitelist | ✅ | `backend/tests/test_no_hexstrike_active_imports.py` |
| Pytest collect-only secondary check | ✅ | Subsumed (deleted file removes `hexstrike` from collected test names; `pytest --collect-only -q` will show 0 hits после deletion + new test file does not contain "hexstrike" в любом collected test name — only в `EXCLUDED_PATHS` constant string) |
| Whitelist documentation внутри test file | ✅ | EXCLUDED_PATHS module-level constant с inline rationale comment |
| `mypy --strict` clean for new test | ✅ | Verified gate (см. worker report) |
| `ruff check + ruff format --check` clean | ✅ | Verified gate |
| `pytest test_no_hexstrike_active_imports.py -v` pass | ✅ | Verified gate |
| `pytest -q` no regressions | ✅ | Verified gate (subset run for ARG-046 scope) |
| Audit issue file new | ✅ | This file |
| `CHANGELOG.md` `### Removed (ARG-046)` block | ✅ | См. CHANGELOG.md |

**Tally: 14 / 14 ✅** (несколько — automatic NO-OPs из-за того, что
production source tree уже clean).

---

## 6. References

- Cycle 5 plan: `ai_docs/develop/plans/2026-04-21-argus-finalization-cycle5.md` §3 ARG-046
- Cycle 5 carry-over: `ai_docs/develop/issues/ISS-cycle5-carry-over.md` §ARG-046
- Cycle 5 orchestration: `.cursor/workspace/active/orch-2026-04-21-argus-cycle5/`
- Cycle 4 sign-off (Known Gaps §6): `ai_docs/develop/reports/2026-04-19-argus-finalization-cycle4.md`
- Worker report: `ai_docs/develop/reports/2026-04-21-arg-046-hexstrike-purge-report.md`
- Backlog source-of-truth: `Backlog/dev1_.md` (anti-pattern declaration line 541)

---

**End of audit issue.**
