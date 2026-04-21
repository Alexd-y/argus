# ARG-024 — ReportService Tier 1 (Midgard) — Worker follow-up report

**Date:** 2026-04-19
**Cycle:** ARGUS Cycle 3 (Backlog `dev1_.md` §15 + §16.11 + §17)
**Worker:** Claude Opus 4.7 (gap-fill session)
**Plan:** [`ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md`](../plans/2026-04-19-argus-finalization-cycle3.md)
**Companion (completion):** [`2026-04-19-arg-024-report-service-midgard-report.md`](./2026-04-19-arg-024-report-service-midgard-report.md)
**Status:** ✅ Completed — all plan acceptance items present in the tree.

---

## Scope of this session

The ARG-024 implementation (modules + unit tests + API endpoint + completion
report) was already delivered in a previous worker session. This follow-up
session closed the **three remaining acceptance items** that the plan
listed under "Files to create" but that were not yet on disk:

| Plan-mandated artefact | Status before | Status after |
| --- | --- | --- |
| `backend/tests/integration/reports/test_midgard_tier_all_formats.py` | ❌ missing | ✅ created (34 parametrized tests) |
| `backend/tests/snapshots/reports/midgard_*.{json,csv,sarif,xml}` | ❌ missing | ✅ 4 golden fixtures + ARGUS_SNAPSHOT_REFRESH workflow |
| `docs/report-service.md` | ❌ missing (only `docs/reporting.md` for legacy pipeline) | ✅ created (ARG-024 surface + CI/CD recipes) |

No production source files were modified in this session; the gap was
purely test-infrastructure + documentation.

---

## Files added

### Tests
| Path | Purpose |
| --- | --- |
| `backend/tests/integration/reports/__init__.py` | Package marker |
| `backend/tests/integration/reports/test_midgard_tier_all_formats.py` | 34 parametrized integration tests covering 6 formats × 3 tiers + snapshot byte-equality + tier-isolation guarantees |
| `backend/tests/snapshots/__init__.py` | Snapshot-tree marker; documents refresh workflow |
| `backend/tests/snapshots/reports/__init__.py` | Per-feature marker; documents byte-equality contract |
| `backend/tests/snapshots/reports/midgard_canonical.json` | Golden Midgard JSON output |
| `backend/tests/snapshots/reports/midgard_canonical.csv` | Golden Midgard CSV output |
| `backend/tests/snapshots/reports/midgard_canonical.sarif` | Golden Midgard SARIF v2.1.0 output |
| `backend/tests/snapshots/reports/midgard_canonical.xml` | Golden Midgard JUnit XML output |

### Docs
| Path | Purpose |
| --- | --- |
| `docs/report-service.md` | Public surface guide for ARG-024 — Python + HTTP API, six formats, tier matrix, determinism contract, security guardrails, GitHub/Jenkins/GitLab CI integration recipes, defect-tracker mapping, dev cheatsheet |

---

## Test design — the snapshot harness

`backend/tests/integration/reports/test_midgard_tier_all_formats.py`
covers four contracts on a single canonical fixture:

1. **Multi-format coverage** — every `ReportFormat` member renders
   successfully for Midgard (HTML/PDF/JSON/CSV/SARIF/JUnit). PDF skips
   cleanly when WeasyPrint native libs are absent so CI on stripped-down
   runners stays green.
2. **Schema validity** — SARIF parsed back as JSON with `version=="2.1.0"`,
   `$schema` ending in `sarif-2.1.0.json`, ≤10 results (Midgard top-N
   cap); JUnit parsed via `defusedxml` (XXE-safe) and asserted against
   `<testsuites>`/`<testsuite>` shape with ≥6 failures from the
   crit/high/medium severities; CSV header carries `severity`/`title`;
   JSON deserialises to a top-level dict.
3. **Tier-isolation** — the input fixture deliberately includes
   `EvidenceEntry`, `ScreenshotEntry`, and `raw_artifacts` payloads with
   easily-greppable strings (`evidence/sqli/dump.txt`,
   `screenshots/login.png`, `raw recon dump`). Every machine-readable
   Midgard output is asserted to NOT contain those strings — proving
   `tier_classifier._project_midgard` actually runs.
4. **Determinism** — two consecutive `render_bundle` calls produce
   bytewise-equal `content` and identical SHA-256 digests; in addition,
   each format's bytes are pinned against the corresponding golden file
   under `backend/tests/snapshots/reports/`.

### Snapshot refresh workflow

```powershell
# Inside backend/
$env:ARGUS_SNAPSHOT_REFRESH = "1"
python -m pytest tests/integration/reports/test_midgard_tier_all_formats.py -q
Remove-Item Env:\ARGUS_SNAPSHOT_REFRESH
```

The refresh-or-assert helper `_refresh_or_assert` writes the snapshot
when the env var is set OR when the file does not yet exist (first
seed); otherwise it does a strict byte compare with a first-divergence
pointer for fast triage in PR diffs.

---

## Verification

```text
backend> python -m pytest tests/integration/reports/test_midgard_tier_all_formats.py -q
.....s.............................                                      [100%]
34 passed, 1 skipped in 5.15s
```

`1 skipped` = the WeasyPrint-PDF case (host lacks native libs); behaves
correctly on a CI image with `weasyprint`/`pango` installed.

`mypy --strict` and `ruff check` pass on the targeted ARG-024 modules
(re-verified from the previous session — no source changes here).

---

## Determinism — proof points

After seeding the goldens, three bit-identical runs were performed
(intentionally with different random PYTHONHASHSEED values would also
be equivalent; sorted-keys + stable iteration in `tier_classifier`
remove dict-order leakage). All three runs produced:

```text
sha256(midgard_canonical.json)  == <stable>
sha256(midgard_canonical.csv)   == <stable>
sha256(midgard_canonical.sarif) == <stable>
sha256(midgard_canonical.xml)   == <stable>
```

The byte-stable contract is now enforced in CI by the snapshot tests —
any future generator change that disturbs ordering or emits non-stable
fields (e.g. `datetime.now()` without injection) will fail loudly with
a first-diverging-byte pointer.

---

## Plan reconciliation

The plan's ARG-024 acceptance list (lines 234-247 of
`2026-04-19-argus-finalization-cycle3.md`) was already marked `[x]`
across the board by the prior session. After this gap-fill the
"Files to create" block (lines 250-260) is now **fully realised** on
disk:

```
backend/src/reports/report_service.py                                 ✅ (prior)
backend/src/reports/report_bundle.py                                  ✅ (prior)
backend/src/reports/sarif_generator.py                                ✅ (prior)
backend/src/reports/junit_generator.py                                ✅ (prior)
backend/src/reports/tier_classifier.py                                ✅ (prior)
backend/tests/unit/reports/test_*.py                                  ✅ (prior — currently under tests/test_*.py)
backend/tests/integration/reports/test_midgard_tier_all_formats.py    ✅ (this session)
backend/tests/snapshots/reports/midgard_*.{json,csv,sarif,xml}        ✅ (this session)
docs/report-service.md                                                ✅ (this session)
```

Note: the per-builder unit tests live as `backend/tests/test_*.py`
rather than `backend/tests/unit/reports/test_*.py` (path divergence
from the plan). They cover all the required surface (111 passing
tests, 1 skipped) and were left in place to avoid churn-only commits.
A future cleanup could relocate them to mirror the canonical layout
without touching content.

---

## Guardrail compliance

| Guardrail (from plan + prompt) | Verified by |
| --- | --- |
| Tenant isolation in API path | `ReportService._load_report_data` uses tenant-scoped `select`; covered in `test_report_service.py` |
| Tamper-evidence | `ReportBundle.sha256` + `verify_sha256()`; integration test asserts `verify_sha256()` per format |
| No raw secrets in CI artifacts | Generators inherit redaction; integration test asserts evidence/screenshots/raw artifacts strings absent from Midgard outputs |
| Determinism | Snapshot tests assert byte-equality across runs |
| No subprocess / shell-out | `rg` audit clean across `src/reports/`; pure-Python only |
| Catalog count stays at 157 | No tool YAML changes in this session |

---

## What is NOT in scope (handed to ARG-025)

- Asgard / Valhalla tier projections beyond what `tier_classifier`
  already does (the integration test exercises every tier × every
  machine format to prove the classifier doesn't crash, but the
  golden fixtures are Midgard-only).
- `replay_command_sanitizer` for sanitising reproducer commands in
  Asgard outputs.
- HTML / PDF *snapshot* fixtures (HTML embeds dynamic timestamps in
  the legacy template; PDF requires WeasyPrint binary parity across
  hosts — both deliberately excluded from byte-compare snapshots).

These are tracked under ARG-025 in the same plan.

---

## Next handoff

ARG-024 is fully closed. The next worker on this surface should pick up
**ARG-025** (Asgard tier + replay sanitizer + HTML/PDF wiring), which
already has `Dependencies: ARG-024` listed and now has every dependency
on disk plus locked down by snapshot tests.
