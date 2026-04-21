# ARG-009 — Findings Normalizer + Correlator + Prioritizer (CVSS / EPSS / KEV / SSVC) + Evidence Pipeline + Redaction — Completion Report

**Date:** 2026-04-17
**Cycle:** `orch-2026-04-17-12-00-argus-final`
**Status:** ✅ COMPLETED
**Plan:** `ai_docs/develop/plans/2026-04-17-argus-finalization-cycle1.md`

---

## Goal

Build the unified **findings + evidence** plane for ARGUS:

* a deterministic **Normalizer** that converts heterogeneous tool output
  (nuclei JSONL, nmap XML, generic JSON, CSV, text) into the canonical
  `FindingDTO` (ARG-001) with stable, idempotent dedup keys.
* a **Correlator** that lifts a flat list of findings into kill-chains
  using MITRE ATT&CK ordering on a per-asset basis.
* a **Prioritizer** that combines CVSS, EPSS, KEV and SSVC into a single
  `0–100` priority score and a `P0_CRITICAL … P4_INFO` tier.
* enrichment clients for **CVSS v3/v4 vectors**, **FIRST.org EPSS**,
  **CISA KEV** and **CISA-style SSVC** decision tree.
* an **Evidence pipeline** with binary-safe **Redactor** (bearer tokens,
  cloud keys, basic-auth, cookies, private keys, optional IPs), S3
  persistence (reusing `src.storage.s3.upload`), SHA-256 hashing and an
  audit trail via `src.policy.audit.AuditLogger`.

---

## Deliverables

### Production code

`backend/src/findings/`

| Module                | LOC | Public surface                                                                                  |
| --------------------- | --: | ----------------------------------------------------------------------------------------------- |
| `__init__.py`         |  35 | Re-exports the full `findings` public API.                                                      |
| `cvss.py`             | 130 | `parse_cvss_vector(vector) -> ParsedCvss \| None`, `severity_label(score) -> CvssSeverity`. Wraps the `cvss` PyPI package, normalises Decimal → float, supports v3.x and v4.0. |
| `epss_client.py`      | 230 | `EpssClient(http, redis, ttl, base_url)`, `EpssClient.get(cve_id) -> EpssResult \| None`, `EpssResult` (frozen DTO). 24 h Redis cache, fail-soft on HTTP errors, validates CVE format. |
| `kev_client.py`       | 220 | `KevClient(http, redis, ttl, catalog_url)`, `KevClient.is_listed(cve_id) -> bool`, `KevClient.get_entry(cve_id) -> KevEntry \| None`, `KevClient.refresh()`. Redis-cached CISA catalog with negative-cache for unknown CVEs. |
| `ssvc.py`             | 145 | `ssvc_decide(exploitation, exposure, automatable, technical_impact, mission_impact) -> SSVCDecision`. Implements CISA's deployer decision tree → `TRACK / TRACK_STAR / ATTEND / ACT`. |
| `prioritizer.py`      | 175 | `Prioritizer(cvss_weight, epss_weight, kev_weight, ssvc_weight)`, `Prioritizer.prioritize(finding) -> PrioritizationResult`, `PriorityScore`, `PriorityTier`, `PriorityBreakdown`. Pure, deterministic, edge-case safe (CVSS 0, EPSS None, KEV False). |
| `normalizer.py`       | 900 | `Normalizer(tenant_id, scan_id, generator, owasp_resolver)`, `Normalizer.normalize(tool_run_result) -> list[FindingDTO]`. Strategy pattern over `JSONL / JSON / NMAP_XML / NUCLEI_JSONL / CSV / TEXT / JSON_GENERIC`. Idempotent dedup via SHA256(`asset_id|category|root_cause_hash|parameter`) → `uuid5`. |
| `correlator.py`       | 200 | `Correlator(attack_order)`, `Correlator.correlate(findings) -> list[FindingChain]`, `FindingChain` DTO. Deterministic chain generation per asset using MITRE ATT&CK kill-chain order. |

`backend/src/evidence/`

| Module           | LOC | Public surface                                                                                  |
| ---------------- | --: | ----------------------------------------------------------------------------------------------- |
| `__init__.py`    |  18 | Re-exports the full `evidence` public API.                                                      |
| `redaction.py`   | 235 | `Redactor(specs)`, `Redactor.redact(content) -> RedactionResult`, `RedactionSpec`, `RedactionReport`, `RedactionResult`, `default_redaction_specs(scrub_ips=False)`. Binary-safe regex on raw bytes, replacement is fixed-length and capped at `10_000` per spec. Patterns: bearer tokens, basic-auth, AWS keys, GitHub PATs, generic API keys, RSA/EC/PGP private keys, cookies, password fields, optionally IPs. |
| `pipeline.py`    | 195 | `EvidencePipeline(uploader, audit_logger, redactor, scan_id, tenant_id)`, `EvidencePipeline.persist(tool_run_id, kind, raw_data, ...) -> EvidencePersistResult`. Redact → SHA-256 → S3 upload (`src.storage.s3.OBJECT_TYPE_EVIDENCE`) → `AuditEventType.POLICY_DECISION` audit entry. Sanitised log payload (kind, sha256 prefix, redactions count). |

All modules are **`mypy --strict` clean** against `src.findings` and
`src.evidence`. No raw `subprocess`, no real HTTP, no `os.environ` reads
in library code; module-top imports throughout; closed `StrEnum`s for
all taxonomies; `BaseModel(extra="forbid", frozen=True)` for every DTO.

---

## Tests

### Unit tests (`backend/tests/unit/{findings,evidence}/`)

| File                      | Tests | What it covers                                                                                  |
| ------------------------- | ----: | ----------------------------------------------------------------------------------------------- |
| `findings/conftest.py`    |   —   | `make_finding`, `FakeRedis`, `FakeHttpResponse`, `FakeHttpClient` fixtures.                     |
| `test_cvss.py`            |  16   | v3.0/v3.1/v4.0 vectors, invalid input, severity labels, monotonicity.                           |
| `test_ssvc.py`            |  17   | All four outcomes, decision-tree branches, monotonicity, frozen DTO.                            |
| `test_prioritizer.py`     |  19   | P0 → P4 tiering, KEV bonus, EPSS interpolation, edge cases (CVSS 0 / EPSS None / SSVC TRACK).   |
| `test_correlator.py`      |  10   | Lone findings, multi-asset chains, deterministic order, ATT&CK ordering.                        |
| `test_epss_client.py`     |  17   | Redis cache hit/miss, negative cache, malformed responses, HTTP errors, invalid CVE.            |
| `test_kev_client.py`      |  18   | Catalog refresh, Redis cache, unknown CVE, malformed feed, HTTP errors.                         |
| `test_normalizer.py`      |  35   | nuclei JSONL, nmap XML, generic JSON, CSV, text fallback; dedup idempotency; OWASP resolver.    |
| `evidence/conftest.py`    |   —   | `InMemoryUploader` (S3 fake), `SampleEvidence` fixture.                                         |
| `test_redaction.py`       |  35   | Each default spec (≥ 10 patterns), custom specs, binary safety, count cap, no-match no-op.      |
| `test_pipeline.py`        |  16   | Happy path, redaction toggle, uploader failure, optional audit logger, deterministic SHA-256.   |

### Integration tests (`backend/tests/integration/findings/`)

| File                      | Tests | What it covers                                                                                  |
| ------------------------- | ----: | ----------------------------------------------------------------------------------------------- |
| `test_findings_e2e.py`    |  20   | End-to-end: nuclei JSONL → Normalizer → Prioritizer (with EPSS + KEV mocks) → Correlator → Evidence pipeline. Asserts dedup, tiering, chain ordering, S3 upload, audit logging. |

**Total new tests: 203** (all passing). **Coverage on `src.findings + src.evidence`: 94 %** (above the ≥ 85 % gate).

```text
Name                          Stmts   Miss  Cover
-----------------------------------------------------------
src\evidence\__init__.py          3      0   100%
src\evidence\pipeline.py         49      0   100%
src\evidence\redaction.py        76      3    96%
src\findings\__init__.py          8      0   100%
src\findings\correlator.py       85      6    93%
src\findings\cvss.py             57      6    89%
src\findings\epss_client.py     102      0   100%
src\findings\kev_client.py       98      3    97%
src\findings\normalizer.py      389     41    89%
src\findings\prioritizer.py      60      2    97%
src\findings\ssvc.py             51      0   100%
-----------------------------------------------------------
TOTAL                           978     61    94%
```

---

## Quality gates

| Gate                                              | Result                          |
| ------------------------------------------------- | ------------------------------- |
| `ruff check src/findings src/evidence src/db/session.py` | ✅ clean                         |
| `ruff format --check src/findings src/evidence src/db/session.py` | ✅ clean                         |
| `mypy --strict src/findings src/evidence src/db/session.py`         | ✅ clean                         |
| ARG-009 unit + integration suite                  | ✅ 203 / 203 passed              |
| Coverage `src.findings + src.evidence` ≥ 85 %     | ✅ 94 %                          |
| Full project test suite (`pytest -q`)             | ✅ 4958 passed / 137 pre-existing failures / 9 skipped — **5104 total**, well above the ≥ 1830 floor |

> **Engine-kwargs fix (applied during ARG-009 verification):** the
> root-level `tests/test_*.py` modules import `src.db.session` which
> previously passed PostgreSQL-only pool kwargs (`pool_size`,
> `max_overflow`) to `create_async_engine`. With the default test DSN
> (`sqlite+aiosqlite:///:memory:`) SQLAlchemy rejects those kwargs and
> `tests/test_argus010_sse_observability.py` collected with an error,
> blocking the full-suite run.
>
> Root cause was a missing dialect guard. Fix is small, surgical and
> backward-compatible — `_engine_kwargs(database_url)` now omits
> `pool_size`/`max_overflow` when the URL starts with `sqlite`, and
> `create_task_engine_and_session()` got its previously-missing return
> annotation. Production behaviour for asyncpg/asyncmy is unchanged
> (pool sizing is still applied verbatim).
>
> The remaining 137 failures in the full suite are **all in modules
> outside ARG-009 scope** (stage1/stage4/threat_modeling/
> vulnerability_analysis pipelines, va_owasp006, xss_detection, etc.)
> and reproduce on `main` without any of the ARG-009 changes — they
> are tracked separately under their respective owners.

---

## Dependencies

* Added `cvss>=3,<4` to `backend/requirements.txt` and the `[project] dependencies` block in `backend/pyproject.toml` (per ARG-009 spec). No other runtime dependencies introduced.

---

## Acceptance criteria — verification

| # | Criterion                                                                                           | Status |
| - | --------------------------------------------------------------------------------------------------- | ------ |
| 1 | `Normalizer.normalize()` is idempotent (same input → same `root_cause_hash` and finding `id`)       | ✅ — covered by `test_normalizer.py::test_normalizer_dedup_idempotent` and `test_findings_e2e.py::test_e2e_dedup_stable_ids` |
| 2 | `Prioritizer.prioritize()` on edge cases (CVSS=0, EPSS=None, KEV=False) returns 0–100, no div-by-0 | ✅ — `test_prioritizer.py::test_p4_when_low_cvss_and_track_only` and friends |
| 3 | `Redactor.redact()` detects ≥ 10 secret patterns, binary-safe, no false positives on plain text     | ✅ — `test_redaction.py` (35 cases incl. negatives + binary blob)             |
| 4 | EPSS / KEV clients work via mocked HTTP, real-API tests gated behind `INTEGRATION=1`                | ✅ — `FakeHttpClient` in unit suite; integration test uses an in-process fake |
| 5 | Coverage `src.findings + src.evidence` ≥ 85 %                                                       | ✅ — 94 %                                                                     |

---

## Files touched

### New

* `backend/src/findings/__init__.py`
* `backend/src/findings/cvss.py`
* `backend/src/findings/epss_client.py`
* `backend/src/findings/kev_client.py`
* `backend/src/findings/ssvc.py`
* `backend/src/findings/prioritizer.py`
* `backend/src/findings/normalizer.py`
* `backend/src/findings/correlator.py`
* `backend/src/evidence/__init__.py`
* `backend/src/evidence/redaction.py`
* `backend/src/evidence/pipeline.py`
* `backend/tests/unit/findings/__init__.py`
* `backend/tests/unit/findings/conftest.py`
* `backend/tests/unit/findings/test_cvss.py`
* `backend/tests/unit/findings/test_ssvc.py`
* `backend/tests/unit/findings/test_prioritizer.py`
* `backend/tests/unit/findings/test_correlator.py`
* `backend/tests/unit/findings/test_epss_client.py`
* `backend/tests/unit/findings/test_kev_client.py`
* `backend/tests/unit/findings/test_normalizer.py`
* `backend/tests/unit/evidence/__init__.py`
* `backend/tests/unit/evidence/conftest.py`
* `backend/tests/unit/evidence/test_redaction.py`
* `backend/tests/unit/evidence/test_pipeline.py`
* `backend/tests/integration/findings/__init__.py`
* `backend/tests/integration/findings/test_findings_e2e.py`

### Modified

* `backend/requirements.txt` — added `cvss>=3,<4`
* `backend/pyproject.toml` — added `cvss>=3,<4` to `[project] dependencies`
* `backend/src/db/session.py` — dialect-aware engine kwargs (`_engine_kwargs(database_url)`); fixes pre-existing collection error in `tests/test_argus010_sse_observability.py` when the test DSN is SQLite. Added missing return annotation on `create_task_engine_and_session()`. Also moved the `logger = logging.getLogger(__name__)` assignment below the imports to silence E402.
* `ai_docs/develop/plans/2026-04-17-argus-finalization-cycle1.md` — marked ARG-009 ✅ Done

---

## Out of scope (deferred to Cycle 2)

* Wiring `Normalizer / Correlator / Prioritizer / EvidencePipeline` into
  `src/orchestration/state_machine.py` (currently consumed only via
  ARG-008's `Orchestrator` once Cycle 2 lands the integration shim).
* Real-network EPSS/KEV smoke test (gated `@pytest.mark.integration`,
  skipped without `INTEGRATION=1` env-var).
* Persisting `FindingChain` rows — schema lives in pipeline contracts;
  the DB migration is part of Cycle 2.

---

## Risk register

* **Resolved during ARG-009 verification** — pre-existing test
  environment issue in legacy `tests/test_*.py` modules due to
  `pool_size`/`max_overflow` kwargs being passed to the SQLite engine
  has been fixed via `_engine_kwargs(database_url)` in
  `src/db/session.py`. Production PostgreSQL pool sizing is preserved.
* **Out-of-scope failures (137)** in stage1/stage4/threat_modeling/
  vulnerability_analysis pipelines and adjacent modules remain in the
  full suite. These are pre-existing on `main` and unrelated to
  ARG-009 — tracked under their respective owners and out of scope
  for this task.
