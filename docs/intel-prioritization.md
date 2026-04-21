# Intel-driven prioritization (ARG-044)

> EPSS percentile + KEV catalog ingest + full CISA SSVC v2.1 + `FindingPrioritizer` — KEV-aware deterministic ranking for Valhalla executive reports.

This document describes how ARGUS enriches findings with public threat
intelligence (FIRST.org EPSS scores, CISA KEV catalog) and how those
signals feed the deterministic prioritisation pipeline used by the
Valhalla executive report renderer and the API filters consumed by the
Frontend.

## High-level architecture

```text
                  ┌────────────────────────────┐
                  │ Daily Celery beat (04:00 UTC)│
                  │   argus.intel.epss_refresh   │
                  │   argus.intel.kev_refresh    │
                  └─────────────┬──────────────┘
                                │  (HTTPS — guarded by Redis lock,
                                │   skipped when intel_airgap_mode=true)
                                ▼
       ┌────────────────────────────────────────────────┐
       │  PostgreSQL (no RLS — public threat intel)     │
       │  ─ epss_scores      (cve_id PK, score, pct)    │
       │  ─ kev_catalog      (cve_id PK, …, date_added) │
       └─────────────┬──────────────────────────────────┘
                     │  read-only point lookups
                     ▼
        ┌──────────────────────────────────┐
        │  src.findings.enrichment          │
        │  FindingEnricher.enrich(...)      │
        │  → epss_score / epss_percentile   │
        │  → kev_listed / kev_added_date    │
        │  → ssvc_decision (CISA v2.1)      │
        └─────────────┬────────────────────┘
                      │
                      ▼
        ┌────────────────────────────────────┐
        │  src.findings.prioritizer           │
        │  FindingPrioritizer.rank_findings  │
        │  KEV → SSVC → CVSS → EPSS → id-hash │
        └─────────────┬──────────────────────┘
                      │
                      ▼
        Valhalla executive report  +  API responses  +  Frontend SsvcBadge
```

The hot path (request handlers, report renderer, normalizer) **never
touches the network**. All HTTP traffic to FIRST.org / CISA happens in
the daily Celery beat job; runtime enrichment is a Postgres point
lookup.

## Components

### Persistence layer

| Module | Class | Responsibility |
|--------|-------|----------------|
| `backend/src/findings/epss_persistence.py` | `EpssScoreRepository` | Async CRUD over `epss_scores` (UPSERT batch, `get`, `get_many`, `get_stale_after`, `count`). |
| `backend/src/findings/kev_persistence.py`  | `KevCatalogRepository` | Async CRUD over `kev_catalog` (UPSERT batch, `get`, `is_listed`, `get_listed_set`, `count`). |

Both repositories are dialect-aware: PostgreSQL gets a true
`INSERT … ON CONFLICT DO UPDATE`; SQLite (used by the unit suite)
emulates the same semantics with `SELECT` + `INSERT/UPDATE`.

CVE IDs are normalised to upper-case (`CVE-YYYY-NNNNN`); invalid IDs are
silently dropped with a single structured log entry per batch — intel
enrichment is best-effort, never a hard dependency.

### Daily refresh — Celery beat tasks

`backend/src/celery/tasks/intel_refresh.py` owns two beat-scheduled
tasks:

| Task | Schedule | Lock key | Behaviour |
|------|----------|----------|-----------|
| `argus.intel.epss_refresh` | 04:00 UTC | `argus:lock:intel:epss_refresh` | Collect distinct CVE IDs from open findings → batch through `EpssClient.fetch_epss_batch` (60 rpm honoured by client semaphore) → upsert into `epss_scores`. |
| `argus.intel.kev_refresh`  | 05:00 UTC | `argus:lock:intel:kev_refresh`  | `KevClient.fetch_kev_catalog` (with ETag / `If-None-Match`) → upsert full catalog → refresh Redis lookup set. |

Lock semantics: `SET … NX EX 1800`. If Redis is unreachable, the task
proceeds without the lock and logs a warning (degraded path; the
duplicate-write window is bounded by the daily cadence and the upsert
idempotency).

#### Air-gap mode

`settings.intel_airgap_mode` (env `INTEL_AIRGAP_MODE`) toggles a
hard short-circuit:

* Both Celery tasks return `{"status": "airgap", "task": "..."}` on
  invocation — no network egress, no Redis lock acquisition.
* `FindingEnricher` skips all repository calls and returns the input
  list unchanged (apart from SSVC, which is always derived from the
  existing DTO state — it requires no external data).
* Operators are expected to seed the `epss_scores` / `kev_catalog`
  tables out of band (e.g. via a periodic mirror import).

### CISA SSVC v2.1 (deployer tree)

`backend/src/findings/ssvc.py` implements the **full** CISA Stakeholder-
Specific Vulnerability Categorization v2.1 deployer decision tree:

* **4 axes** (`Exploitation` × `Automatable` × `TechnicalImpact` ×
  `MissionWellbeing`).
* **36 leaves** — one outcome per `(3 × 2 × 2 × 3)` combination.
* **4 outcomes** — `TRACK`, `TRACK*` (Track-star), `ATTEND`, `ACT`.

The matrix is stored as an immutable `types.MappingProxyType` so it
cannot be mutated at runtime (defence-in-depth — a future regression
attempting to "soften" a critical leaf would surface as a `TypeError`).

`derive_ssvc_inputs(finding, *, kev_listed, public_exploit_known,
mission_wellbeing)` projects a `FindingDTO` onto the four axes. Notable
heuristics:

* `kev_listed=True` ⇒ `Exploitation = ACTIVE`.
* `public_exploit_known=True` (e.g. EPSS percentile ≥ 0.5) and not
  KEV-listed ⇒ `Exploitation = POC`.
* `automatable` is computed from CVSS attack vector (`AV:N` + `AC:L` +
  `PR:N` + `UI:N` ⇒ `YES`).
* `technical_impact` is computed from CVSS impact metrics (any of
  `C:H`, `I:H`, `A:H` with scope unchanged ⇒ `TOTAL`).

The full reference matrix is asserted leaf-by-leaf in
`backend/tests/unit/findings/test_ssvc.py`.

### `FindingPrioritizer` — deterministic ordinal ranker

`backend/src/findings/prioritizer.py` exposes the
**non-mutating** ranker used by Valhalla and the API:

```python
class FindingPrioritizer:
    @staticmethod
    def rank_findings(findings: Iterable[FindingDTO]) -> list[FindingDTO]: ...

    @staticmethod
    def top_n(findings: Sequence[FindingDTO], n: int) -> list[FindingDTO]: ...

    @staticmethod
    def rank_objects(findings: Sequence[Any], *, id_extractor=None) -> list[Any]:
        """Duck-typed variant for the API ``Finding`` schema."""
```

Tie-break order (descending priority):

1. `kev_listed` — actively exploited per CISA.
2. `ssvc_decision` (`ACT > ATTEND > TRACK* > TRACK`).
3. CVSSv3 base score (higher first).
4. EPSS percentile (higher first, falls back to raw EPSS score, then
   `0` — never `None`, so comparisons stay total even with mixed
   enrichment coverage).
5. Stable hash of the finding `id` (or `id_extractor(finding)` for
   `rank_objects`) — guarantees a total order even when every other
   signal ties.

The legacy `Prioritizer.prioritize(finding) -> PriorityScore` (weighted
0..100 scoring used by the older Asgard tier) is **unchanged** — the
new ranker is additive.

### `FindingEnricher` — async I/O wrapper around the synchronous normalizer

`backend/src/findings/enrichment.py` decouples the synchronous
`Normalizer` from the async repository calls. The enricher:

* Accepts an already-normalised list of `FindingDTO` plus an optional
  `cve_ids_by_finding: dict[str, list[str]]` mapping (extracted by the
  normalizer from CVE references in finding titles / descriptions).
* Bulk-fetches EPSS scores (`EpssScoreRepository.get_many`) and the KEV
  listed set (`KevCatalogRepository.get_listed_set`) in **two**
  round-trips for the entire batch — never per-finding.
* Picks the **worst** signal for multi-CVE findings (highest EPSS,
  earliest KEV `date_added`, KEV-listed if any CVE is listed).
* Re-derives the SSVC decision after EPSS / KEV are populated.
* Returns a new list of immutable `FindingDTO` copies (`model_copy`) —
  the input is never mutated.

Failure modes:

* DB error during EPSS lookup → original DTO returned, single warning
  log per batch.
* DB error during KEV lookup → same.
* `airgap=True` → all repository calls skipped.

### Valhalla integration

`backend/src/reports/valhalla_tier_renderer.py` consumes the prioritizer
and exposes two enriched sections in the executive report:

* **Top findings by business impact** — the top
  `VALHALLA_BUSINESS_IMPACT_CAP` findings ordered by
  `FindingPrioritizer.rank_objects`. New columns: SSVC badge, KEV
  badge, EPSS percentile.
* **KEV-listed findings (actively exploited)** — a dedicated section
  capped at `VALHALLA_KEV_LISTED_CAP`. Includes CVE ID, KEV
  `date_added`, vendor / product, and required action.

The Jinja2 template
(`backend/src/reports/templates/reports/partials/valhalla/executive_report.html.j2`)
was extended with CSS classes `ssvc-badge`, `kev-badge`, `epss-pct` and
two new table fragments. Existing Valhalla report snapshots remain
backwards-compatible — the new columns / section render as empty when
intel is missing.

### Frontend

* `Frontend/src/components/findings/SsvcBadge.tsx` — colour-coded badge
  (`Act` red, `Attend` orange, `Track*` amber, `Track` neutral) with a
  tooltip describing the CISA outcome semantics. Accessible (`role`,
  `aria-label`). Comprehensive unit suite in
  `Frontend/src/components/findings/SsvcBadge.test.tsx`.
* `Frontend/src/components/findings/FindingFilters.tsx` — controlled
  filter bar exposing severity, SSVC outcome, and a KEV-only toggle.
  `applyFindingFilters(findings, value)` is a pure helper used by the
  finding list and the report viewer.

## API schema additions

`backend/src/api/schemas.py` extends both `Finding` and
`FindingDetailResponse` with **optional** intel fields:

| Field | Type | Notes |
|-------|------|-------|
| `epss_score` | `float \| null` | 0..1 probability of exploitation in the next 30 days. |
| `epss_percentile` | `float \| null` | 0..1 model percentile (FIRST.org convention). |
| `kev_listed` | `bool \| null` | True iff at least one referenced CVE is in the CISA KEV catalog. |
| `kev_added_date` | `date \| null` | Earliest `date_added` across the listed CVE(s). |
| `ssvc_decision` | `"Act" \| "Attend" \| "Track*" \| "Track" \| null` | CISA SSVC v2.1 outcome. |

All five fields default to `null` so existing clients (Frontend, MCP
SDK consumers) continue to work without changes.

## Database schema (`023_epss_kev_tables`)

```sql
CREATE TABLE epss_scores (
    cve_id           VARCHAR(20)         PRIMARY KEY,
    epss_score       DOUBLE PRECISION    NOT NULL CHECK (epss_score BETWEEN 0 AND 1),
    epss_percentile  DOUBLE PRECISION    NOT NULL CHECK (epss_percentile BETWEEN 0 AND 1),
    model_date       DATE                NOT NULL,
    created_at       TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ         NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_epss_scores_model_date ON epss_scores(model_date);

CREATE TABLE kev_catalog (
    cve_id                VARCHAR(20)    PRIMARY KEY,
    vendor_project        VARCHAR(255)   NOT NULL DEFAULT '',
    product               VARCHAR(255)   NOT NULL DEFAULT '',
    vulnerability_name    VARCHAR(500)   NOT NULL DEFAULT '',
    date_added            DATE           NOT NULL,
    short_description     TEXT           NOT NULL DEFAULT '',
    required_action       TEXT           NOT NULL DEFAULT '',
    due_date              DATE,
    known_ransomware_use  BOOLEAN        NOT NULL DEFAULT FALSE,
    notes                 TEXT,
    created_at            TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);
CREATE INDEX ix_kev_catalog_date_added ON kev_catalog(date_added);
```

**No RLS.** EPSS / KEV are global threat intelligence — public data
feeds, not tenant-scoped.

## Operations

### Seeding the tables in air-gap deployments

```bash
# Inside the deployment perimeter:
psql "$DATABASE_URL" -c "TRUNCATE epss_scores;"
psql "$DATABASE_URL" -c "\\copy epss_scores FROM 'epss_scores.csv' CSV HEADER"

psql "$DATABASE_URL" -c "TRUNCATE kev_catalog;"
psql "$DATABASE_URL" -c "\\copy kev_catalog FROM 'kev_catalog.csv' CSV HEADER"
```

Operators typically run a periodic mirror import (e.g. weekly) from a
trusted internal mirror of the FIRST.org / CISA feeds.

### Health checks

* `EpssScoreRepository.count()` and `KevCatalogRepository.count()` are
  exposed by the existing readiness endpoint surface — non-zero counts
  on a fresh deployment confirm the seed migration worked.
* `argus_findings_emitted_total{kev_listed="true"}` (Prometheus) tracks
  KEV-tagged finding emission over time.

## Test coverage

| Test file | Cases | Scope |
|-----------|-------|-------|
| `tests/unit/findings/test_epss_persistence.py` | 15 | Repository CRUD + edge cases (in-memory SQLite). |
| `tests/unit/findings/test_kev_persistence.py`  | 15 | Repository CRUD + edge cases (in-memory SQLite). |
| `tests/unit/findings/test_epss_client.py`      | 39 | EPSS HTTP client + cache. |
| `tests/unit/findings/test_kev_client.py`       | 35 | KEV HTTP client + ETag + airgap. |
| `tests/unit/findings/test_ssvc.py`             | 62 | Full 36-leaf matrix + monotonicity + surjectivity. |
| `tests/unit/findings/test_prioritizer.py`      | 48 | Legacy weighted scoring + new `FindingPrioritizer.rank_*`. |
| `tests/unit/findings/test_intel_refresh.py`    | 14 | Celery dispatcher: lock / airgap / error paths. |
| `tests/unit/findings/test_enrichment_pipeline_with_epss_kev_ssvc.py` | 14 | `FindingEnricher` end-to-end with fakes. |

All suites run **fully offline** (no Postgres, no Redis, no network).
