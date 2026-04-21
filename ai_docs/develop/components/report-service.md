# ReportService — Tier × Format Dispatcher (ARG-024)

**Type:** Backend service component
**Location:** `backend/src/reports/`
**Last updated:** 2026-04-19
**Status:** Tier 1 (Midgard) production-ready; Tier 2/3 wired through `tier_classifier`, full enrichment pending ARG-025
**Owners:** Backend / Reporting

---

## Purpose

`ReportService` is the **single, canonical front door** for report
generation across the ARGUS platform. It accepts a `(tenant_id, scan_id |
report_id, tier, format)` tuple and returns an immutable `ReportBundle`
of bytes, with content-type metadata and a SHA-256 digest for
tamper-evidence.

It replaces ad-hoc, format-specific generation calls scattered through
the codebase with a stateless, tenant-scoped, deterministic pipeline:

1. Resolve `Report` + `Finding` rows from PostgreSQL (RLS + explicit
   `tenant_id` filter).
2. Build a unified `ReportData` (`build_report_data_from_db`).
3. Apply `tier_classifier.classify_for_tier(data, tier)` (pure projection).
4. Dispatch to the right format generator (HTML/PDF/JSON/CSV/SARIF/JUnit).
5. Wrap the bytes in `ReportBundle` (computes SHA-256 + size).

ARG-024 is the *Midgard* (Tier 1, executive-summary) implementation.
Asgard (Tier 2) and Valhalla (Tier 3) are already wired through
`classify_for_tier` so ARG-025 only needs to plug in
`replay_command_sanitizer` — no service surgery required.

---

## Architecture

```
backend/src/reports/
├── report_bundle.py        ← ReportTier, ReportFormat, ReportBundle (immutable result)
├── tier_classifier.py      ← classify_for_tier(data, tier) — pure
├── sarif_generator.py      ← SARIF v2.1.0 builder (build_sarif_payload, generate_sarif)
├── junit_generator.py      ← JUnit XML builder (build_junit_tree, generate_junit)
├── report_service.py       ← ReportService class — DB → projection → render → bundle
├── generators.py           ← (existing) HTML/PDF/JSON/CSV via Jinja + WeasyPrint
└── __init__.py             ← re-exports the public surface
```

### Module responsibilities

| Module | Responsibility | I/O? |
| --- | --- | --- |
| `report_bundle` | Enums + immutable bundle dataclass; SHA-256 hashing | None (pure) |
| `tier_classifier` | Project full `ReportData` to tier-visible subset | None (pure) |
| `sarif_generator` | Render `ReportData` as SARIF v2.1.0 JSON | None (pure) |
| `junit_generator` | Render `ReportData` as JUnit XML | None (pure) |
| `report_service` | Orchestrate DB load → classify → render → wrap | DB (async) |

---

## Public API

### Python

```python
from src.reports import ReportFormat, ReportService, ReportTier

service = ReportService()  # stateless; safe to share

bundle = await service.generate(
    tenant_id="acme",
    scan_id="scan-abc",
    tier=ReportTier.MIDGARD,
    fmt=ReportFormat.SARIF,
)

assert bundle.tier is ReportTier.MIDGARD
assert bundle.format is ReportFormat.SARIF
assert bundle.verify_sha256()
print(bundle.mime_type)        # "application/sarif+json"
print(bundle.filename())       # "report-midgard.sarif"
print(len(bundle.content))     # bytes count
```

If the caller already has a fully-built `ReportData` (e.g. an
orchestrator stage that just produced one), use the synchronous helper:

```python
bundle = service.render_bundle(
    data,
    tier=ReportTier.MIDGARD,
    fmt=ReportFormat.JUNIT,
)
```

### HTTP

```
POST /api/v1/reports/generate
Content-Type: application/json
X-Tenant-ID: acme

{
  "scan_id": "scan-abc",
  "tier": "midgard",
  "format": "sarif"
}
```

Response: the report bytes inline (`Content-Disposition: attachment`)
with the following metadata headers:

| Header | Example |
| --- | --- |
| `Content-Type` | `application/sarif+json` |
| `Content-Length` | `4216` |
| `X-Argus-Report-Tier` | `midgard` |
| `X-Argus-Report-Format` | `sarif` |
| `X-Argus-Report-SHA256` | `9a2…` (64 hex chars) |
| `X-Argus-Report-Size-Bytes` | `4216` |

---

## Tiers

| Tier | Audience | Findings cap | Evidence | Screenshots | Raw artifacts | AI insights | Remediation |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **Midgard** | CISO / exec | top 10 | ✗ | ✗ | ✗ | ✗ | ✗ |
| **Asgard** | Security team | all | ✓ | ✓ | ✗ | ✓ | ✓ |
| **Valhalla** | Leadership-technical | all | ✓ | ✓ | ✓ | ✓ | ✓ |

The classifier is a **pure function**; it returns a new `ReportData`
instance and never mutates the input. Bugs in the classifier cannot
*add* fields the caller did not pass in — only redact.

---

## Formats

| Format | MIME type | Extension | Backend | Determinism |
| --- | --- | --- | --- | --- |
| `html` | `text/html; charset=utf-8` | `.html` | Jinja2 | Stable (no clock) |
| `pdf` | `application/pdf` | `.pdf` | WeasyPrint | Stable per template |
| `json` | `application/json; charset=utf-8` | `.json` | `json.dumps` | Stable (sort_keys) |
| `csv` | `text/csv; charset=utf-8` | `.csv` | `csv.DictWriter` | Stable (sort_keys) |
| `sarif` | `application/sarif+json` | `.sarif` | hand-rolled | **Byte-identical** |
| `junit` | `application/xml; charset=utf-8` | `.xml` | `xml.etree.ElementTree` | **Byte-identical** |

### SARIF v2.1.0 mapping

| FindingDTO field | SARIF target |
| --- | --- |
| `severity` | `result.level` (`error`/`warning`/`note`) |
| `title` | `result.message.text` |
| `description` | `result.message.markdown` |
| `cwe` | `rule.properties.cwe` + `rule.helpUri` |
| `cvss` | `rule.properties.security-severity` (string per spec) |
| `target` | `result.locations[].physicalLocation.artifactLocation.uri` |
| `owasp_category` | `result.properties.owasp_top10_2025` |
| `evidence_refs` | `result.properties.evidence_refs[]` |
| `confidence` | `result.properties.confidence` |
| (computed) | `result.fingerprints["primaryFinding/v1"]` (SHA-256) |

The fingerprint enables **cross-run dedup** — same finding on the same
target produces the same digest, so GitHub Code Scanning / Sonar can
collapse re-runs.

### JUnit XML mapping

| FindingDTO field | JUnit XML target |
| --- | --- |
| `severity = critical/high/medium` | `<failure>` element (test fails) |
| `severity = low/info` | `<system-out>` element (informational) |
| `title` | `<testcase>` `name` attribute (with index prefix) |
| `cwe` | `<failure>` `type` attribute |
| `cvss` | `<failure>` `message` prefix |
| `description` | `<failure>` body text |

CI gate semantics: the `failures` count on `<testsuite>` includes every
critical/high/medium finding, so any consumer that counts JUnit
failures (Jenkins, GitLab, GitHub Actions, CircleCI) will fail the
pipeline when ARGUS finds vulnerabilities.

---

## Security guardrails

| Concern | Mitigation |
| --- | --- |
| Cross-tenant leak | Every DB query has `tenant_id` filter (defense-in-depth on top of RLS) |
| Tampering after generation | SHA-256 digest exposed via `X-Argus-Report-SHA256` header and `ReportBundle.verify_sha256()` |
| Secrets in CI artifacts | Midgard tier strips evidence/screenshots/raw_artifacts/PoC bodies *before* rendering |
| PoC body leak | SARIF / JUnit consume only redacted `description` + `proof_of_concept` (already normalised upstream) |
| XML attacks | JUnit uses stdlib for **emission only**; tests parse via `defusedxml` |
| URL spoofing in storage | Bundle's `presigned_url` is opaque — never validated; backend issues clean URLs without secrets in querystring |
| Engine init in cold path | `db.session` import is lazy inside `ReportService` so importing the module doesn't trigger `create_async_engine` |

---

## Determinism

`ReportService.render_bundle(data, tier, fmt)` produces **byte-identical**
output for the same input across processes for SARIF, JUnit, JSON, and
CSV. This is required for:

* CI snapshot tests (rev-locked diffs in PRs)
* Tamper-evidence (a SHA-256 mismatch means the artifact was modified
  in transit, not regenerated)
* Pinning report digests in compliance evidence

PDF determinism depends on WeasyPrint version + system fonts; we do
NOT promise byte-identical PDFs across hosts.

HTML determinism depends on Jinja template version; rendering is stable
within a template version but PR-induced template changes are expected
to alter the output (and therefore the SHA-256).

---

## Tests

| Suite | Location | Tests |
| --- | --- | --- |
| `report_bundle` | `backend/tests/test_report_bundle.py` | 20 |
| `tier_classifier` | `backend/tests/test_tier_classifier.py` | 15 |
| `sarif_generator` | `backend/tests/test_sarif_generator.py` | 27 |
| `junit_generator` | `backend/tests/test_junit_generator.py` | 16 |
| `report_service` (unit) | `backend/tests/test_report_service.py` | 20 |
| `report_service` (integration) | `backend/tests/test_report_service_integration.py` | 14 |
| **Total** | | **112** (1 PDF skip on hosts without WeasyPrint native libs) |

Run with:

```powershell
cd backend
python -m pytest tests/test_report_bundle.py `
                tests/test_tier_classifier.py `
                tests/test_sarif_generator.py `
                tests/test_junit_generator.py `
                tests/test_report_service.py `
                tests/test_report_service_integration.py
```

Linux / macOS:

```bash
cd backend
python -m pytest tests/test_report_bundle.py \
                tests/test_tier_classifier.py \
                tests/test_sarif_generator.py \
                tests/test_junit_generator.py \
                tests/test_report_service.py \
                tests/test_report_service_integration.py
```

---

## Roadmap

| Ticket | Scope |
| --- | --- |
| ARG-024 (this) | Midgard tier, SARIF, JUnit, unified API |
| ARG-025 | Asgard tier — sanitised reproducer recipes via `replay_command_sanitizer` |
| Cycle 4 | Valhalla tier — AI exploit chains, hardening roadmap, zero-day potential |
| Future | Object-storage offload (`ReportBundle.presigned_url`), Ed25519 signing of bundles |

---

## Related docs

* `ai_docs/develop/plans/2026-04-19-argus-finalization-cycle3.md` — overall Cycle 3 plan
* `ai_docs/develop/components/docker-build-tests.md` — Docker verification (sibling component doc)
