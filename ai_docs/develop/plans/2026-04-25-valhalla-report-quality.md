# Plan: Valhalla report 10/10 (truthful, evidence-driven, professional)

**Created:** 2026-04-25  
**Orchestration:** `orch-2026-04-25-14-00-valhalla`  
**Goal:** Fix Valhalla report generation: deduplication, canonical CVSS/exploit model, quality gates, section naming/OWASP/WSTG, executive/threat/business tone, remediation guidance, and tests — all via real pipeline code (no manual HTML, no fake data).

**Repo reality:** `backend/app/reporting/*` is absent; Valhalla lives under **`backend/src/reports/`** (pipeline, `valhalla_report_context.py`, `report_quality_gate.py`, `finding_dedup.py`, templates `templates/reports/valhalla*.j2`, partials). Prompts: **`backend/app/prompts/reporter.md`**, `validator.md`, `parser_normalizer.md`; orchestration wiring: `backend/src/orchestration/`, `backend/src/services/reporting.py`, API `backend/src/api/routers/reports.py`, schemas under `backend/app/schemas/` / `backend/src/api/schemas.py`.

**Dependencies graph (summary):** VAL-001 → VAL-002 → VAL-003; VAL-001 → VAL-004; VAL-005 → VAL-006; VAL-003+VAL-007 → VAL-008; VAL-010 after implementation tasks.

---

## VAL-001 — Canonical CVSS + `exploit_*` + quality gate (Critical path)

- **Priority:** Critical  
- **Complexity:** Complex  
- **Areas:** `backend/src/reports/report_data_validation.py`, `valhalla_report_context.py`, `report_quality_gate.py`, `backend/app/schemas/vulnerability_analysis/schemas.py` (or `backend/src/reports` DTOs), `data_collector.py`, any `cvss_base_score` / duplicate CVSS fields in collectors and Jinja context.
- **Acceptance criteria:**
  - Single canonical model: `cvss_score`, `cvss_vector`, `severity` (from score bands), `confidence`, `validation_status`, `evidence_quality`; no conflicting `cvss` vs `cvss_base_score` in output paths.
  - New fields: `exploit_demonstrated: bool`, `exploit_summary: str` (empty OK when false); **curl/header checks are not exploits** (documented in model/prompts).
  - Default for **header-only absence** (no other impact): CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N` → **4.3 Medium** unless stronger evidence justifies else.
  - Quality gate **fails or warns** on severity/CVSS band mismatch per existing `report_quality_gate` patterns; tests cover mismatch and header-default path.

---

## VAL-002 — Deduplicate security header findings

- **Priority:** High  
- **Complexity:** Moderate  
- **Areas:** `backend/src/reports/finding_dedup.py`, `report_pipeline.py`, `report_findings_scope.py` (if merge point), title normalization helpers.
- **Acceptance criteria:**
  - Variants like “Missing Security HTTP Response Headers” and similar header-gap findings merge into **one** canonical title, e.g. **“Missing or incomplete HTTP security response headers”** (wording fixed in code/templates).
  - Snapshots or unit tests prove one row/entry after merge for representative inputs; no data loss of distinct non-header issues.

---

## VAL-003 — Critical section: only real criticals; no “missing headers” in Critical

- **Priority:** Critical  
- **Complexity:** Complex  
- **Areas:** `report_findings_scope.py`, `valhalla_tier_renderer.py`, `finding_quality_filter.py`, `section_06_results_overview.html.j2` / critical-tier partials, `valhalla_report_context.py`.
- **Acceptance criteria:**
  - **Critical** tier lists only: **Critical severity OR CVSS ≥ 9**, **verified**, **strong evidence**, **`exploit_demonstrated === true`** (pipeline-enforced or filtered with explicit downgrade reason).
  - Header-only / misconfig-without-exploit: **excluded** from Critical; “Not found” / non-findings for alleksy-style low-signal (aligned with product wording in templates + context flags).
  - Template + context tests: missing-headers finding never appears in Critical block.

---

## VAL-004 — AI sections: prompts + `ai_text_generation` for header-only

- **Priority:** High  
- **Complexity:** Moderate  
- **Areas:** `backend/app/prompts/reporter.md`, `validator.md`, `parser_normalizer.md`, `backend/src/reports/ai_text_generation.py`, `backend/src/orchestration/prompt_registry.py` / `ai_prompts.py` if task routing references reporter.
- **Acceptance criteria:**
  - For **header-only** findings: **no** stale rate-limit or credential-breach style narrative; **prescribed** short exploit-chain / impact text that states limitations (headers ≠ RCE) where applicable.
  - Validator/parser rules reject or normalize contradictory AI output (aligned with product rules above).

---

## VAL-005 — Rename “Data Breach Detection” → “Compliance and OWASP Mapping”; add HIBP section

- **Priority:** High  
- **Complexity:** Moderate  
- **Areas:** Valhalla partials (e.g. `section_data_coverage.html.j2`, `valhalla.html.j2`, `sections_03_05_*.j2` / appendices), `valhalla_report_context.py` for section titles and HIBP flags.
- **Acceptance criteria:**
  - Old title replaced globally in Valhalla output.
  - New subsection **“Data Breach Exposure Check”** with explicit **HIBP sample=0** / no-breach-data messaging when applicable (driven by real collected counts, not hardcoded fake breaches).

---

## VAL-006 — OWASP: A05 misconfig, columns, “Not assessed”

- **Priority:** High  
- **Complexity:** Moderate  
- **Areas:** `templates/reports/partials/owasp_compliance_table.html.j2`, `valhalla_report_context.py` (or `jinja_minimal_context.py`), mapping from test coverage → row state.
- **Acceptance criteria:**
  - Misconfiguration class uses **A05:2021** (not A06) where the report maps “misconfig/headers.”
  - Table columns: **Assessed / Result / Findings** (or project-equivalent names already in i18n).
  - **“Not assessed”** when the related tests did not run or scope didn’t cover (from collector/coverage data).

---

## VAL-007 — WSTG &lt;70%: warnings + “degraded execution” label

- **Priority:** High  
- **Complexity:** Moderate  
- **Areas:** `wstg_coverage.py`, `wstg_coverage_table.html.j2`, `section_status_macro.html.j2`, `sections_01_02_title_executive.html.j2` or cost/status partials.
- **Acceptance criteria:**
  - If WSTG coverage **&lt; 70%**, show clear **warnings** and label engagement as **“Valhalla Automated Security Assessment — degraded execution”** (or exact agreed string from product), **not** claiming full manual pentest.
  - Test with threshold boundary (69% vs 71%) if feasible.

---

## VAL-008 — Executive summary, business risk, threat model (tone + structure)

- **Priority:** High  
- **Complexity:** Moderate  
- **Areas:** `sections_01_02_title_executive.html.j2`, `executive_report.html.j2`, `sections_07_08_threat_findings.html.j2`, `valhalla_report_context.py`, optional `nist_limitations.html.j2`.
- **Acceptance criteria:**
  - Executive summary: **concise**, **no false reassurance**; sample / alleksy-style copy path **honest** about limits.
  - Business risk: **proportional**; no forbidden claims without evidence in structured findings.
  - Threat model: guessed paths / hypotheticals labeled **not validated**; **no raw JSON dump** in user-facing body (use formatted lists or redacted snippets if needed in appendix only).

---

## VAL-009 — Remediation: modern security headers, no X-XSS-Protection, stack-neutral

- **Priority:** Medium  
- **Complexity:** Simple  
- **Areas:** `sections_10_12_remediation_conclusion.html.j2`, static strings in `valhalla_report_context.py` or i18n.
- **Acceptance criteria:**
  - **Remove** X-XSS-Protection as a recommended control (or mark deprecated) per modern practice.
  - **Modern** header set (CSP, HSTS, etc.) in neutral wording; **stack-agnostic** (no framework-specific blurb unless data says stack).

---

## VAL-010 — Report tests: linters, quality gate, snapshots

- **Priority:** Critical  
- **Complexity:** Moderate  
- **Areas:** `backend/tests/test_report_quality_gate.py`, `test_valhalla_report_context.py`, `test_report_valhalla_full.py`, `tests/snapshots/reports/valhalla_canonical.*`, `test_report_export_bundle_parity_rpt006.py`, Frontend `Frontend/src/lib/reports.test.ts` if bundle parity touches UI types.
- **Acceptance criteria:**
  - All relevant existing tests **green**; new/updated tests for: CVSS gate, header dedup, Critical exclusion, WSTG degraded label, OWASP table, executive/HIBP strings as applicable.
  - Snapshot updates only when behavior change is **intended**; no fake fixture data.

---

## Progress (orchestrator)

- ⏳ VAL-001 … VAL-010 — pending

## Architecture notes (non-negotiables)

- **Single pipeline:** changes flow collector → normalize/dedup → quality gate → context → Jinja → PDF; prompts align with structured fields.
- **Security:** no user-facing stack traces; structured logs without secrets.
- **No placeholders** in shipped strings; use real flags/counts from data layer.
