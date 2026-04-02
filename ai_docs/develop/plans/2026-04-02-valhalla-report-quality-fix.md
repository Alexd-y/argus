# Plan: Valhalla Report Quality Fix — 6 Problems

**Created:** 2026-04-02
**Orchestration:** orch-valhalla-fix
**Status:** ⏳ Ready to execute
**Goal:** Fix 6 critical/high/medium quality issues in ARGUS Valhalla HTML report generation
**Total Tasks:** 6
**Priority:** Critical

## Architecture Context

### Report Generation Pipeline (data flow)

```
DB(findings by scan_id)
  → ReportDataCollector.collect_async()          [data_collector.py]
  → build_valhalla_report_context()              [valhalla_report_context.py]
  → ReportGenerator.build_ai_input_payload()     [reporting.py:1101]
  → run_ai_text_generation() × N sections        [ai_text_generation.py]
  → ReportGenerator.ai_results_to_text_map()     [reporting.py:1286]
  → ReportGenerator.prepare_template_context()   [reporting.py:1300]
  → ReportGenerator.to_generator_report_data()   [reporting.py:1455]
  → validate_report_data()                       [report_data_validation.py]
  → generate_html() → render_tier_report_html()  [generators.py → template_env.py]
  → upload_report_artifact()                     [s3.py]
```

### Key Files Map

| Component | File |
|-----------|------|
| Jinja2 env + filters | `backend/src/reports/template_env.py` |
| Base CSS (`.ai-slot-body`) | `backend/src/reports/templates/reports/base.html.j2` (line 24) |
| Valhalla master template | `backend/src/reports/templates/reports/valhalla.html.j2` |
| AI slot partials (15+ `div.ai-slot-body`) | `backend/src/reports/templates/reports/partials/valhalla/*.html.j2` |
| Generic AI slot loop | `backend/src/reports/templates/reports/partials/ai_slots.html.j2` |
| Report service (pipeline hub) | `backend/src/services/reporting.py` |
| Data collector + FindingRow | `backend/src/reports/data_collector.py` |
| Report validation | `backend/src/reports/report_data_validation.py` |
| Pipeline entry point | `backend/src/reports/report_pipeline.py` |
| AI prompts (system + user templates) | `backend/src/orchestration/prompt_registry.py` |
| AI text generation | `backend/src/reports/ai_text_generation.py` |
| MinIO/S3 storage + presigned URLs | `backend/src/storage/s3.py` |
| Reports storage re-export | `backend/src/reports/storage.py` |
| ORM Finding model | `backend/src/db/models.py` (line 246) |
| API Finding schema | `backend/src/api/schemas.py` (line 151) |
| Valhalla context builder | `backend/src/reports/valhalla_report_context.py` |
| Existing recon dedup | `backend/src/recon/normalization/dedup.py` |
| Finding normalizer (VA) | `backend/src/recon/vulnerability_analysis/finding_normalizer.py` |
| Config (Settings) | `backend/src/core/config.py` |
| Env example | `infra/.env.example` |

---

## Tasks

- [ ] VHQ-001: Markdown → HTML render in ai-slot-body (⏳ Pending)
- [ ] VHQ-002: Deduplicate findings before report (⏳ Pending)
- [ ] VHQ-003: Filter degenerate / unknown findings (⏳ Pending)
- [ ] VHQ-004: CVSS ↔ severity normalization (⏳ Pending)
- [ ] VHQ-005: Rewrite AI prompts for section differentiation (⏳ Pending)
- [ ] VHQ-006: MinIO presigned URL rewrite for public access (⏳ Pending)

## Dependencies

```
VHQ-001 (standalone)
VHQ-002 (standalone)
VHQ-003 → VHQ-004 (severity normalization after filter)
VHQ-005 depends on VHQ-001 (AI text must render as HTML first)
VHQ-006 (standalone)
```

## Execution Order

1. VHQ-001 — Markdown render
2. VHQ-002 — Deduplication
3. VHQ-003 — Unknown finding filter
4. VHQ-004 — CVSS/severity normalization
5. VHQ-005 — AI prompts rewrite
6. VHQ-006 — MinIO URLs

---

## VHQ-001: Markdown → HTML render in `ai-slot-body`

**Priority:** Critical
**Complexity:** Moderate
**Estimated time:** 1–2 hours

### Problem

AI-generated text (from `run_ai_text_generation`) is plain prose with Markdown formatting (`**bold**`, `### heading`, `- list item`). The Jinja2 templates insert it raw into `<div class="ai-slot-body">`. Combined with `white-space: pre-wrap` CSS, users see raw Markdown syntax instead of rendered HTML.

### Root Cause

1. `template_env.py:18-25` — Jinja2 Environment has `autoescape=True`, so any HTML from markdown conversion would be escaped. No custom filter is registered to convert Markdown → HTML.
2. `base.html.j2:24` — CSS `.ai-slot-body { white-space: pre-wrap; }` preserves literal whitespace/newlines from the Markdown source.
3. Templates use `{{ text }}` or `{{ text | e }}` for AI content — both are auto-escaped.

### Solution

#### Step 1: Add `markdown` dependency

**File:** `backend/requirements.txt`
- Add `markdown>=3.7` (pure Python, no C deps)

#### Step 2: Create Jinja2 `md` filter

**File:** `backend/src/reports/template_env.py`

```python
import markdown as _markdown_lib
from markupsafe import Markup

def _md_filter(text: str) -> Markup:
    """Convert Markdown to safe HTML. Returns Markup to bypass autoescape."""
    if not isinstance(text, str) or not text.strip():
        return Markup("")
    html = _markdown_lib.markdown(
        text,
        extensions=["tables", "fenced_code", "nl2br", "sane_lists"],
        output_format="html",
    )
    return Markup(html)
```

Register in `get_report_jinja_environment()`:
```python
env = Environment(...)
env.filters["md"] = _md_filter
return env
```

**Security note:** AI text is internally generated (not user input), and `autoescape=True` protects other fields. The `Markup()` wrapper is intentional — it tells Jinja2 this HTML is pre-sanitized. If defense-in-depth is desired, add `bleach` or `nh3` sanitization inside `_md_filter` to strip `<script>`, `<iframe>`, etc.

#### Step 3: Update templates — replace `{{ text }}` with `{{ text | md }}`

**Files to update (all `div.ai-slot-body` instances):**

1. `partials/ai_slots.html.j2` (line 9):
   - `{{ text }}` → `{{ text | md }}`

2. `partials/valhalla/sections_01_02_title_executive.html.j2` (lines 16–76):
   - 4 instances of `{{ exec_ai }}`, `{{ breach }}`, `{{ br }}`, `{{ pr }}` → apply `| md`

3. `partials/valhalla/sections_07_08_threat_findings.html.j2` (line 7):
   - `{{ atk }}` → `{{ atk | md }}`

4. `partials/valhalla/section_09_exploit_chains.html.j2` (line 4):
   - `{{ ch }}` → `{{ ch | md }}`

5. `partials/valhalla/sections_10_12_remediation_conclusion.html.j2` (lines 4, 13, 40, 53, 62, 71, 80):
   - 7 instances → apply `| md`

**DO NOT apply `| md` to:**
- `<pre class="ai-slot-body">` blocks (appendices, nmap excerpts) — these are raw text, keep `| e`
- `active_web_scan.html.j2` `{{ row.text | e }}` — these are short AI summary rows
- `{{ active_web_scan.curl_xss_example | e }}` — code example, keep escaped

#### Step 4: Remove `white-space: pre-wrap` from `.ai-slot-body`

**File:** `base.html.j2` (line 24)

```css
/* Before */
.ai-slot-body { margin: 0.25rem 0 0.75rem; white-space: pre-wrap; word-break: break-word; }

/* After */
.ai-slot-body { margin: 0.25rem 0 0.75rem; word-break: break-word; }
.ai-slot-body h1, .ai-slot-body h2, .ai-slot-body h3 { margin: 0.75rem 0 0.25rem; }
.ai-slot-body ul, .ai-slot-body ol { margin: 0.25rem 0 0.5rem 1.25rem; }
.ai-slot-body p { margin: 0.25rem 0; }
```

Keep `white-space: pre-wrap` only for `pre.ai-slot-body` (appendices):
```css
pre.ai-slot-body { white-space: pre-wrap; word-break: break-word; }
```

### Acceptance Criteria

- [ ] AI sections in Valhalla HTML render headings, bold, lists, tables as HTML
- [ ] Appendix `<pre>` blocks remain as pre-formatted text
- [ ] No raw Markdown syntax visible in browser
- [ ] `autoescape=True` still protects non-AI user data
- [ ] Unit test: `_md_filter("**bold**")` returns `<p><strong>bold</strong></p>`

---

## VHQ-002: Deduplicate Findings Before Report

**Priority:** Critical
**Complexity:** Moderate
**Estimated time:** 2–3 hours

### Problem

Same vulnerability appears multiple times in the report (e.g., "Missing Security Headers" from both tool scanning and LLM heuristic inference). The existing `recon/normalization/dedup.py` deduplicates by `finding_type` + `value` for recon intel — but findings stored in DB (and loaded for reporting) are not deduped at the report level.

### Root Cause

- `ReportDataCollector.collect_async()` loads all `Finding` rows for `scan_id` without deduplication.
- `findings_rows_for_jinja()` passes them 1:1 to templates.
- Multiple pipeline phases can create overlapping findings (tool output + LLM analysis + active scan).

### Solution

#### Step 1: Create `backend/src/reports/finding_dedup.py`

```python
"""Report-level finding deduplication (CWE+URL hard-match, title similarity soft-match)."""

from __future__ import annotations
import logging
from difflib import SequenceMatcher
from typing import Any

logger = logging.getLogger(__name__)

TITLE_SIMILARITY_THRESHOLD = 0.85


def _hard_dedup_key(f: Any) -> str | None:
    """CWE + affected URL/asset — exact match. Returns None if both empty."""
    cwe = (getattr(f, "cwe", None) or "").strip().upper()
    url = ""
    poc = getattr(f, "proof_of_concept", None)
    if isinstance(poc, dict):
        url = (poc.get("affected_url") or poc.get("url") or "").strip().lower()
    if not cwe and not url:
        return None
    return f"{cwe}|{url}"


def _title_similarity(a: str, b: str) -> float:
    """Normalized title similarity (0.0–1.0)."""
    a_n = a.strip().lower()
    b_n = b.strip().lower()
    if not a_n or not b_n:
        return 0.0
    return SequenceMatcher(None, a_n, b_n).ratio()


def _severity_rank(sev: str) -> int:
    ranks = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return ranks.get((sev or "").strip().lower(), 0)


def _pick_winner(existing: Any, candidate: Any) -> Any:
    """Keep the finding with higher severity; tie-break by higher CVSS."""
    e_rank = _severity_rank(getattr(existing, "severity", ""))
    c_rank = _severity_rank(getattr(candidate, "severity", ""))
    if c_rank > e_rank:
        return candidate
    if c_rank == e_rank:
        e_cvss = getattr(existing, "cvss", None) or 0.0
        c_cvss = getattr(candidate, "cvss", None) or 0.0
        if c_cvss > e_cvss:
            return candidate
    return existing


def deduplicate_findings_for_report(findings: list[Any]) -> list[Any]:
    """
    Two-pass dedup:
    1. Hard dedup: CWE + URL exact match
    2. Soft dedup: title similarity > 85%
    Winner: higher severity, then higher CVSS.
    """
    # Pass 1: hard dedup
    hard_map: dict[str, Any] = {}
    no_key: list[Any] = []
    for f in findings:
        key = _hard_dedup_key(f)
        if key is None:
            no_key.append(f)
            continue
        if key in hard_map:
            hard_map[key] = _pick_winner(hard_map[key], f)
        else:
            hard_map[key] = f

    after_hard = list(hard_map.values()) + no_key

    # Pass 2: soft dedup by title
    result: list[Any] = []
    for f in after_hard:
        title = (getattr(f, "title", None) or "").strip()
        merged = False
        for i, existing in enumerate(result):
            ex_title = (getattr(existing, "title", None) or "").strip()
            if _title_similarity(title, ex_title) >= TITLE_SIMILARITY_THRESHOLD:
                result[i] = _pick_winner(existing, f)
                merged = True
                break
        if not merged:
            result.append(f)

    removed = len(findings) - len(result)
    if removed > 0:
        logger.info(
            "report_findings_deduped",
            extra={"event": "report_findings_deduped", "removed": removed, "remaining": len(result)},
        )
    return result
```

#### Step 2: Integrate into pipeline

**File:** `backend/src/services/reporting.py`

In `prepare_template_context()` (line ~1340), before `findings_rows_for_jinja(data)`:

```python
from src.reports.finding_dedup import deduplicate_findings_for_report

# Deduplicate before rendering
data.findings = deduplicate_findings_for_report(data.findings)
```

**Also** in `build_ai_input_payload()` (line ~1101), deduplicate before generating AI payloads to avoid repetitive AI text:

```python
data.findings = deduplicate_findings_for_report(data.findings)
```

Or preferably, deduplicate once in `build_context()` (line ~1414) right after `collect_scan_report_data`:

```python
raw = await self.collect_scan_report_data(...)
raw.findings = deduplicate_findings_for_report(raw.findings)
```

This ensures both AI payloads and template context use deduplicated findings.

### Acceptance Criteria

- [ ] Finding with same CWE+URL appearing from tool + LLM → only higher severity instance kept
- [ ] Findings with >85% similar titles merged (winner = higher severity/CVSS)
- [ ] Structured log event `report_findings_deduped` with count
- [ ] Unit tests: hard dedup, soft dedup, winner selection

---

## VHQ-003: Filter Degenerate / Unknown Findings

**Priority:** High
**Complexity:** Simple
**Estimated time:** 1 hour

### Problem

Findings with `title="unknown finding"`, empty `description`, and empty/unknown `severity` appear in the rendered report, polluting the vulnerability table.

### Root Cause

`validate_report_data()` in `report_data_validation.py` (line 94–101) already **detects** such findings but only adds a `finding_unknown_empty` reason code and **fails the entire report generation** rather than filtering them out. It also only catches `break` on the first one.

### Solution

#### Step 1: Create validation filter function

**File:** `backend/src/reports/finding_quality_filter.py`

```python
"""Filter degenerate findings before report rendering (VHQ-003)."""

from __future__ import annotations
import logging
from typing import Any

logger = logging.getLogger(__name__)

_DEGENERATE_TITLES = frozenset({
    "unknown finding",
    "unknown",
    "untitled",
    "n/a",
    "",
})


def is_valid_finding_for_report(f: Any) -> bool:
    """True if the finding has enough substance for report inclusion."""
    title = (getattr(f, "title", None) or "").strip().lower()
    desc = (getattr(f, "description", None) or "").strip()
    sev = (getattr(f, "severity", None) or "").strip().lower()

    # Reject: no title or degenerate title AND no description
    if (not title or title in _DEGENERATE_TITLES) and not desc:
        return False

    # Reject: severity is empty or "unknown" AND no CVSS score
    if (not sev or sev == "unknown"):
        cvss = getattr(f, "cvss", None)
        if cvss is None or cvss == 0.0:
            if not desc:
                return False

    return True


def filter_findings_for_report(findings: list[Any]) -> list[Any]:
    """Remove degenerate findings, log count."""
    valid = [f for f in findings if is_valid_finding_for_report(f)]
    removed = len(findings) - len(valid)
    if removed > 0:
        logger.info(
            "report_findings_filtered",
            extra={"event": "report_findings_filtered", "removed": removed, "remaining": len(valid)},
        )
    return valid
```

#### Step 2: Integrate in pipeline

**File:** `backend/src/services/reporting.py`

In `build_context()` (line ~1414), after dedup (VHQ-002):

```python
from src.reports.finding_quality_filter import filter_findings_for_report

raw = await self.collect_scan_report_data(...)
raw.findings = deduplicate_findings_for_report(raw.findings)
raw.findings = filter_findings_for_report(raw.findings)
```

#### Step 3: Soften validation in `report_data_validation.py`

Change validation behavior from **fail** to **warning** for `finding_unknown_empty`. Lines 94–101 currently cause the whole pipeline to fail. After VHQ-003 pre-filters, this check becomes a safety net. Options:

- Option A: Remove the check (pre-filter handles it).
- Option B: Keep as warning-only (log but don't add to `reasons`).

**Recommended: Option B** — downgrade to `logger.warning()` instead of failing.

### Acceptance Criteria

- [ ] Findings with title="unknown finding" + empty description removed before report render
- [ ] Valid findings with real titles preserved even if severity is "unknown"
- [ ] Structured log event `report_findings_filtered`
- [ ] Validation no longer fails entire pipeline for degenerate findings (soft-handled)
- [ ] Unit test: various edge cases (empty title, unknown severity, valid finding with just title)

---

## VHQ-004: CVSS ↔ Severity Normalization

**Priority:** Critical
**Complexity:** Moderate
**Estimated time:** 1.5–2 hours

### Problem

Findings have CVSS scores that contradict their severity label (e.g., CVSS 7.2 with severity="low"). This creates confusion in the report and undermines trust.

### Root Cause

- `state_machine.py` stores `severity=str(f.get("severity", "info"))[:20]` from LLM/tool JSON verbatim.
- `finding_normalizer.py` has `_severity_rank` / `_rank_to_severity` but only for VA merge logic, not report-level normalization.
- No post-hoc validation that CVSS aligns with severity.

### Solution

#### Step 1: Create normalization function

**File:** `backend/src/reports/finding_severity_normalizer.py`

```python
"""Normalize severity from CVSS score (CVSS v3.x ranges) — VHQ-004."""

from __future__ import annotations
import logging
from typing import Any

logger = logging.getLogger(__name__)

# CVSS v3.1 severity ranges (FIRST standard)
_CVSS_SEVERITY_MAP: list[tuple[float, float, str]] = [
    (0.0, 0.0, "info"),
    (0.1, 3.9, "low"),
    (4.0, 6.9, "medium"),
    (7.0, 8.9, "high"),
    (9.0, 10.0, "critical"),
]


def severity_from_cvss(cvss: float) -> str:
    """Derive severity label from CVSS v3 score."""
    for low, high, label in _CVSS_SEVERITY_MAP:
        if low <= cvss <= high:
            return label
    return "info"


def _severity_rank(sev: str) -> int:
    ranks = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return ranks.get(sev.strip().lower(), 0)


def normalize_finding_severity(f: Any) -> None:
    """
    If CVSS exists and severity contradicts it (off by > 1 tier), override severity with CVSS-derived.
    Mutates the finding in-place.
    """
    cvss = getattr(f, "cvss", None)
    if cvss is None:
        return

    try:
        cvss_f = float(cvss)
    except (TypeError, ValueError):
        return

    if not (0.0 <= cvss_f <= 10.0):
        return

    current_sev = (getattr(f, "severity", None) or "info").strip().lower()
    expected_sev = severity_from_cvss(cvss_f)

    current_rank = _severity_rank(current_sev)
    expected_rank = _severity_rank(expected_sev)

    if abs(current_rank - expected_rank) > 1:
        logger.info(
            "finding_severity_normalized",
            extra={
                "event": "finding_severity_normalized",
                "finding_id": getattr(f, "id", "?"),
                "cvss": cvss_f,
                "old_severity": current_sev,
                "new_severity": expected_sev,
            },
        )
        f.severity = expected_sev


def normalize_findings_severity(findings: list[Any]) -> list[Any]:
    """Apply CVSS-based severity normalization to all findings."""
    for f in findings:
        normalize_finding_severity(f)
    return findings
```

**Policy:** Only override when the mismatch is > 1 tier (e.g., CVSS 7.2 → high, but severity="low" is 2 tiers off → override). A 1-tier tolerance allows for expert judgment (e.g., CVSS 6.8 medium but analyst says "high" for context reasons).

#### Step 2: Integrate in pipeline

**File:** `backend/src/services/reporting.py`

In `build_context()`, after dedup and filter:

```python
from src.reports.finding_severity_normalizer import normalize_findings_severity

raw.findings = deduplicate_findings_for_report(raw.findings)
raw.findings = filter_findings_for_report(raw.findings)
normalize_findings_severity(raw.findings)
```

### Acceptance Criteria

- [ ] CVSS 7.2 + severity="low" → severity overridden to "high"
- [ ] CVSS 6.5 + severity="high" → kept (1-tier tolerance)
- [ ] CVSS 9.5 + severity="medium" → overridden to "critical"
- [ ] Finding without CVSS → severity unchanged
- [ ] Structured log for each normalization event
- [ ] Unit tests for all CVSS ranges and edge cases

---

## VHQ-005: Rewrite AI Prompts for Section Differentiation

**Priority:** High
**Complexity:** Complex
**Estimated time:** 3–4 hours

### Problem

Executive Summary, Threat Modeling (attack scenarios), Zero-day Potential, and Remediation Stages all contain repetitive/overlapping content. The AI rehashes the same findings list in each section instead of addressing unique analytical angles.

### Root Cause

All prompts in `REPORT_AI_USER_TEMPLATES` (prompt_registry.py, lines 494–645) receive the same `{context_json}` payload and don't strongly differentiate the analysis focus. Each template says "use context" but doesn't enforce a distinct analytical lens.

### Solution

**File:** `backend/src/orchestration/prompt_registry.py`

Rewrite 4 key prompts with explicit differentiation directives:

#### 1. `executive_summary_valhalla` (line 583)

**Focus:** Business impact synthesis for leadership. NO technical details, NO individual finding descriptions.

Add explicit directives:
```
CONSTRAINTS:
- Do NOT list individual vulnerabilities or technical details.
- Do NOT repeat content that belongs in attack scenarios, exploit chains, or remediation sections.
- Focus ONLY on: overall security posture, aggregate risk level, business impact themes, and 
  whether the target meets baseline security expectations.
- Structure: 3-5 bullets for key risk themes, then 1 paragraph on posture.
- This section is for C-level / board audience — no CVE IDs, no CWE codes, no parameter names.
```

#### 2. `attack_scenarios` (line 605)

**Focus:** Multi-step attack narratives that CHAIN findings together. NOT a list of individual vulnerabilities.

Add explicit directives:
```
CONSTRAINTS:
- Do NOT simply restate individual findings. Each scenario MUST chain 2+ findings into a 
  realistic attack path (e.g., reconnaissance via exposed tech stack → exploit known CVE → 
  lateral movement via weak session management).
- Structure each scenario as: Attacker profile → Entry point → Exploitation chain → Impact.
- Name each scenario (e.g., "Scenario A: External attacker leveraging outdated dependencies").
- If fewer than 2 findings can be chained, describe the single highest-risk attack path with 
  assumptions clearly labeled.
- Do NOT include remediation advice here — that belongs in remediation_stages.
```

#### 3. `zero_day_potential` (line 637)

**Focus:** Novel exploitation potential and research surface analysis. NOT a restatement of known vulnerabilities.

Add explicit directives:
```
CONSTRAINTS:
- Do NOT restate known CVEs or confirmed findings — those are covered in other sections.
- Focus on: (a) attack surface that could harbor UNKNOWN vulnerabilities (custom code, unusual 
  stack combinations, exposed admin interfaces), (b) outdated components with historically 
  frequent CVE disclosure rates, (c) configuration gaps that could enable novel exploitation.
- Clearly separate: "Known risk (confirmed)" vs "Research surface (speculative)".
- Assess the LIKELIHOOD of zero-day discovery based on component age, exposure, and complexity.
- Do NOT claim zero-days exist — assess potential only.
```

#### 4. `remediation_stages` (line 621)

**Focus:** Prioritized fix plan with 3 clear tiers. NO attack descriptions, NO executive summary content.

Add explicit directives:
```
CONSTRAINTS:
- Structure as EXACTLY 3 horizons with clear deliverables:
  Horizon 1 (0–48h): emergency mitigations (WAF rules, config changes, service disabling)
  Horizon 2 (1–2 weeks): code fixes, patching, dependency updates
  Horizon 3 (1–3 months): architectural improvements, SDLC integration, monitoring
- Each horizon item MUST name a specific finding_id and a concrete action (not "fix the issue").
- Do NOT describe how attacks work — that's in attack_scenarios / exploit_chains.
- Do NOT restate executive summary risk themes — focus on actionable technical steps.
- Include verification steps: how to confirm each fix was effective.
```

#### Also bump prompt versions

All 4 prompts should get new version strings to invalidate Redis cache:
```python
REPORT_AI_PROMPT_VERSIONS[key] = "vhq010-20260402"
```

### Acceptance Criteria

- [ ] Executive summary focuses on business posture, no individual CVE/CWE listings
- [ ] Attack scenarios describe multi-step chains, not finding-by-finding restating
- [ ] Zero-day section analyzes research surface, clearly separates known vs speculative
- [ ] Remediation has exactly 3 horizons with concrete actions per finding_id
- [ ] Minimal content overlap between sections when given the same context payload
- [ ] Prompt versions bumped → Redis cache invalidated
- [ ] Manual test: generate Valhalla report and verify section differentiation

---

## VHQ-006: MinIO Presigned URL Rewrite for Public Access

**Priority:** Medium
**Complexity:** Simple
**Estimated time:** 1 hour

### Problem

Presigned URLs in the HTML report point to Docker-internal hostname (e.g., `http://minio:9000/...`). When the report is opened outside the Docker network (browser, email attachment), artifact links are broken.

### Root Cause

`s3.py:_get_client()` (line 90–93) builds the boto3 endpoint from `settings.minio_endpoint` which is `minio:9000` (Docker service name). `generate_presigned_url` uses this endpoint as the URL base.

### Solution

#### Step 1: Add `minio_public_url` to Settings

**File:** `backend/src/core/config.py`

```python
# Public-facing MinIO URL for presigned links in reports/external access.
# When set, presigned URLs are rewritten from internal endpoint to this base.
# Example: "https://storage.example.com" or "http://localhost:9000"
minio_public_url: str | None = None
```

#### Step 2: Create URL rewriter

**File:** `backend/src/storage/s3.py`

Add function after `get_presigned_url_by_key`:

```python
def rewrite_minio_url_for_report(presigned_url: str) -> str:
    """Replace internal MinIO host with public URL for report embedding."""
    public_base = settings.minio_public_url
    if not public_base or not presigned_url:
        return presigned_url

    internal_endpoint = settings.minio_endpoint
    if not internal_endpoint.startswith("http"):
        scheme = "https" if settings.minio_secure else "http"
        internal_endpoint = f"{scheme}://{internal_endpoint}"

    public_base = public_base.rstrip("/")
    internal_endpoint = internal_endpoint.rstrip("/")

    if presigned_url.startswith(internal_endpoint):
        return presigned_url.replace(internal_endpoint, public_base, 1)

    return presigned_url
```

#### Step 3: Apply in report pipeline

**File:** `backend/src/services/reporting.py`

In `findings_rows_for_jinja()` (line ~476–482), wrap presigned URL:
```python
from src.storage.s3 import rewrite_minio_url_for_report

if url:
    row["poc_screenshot_url"] = rewrite_minio_url_for_report(url)
```

Also in `build_scan_artifacts_section_context()` where `download_url` is set for raw artifacts — apply the same rewrite.

#### Step 4: Add env var to infra

**Files:**
- `infra/.env.example` — add `MINIO_PUBLIC_URL=` with comment
- `infra/.env` — add `MINIO_PUBLIC_URL=` (empty default)

### Acceptance Criteria

- [ ] `MINIO_PUBLIC_URL` not set → URLs unchanged (backward compatible)
- [ ] `MINIO_PUBLIC_URL=https://storage.example.com` → all presigned URLs rewritten
- [ ] PoC screenshot links in HTML report resolve when opened in browser
- [ ] Raw artifact download links in Valhalla appendices resolve
- [ ] Unit test: rewrite logic with various endpoint formats
- [ ] Env var documented in `.env.example`

---

## Architecture Decisions

1. **Markdown library choice:** `markdown` (Python-Markdown) — pure Python, well-maintained, supports tables/fenced_code extensions. Alternative: `mistune` (faster but less extensible). `markdown` is safer for formal reports.

2. **Dedup placement:** In `build_context()` after data collection, before AI payload generation. This ensures both AI text and HTML templates see deduplicated findings.

3. **Severity normalization tolerance:** 1-tier tolerance to respect expert judgment while catching gross mismatches. CVSS v3.1 FIRST standard mapping.

4. **Prompt differentiation strategy:** Explicit `CONSTRAINTS` blocks at the end of each prompt that explicitly forbid content overlap. This is more reliable than vague "focus on X" instructions.

5. **MinIO URL rewrite:** Post-hoc rewrite at report render time (not at storage level) to avoid breaking internal presigned access for APIs.

## Implementation Notes

- All new modules follow existing patterns: structured logging, type hints, no secrets in logs.
- New files: `finding_dedup.py`, `finding_quality_filter.py`, `finding_severity_normalizer.py` in `backend/src/reports/`.
- No DB schema changes required.
- No breaking API changes.
- Prompt version bump invalidates Redis-cached AI sections — first report after deploy will regenerate.

## Progress (updated by orchestrator)
- ⏳ VHQ-001: Markdown → HTML render (Pending)
- ⏳ VHQ-002: Deduplicate findings (Pending)
- ⏳ VHQ-003: Filter degenerate findings (Pending)
- ⏳ VHQ-004: CVSS/severity normalization (Pending)
- ⏳ VHQ-005: AI prompts rewrite (Pending)
- ⏳ VHQ-006: MinIO URL rewrite (Pending)
