# ARGUS Pentest Report Enhancement Plan — 100% Evidentiary Quality

**Version:** 1.0  
**Target:** 100/100 Pentest Report  
**WSTG Coverage:** 100% (69 tests, 14 categories)  
**Evidence Quality:** 100%  
**AI Ghosts:** 0  

---

## 1. Evidence Quality Gates

### 1.1 Evidence Gate Definitions

| Gate | Description | Required Evidence |
|------|-------------|-------------------|
| `VALIDATED` | Raw request/response + browser proof | HTTP exchange artifact, Playwright screenshot, test artifact reference |
| `OBSERVED` | Server-side evidence without full exchange | Log entry, response body artifact, tool stdout capture |
| `CANDIDATE` | Indirect evidence requiring manual verification | Tool warning, heuristic match, header-only finding |
| `INCONCLUSIVE` | Insufficient evidence for reporting | No artifact, raw output empty, tool failed |

**Implementation Files:**
- `backend/src/reports/evidence_gates.py` (NEW)
- `backend/src/reports/valhalla_report_context.py` → Add `evidence_gate: Literal["validated", "observed", "candidate", "inconclusive"]` to `ValhallaReportContext`

**Requirements:**
- High/Critical findings MUST be `VALIDATED`
- All XSS, CSRF, Command Injection: `VALIDATED` only
- Template rendering: Show gate badge: 🟢 VALIDATED / 🟠 OBSERVED / 🟡 CANDIDATE / 🔴 INCONCLUSIVE

### 1.2 Evidence Gate Validation Rules

**XSS (VALIDATED requires):**
1. Reflection context: parameter name + payload entered + reflected payload
2. Browser execution: Playwright `evaluate()` returning boolean `true`
3. Screenshot: `.png` artifact reference (s3_key or relative path)
4. Negative control: `<img src=invalid>` or `<script>console.log(0)</script>`
5. Affected parameter: exact query/path/body parameter name
6. PoC URL: Full URL with payload, must be reproducible

**CSRF (VALIDATED requires):**
1. Raw HTML form: `<form action="..." method="POST">` as artifact
2. Raw POST: Exact curl command or body bytes
3. Cookies: `Set-Cookie` header + `Cookie` header pair
4. Origin/Referer: Missing/absent or attacker-controlled
5. Token status: Missing, weak, or absent CSRF token
6. State-changing: POST/PUT/DELETE/PATCH with side effect
7. Negative control: GET request to same endpoint (idempotent)

**Command Injection (VALIDATED requires):**
1. Harmless marker: `id`, `whoami`, `date`, `hostname`
2. Controlled output: predictable command execution result
3. Server-side proof: Network capture, log entry, or file artifact
4. Shell metacharacters: `;`, `|`, `&`, `$(...)`, backtick expansion

---

## 2. Toolset Integration Map

| Tool | Phase | Evidence Gate | Output Artifact Pattern | Missing artifact → AI Ghost Prevention |
|------|-------|---------------|------------------------|----------------------------------------|
| `nmap` | recon | OBSERVED | `tool_nmap_stdout.txt` | "Not assessed: missing artifact `tool_nmap_stdout.txt`" |
| `httpx` | recon | OBSERVED | `tool_httpx_stdout.json` | "Not assessed: missing artifact `tool_httpx_*.json`" |
| `subfinder` | recon | OBSERVED | `tool_subfinder_stdout.txt` | Same pattern |
| `nuclei` | vuln_analysis | VALIDATED | `tool_nuclei_stdout.json` + screenshot | Check for `screenshot_key` in PoC |
| `dalfox` | vuln_analysis | VALIDATED | `tool_dalfox_stdout.json` + browser proof | `verified_via_browser: true` required |
| `sqlmap` | exploitation | VALIDATED | `tool_sqlmap_stdout.json` | `exploit_demonstrated: true` required |
| `testssl.sh` | TLS | VALIDATED | `tool_testssl_stdout.txt` | Parse to `ssl_tls_analysis` |
| `sslscan` | TLS | VALIDATED | `tool_sslscan_stdout.txt` | Parse to `ssl_tls_analysis` |
| `xss_verifier` | POC | VALIDATED | `tool_xss_verifier_screenshot.png` | Browser proof: `verified_via_browser: true` |
| `poc_visual_enrichment` | POC | VALIDATED | `tool_screenshot_*.png` | Screenshot artifact key mapping |

**Missing Artifact Pattern (AI Ghost Prevention):**
```
Not assessed: missing artifact <artifact_key>
Affected section: <section_name>
Tool: <tool_name>
Recommended command: <recovery_command>
```

---

## 3. Section Enhancement Specifications

### 3.1 Evidence Quality Table

**Location:** Report body, after Executive Summary  
**Template:** `templates/reports/partials/valhalla/finding_evidence_gate.html.j2`

**Columns:**
| Finding ID | Severity | Evidence Gate | Validation Status | Required Evidence | Current Evidence | Gaps |
|------------|----------|---------------|-------------------|-------------------|-----------------|------|
| XSS-001 | HIGH | VALIDATED | ✅ Verified |反射+浏览器+截图 | 3/3 | — |
| XSS-002 | HIGH | INVALIDATED | ❌ Missing Browser Proof | Reflection+payload+browser+screenshot+control+param | 2/6 | Browser screenshot artifact key missing |
| SQLI-003 | CRITICAL | CANDIDATE | ⚠️ Requir. Manual | Raw request+response+payload+ PoC URL | 1/5 | No exploit demonstrated artifact |

**Jinja2 Template Structure:**
```jinja2
{# templates/reports/partials/valhalla/finding_evidence_gate.html.j2 #}
<table class="evidence-quality-table">
  <thead>
    <tr>
      <th>Finding ID</th>
      <th>Severity</th>
      <th>Evidence Gate</th>
      <th>Validation Status</th>
      <th>Required Evidence</th>
      <th>Current Evidence</th>
      <th>Gaps</th>
    </tr>
  </thead>
  <tbody>
    {% for f in findings %}
    <tr>
      <td><a href="#{{ f.finding_id }}">{{ f.finding_id }}</a></td>
      <td class="severity-{{ f.severity | lower }}">{{ f.severity }}</td>
      <td>
        <span class="evidence-badge badge-{{ f.evidence_gate | lower }}">
          {{ f.evidence_gate | upper }}
        </span>
      </td>
      <td>
        {% if f.evidence_gate == "validated" %}✅{% elif f.evidence_gate == "observed" %}⚠️{% else %}❌{% endif %}
      </td>
      <td>{{ f.required_evidence_count }} items</td>
      <td>{{ f.current_evidence_count }}/{{ f.required_evidence_count }}</td>
      <td class="evidence-gaps">{{ f.missing_evidence | join(', ') }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
```

---

### 3.2 WSTG Coverage Matrix v4.2

**Location:** Appendix A  
**Template:** `templates/reports/partials/valhalla/wstg_coverage_v2.html.j2`

**Columns:**
| Test ID | Test Name | Category | Tools | Status | Evidence ID | Notes |
|---------|-----------|----------|-------|--------|-------------|-------|
| WSTG-INPV-01 | Reflected XSS | Input Validation | dalfox, playwright | ✅ Covered | EV-XSS-001 | Browser verification |
| WSTG-INPV-05 | SQL Injection | Input Validation | sqlmap | ⚠️ Partial | EV-SQL-001 | No HTTP exchange artifact |
| WSTG-SESS-05 | CSRF | Session Management | — | ❌ Not Assessed | — | "Not assessed: missing artifact `tool_csrf_prober_stdout.txt`" |

**WSTG Coverage Results:**
- **Total Tests:** 69
- **Covered:** 69 (100%)
- **Partial:** 0
- **Not Covered:** 0
- **Evidence IDs:** 69 unique

**AI Ghost Prevention:**
For each uncategorized test:
```
Not assessed: missing artifact <tool_name>_[stdout|stdout.json]
Test ID: WSTG-xxx-xx
Category: <category>
Recommended Command: <recovery_command>
```

**Function Name:** `build_wstg_coverage_v2(tools_executed: list[str], findings: list[dict], evidence_inventory: list[dict]) → dict`

**Fields in Context:**
```python
wstg_coverage_v2 = {
    "summary": {
        "total_tests": 69,
        "covered": 69,
        "partial": 0,
        "not_covered": 0,
        "coverage_pct": 100.0,
        "by_category": {...},
        "missing_artifacts": [
            {"test_id": "WSTG-xxx-xx", "tool": "tool_name", "artifact_hint": "..."},
            ...
        ]
    },
    "tests": [
        {
            "id": "WSTG-INPV-01",
            "name": "Reflected Cross Site Scripting",
            "category": "Input Validation",
            "status": "covered",
            "tools": ["dalfox", "playwright"],
            "evidence_id": "EV-XSS-001",
            "artifacts": ["tool_dalfox_stdout.json", "tool_xss_verifier_screenshot.png"]
        },
        ...
    ]
}
```

---

### 3.3 TLS Analysis Table

**Location:** Infrastructure Security Section  
**Template:** `templates/reports/partials/valhalla/tls_analysis_v2.html.j2`

**Parsing Sources:**
- `testssl.sh` → stdout as JSON or text (parse with `tls_parser_v2.py`)
- `sslscan` → stdout XML or text (parse with `tls_parser_v2.py`)
- `openssl s_client` → PEM chain + protocol negotiation

**Columns:**
| Domain | Certificate Subject | Issuer | Validity | TLS 1.0 | TLS 1.1 | TLS 1.2 | TLS 1.3 | Weak Ciphers | HSTS | Grade |
|--------|---------------------|--------|----------|---------|---------|---------|---------|--------------|------|-------|
| api.example.com | CN=*.example.com | DigiCert | 2025-06-25 | ❌ | ❌ | ✅ | ✅ | 0 | max-age=31536000 | A+ |

**Function:** `parse_tls_analysis(tls_artifacts: list[dict]) → SslTlsAnalysisModel`

**TLS Validation Rules (VALIDATED):**
1. Cert chain: issuer → subject chain (max depth 5)
2. Protocols: list ALL enabled/disabled (TLS 1.0-1.3)
3. Ciphers: list weak ciphers (RC4, DES, 3DES, MD5, export-grade)
4. HSTS: presence + max-age + includeSubDomains + preload
5. Expiry: calculate days remaining from `valid_to`
6. Grade: parse from testssl.sh/sslscan output (A+ to F)

**AI Ghost Prevention:**
```
Not assessed: missing artifact `tool_testssl_stdout.txt`
Tool: testssl.sh
Recommended Command: testssl.sh --protocol --protocols --sigs --chain --hsts --alpn --server-defaults https://<target>
```

---

### 3.4 Security Headers Gap Table

**Location:** Infrastructure Security Section  
**Template:** `templates/reports/partials/valhalla/headers_analysis_v2.html.j2`

**Parsing Source:**
- `curl -sS -D- -o /dev/null` per endpoint (from `headers_parser_v2.py`)
- Extract redirect chain: `curl -sS -I <url> | grep -E '^<'`

**Columns:**
| Endpoint | Status Code | Redirect Chain | Missing Headers | Recommendations | Confidence |
|----------|-------------|-----------------|-----------------|-----------------|------------|
| https://example.com | 200 | example.com → /login (302) | Content-Security-Policy, X-Frame-Options | Add at CDN level | HIGH |
| https://api.example.com/v1 | 401 | — | Strict-Transport-Security | Add at API gateway | MEDIUM |

**Function:** `analyze_headers(endpoints: list[dict]) → FullHeadersContext`

**Security Headers Target:**
- ✅ Content-Security-Policy (CSP)
- ✅ X-Content-Type-Options: nosniff
- ✅ X-Frame-Options: DENY
- ✅ X-XSS-Protection: 1; mode=block
- ✅ Referrer-Policy: strict-origin-when-cross-origin
- ✅ Permissions-Policy
- ✅ Strict-Transport-Security (HSTS)
- ✅ Cache-Control: no-store (for sensitive endpoints)

**AI Ghost Prevention:**
```
Not assessed: missing artifact `tool_httpx_headers_*.json`
Tool: httpx
Recommended Command: httpx -u https://<target> -status-code -head -json -o headers_output.json
```

---

### 3.5 Remediation Matrix v2

**Location:** Remediation Section  
**Template:** `templates/reports/partials/valhalla/remediation_matrix_v2.html.j2`

**Columns:**
| Finding ID | Severity | Category | Layer | Owner Team | Component | Fix Action | Rollback Risk | Verification Command | Acceptance Criteria |
|------------|----------|----------|-------|------------|-----------|------------|---------------|---------------------|---------------------|
| XSS-001 | HIGH | WSTG-INPV-01 | app/frontend | Frontend Team | Next.js Template | Context-aware encoding + CSP | Low | `curl -sS '<poc_url>' \| grep -i '<payload>'` | Payload encoded, console no alert |
| SQLI-003 | CRITICAL | WSTG-INPV-05 | app/database | Backend Team | ORM Layer | Parameterized queries | Medium | `sqlmap --url '<poc_url>' --batch` | No injection points |

**Remediation Matrix Requirements:**
1. **Layer:** infrastructure/reverse-proxy / app/frontend / app/backend / app/database / CI/CD
2. **Owner Team:** Specific team (Frontend / Backend / DevOps / Security)
3. **Component:** Exact config file / directory / code module
4. **Fix Action:** Direct remediation steps (not generic)
5. **Rollback Risk:** Low / Medium / High (with reasoning)
6. **Verification Command:** Exact command for retest (copy-paste ready)
7. **Acceptance Criteria:** Measurable success condition

**Function:** `build_remediation_matrix_v2(findings: list[dict], tech_stack: dict) → list[RemediationMatrixRow]`

**Fields:**
```python
class RemediationMatrixRow(BaseModel):
    finding_id: str
    title: str
    severity: str
    category: str  # WSTG-xxx-xx
    affected_layer: Literal["infrastructure", "app/frontend", "app/backend", "app/database", "CI/CD"]
    owner_team: str
    config_component: str
    fix_action: str
    rollback_risk: Literal["low", "medium", "high"]
    verification_step: str  # Command
    acceptance_criteria: str
    priority: Literal["P0", "P1", "P2", "P3"]
    deadline: str  # e.g., "48 hours", "2 weeks"
    created_at: str
    updated_at: str
    notes: str = ""
```

---

### 3.6 XSS PoC Table

**Template:** `templates/reports/partials/valhalla/finding_xss_poc_v2.html.j2`

**Columns:**
| Parameter | Payload Entered | Payload Reflected | Reflection Context | Browser Verified | Screenshot | Negative Control | Verified via Browser |
|-----------|-----------------|-------------------|-------------------|------------------|------------|------------------|---------------------|
| q | `<script>alert(1)</script>` | `<script>alert(1)</script>` | HTML body | ✅ Yes | `tool_xss_verifier_screenshot_001.png` | `<img src=invalid>` | Playwright evaluate |

**Validation Rules (VALIDATED):**
All 6 fields required. Missing any → downgrade to OBSERVED/CANDIDATE.

**Negative Control Requirements:**
1. Non-executable payload: `<img src=invalid>` or `<script>console.log(0)</script>`
2. Must NOT trigger alert/popup/console.log in control test
3. Must trigger in test payload

**Function:** `build_xss_poc_table(findings: list[dict]) → list[ValhallaXssStructuredRowModel]`

---

### 3.7 CSRF PoC Table

**Template:** `templates/reports/partials/valhalla/finding_csrf_poc_v2.html.j2`

**Columns:**
| Endpoint | Method | State-Changing? | Token Status | Raw HTML Form | Raw POST | Cookies | Origin/Referer | Negative Control | Verified |
|----------|--------|-----------------|--------------|---------------|----------|---------|----------------|------------------|----------|
| /transfer | POST | ✅ Yes | Missing | `<form...action="/transfer"...>` | `curl -X POST -d '...'/transfer` | sessionid=..., auth=... | Missing | GET /transfer (idempotent) | ✅ PoC URL |

**Validation Rules (VALIDATED):**
All 10 fields required. Missing any → downgrade.

**Raw POST Requirements:**
- Exact HTTP request bytes (cURL or raw TCP)
- Must include headers: `Content-Type`, `Cookie`, `Origin` (if present)
- Must show successful state change (e.g., balance change, record creation)

**Function:** `build_csrf_poc_table(findings: list[dict]) → list[dict]`

---

### 3.8 Command Injection PoC Table

**Template:** `templates/reports/partials/valhalla/finding_cmdi_poc_v2.html.j2`

**Columns:**
| Parameter | Payload | Marker Command | Command Output | Server Proof | Output Source | Negative Control | Verified |
|-----------|---------|----------------|----------------|--------------|---------------|------------------|----------|
| host | `;id` | id | uid=1000(app) | Log entry /net/packets/curl_*.log | stdout | `;hostname` → invalid command | ✅ PoC |

**Validation Rules (VALIDATED):**
1. Harmless marker: `id`, `whoami`, `date`, `hostname`, `pwd`, `who`
2. Predictable output: The exact command must execute with expected result
3. Server-side proof: Log file, stdout capture, file artifact
4. Negative control: Non-executive payload (e.g., `hostname` which fails but doesn't execute)

**Function:** `build_cmdi_poc_table(findings: list[dict]) → list[dict]`

---

## 4. Technical Implementation Tasks

### 4.1 New Files to Create

| File | Purpose | Priority |
|------|---------|----------|
| `backend/src/reports/evidence_gates.py` | Evidence gate definitions, validation functions | HIGH |
| `backend/src/reports/wstg_coverage_v2.py` | WSTG v4.2 100% coverage mapper | HIGH |
| `backend/src/reports/tls_parser_v2.py` | Parse testssl.sh/sslscan/openssl → SslTlsAnalysisModel | HIGH |
| `backend/src/reports/headers_parser_v2.py` | Parse curl headers → FullHeadersContext | HIGH |
| `backend/src/reports/remediation_matrix.py` | Build 16-column remediation matrix (enriched) | HIGH |
| `backend/src/reports/poc_validation.py` | XSS/CSRF/Command Injection validation rules | HIGH |
| `backend/src/reports/authenticated_testing.py` | Authenticated testing context, IDOR, session hijacking | HIGH |
| `backend/src/reports/retest_manager.py` | Retest verification commands, acceptance criteria | MEDIUM |
| `templates/reports/partials/valhalla/findings/findings_evidence_gate.html.j2` | Evidence quality table template | HIGH |
| `templates/reports/partials/valhalla/tls_analysis_v2.html.j2` | TLS summary table template | HIGH |
| `templates/reports/partials/valhalla/headers_analysis_v2.html.j2` | Security headers gap table template | HIGH |
| `templates/reports/partials/valhalla/remediation_matrix_v2.html.j2` | Remediation matrix template | HIGH |
| `templates/reports/partials/valhalla/wstg_coverage_v2.html.j2` | WSTG coverage matrix template | HIGH |
| `templates/reports/partials/valhalla/findings/finding_xss_poc_v2.html.j2` | XSS PoC table template | HIGH |
| `templates/reports/partials/valhalla/findings/finding_csrf_poc_v2.html.j2` | CSRF PoC table template | HIGH |
| `templates/reports/partials/valhalla/findings/finding_cmdi_poc_v2.html.j2` | Command injection PoC table template | HIGH |

---

### 4.2 Enhancement to Existing Files

**File: `backend/src/reports/valhalla_report.py`**

**Tasks:**
1. Add `evidence_gate` field to `ValhallaReportContext`:
   ```python
   evidence_gate: Literal["validated", "observed", "candidate", "inconclusive"] = "candidate"
   ```
2. Add evidence gate calculation for each finding in `build_valhalla_context()`:
   ```python
   f["evidence_gate"] = "validated" if all(
       f.get("proof_of_concept", {}).get(k) for k in required_fields
   ) else "observed"
   ```
3. Add XSS, CSRF, Command Injection PoC enrichment in `build_valhalla_context()`:
   ```python
   xss_structured: list[dict[str, Any]] = Field(default_factory=list)
   csrf_structured: list[dict[str, Any]] = Field(default_factory=list)
   cmdi_structured: list[dict[str, Any]] = Field(default_factory=list)
   ```

**File: `backend/src/reports/valhalla_report_context.py`**

**Tasks:**
1. Add new data models (if not present):
   - `XssPocValidationModel`
   - `CsrfPocValidationModel`
   - `CmdiPocValidationModel`
2. Add `missing_artifacts` field to `ValhallaSectionEnvelopeModel`:
   ```python
   missing_artifacts: list[str] = Field(default_factory=list)
   ```

**File: `backend/src/reports/wstg_coverage.py`**

**Tasks:**
1. Add WSTG v4.2 69 tests (already present in `_WSTG_TESTS`)
2. Add tool-to-WSTG mapping for argus_recon, argus_active_scan, playwright
3. Add `build_wstg_coverage_v2()` function with missing artifact tracking:
   ```python
   def build_wstg_coverage_v2(tools_executed: list[str], findings: list[dict]) → dict:
       # ...
       "missing_artifacts": [
           {"test_id": "WSTG-xxx-xx", "tool": "tool_csrf_prober", "hint": "..."}
       ]
   ```

**File: `backend/src/reports/template_env.py`**

**Tasks:**
1. Add new template directory mapping:
   ```python
   JINJA2_TEMPLATES = {
       "valhalla/partials": "templates/reports/partials/valhalla",
       "valhalla/partials/findings": "templates/reports/partials/valhalla/findings",
   }
   ```

---

### 4.3 Jinja2 Template Structure

**Directory Layout:**
```
templates/reports/partials/valhalla/
├── finding_evidence_gate.html.j2
├── tls_analysis_v2.html.j2
├── headers_analysis_v2.html.j2
├── remediation_matrix_v2.html.j2
├── wstg_coverage_v2.html.j2
├── findings/
│   ├── finding_xss_poc_v2.html.j2
│   ├── finding_csrf_poc_v2.html.j2
│   └── finding_cmdi_poc_v2.html.j2
└── table_styles.css.j2 (shared CSS for tables)
```

**Template Naming Convention:**
- `finding_*.html.j2`: Individual finding tables (per severity)
- `*_analysis_v2.html.j2`: Section-level analysis (TLS, headers, WSTG)
- `_*.html.j2`: partials only (no standalone rendering)

---

## 5. AI Proofing Rules

### 5.1 Missing Artifact Detection

**Rule 1:** Every section must report missing artifacts with:
```
Not assessed: missing artifact <artifact_key>
Affected section: <section_name>
Tool: <tool_name>
Recommended Command: <recovery_command>
```

**Rule 2:** For each WSTG test not covered:
```
Not assessed: missing artifact <tool_name>_[stdout|stdout.json]
Test ID: WSTG-xxx-xx
Category: <category>
Recommended Command: <recovery_command>
```

**Rule 3:** For each finding below VALIDATED:
```
Evidence gate: <current_gate>
Required gate: VALIDATED
Missing evidence: <list of missing items>
```

### 5.2 CSP/HSTS Specificity

**Per Infrastructure Layer:**

**CDN (CloudFront/Akamai):**
- CSP: `Content-Security-Policy: default-src 'none'; script-src 'nonce-...' 'unsafe-inline' 'unsafe-eval'`
- HSTS: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`

**Application Server (nginx/Apache):**
- CSP: `Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'`
- HSTS: `Strict-Transport-Security: max-age=31536000; includeSubDomains`

**API Gateway (Kong/Apigee):**
- CSP: `Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'`
- HSTS: `Strict-Transport-Security: max-age=86400`

**AI Ghost Prevention:**
```
Not assessed: missing artifact <artifact_key>
Affected layer: infrastructure/reverse-proxy
Configuration location: <CDN settings / nginx.conf / Kong plugin>
```

---

## 6. Sign-Off Criteria Checklist

| Criterion | Status | Evidence |
|-----------|--------|----------|
| **100/100 Pentest Report** | ✅ / ⭕ | Report quality gate: `report_quality_gate: {"score": 100, "total": 100}` |
| **100% WSTG Coverage** | ✅ / ⭕ | WSTG coverage: 69/69 tests covered (100%) |
| **100% Evidence Quality** | ✅ / ⭕ | All High/Critical findings: `evidence_gate: "validated"` |
| **0 AI Ghosts** | ✅ / ⭕ | Missing artifacts tracked with recommended test commands |
| **Specific Remediation** | ✅ / ⭕ | 16-column remediation matrix with ownership, layer, component |
| **Authenticated Testing** | ✅ / ⭕ | Session, token, MFA, IDOR tested (context in `auth_testing`) |
| **TLS/Headers Parsed** | ✅ / ⭕ | `testssl.sh`/`sslscan` parsed → `SslTlsAnalysisModel` |
| **Browser Proof** | ✅ / ⭕ | XSS, CSRF confirmed via Playwright screenshot artifacts |
| **Negative Controls** | ✅ / ⭕ | Each XSS/CSRF/Command Injection has negative control payload |

---

## 7. Implementation Roadmap

### Phase 1: Evidence Gate Foundation (Week 1)
- [ ] Create `evidence_gates.py`
- [ ] Add `evidence_gate` field to context models
- [ ] Implement validation functions (XSS, CSRF, Command Injection)
- [ ] Write unit tests for gate logic

### Phase 2: WSTG 100% Coverage (Week 1-2)
- [ ] Update `wstg_coverage.py` with 69 tests
- [ ] Add missing artifact tracking
- [ ] Create `wstg_coverage_v2.html.j2` template
- [ ] Integrate into `valhalla_report_context.py`

### Phase 3: TLS & Headers Parsing (Week 2)
- [ ] Create `tls_parser_v2.py`
- [ ] Create `headers_parser_v2.py`
- [ ] Parse testssl.sh/sslscan/openssl
- [ ] Create `tls_analysis_v2.html.j2`, `headers_analysis_v2.html.j2`
- [ ] Add `ssl_tls_analysis`, `security_headers_analysis` to context

### Phase 4: Remediation Matrix v2 (Week 3)
- [ ] Create `remediation_matrix.py`
- [ ] Implement 16-column matrix (layer, owner, component, fix, rollback, verification, acceptance)
- [ ] Create `remediation_matrix_v2.html.j2`
- [ ] Enrich with tech stack hints

### Phase 5: PoC Tables (Week 3-4)
- [ ] Create `poc_validation.py`
- [ ] Create XSS/CSRF/Command Injection PoC tables
- [ ] Implement negative control validation
- [ ] Add browser verification artifact keys
- [ ] Create Jinja2 templates

### Phase 6: Authenticated Testing (Week 4)
- [ ] Create `authenticated_testing.py`
- [ ] Implement session, token, MFA, IDOR testing context
- [ ] Add auth matrix to context
- [ ] Create IDOR testing rows

### Phase 7: Retest Manager (Week 4-5)
- [ ] Create `retest_manager.py`
- [ ] Generate verification commands for each finding
- [ ] Implement acceptance criteria per category
- [ ] Add retest timeline and methodology

### Phase 8: AI Proofing & Templates (Week 5)
- [ ] Implement missing artifact detection rules
- [ ] Create missing artifact templates
- [ ] Add CSP/HSTS per layer guidance
- [ ] Review and validate all templates

### Phase 9: Integration & Testing (Week 5-6)
- [ ] Integrate all modules into `valhalla_report_context.py`
- [ ] Run full test suite on sample scans
- [ ] Validate evidence gates against real findings
- [ ] Perform end-to-end report generation
- [ ] Sign-off: 100/100 criteria check

---

## 8. Acceptance Criteria

### 8.1 Report Quality Gate
```python
def validate_report_for_valhalla(context: ValhallaReportContext) -> dict:
    return {
        "score": 100 if all([
            len(context.wstg_coverage["tests"]) == 69,
            all(f.get("evidence_gate") == "validated" for f in context.findings if f.get("severity") in ("critical", "high")),
            len(context.missing_artifacts) == 0,
            all(
                all(
                    field in xss for field in ("payload_entered", "payload_reflected", "verified_via_browser", "screenshot", "negative_control", "parameter")
                ) for xss in context.xss_structured
            ),
            all(
                all(
                    field in remed for field in ("affected_layer", "owner_team", "config_component", "fix_action", "rollback_risk", "verification_step", "acceptance_criteria")
                ) for remed in context.remediation_matrix
            ),
        ]) else 0,
        "total": 100,
        "details": {...}
    }
```

### 8.2 Sign-Off Checklist (Automated)
- [ ] All Critical/High findings have `evidence_gate: "validated"`
- [ ] WSTG coverage: 69/69 tests (100%)
- [ ] No missing artifacts in evidence inventory
- [ ] All XSS PoCs include browser verification + screenshot + negative control + parameter
- [ ] All CSRF PoCs include raw form, raw POST, cookies, Origin/Referer, token status, state-changing, negative control
- [ ] All Command Injection PoCs include harmless marker, controlled output, server proof, negative control
- [ ] TLS analysis includes cert chain, protocols, ciphers, HSTS, expiry, grade
- [ ] Headers analysis includes endpoint, redirect chain, missing headers per endpoint
- [ ] Remediation matrix includes layer, owner, component, fix, rollback risk, verification, acceptance criteria
- [ ] Authenticated testing context populated (session, token, MFA, IDOR)
- [ ] No AI ghosts (all sections have evidence or explicit "Not assessed" messages)

---

**Document Status:** ✅ Draft  
**Next Review:** Post implementation, Week 6  
**Version Control:** ARGUS/git#REPORT_ENHANCEMENT_PLAN.md  
**Owner:** ARGUS Engineering Team
