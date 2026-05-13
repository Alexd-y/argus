# ARGUS Prompt Registry

> **Documented version**: `kal008-20250327` / `vhq015-20260425`  
> **Last updated**: 2026-05-12  
> **Total prompts**: 67 (60 user templates + 7 distinct system prompts)

---

## 1. Overview

The ARGUS prompt registry spans **60 unique user-prompt templates** and **7 distinct system prompts** across the following categories:

| Category | Count | Description |
|---|---|---|
| Phase Prompts | 6 | Scanning pipeline phases (recon → reporting) |
| JSON Fixer | 1 | Repair malformed LLM JSON output |
| Report AI Sections | 13 | RPT-004 / VHL-003 Celery `ai_text_generation` supplements |
| Signed YAML Agents | 5 | Planner, Critic, Verifier, Reporter, Fixer (validation pipeline) |
| Active Scan Prompts | 2 | AI-assisted OWASP/sandbox tool planning + fixer |
| Specialized Prompts | 3 | Anomaly interpretation, Stage 2 inputs, Exploitability assessment |
| MCP Prompts | 3 | Remediation advisor, vulnerability explainer, severity normalizer |
| Threat Modeling Tasks | 9 | Granular TM sub-tasks per `ThreatModelingAiTask` enum |
| Vulnerability Analysis Tasks | 8 | Granular VA sub-tasks per `_VA_PROMPTS` registry |
| Recon AI Tasks | 8 | Stage 1 enrichment task prompt templates |
| **Total user templates** | **60** | |
| **Total system prompts** | **7** | (3 unique + 4 reused across categories) |

**Primary model**: WhiteRabbitNeo V3 (7B) for pipeline orchestration; `gpt-5.4-medium` for YAML agents.

**Injection mitigations**: All user-provided strings are sanitized via `_sanitize_for_prompt()` — normalised whitespace, truncated at suspicious substrings (jailbreak patterns), capped at 4096 chars (strings) or 65536 chars (objects).

---

## 2. Phase Prompts

Defined in `backend/src/orchestration/prompt_registry.py:134-272`. Each phase uses `SYSTEM_PROMPT_BASE` (line 111) as its system prompt unless otherwise noted.

### 2.1 Reconnaissance

| Field | Value |
|---|---|
| **Phase key** | `recon` |
| **LLM task** | `LLMTask.ORCHESTRATION` |
| **System prompt** | `SYSTEM_PROMPT_BASE` |
| **Template vars** | `target`, `options`, `tool_results` |
| **Expected JSON keys** | `assets`, `subdomains`, `ports` |
| **JSON schema** | `RECON_SCHEMA` (line 310) |

**User prompt highlights**:
- Embeds `KALI_MCP_ORCHESTRATION_BLOCK` — taxonomy and allowlisted binaries for Kali MCP categories
- Instructs LLM to extract ONLY real data from tool output (`nmap`, `dig`, `whois`, etc.)
- Outputs `assets[]`, `subdomains[]`, `ports[]`

### 2.2 Threat Modeling

| Field | Value |
|---|---|
| **Phase key** | `threat_modeling` |
| **LLM task** | `LLMTask.THREAT_MODELING` |
| **System prompt** | `SYSTEM_PROMPT_BASE` |
| **Template vars** | `assets`, `recon_context`, `nvd_data` |
| **Expected JSON keys** | `threat_model` |
| **JSON schema** | `THREAT_MODEL_SCHEMA` (line 320) |

**User prompt highlights**:
- STRIDE-based modeling (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, Elevation of Privilege)
- Requires CVE-to-technology version matching from NVD data
- Output sub-objects: `attack_surface[]`, `threats[]`, `cves[]`, `mitigations[]`

### 2.3 Vulnerability Analysis

| Field | Value |
|---|---|
| **Phase key** | `vuln_analysis` |
| **LLM task** | `LLMTask.ZERO_DAY_ANALYSIS` |
| **System prompt** | `SYSTEM_PROMPT_BASE` |
| **Template vars** | `threat_model`, `assets`, `active_scan_context` |
| **Expected JSON keys** | `findings` |
| **JSON schema** | `VULN_ANALYSIS_SCHEMA` (line 380) |

**User prompt highlights**:
- Embeds both `KALI_MCP_ORCHESTRATION_BLOCK` and `VA_SANDBOX_MCP_RUN_BLOCK`
- Each finding requires: `severity`, `title`, `cwe`, `cvss`, `description`, `affected_asset`, `remediation`, `confidence` (confirmed/likely/possible/advisory), `evidence_type`, `evidence_refs`, `reproducible_steps`, `applicability_notes`
- Active scan findings are incorporated: confirm, correlate, or augment

### 2.4 Exploitation

| Field | Value |
|---|---|
| **Phase key** | `exploitation` |
| **LLM task** | `LLMTask.EXPLOIT_GENERATION` |
| **System prompt** | `SYSTEM_PROMPT_BASE` |
| **Template vars** | `findings` |
| **Expected JSON keys** | `exploits`, `evidence` |
| **JSON schema** | `EXPLOITATION_SCHEMA` (line 409) |

**User prompt highlights**:
- Plans AND validates exploit paths
- Output for each finding: `status` (executed/verified/theoretical), `technique` (MITRE ATT&CK), `tool` (dalfox, xsstrike, sqlmap, nuclei, ffuf, commix), `args[]`, `payload`, `difficulty` (easy/medium/hard)

### 2.5 Post-Exploitation

| Field | Value |
|---|---|
| **Phase key** | `post_exploitation` |
| **LLM task** | `LLMTask.REMEDIATION_PLAN` |
| **System prompt** | `SYSTEM_PROMPT_BASE` |
| **Template vars** | `exploits` |
| **Expected JSON keys** | `lateral`, `persistence` |
| **JSON schema** | `POST_EXPLOITATION_SCHEMA` (line 438) |

**User prompt highlights**:
- Analyzes lateral movement opportunities (`technique`, `description`, `from_exploit`)
- Persistence mechanisms (`type`, `description`, `risk_level`)

### 2.6 Reporting

| Field | Value |
|---|---|
| **Phase key** | `reporting` |
| **LLM task** | `LLMTask.REPORT_SECTION` |
| **System prompt** | `SYSTEM_PROMPT_BASE` (prepended with "Generate all text in English" directive) |
| **Template vars** | `summary` (whole-pipeline dump via `ReportingInput`) |
| **Expected JSON keys** | `report` |
| **JSON schema** | `REPORTING_SCHEMA` (line 459) |

**User prompt highlights**:
- Evidence-bound security assessment report
- Output sections: `summary` (severity counts), `executive_summary`, `sections[]`, `findings_detail[]`, `ai_insights[]`, `risk_rating`

### 2.7 JSON Fixer (cross-phase)

| Field | Value |
|---|---|
| **Phase key** | `_fixer` (invoked automatically on parse failure) |
| **System prompt** | `FIXER_SYSTEM_PROMPT` (line 127) |
| **Template vars** | `invalid_json`, `expected_schema` (serialized) |
| **Retry count** | 1 (`MAX_JSON_RETRIES`) |

**User prompt**: Instructs LLM to fix the invalid JSON to match the expected schema. Returns ONLY the corrected JSON object.

---

## 3. Report AI Sections

Defined in `backend/src/orchestration/prompt_registry.py:502-973`. All 13 sections share a single `REPORT_AI_SYSTEM` (line 552) and per-section `REPORT_AI_USER_TEMPLATES` (line 625). Each section includes a `SECTION CONTEXT` preamble with `SECTION_ID` and `ALREADY WRITTEN SECTIONS` summary (for de-duplication). Prompt version: `vhq015-20260425`.

| # | Section Key | Role Persona | Tier | Description |
|---|---|---|---|---|
| 1 | `executive_summary` | CISO | Standard | 1-2 paragraph severity-bound summary for business stakeholders; exact severity counts; quantified risk metrics |
| 2 | `vulnerability_description` | Application Security Engineer | Standard | Technical root-causes, affected components, exploitation preconditions; XSS rows from `xss_structured` woven in |
| 3 | `remediation_step` | DevSecOps Engineer | Standard | Prioritized fixes by CVSS score; effort estimates [Quick Fix/Moderate/Complex Refactor]; verification commands (curl) |
| 4 | `business_risk` | Risk Management Consultant | Standard | Conditional & proportional business impact tied to validated findings |
| 5 | `compliance_check` | GRC Analyst | Standard | Findings → compliance themes mapping (confidentiality, integrity, availability, privacy) |
| 6 | `prioritization_roadmap` | Security Program Manager | Standard | Near-term vs longer-term roadmap using severity & dependencies |
| 7 | `hardening_recommendations` | Infrastructure Security Architect | Standard | Defense-in-depth config/monitoring/architecture guidance tied to detected stack |
| 8 | `executive_summary_valhalla` | Senior Pentester (Leadership Brief) | Valhalla | Coverage-limited assessment narrative; exact severity distribution; top 3 evidence-backed findings |
| 9 | `attack_scenarios` | Threat Modeling Expert | Valhalla | Validated attack chains (2+ findings) with attacker persona, likelihood, concrete damage |
| 10 | `exploit_chains` | Red Team Operator | Valhalla | Multi-step exploit chains from validated findings with `exploit_demonstrated` evidence |
| 11 | `remediation_stages` | DevSecOps Engineer | Valhalla | 3-tier plan: Tier 1 (48h), Tier 2 (2 weeks), Tier 3 (architectural/SDLC) |
| 12 | `zero_day_potential` | Vulnerability Researcher | Valhalla | Novel vulnerability indication: non-standard attack surfaces, chaining elevation, n-day exposure, manual testing gaps |
| 13 | `cost_summary` | Security Program Manager | Valhalla | Scan economics: findings discovered, noise reduction, LLM cost breakdown |

**REPORT_AI_SYSTEM key constraints** (line 552-623):
- 12 strict rules governing all sections
- Forbidden phrases: "relatively stable", "absence of critical vulnerabilities", "comprehensive penetration test", etc.
- Findings with `evidence_quality` none/weak MUST NOT be called confirmed
- CVSS:3.1 vector strings required alongside scores
- `tech_stack_structured` must be available for stack-tailored remediation

---

## 4. Signed YAML Agent Prompts

Defined in `backend/config/prompts/*.yaml`. These are the validation pipeline agents — each emits structured JSON against a Pydantic `expected_schema_ref`.

| Agent | `prompt_id` | File | Default Model | Temp | Max Tokens | Schema Ref | Purpose |
|---|---|---|---|---|---|---|---|
| **Planner** | `planner_v1` | `planner_v1.yaml:1` | `gpt-5.4-medium` | 0.2 | 4096 | `validation_plan_v1` | Generates a single `ValidationPlanV1` for the next active-scan validation step |
| **Critic** | `critic_v1` | `critic_v1.yaml:1` | `gpt-5.4-medium` | 0.0 | 2048 | `critic_verdict_v1` | Reviews draft plan for risk/scope/policy violations; approves or rejects with reasons |
| **Verifier** | `verifier_v1` | `verifier_v1.yaml:1` | `gpt-5.4-medium` | 0.1 | 6144 | `finding_dto_list_v1` | Classifies tool output + OAST evidence into `FindingDTO` objects |
| **Reporter** | `reporter_v1` | `reporter_v1.yaml:1` | `gpt-5.4-medium` | 0.3 | 6144 | `report_narrative_v1` | Produces executive/technical narrative + recommendations from finding list |
| **Fixer** | `fixer_v1` | `fixer_v1.yaml:1` | `gpt-5.4-medium` | 0.0 | 4096 | (schema-agnostic) | Repairs malformed JSON from another agent without changing semantics |

### Planner key rules
- References payload templates only by `registry_family` (e.g. `web.injection.sqli.v1`) — never inline raw payload bytes
- `raw_payloads_allowed` is locked to false
- `approval_required` must be true for high/destructive risk families
- Hypothesis: one sentence, 8-500 chars

### Critic rejection conditions
- `registry_family` not in tenant's allowed catalog
- `approval_required: false` but plan touches destructive/high-risk family
- Validator tool would produce side-effects outside scope
- Mutation classes contain policy-banned combinations
- Hypothesis references PII or production user accounts

### Verifier constraints
- Confidence: `suspected | likely | confirmed | exploitable`
- `cwe`: non-empty array of positive integers
- `cvss_v3_vector` must be valid 3.x or 4.0 vector
- `status` MUST be `"new"` (persistence layer transitions)
- Max 32 findings per response

### Reporter constraints
- `executive_summary`: 1-4000 chars for non-technical stakeholders
- `technical_summary`: 1-8000 chars with category/CWE/CVSS/confidence per finding
- `recommendations`: up to 16 prioritized, vendor-neutral entries
- No unverified CVE IDs, no invented statistics, no PII

---

## 5. Active Scan Prompts

### 5.1 Active Scan Planning

| Field | Value |
|---|---|
| **System prompt** | `ACTIVE_SCAN_PLANNING_SYSTEM` (line 904) |
| **User template** | `ACTIVE_SCAN_PLANNING_USER_TEMPLATE` (line 920) |
| **Template var** | `bundle_summary_json` (built via `build_active_scan_planning_user_prompt`, line 929) |
| **Prompt version** | `va-plan-kal008-20250327` |

**System prompt highlights**:
- Unrestricted offensive tool usage against in-scope targets in sandbox
- Allowlisted tools: `dalfox, xsstrike, ffuf, sqlmap, nuclei, gobuster, feroxbuster, wfuzz, commix, sstimap, nosqli, graphql-cop, hydra, medusa, nmap, whatweb, nikto, testssl, amass, subfinder, trivy, grype, prowler`
- Output: JSON array of `{tool: string, args: [string]}` objects
- Destructive actions are authorized (sandboxed)
- Avoids duplicating baseline plan scans; returns `[]` if none justified

### 5.2 Active Scan JSON Array Fixer

| Field | Value |
|---|---|
| **System prompt** | `FIXER_SYSTEM_PROMPT` (reused) |
| **User template** | `ACTIVE_SCAN_PLANNING_JSON_ARRAY_FIXER_USER` (line 936) |
| **Template var** | `invalid_fragment` |

Fixes a response that was supposed to be a JSON array of `{tool, args}` objects. Invoked on first parse failure in `active_scan_planner.py:287`.

---

## 6. Specialized Prompts

### 6.1 Anomaly Interpretation

| Field | Value |
|---|---|
| **File:line** | `backend/src/recon/reporting/anomaly_builder.py:50` |
| **Name** | `ANOMALY_PROMPT_TEMPLATE` |
| **Input vars** | `anomalies_json` |
| **Output** | JSON: `{interpretations: [{anomaly_id, significance, hypotheses[]}], summary: string}` |

Role: "security analyst reviewing recon anomalies for threat modeling." Input: Stage 1 anomalies (subdomain enumeration, live host probing, tech fingerprinting). Produces 1-3 hypotheses per anomaly. Rule-based fallback when LLM unavailable.

### 6.2 Stage 2 Inputs

| Field | Value |
|---|---|
| **File:line** | `backend/src/recon/reporting/stage2_builder.py:43` |
| **Name** | `STAGE2_PROMPT_TEMPLATE` |
| **Input vars** | `anomalies_excerpt`, `subdomains_json`, `live_hosts_summary` |
| **Output** | JSON: `{priority_hypotheses[], trust_boundaries[], critical_assets[], entry_points[]}` |

Role: "security architect preparing inputs for threat modeling." Extracts: priority hypotheses (top 3-5), candidate trust boundaries, critical assets, candidate entry points. Rule-based extraction fallback when LLM unavailable.

### 6.3 Exploitability Assessment

| Field | Value |
|---|---|
| **File:line** | `backend/src/orchestration/exploitation_executor.py:264` |
| **Role** | WhiteRabbitNeo assessor |
| **Input** | Finding title, vuln_type, severity, tool, exit_code, stdout, stderr |
| **Output** | JSON: `{exploitable: bool, confidence: 0.0-1.0, rationale: string}` |

System prompt (line 280): "You assess exploitability from pentest tool output. Be conservative: only mark exploitable when clear evidence of successful exploitation exists."

### 6.4-6.6 MCP Prompts

Defined in `backend/src/mcp/prompts/`. These are FastMCP `@mcp.prompt` templates — rendered locally by the LLM client; never call the live API.

| Prompt Name | File:line | System Guidance | Inputs | Purpose |
|---|---|---|---|---|
| `remediation.advisor` | `remediation_advisor.py:16` | ARGUS remediation advisor — safe-by-default, prefer framework fixes, include fix + defense-in-depth + verification | title, severity, stack, evidence_summary, cwe | Step-by-step remediation with pre-deploy verification |
| `vulnerability.explainer` | `vulnerability_explainer.py:16` | ARGUS security analyst — non-jargon explanation for stakeholders, cite CWE/OWASP in plain language | title, severity, description, cwe, owasp_category | 3-paragraph stakeholder-friendly explanation |
| `severity.normalizer` | `severity_normalizer.py:16` | ARGUS severity normalizer — map advisory to CRITICAL/HIGH/MEDIUM/LOW/INFO, CVSS:3.1 vector, OWASP 2025 A01-A10 | advisory_text, impact_hint | Normalize unstructured advisory to canonical severity |

---

## 7. Threat Modeling Task Prompts

Defined in `backend/src/prompts/threat_modeling_prompts.py:3-49`. All 9 tasks map to `ThreatModelingAiTask` enum values from `backend/src/schemas/ai/common.py:22-31`. Each prompt returns valid JSON.

| # | Task Name | File:line | Purpose |
|---|---|---|---|
| 1 | `critical_assets` | `threat_modeling_prompts.py:4` | Identify critical assets from recon data |
| 2 | `trust_boundaries` | `threat_modeling_prompts.py:9` | Identify trust boundaries in target architecture |
| 3 | `attacker_profiles` | `threat_modeling_prompts.py:14` | Define attacker profiles relevant to target |
| 4 | `entry_points` | `threat_modeling_prompts.py:19` | Identify entry points from recon data |
| 5 | `application_flows` | `threat_modeling_prompts.py:24` | Map application data flows between components |
| 6 | `threat_scenarios` | `threat_modeling_prompts.py:29` | Generate threat scenarios from assets, boundaries, entry points |
| 7 | `scenario_scoring` | `threat_modeling_prompts.py:34` | Score threat scenarios by likelihood and impact |
| 8 | `testing_roadmap` | `threat_modeling_prompts.py:39` | Generate prioritized testing roadmap from scored scenarios |
| 9 | `report_summary` | `threat_modeling_prompts.py:44` | Generate executive summary of threat model |

**Default prompt** (line 51): Used when `task_name` doesn't match any defined prompt — "Analyze the provided data and output valid JSON."

---

## 8. Vulnerability Analysis Task Prompts

Defined in `backend/src/prompts/vulnerability_analysis_prompts.py:3-43`. Maps to `_VA_PROMPTS` registry and `VulnerabilityAnalysisAiTask` enum (partial) from `backend/src/schemas/ai/common.py:34-71`.

| # | Task Name | File:line | Purpose |
|---|---|---|---|
| 1 | `evidence_bundle` | `vulnerability_analysis_prompts.py:4` | Organize vulnerability evidence into structured bundles |
| 2 | `contradiction_analysis` | `vulnerability_analysis_prompts.py:9` | Review findings for contradictions and confidence mismatches |
| 3 | `evidence_sufficiency` | `vulnerability_analysis_prompts.py:14` | Evaluate whether evidence supports severity/confidence rating |
| 4 | `confirmation_policy` | `vulnerability_analysis_prompts.py:19` | Apply confirmation policy to determine final finding status |
| 5 | `scenario_mapping` | `vulnerability_analysis_prompts.py:24` | Map findings to threat scenarios, assets, and trust boundaries |
| 6 | `next_phase_gate` | `vulnerability_analysis_prompts.py:29` | Evaluate VA coverage sufficiency to proceed to next phase |
| 7 | `exploitation_candidates` | `vulnerability_analysis_prompts.py:34` | Identify exploitation candidates from confirmed vulnerabilities, ranked by exploitability |
| 8 | `duplicate_correlation` | `vulnerability_analysis_prompts.py:39` | Identify duplicate and related findings; group into clusters |

**Default prompt** (line 46): Used when `task_name` doesn't match — "Analyze the provided data and output valid JSON."

**Additional Vuln Analysis enum values** (not in `_VA_PROMPTS` registry but valid via default prompt):
`active_scan_planning`, `web_scan_planning`, `xss_analysis`, `sqli_analysis`, `nuclei_analysis`, `generic_web_finding`, `validation_target_planning`, `auth_surface_analysis`, `authorization_analysis`, `input_surface_analysis`, `route_and_workflow_analysis`, `api_surface_analysis`, `resource_access_analysis`, `frontend_logic_analysis`, `security_controls_analysis`, `anomalous_host_analysis`, `trust_boundary_validation_analysis`, `business_logic_analysis`, `evidence_bundle_assembly`, `finding_confirmation_assessment`, `finding_to_scenario_mapping`, `remediation_generation`, `stage3_confirmation_summary`.

---

## 9. Recon AI Task Prompt Templates (Stage 1 Enrichment)

Defined in `backend/app/schemas/ai/schema_export.py:62-191`. These 8 tasks produce structured JSON for Stage 1 report enrichment. Each task has a `prompt_template`, Pydantic `input_model` and `output_model` with validation, and persistence mapping.

| # | Task Name | File:line | Prompt Template | Report Section |
|---|---|---|---|---|
| 1 | `js_findings_analysis` | `schema_export.py:66` | "Analyze JavaScript-derived recon findings. Keep only evidence-grounded statements, classify into known categories, and include confidence [0..1] with evidence_refs." | `js_frontend_analysis` |
| 2 | `parameter_input_analysis` | `schema_export.py:82` | "Analyze discovered URL/form/path parameters. Classify each parameter category using allowed enum values and preserve context_url + evidence_refs." | `params_input_surfaces` |
| 3 | `api_surface_inference` | `schema_export.py:98` | "Infer API surface from discovered candidates. Output only enum-safe api_type/auth hints, confidence [0..1], and evidence_refs for non-hypothesis statements." | `api_surface_mapping` |
| 4 | `headers_tls_summary` | `schema_export.py:114` | "Summarize headers/cookies/TLS posture by host. Use strong/moderate/weak enum only and attach evidence_refs for each control statement." | `headers_tls` |
| 5 | `content_similarity_interpretation` | `schema_export.py:130` | "Interpret content and redirect clustering artifacts. Use only allowed interpretation enum values and include confidence + evidence_refs." | `content_routing` |
| 6 | `anomaly_interpretation` | `schema_export.py:146` | "Classify anomalies using approved taxonomy only. Provide bounded confidence and recommended follow-up actions with evidence_refs." | `anomaly_validation` |
| 7 | `stage2_preparation_summary` | `schema_export.py:162` | "Produce Stage-2 preparation summary: prioritized next steps, confidence, and strict evidence_refs linked to Stage-1 artifacts." | `stage2_prep` |
| 8 | `stage3_preparation_summary` | `schema_export.py:178` | "Produce Stage-3 preparation summary from stage3_readiness: prioritized next steps for penetration testing readiness, confidence, and strict evidence_refs linked to Stage-1/2 artifacts." | `stage3_readiness` |

---

## 10. Summary Table

| # | Prompt Name | Category | File:Line | System Prompt | Has User Template | JSON Output | Retry/Fixer |
|---|---|---|---|---|---|---|---|
| 1 | Phase: Recon | Phase | `prompt_registry.py:134` | `SYSTEM_PROMPT_BASE` | Yes (Kali MCP) | `{assets, subdomains, ports}` | Phase fixer |
| 2 | Phase: Threat Modeling | Phase | `prompt_registry.py:152` | `SYSTEM_PROMPT_BASE` | Yes (STRIDE) | `{threat_model: {attack_surface, threats, cves, mitigations}}` | Phase fixer |
| 3 | Phase: Vuln Analysis | Phase | `prompt_registry.py:187` | `SYSTEM_PROMPT_BASE` | Yes (Kali + Sandbox) | `{findings: [...]}` | Phase fixer |
| 4 | Phase: Exploitation | Phase | `prompt_registry.py:220` | `SYSTEM_PROMPT_BASE` | Yes | `{exploits, evidence}` | Phase fixer |
| 5 | Phase: Post-Exploitation | Phase | `prompt_registry.py:244` | `SYSTEM_PROMPT_BASE` | Yes | `{lateral, persistence}` | Phase fixer |
| 6 | Phase: Reporting | Phase | `prompt_registry.py:256` | `SYSTEM_PROMPT_BASE` | Yes | `{report: {summary, executive_summary, sections, findings_detail, ai_insights, risk_rating}}` | Phase fixer |
| 7 | JSON Fixer | Cross-phase | `prompt_registry.py:295` | `FIXER_SYSTEM_PROMPT` | Yes | Matches expected schema | N/A |
| 8 | Report: executive_summary | Report AI | `prompt_registry.py:626` | `REPORT_AI_SYSTEM` | Yes | Prose only | No |
| 9 | Report: vulnerability_description | Report AI | `prompt_registry.py:648` | `REPORT_AI_SYSTEM` | Yes | Prose only | No |
| 10 | Report: remediation_step | Report AI | `prompt_registry.py:666` | `REPORT_AI_SYSTEM` | Yes | Prose only | No |
| 11 | Report: business_risk | Report AI | `prompt_registry.py:697` | `REPORT_AI_SYSTEM` | Yes | Prose only | No |
| 12 | Report: compliance_check | Report AI | `prompt_registry.py:716` | `REPORT_AI_SYSTEM` | Yes | Prose only | No |
| 13 | Report: prioritization_roadmap | Report AI | `prompt_registry.py:728` | `REPORT_AI_SYSTEM` | Yes | Prose only | No |
| 14 | Report: hardening_recommendations | Report AI | `prompt_registry.py:744` | `REPORT_AI_SYSTEM` | Yes | Prose only | No |
| 15 | Report: executive_summary_valhalla | Report AI | `prompt_registry.py:761` | `REPORT_AI_SYSTEM` | Yes | Prose only | No |
| 16 | Report: attack_scenarios | Report AI | `prompt_registry.py:788` | `REPORT_AI_SYSTEM` | Yes | Prose only | No |
| 17 | Report: exploit_chains | Report AI | `prompt_registry.py:813` | `REPORT_AI_SYSTEM` | Yes | Prose only | No |
| 18 | Report: remediation_stages | Report AI | `prompt_registry.py:828` | `REPORT_AI_SYSTEM` | Yes | Prose only | No |
| 19 | Report: zero_day_potential | Report AI | `prompt_registry.py:859` | `REPORT_AI_SYSTEM` | Yes | Prose only | No |
| 20 | Report: cost_summary | Report AI | `prompt_registry.py:885` | `REPORT_AI_SYSTEM` | Yes | Prose only | No |
| 21 | Active Scan Planning | Active Scan | `prompt_registry.py:904` | `ACTIVE_SCAN_PLANNING_SYSTEM` | Yes | `[{tool, args}]` | Array fixer |
| 22 | Active Scan Array Fixer | Active Scan | `prompt_registry.py:936` | `FIXER_SYSTEM_PROMPT` | Yes | JSON array | N/A |
| 23 | Agent: Planner | Agent (YAML) | `planner_v1.yaml:5` | Inline | Yes (`planner_v1.yaml:24`) | `ValidationPlanV1` | Fixer agent |
| 24 | Agent: Critic | Agent (YAML) | `critic_v1.yaml:5` | Inline | Yes (`critic_v1.yaml:32`) | `{approved, reasons, suggested_modifications}` | No |
| 25 | Agent: Verifier | Agent (YAML) | `verifier_v1.yaml:5` | Inline | Yes (`verifier_v1.yaml:37`) | `{findings: [FindingDTO]}` | No |
| 26 | Agent: Reporter | Agent (YAML) | `reporter_v1.yaml:5` | Inline | Yes (`reporter_v1.yaml:25`) | `{executive_summary, technical_summary, recommendations}` | No |
| 27 | Agent: Fixer | Agent (YAML) | `fixer_v1.yaml:5` | Inline | Yes (`fixer_v1.yaml:20`) | Corrected JSON | N/A |
| 28 | Anomaly Interpretation | Specialized | `anomaly_builder.py:50` | Inline (role: security analyst) | Yes (`anomalies_json`) | `{interpretations, summary}` | No |
| 29 | Stage 2 Inputs | Specialized | `stage2_builder.py:43` | Inline (role: security architect) | Yes (`anomalies_excerpt, subdomains_json, live_hosts_summary`) | `{priority_hypotheses, trust_boundaries, critical_assets, entry_points}` | No |
| 30 | Exploitability Assessment | Specialized | `exploitation_executor.py:264` | Inline (conservative assessor) | Inline | `{exploitable, confidence, rationale}` | No |
| 31 | MCP: remediation.advisor | MCP Prompt | `remediation_advisor.py:16` | `_SYSTEM_GUIDANCE` | Yes (rendered args) | Prose bullet list | No |
| 32 | MCP: vulnerability.explainer | MCP Prompt | `vulnerability_explainer.py:16` | `_SYSTEM_GUIDANCE` | Yes (rendered args) | 3-paragraph prose | No |
| 33 | MCP: severity.normalizer | MCP Prompt | `severity_normalizer.py:16` | `_SYSTEM_GUIDANCE` | Yes (rendered args) | `severity / cvss / owasp` lines | No |
| 34-42 | TM: 9 tasks | Threat Modeling | `threat_modeling_prompts.py:3-49` | Inline (role: security analyst) | N/A (prompt IS the template) | Valid JSON (task-specific) | No |
| 43-50 | VA: 8 tasks | Vuln Analysis | `vulnerability_analysis_prompts.py:3-43` | Inline (role: security analyst) | N/A (prompt IS the template) | Valid JSON (task-specific) | No |
| 51-58 | Recon AI: 8 tasks | Recon AI | `app/schemas/ai/schema_export.py:62-191` | N/A (task definitions only) | Prompt template inline | Pydantic-validated JSON | No |

---

## Key Source Files

| File | Purpose |
|---|---|
| `backend/src/orchestration/prompt_registry.py` | Phase prompts, JSON fixer, report AI sections, active scan prompts, sanitization |
| `backend/src/orchestration/ai_prompts.py` | Phase prompt invocation, JSON retry logic, LLM task routing |
| `backend/config/prompts/planner_v1.yaml` | Planner agent system + user prompt |
| `backend/config/prompts/critic_v1.yaml` | Critic agent system + user prompt |
| `backend/config/prompts/verifier_v1.yaml` | Verifier agent system + user prompt |
| `backend/config/prompts/reporter_v1.yaml` | Reporter agent system + user prompt |
| `backend/config/prompts/fixer_v1.yaml` | Fixer agent system + user prompt |
| `backend/src/prompts/threat_modeling_prompts.py` | 9 TM sub-task prompts |
| `backend/src/prompts/vulnerability_analysis_prompts.py` | 8 VA sub-task prompts |
| `backend/app/schemas/ai/schema_export.py` | 8 Recon AI task definitions with prompt templates |
| `backend/src/recon/reporting/anomaly_builder.py` | Anomaly interpretation prompt + rule-based fallback |
| `backend/src/recon/reporting/stage2_builder.py` | Stage 2 input prompt + rule-based fallback |
| `backend/src/orchestration/exploitation_executor.py` | Exploitability assessment prompt |
| `backend/src/mcp/prompts/remediation_advisor.py` | MCP remediation advisor prompt |
| `backend/src/mcp/prompts/vulnerability_explainer.py` | MCP vulnerability explainer prompt |
| `backend/src/mcp/prompts/severity_normalizer.py` | MCP severity normalizer prompt |
| `backend/src/schemas/ai/common.py` | Enum definitions: `ReconAiTask`, `ThreatModelingAiTask`, `VulnerabilityAnalysisAiTask` |
