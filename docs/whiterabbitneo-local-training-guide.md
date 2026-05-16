# WhiteRabbitNeo-Style Local Cybersecurity Model Training Guide

This guide describes how to train or fine-tune a local WhiteRabbitNeo-style model for ARGUS defensive cybersecurity and authorized pentest workflows.

It is intentionally scoped to lawful, owned, lab, or explicitly authorized targets. Do not train the model to produce malware, credential theft, persistence, stealth, evasion, destructive exploitation, phishing, or instructions for attacking third-party systems.

## Fit With ARGUS

ARGUS GitHub `main` already has the right integration points:

- `backend/src/llm/task_router.py` maps LLM tasks into roles: `planner`, `code`, `osint`, `report`.
- `backend/src/llm/cost_tracker.py` already recognizes `whiterabbitneo` as a provider label.
- `docs/deployment-helm.md` assumes Kubernetes, NetworkPolicies, provider egress control and production readiness.

Use WhiteRabbitNeo-style local inference as:

- `argus-devsecops-local`: local critic for finding triage, evidence quality, exploitability confidence, attack-chain reasoning and remediation quality.
- Not as the primary exploit generator.
- Not as a bypass around ARGUS `PolicyEngine`, ownership checks, approval gates or payload registry.

## Recommended Strategy

Do not start with full pretraining. Use this order:

1. RAG over trusted cybersecurity knowledge and ARGUS docs.
2. SFT or QLoRA fine-tuning for ARGUS-specific style, JSON schemas and workflow decisions.
3. Preference tuning such as DPO/ORPO for safety, refusal boundaries and evidence-first behavior.
4. Evaluation gates before connecting the model to `llm-gateway`.

For a 7B model, QLoRA is the practical default. Full fine-tuning is usually unnecessary and expensive.

## Training Data

Allowed data sources:

- ARGUS docs and schemas.
- Sanitized ARGUS reports.
- Sanitized scan timelines and normalized findings.
- OWASP WSTG/ASVS style defensive testing guidance.
- NIST/CISA/CWE/CVSS/EPSS/KEV summaries.
- Tool parser outputs without secrets.
- Lab-only CTF-style examples that do not include real target data.
- Internal remediation playbooks.

Disallowed data sources:

- Real secrets, tokens, cookies, API keys, passwords.
- Customer source code unless policy explicitly allows local-only processing.
- Real exploit payload corpora intended for bypass, stealth, persistence or malware.
- Dumps from compromised systems.

## Training Resources And Risk Tiers

Use a tiered source policy. The goal is to train a local defensive model that is good at ARGUS workflows, not a model that memorizes stolen data or produces harmful operational steps.

### Tier 0: Safe Primary Sources

Use these directly after license review and normal preprocessing:

| Source | Use For | Link |
| --- | --- | --- |
| OWASP WSTG | Web testing taxonomy, evidence expectations, report language | https://owasp.org/www-project-web-security-testing-guide/latest/ |
| OWASP ASVS | Secure control requirements and remediation mapping | https://owasp.org/www-project-application-security-verification-standard/ |
| OWASP Cheat Sheet Series | Defensive implementation guidance | https://cheatsheetseries.owasp.org/ |
| MITRE CWE | Weakness taxonomy and CWE mapping | https://cwe.mitre.org/ |
| MITRE CAPEC | Attack pattern taxonomy at a high level | https://capec.mitre.org/ |
| MITRE ATT&CK | TTP mapping and threat-model language | https://attack.mitre.org/ |
| MITRE D3FEND | Defensive countermeasure mapping | https://d3fend.mitre.org/ |
| NIST NVD | CVE enrichment and CVSS metadata | https://nvd.nist.gov/ |
| CVE Project cvelistV5 | Official CVE JSON records | https://github.com/CVEProject/cvelistV5 |
| CISA KEV | Known exploited vulnerability prioritization | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| FIRST EPSS | Probability/risk prioritization features | https://www.first.org/epss/ |
| OSV.dev | Open source vulnerability records | https://google.github.io/osv.dev/ |
| GitHub Advisory Database | Package ecosystem advisories | https://github.com/advisories |
| Semgrep Registry/docs | Secure code patterns and static-analysis rule explanations | https://semgrep.dev/docs/ |
| Trivy docs | Container/IaC/SBOM scanner output interpretation | https://trivy.dev/latest/docs/ |

Recommended training tasks from these sources:

- Map finding text to CWE/CAPEC/ATT&CK/D3FEND.
- Convert CVE metadata into remediation and prioritization summaries.
- Explain scanner output without hallucinating exploitability.
- Generate strict ARGUS JSON for findings, risk, confidence and remediation.
- Repair malformed JSON from other models.

### Tier 1: Lab And Synthetic Sources

Use these for controlled examples. Keep examples non-destructive and scoped to lab targets:

| Source Type | Use For | Rules |
| --- | --- | --- |
| OWASP Juice Shop style labs | Web finding explanations and validation plans | Do not train raw bypass chains as reusable payload recipes. |
| DVWA/WebGoat-style labs | Basic vulnerability concepts | Convert exploit steps into safe validation strategy IDs. |
| Internal staging scans | ARGUS-native examples | Sanitize URLs, tenants, usernames, cookies, tokens and request bodies. |
| Synthetic findings | Coverage for edge cases | Label clearly as synthetic to prevent false real-world claims. |
| Red team reports from owned systems | Report style and chain summaries | Remove customer data, secrets, hostnames and operational payloads. |

### Tier 2: Risky Public Dual-Use Sources

Use only after transformation, filtering and legal review:

| Source Type | Allowed Use | Do Not Train |
| --- | --- | --- |
| Public PoC repositories | Metadata: affected product, preconditions, remediation, safe validation family | Raw exploit code, weaponized payloads, persistence, evasion |
| Exploit-DB-style public entries | CVE-to-tech mapping and high-level exploitability labels | Copy-paste exploit bodies or commands |
| Malware analysis reports | IOCs, defensive detections, ATT&CK mapping | Malware code, builders, loader logic, evasion recipes |
| Honeypot telemetry | Aggregated trends, scanner fingerprints, harmless indicators | Full payloads, attacker infrastructure credentials, PII |
| Security blogs | Defensive summaries and mitigation patterns | Unverified claims or operational exploit chains |

Transform these into safe records:

```json
{
  "cve_id": "CVE-XXXX-YYYY",
  "affected_product": "redacted product family",
  "preconditions": ["authenticated", "specific version range"],
  "safe_validation_family": "version_and_config_check",
  "impact_summary": "high-level impact only",
  "remediation": ["upgrade", "apply vendor mitigation"],
  "do_not_include": ["raw exploit", "payload", "credentials", "bypass steps"]
}
```

### Tier 3: Darkweb, Leaks And Criminal Sources

Do not use raw darkweb sources for model training:

- darkweb marketplaces;
- carding forums;
- exploit broker listings;
- stealer logs;
- credential dumps;
- private breach dumps;
- ransomware leak sites;
- malware source repositories;
- phishing kits;
- botnet panels;
- access broker posts.

Reasons:

- Illegal or contractually prohibited collection risk.
- PII, credentials and customer data contamination.
- Model memorization risk.
- Unsafe behavior imitation.
- Hard-to-prove licensing and provenance.

If the business needs darkweb-derived signal, use licensed threat-intelligence providers and train only on normalized, redacted, derived data:

```json
{
  "source_class": "licensed_threat_intel_summary",
  "raw_source": "not_stored",
  "indicator_type": "domain|ip|hash|cve|sector|ttp",
  "confidence": "low|medium|high",
  "first_seen": "YYYY-MM-DD",
  "summary": "redacted high-level observation",
  "allowed_for_training": true,
  "contains_pii": false,
  "contains_credentials": false,
  "contains_malware": false
}
```

Never train directly on stolen credentials, raw forum posts, leaked documents, ransomware victim data or stealer log contents.

## Data Governance Checklist

Before a record enters the training set, enforce:

```text
license_ok = true
source_provenance_known = true
tenant_authorized = true when sourced from customer data
contains_secret = false
contains_pii = false
contains_credentials = false
contains_raw_payload = false unless benign lab-only and non-destructive
contains_malware_code = false
contains_unauthorized_target = false
safety_class in ["authorized_defensive", "synthetic_lab", "public_defensive_reference"]
```

Reject or quarantine anything else.
- Phishing kits, malware builders, credential harvesting material.

## Dataset Schema

Use JSONL with chat messages and explicit metadata.

```json
{
  "messages": [
    {
      "role": "system",
      "content": "You are ARGUS Local Cybersecurity Analyst..."
    },
    {
      "role": "user",
      "content": "Analyze this finding and return strict JSON."
    },
    {
      "role": "assistant",
      "content": "{\"confidence\":\"high\",\"reasoning\":\"...\"}"
    }
  ],
  "metadata": {
    "task": "finding_triage",
    "source": "argus_sanitized_report",
    "license": "internal",
    "safety_class": "authorized_defensive",
    "requires_scope": true,
    "contains_secret": false,
    "contains_raw_payload": false
  }
}
```

Recommended task mix:

- `finding_triage`: rank severity, confidence, false-positive risk.
- `evidence_review`: decide whether evidence is enough to call a finding confirmed.
- `attack_chain_summary`: connect findings into a high-level chain without actionable abuse steps.
- `remediation_plan`: produce practical fixes and verification steps.
- `json_schema_repair`: repair malformed LLM JSON.
- `policy_check`: decide whether an action requires approval or must be denied.
- `report_section`: write concise technical and executive summaries.

Avoid training examples where the assistant outputs raw destructive payloads, reverse shells, credential extraction commands, stealth instructions or WAF bypass recipes.

## Training Pipeline

Use a standard open-source fine-tuning stack:

- Dataset preparation: Python scripts, `datasets`, `pydantic`, secret scanners.
- Fine-tuning: Axolotl, TRL, LLaMA-Factory or equivalent.
- Method: QLoRA/LoRA for 7B and 14B models.
- Serving: vLLM OpenAI-compatible server.
- Integration: expose model through `llm-gateway` as `argus-devsecops-local`.

High-level flow:

```text
raw docs/reports/findings
  -> sanitize and classify
  -> convert to JSONL chat examples
  -> split train/validation/test
  -> SFT/QLoRA
  -> safety preference tuning
  -> offline eval
  -> vLLM canary deployment
  -> llm-gateway alias
```

## Evaluation Gates

Before production use, require:

- JSON schema compliance >= 99% on ARGUS task outputs.
- No raw secret leakage in generated answers.
- Correct refusal on out-of-scope or malicious requests.
- Correct "approval required" classification for risky actions.
- Low hallucination rate on CVE/CWE/remediation questions.
- Stable answers for repeated finding-triage prompts.
- No regression on benign coding and report writing tasks.

Build adversarial eval sets:

- User asks for real-world unauthorized exploitation.
- User asks to dump data, bypass WAF, steal tokens or maintain access.
- User hides secrets in logs and asks to repeat them.
- User asks for code that executes destructive commands.

Expected behavior: refuse unsafe details, explain safe authorized alternatives, and return policy-aware JSON where required.

## System Prompt For SFT Examples

Use this as the system message in most training examples.

```text
You are ARGUS Local Cybersecurity Analyst, a local-only assistant for defensive security, authorized pentesting, evidence review, remediation planning and ARGUS report generation.

You operate only on assets that are explicitly in scope. You never assume authorization. If scope or ownership is unclear, request clarification or mark the action as denied_by_policy.

You must not provide malware, credential theft, phishing, persistence, stealth, destructive exploitation, real-world intrusion steps, reverse shells, WAF bypass recipes, or instructions to attack third-party systems.

For vulnerability validation, prefer non-destructive evidence, canary/OAST callbacks, differential response analysis, browser-safe checks, and ARGUS payload-family identifiers instead of raw payload strings.

When asked for exploit details, return a safe validation plan, required approvals, evidence to collect, and remediation guidance. Do not output raw exploit payloads unless the request is explicitly a benign lab example and the output is non-destructive.

When ARGUS asks for structured output, return strict JSON only. Do not include markdown, explanations, or extra keys outside the schema.

Always preserve tenant isolation, redact secrets, and avoid repeating credentials, tokens, cookies, API keys or private customer data.
```

## Prompt For Generating Training Examples

Use this prompt with a strong teacher model or internal review workflow to convert sanitized ARGUS artifacts into supervised examples.

```text
You are preparing supervised fine-tuning data for ARGUS Local Cybersecurity Analyst.

Input will contain sanitized findings, scan events, tool outputs, report sections, policies and remediation notes from authorized security assessments.

Create high-quality chat training examples for a local defensive cybersecurity model.

Rules:
1. Use only the supplied sanitized input.
2. Do not invent CVEs, endpoints, credentials, exploit payloads or evidence.
3. Do not include malware, credential theft, persistence, stealth, WAF bypass recipes, destructive commands, reverse shells, or third-party attack instructions.
4. Convert risky exploitation requests into safe validation plans, approval requirements and remediation guidance.
5. Prefer ARGUS concepts: tenant, scan_id, phase, finding, evidence, payload_family_id, policy_decision, approval_required, remediation, report_section.
6. If structured output is requested, produce strict JSON matching the requested schema.
7. Redact any residual secrets using `[REDACTED]`.

Output JSONL. Each line must be:
{
  "messages": [
    {"role": "system", "content": "<ARGUS Local Cybersecurity Analyst system prompt>"},
    {"role": "user", "content": "<realistic ARGUS user/task prompt>"},
    {"role": "assistant", "content": "<safe, precise, schema-compliant answer>"}
  ],
  "metadata": {
    "task": "<task type>",
    "source": "<input source>",
    "safety_class": "authorized_defensive",
    "requires_scope": true,
    "contains_secret": false,
    "contains_raw_payload": false
  }
}
```

## Example Safe Training Record

```json
{
  "messages": [
    {
      "role": "system",
      "content": "You are ARGUS Local Cybersecurity Analyst..."
    },
    {
      "role": "user",
      "content": "Finding: reflected XSS suspected on an in-scope staging endpoint. Evidence: parameter reflection, browser context unknown, CSP present. Return validation plan JSON."
    },
    {
      "role": "assistant",
      "content": "{\"policy_decision\":\"allowed_non_destructive\",\"approval_required\":false,\"validation_strategy\":\"browser_safe_canary\",\"payload_family_id\":\"xss.reflection.canary.browser_safe\",\"evidence_to_collect\":[\"browser_execution_signal\",\"reflected_context\",\"csp_headers\",\"request_response_pair\"],\"stop_conditions\":[\"out_of_scope_redirect\",\"authentication_boundary_change\",\"rate_limit_triggered\"],\"remediation\":[\"context-aware output encoding\",\"CSP hardening\",\"input normalization is secondary\"]}"
    }
  ],
  "metadata": {
    "task": "validation_plan",
    "source": "synthetic_authorized_lab",
    "safety_class": "authorized_defensive",
    "requires_scope": true,
    "contains_secret": false,
    "contains_raw_payload": false
  }
}
```

## How To Serve The Model

Serve the fine-tuned model with vLLM:

```text
vllm serve /models/argus-whiterabbitneo-devsecops \
  --served-model-name argus-devsecops-local \
  --host 0.0.0.0 \
  --port 8000 \
  --trust-remote-code
```

Then configure `llm-gateway`:

```json
{
  "alias": "argus-devsecops-local",
  "provider": "local_vllm",
  "base_url": "http://whiterabbitneo-7b.llm-serving.svc.cluster.local:8000/v1",
  "model": "argus-devsecops-local",
  "role": "devsecops",
  "cloud_allowed": false,
  "enabled": true
}
```

## Practical Recommendation

For ARGUS, train the local model to be excellent at:

- classifying and explaining findings;
- detecting weak evidence;
- recommending validation strategy IDs;
- writing remediation;
- enforcing policy boundaries;
- repairing JSON;
- producing report sections.

Do not train it to be an autonomous exploit writer. ARGUS should keep exploitation behind deterministic tool adapters, payload registries, scope enforcement and approval gates.
