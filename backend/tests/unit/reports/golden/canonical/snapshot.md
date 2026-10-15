# ARGUS Report — https://example.com

- scan_id: `scan-1`
- tenant_id: `tenant-1`
- scan_profile: `light`
- resolved_scan_mode: `standard`
- execution_mode: `production`
- nuclei_profile: `vuln_default`
- completed_at: `2026-01-01T00:10:00Z`
- schema_version: `v2`
- snapshot_hash: `dee338072a11c6f2496b9b48398141dd4a4f0d3b7a5f9c0553ed3a3e183e09b4`
- generated_at: `2026-01-01T00:00:00+00:00`

## Report Passport

- generation_status: `unknown`
- llm_analysis_status: `not_run`
- assessment_completeness: `unknown`
- evidence_integrity: `unknown`
- review_status: `not_required`

## Attack Surface Inventory

| Host | Port | Service | Version | Technology |
|---|---|---|---|---|
| example.com | not_assessed | not_assessed | not_assessed | not_assessed |

## Findings (3)

| Severity | Count | Findings |
|---|---|---|
| critical | 1 | `F-1` |
| high | 1 | `F-2` |
| medium | 0 | — |
| low | 1 | `F-3` |
| info | 0 | — |

### 01 · CRITICAL · confirmed — t
`F-1`

| | |
|---|---|
| CWE | CWE-89 |
| OWASP | A03:2021 — Injection |
| Статус верификации | confirmed |
| Уверенность | 0.95 |
| Сырой артефакт | E-1 |
| Evidence | `E-1` |


### 02 · HIGH · insufficient_evidence — t
`F-2`

| | |
|---|---|
| OWASP | не сопоставлено |
| Статус верификации | insufficient_evidence |
| Уверенность | 0.95 |


### 03 · LOW · not_tested — t
`F-3`

| | |
|---|---|
| OWASP | не сопоставлено |
| Статус верификации | not_tested |
| Уверенность | 0.50 |


## Attack Narrative

1. **entry**: t (F-1) · evidence: `E-1`

## Evidence Register

| Evidence ID | Kind | Collector | Collected (UTC) | SHA-256 | Chain hash | Redacted | Producer run | Size | MIME | Object Key | Description |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `E-1` | http | not_assessed | not_assessed | `not_assessed` | `not_assessed` | not_assessed | `not_assessed` | not_assessed | not_assessed | `E-1` | not_assessed |

## Coverage

- tested_capabilities: `cap.sqli`
- not_assessed_capabilities: `cap.xss`
- `cap.sqli`: `tested` · evidence: `E-1`
- `cap.xss`: `not_assessed` (reason: `budget_exhausted`)

## Tool runs

- `TR-1` sqlmap: `ok`

## WSTG v4.2 Coverage

- versions: policy `argus-wstg-cov-1`, rules `argus-wstg-cov-1`, scenarios `argus-wstg-scn-1`
> pass/fail is a control's security result; the percentage is execution completeness, not application security.

- assessment: `incomplete`
- completed X of applicable: `1` / `96` = `1.0417%` (threshold `80.0%`)
- completed X of catalog: `1` / `96`
- coverage_gate_passed: `False`, evidence_integrity_passed: `True`
- not_applicable: `0`, out_of_scope: `0`, unknown: `49`, blocked: `0`
- completed_pass: `0`, completed_fail: `1`, partial: `0`, not_started: `95`

## Limitations

_none_

## Validation errors

- `insufficient_evidence` F-2: Finding 'F-2' claimed 'confirmed' without a verifiable evidence chain (evidence→run/session); downgraded.

## Section Coverage

| Section | Status |
|---|---|
| Report Passport | `present` |
| Executive Summary | `llm_not_generated` |
| Engagement Parameters | `not_recorded` |
| Methodology | `not_recorded` |
| Attack Surface Inventory | `present` |
| Priority Findings | `present` |
| Findings by Asset | `present` |
| Findings | `present` |
| Unconfirmed Observations | `none` |
| Executed Checks Without Findings | `not_recorded` |
| Attack Narrative | `present` |
| Impact Chains | `none_proven` |
| Business Risk | `llm_not_generated` |
| Prioritised Remediation Plan | `llm_not_generated` |
| Retest & Closure | `not_retested` |
| Evidence Inventory | `present` |
| Coverage | `present` |
| WSTG v4.2 Coverage | `present` |
| Execution Log | `present` |
| Impact on Client Environment | `nothing_created` |
| Limitations | `none` |
| Claims Ledger | `none` |
| Appendix A — All Findings | `present` |
| Appendix B — Assets & Subdomains | `present` |
| Appendix C — Tool Runs & Artifacts | `present` |
| Appendix D — Independent Verification Kit | `not_generated` |
| Validation Notes | `present` |
| Methodology, Limits of Conclusions & Disclaimer | `present` |
