# ARGUS Report — https://example.com

- scan_id: `scan-1`
- scan_profile: `light`
- resolved_scan_mode: `standard`
- execution_mode: `production`
- nuclei_profile: `vuln_default`
- completed_at: `2026-01-01T00:10:00Z`
- schema_version: `v2`
- snapshot_hash: `549023acdf740d893298758b2b9c0a97f28619e4f231e5bb9ec4a3345c66004d`

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

### 01 · CRITICAL · confirmed — t
`F-1`

| | |
|---|---|
| CWE | CWE-89 |
| OWASP | A03:2021 — Injection |
| Статус верификации | confirmed |
| Уверенность | 0.95 |
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

1. **entry**: t (F-1)

## Evidence Inventory

| Evidence ID | Kind | Object Key | Description |
|---|---|---|---|
| `E-1` | http | `E-1` | not_assessed |

## Coverage

- `cap.sqli`: `tested`
- `cap.xss`: `not_assessed` (reason: `budget_exhausted`)

## Tool runs

- `TR-1` sqlmap: `ok`

## WSTG v4.2 Coverage

- versions: policy `argus-wstg-cov-1`, rules `argus-wstg-cov-1`, scenarios `argus-wstg-scn-0`
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
