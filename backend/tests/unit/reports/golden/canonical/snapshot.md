# ARGUS Report — https://example.com

- scan_id: `scan-1`
- scan_profile: `light`
- resolved_scan_mode: `standard`
- execution_mode: `production`
- nuclei_profile: `vuln_default`
- started_at: `not_assessed`
- completed_at: `2026-01-01T00:10:00Z`
- schema_version: `v1`
- snapshot_hash: `5c35d254497322e2c94a572f192a74e1abaff3a9be511da87279868adac85423`

## Findings (3)

### t — `F-1`
- severity: `critical`
- verification_status: `confirmed`
- confidence: `0.9500`
- cwe: `CWE-89`
- tool_run_id: `TR-1`
- validator_id: `not_assessed`
- raw_artifact_ref: `E-1`
- evidence_ids: `E-1`

### t — `F-2`
- severity: `high`
- verification_status: `insufficient_evidence`
- confidence: `0.9500`
- cwe: `not_assessed`
- tool_run_id: `not_assessed`
- validator_id: `not_assessed`
- raw_artifact_ref: `not_assessed`
- evidence_ids: _none_

### t — `F-3`
- severity: `low`
- verification_status: `not_tested`
- confidence: `0.5000`
- cwe: `not_assessed`
- tool_run_id: `not_assessed`
- validator_id: `not_assessed`
- raw_artifact_ref: `not_assessed`
- evidence_ids: _none_

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
