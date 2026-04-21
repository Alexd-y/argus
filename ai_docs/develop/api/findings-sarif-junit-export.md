# Scan findings export — SARIF & JUnit (T04)

## Feature flag

- **Column:** `tenants.exports_sarif_junit_enabled` (boolean, default `false`, Alembic `024`).
- **Admin:** `PATCH /api/v1/admin/tenants/{tenant_id}` with  
  `{"exports_sarif_junit_enabled": true}` (requires `X-Admin-Key` when configured).

## Endpoints (tenant JWT / `X-Tenant-ID` context)

| Method | Path | Notes |
|--------|------|--------|
| GET | `/api/v1/scans/{scan_id}/findings/export?format=sarif` | SARIF 2.1.0 JSON |
| GET | `/api/v1/scans/{scan_id}/findings/export?format=junit` | JUnit XML |
| GET | `/api/v1/scans/{scan_id}/findings/export.sarif` | Same as `format=sarif` |
| GET | `/api/v1/scans/{scan_id}/findings/export.junit.xml` | Same as `format=junit` |

Optional query params (aligned with `GET .../findings`): `severity`, `validated_only`.

## Access control

1. Scan must belong to the authenticated tenant (`scan.tenant_id` match).
2. `exports_sarif_junit_enabled` must be true for that tenant.
3. If either fails: **404** with detail `"Not found"` (no distinction — avoids probing).

## Serialization & mapping

- **Pipeline:** DB findings → `build_report_data_from_scan_findings` → `generate_sarif` / `generate_junit` (same as report bundle generators).
- **SARIF:** OASIS SARIF v2.1.0; per-finding `result` objects; severity → `level`; CWE/CVSS/OWASP in rule/result properties. See `backend/src/reports/sarif_generator.py` (no raw PoC bodies or storage paths in output).
- **JUnit:** One `<testcase>` per finding (or a single passing placeholder when there are zero findings). Severity drives `failure` vs `skipped` vs pass. See `backend/src/reports/junit_generator.py`.

## Default API

`POST /api/v1/scans/{id}/reports/generate-all` is unchanged (still 12 bundle formats); SARIF/JUnit for *ad-hoc scan findings* are opt-in via the routes above.
