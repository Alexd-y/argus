# Plan: Stage 1 (Recon) Data Collection Improvements

**Created:** 2026-03-19
**Orchestration:** orch-2026-03-19-12-00-stage1-recon
**Goal:** Modify Stage 1 pipeline to generate full set of machine-readable artifacts for Stage 2 (Threat Modeling), save to `artifacts/stage1/{scan_id}/` and MinIO `stage1-artifacts` bucket.

**Total Tasks:** 10
**Priority:** High

---

## Context

- **Project:** ARGUS (`d:\Developer\Pentest_test\ARGUS`)
- **Stage 1 pipeline:** `backend/src/recon/reporting/stage1_report_generator.py`
- **Contract:** `backend/src/recon/reporting/stage1_contract.py` (STAGE1_BASELINE_ARTIFACTS)
- **MCP audit:** `backend/src/recon/mcp/audit.py` (mcp_invocation_audit.jsonl)
- **Storage:** `backend/src/reports/storage.py`, `backend/src/storage/s3.py`, `backend/src/recon/storage.py`
- **Current outputs:** HTML report, CSV/MD artifacts in recon dir

---

## Required Artifacts

| Artifact | Description |
|----------|-------------|
| **recon_results.json** | Unified JSON: DNS (A, AAAA, CNAME, MX, TXT, NS) for domain + subdomains; full WHOIS; SSL certs (CN, SANs, Issuer, Validity) for HTTPS hosts; tech stack (Wappalyzer/Server headers); HTTP headers analysis |
| **mcp_trace.jsonl** | Audit log: timestamp, tool_name, input_parameters (incl target), output_summary (or error status), run_id, job_id |
| **raw_tool_outputs/** | subfinder_output.json/txt, httpx_output.json, nuclei_output_initial.json (if safe mode) |
| **tech_profile.json** | JSON version of tech_profile.csv (httpx + wappalyzer) |
| **anomalies_structured.json** | Already exists; ensure format ready for AI prompt |

---

## Tasks Overview

1. **REC-001:** Pydantic Schemas for Stage 1 Artifacts
2. **REC-002:** recon_results.json Builder
3. **REC-003:** mcp_trace.jsonl Format and Generation
4. **REC-004:** raw_tool_outputs/ Aggregation
5. **REC-005:** tech_profile.json Export
6. **REC-006:** anomalies_structured.json AI-Ready Format
7. **REC-007:** stage1-artifacts MinIO Bucket and Storage
8. **REC-008:** artifacts/stage1/{scan_id}/ Layout and Pipeline Integration
9. **REC-009:** Stage 1 Report Generator Integration
10. **REC-010:** Update docs/recon-stage1-flow.md

---

## Dependencies Graph

```
REC-001 ─┬─► REC-002, REC-003, REC-005, REC-006
REC-002, REC-003, REC-004, REC-005, REC-006, REC-007 ─► REC-008 ─► REC-009 ─► REC-010
```

---

## Architecture Decisions

- **scan_id:** Use `run_id` as scan_id (recon_dir.name)
- **Wappalyzer:** Extend Server-based fingerprinting; optional Wappalyzer API/CLI later
- **Raw outputs:** Copy from 02_subdomains, 04_live_hosts when present
- **MinIO path:** `{scan_id}/recon_results.json`, `{scan_id}/mcp_trace.jsonl`, etc.
