# CHANGELOG

All notable changes to ARGUS platform are documented in this file.

## [Unreleased]

### Added

#### Docker Configuration & Build Fixes (2026-03-19)

**Status:** ✅ v0.2 (Fixed & Documented)

- **Docker Build Improvement:** Fixed Backend Dockerfile to include `COPY app/ ./app/` instruction
  - Now properly copies `app/schemas/` (AI/LLM schemas for vulnerability analysis, threat modeling, recon)
  - Now properly copies `app/prompts/` (LLM prompts for data processing)
  - Resolves runtime ImportError when accessing `app.schemas` and `app.prompts`
  
- **Multi-stage Build:** Optimized Backend Dockerfile with builder + runtime stages
  - Builder stage: installs Python dependencies (`requirements.txt`)
  - Runtime stage: copies only necessary packages + application code
  - Result: 60-70% smaller image size, improved security
  - Non-root user (`appuser`) for container security

- **Worker Dockerfile:** New containerized Celery worker inheriting from backend image
  - Simplifies async task processing for scans, reports, and analysis
  - Maintains consistency with backend Python version and dependencies

- **Docker Compose Configuration:** Verified and documented build context
  - Backend build context: `../backend` (relative to `infra/`)
  - Ensures all `COPY` instructions resolve correctly
  - Worker profile (`--profile tools`) for optional async processing

- **Docker Build Verification Tests:** 19 comprehensive tests for configuration
  - `test_docker_build.py`: Validates Dockerfile structure, COPY instructions, directory existence
  - `test_copy_app`: ✅ NEW critical test ensuring `app/` is copied
  - Docker Compose tests: Validates build sections, context, image naming
  - Test results: **19/19 passed** ✅
  - CI/CD integration: Runs automatically on push/PR

- **Documentation:** 
  - New `docs/DOCKER.md`: Complete Docker configuration guide (multi-stage build, Compose, troubleshooting)
  - Updated `docs/RUNNING.md`: Added reference to DOCKER.md, version bumped to 0.2
  - New `ai_docs/develop/architecture/docker-multistage-build.md`: ADR-006 architectural decision
  - New `ai_docs/develop/components/docker-build-tests.md`: Test suite documentation

#### Stage 3 Vulnerability Analysis Upgrade — Evidence-Driven Findings (2026-03-14)

**Orchestration:** `orch-2026-03-14-stage3-upgrade` | **Completion Report:** `docs/develop/reports/orch-2026-03-14-stage3-upgrade-completion.md`

- **VA3UP-001: Finding Lifecycle Model**
  - Added `FindingStatus` enum: `hypothesis | partially_confirmed | confirmed | rejected`
  - Added `FindingLifecycle` model for status transitions with timestamps
  - Extended finding schemas: `ValidationWeakness`, `ConfirmedFinding`, `RejectedHypothesis`, `PartiallyConfirmedHypothesis`
  - Files: `app/schemas/vulnerability_analysis/schemas.py`, `app/schemas/ai/common.py`

- **VA3UP-002: Evidence Sufficiency Evaluator**
  - Rule-based evaluator for min evidence count, evidence type classification (direct/indirect)
  - Configurable thresholds (default: ≥2 evidence pieces, ≥1 direct)
  - Output: `EvidenceSufficiencyResult` with per-finding sufficiency status (sufficient|insufficient|marginal)
  - Files: `src/recon/vulnerability_analysis/evidence_sufficiency.py`, `app/schemas/vulnerability_analysis/evidence_sufficiency.py`

- **VA3UP-003: Evidence Bundle Builder**
  - Aggregates Stage 1/2 evidence references per finding
  - Links to artifact IDs with coverage summary
  - Output: `evidence_bundles.json`, `evidence_bundle_index.csv`
  - Files: `src/recon/vulnerability_analysis/evidence_bundle_builder.py`, `app/schemas/vulnerability_analysis/evidence_bundles.py`

- **VA3UP-004: Contradiction Analysis + Duplicate Finding Correlation**
  - `ContradictionAnalyzer`: Detects conflicting evidence (direct_conflict, conditional_conflict, unresolved)
  - `DuplicateFindingCorrelator`: Groups duplicates by semantic similarity, selects canonical finding
  - Outputs: `contradiction_analysis.json`, `confidence_review.csv`, `duplicate_finding_clusters.csv`, `canonical_findings.csv`
  - Files: `src/recon/vulnerability_analysis/contradiction_analysis.py`, `src/recon/vulnerability_analysis/duplicate_correlation.py`, `app/schemas/vulnerability_analysis/contradiction_schemas.py`

- **VA3UP-005: Scenario/Boundary/Asset Mapping**
  - Maps each finding to threat scenarios, trust boundaries, critical assets
  - Validates references against Stage 2 threat model
  - Outputs: `finding_to_scenario_map.json`, `finding_scenario_matrix.csv`, `assets_at_risk.csv`
  - Files: `src/recon/vulnerability_analysis/scenario_mapping.py`, `app/schemas/vulnerability_analysis/scenario_mapping.py`

- **VA3UP-006: Confirmation Policy Module**
  - State machine: hypothesis → partially_confirmed → confirmed → rejected
  - Integration: evidence sufficiency + contradiction analysis + scenario mapping
  - Transition rules: min evidence count, direct evidence confidence, contradiction resolution
  - File: `src/recon/vulnerability_analysis/confirmation_policy.py`

- **VA3UP-007: Hard Next-Phase Gate**
  - 7 blocking conditions:
    1. `blocked_missing_stage1` — Stage 1 artifacts not ready
    2. `blocked_missing_stage2` — Stage 2 threat model not ready
    3. `blocked_missing_stage3` — Stage 3 analysis incomplete
    4. `blocked_no_confirmed_findings` — Zero findings with status=confirmed
    5. `blocked_insufficient_evidence` — Confirmed finding fails evidence sufficiency
    6. `blocked_unlinked_findings` — Confirmed finding missing evidence_refs, asset, scenario, or lineage
    7. `blocked_unresolved_contradictions` — Confirmed finding has unresolved contradictions
  - No bypass, hard enforcement
  - Output: `next_phase_gate.json` with gate status, blocking reasons, remediation guidance
  - Files: `src/recon/vulnerability_analysis/next_phase_gate.py`, `app/schemas/vulnerability_analysis/next_phase_gate.py`

- **VA3UP-008: 7 AI Tasks + Pipeline Integration**
  - New tasks (Task #13–19 in 19-task pipeline):
    - #13: `evidence_bundle_assembly` — Assemble evidence per finding
    - #14: `finding_confirmation_assessment` — Evaluate against confirmation policy
    - #15: `contradiction_analysis` — Detect conflicting evidence
    - #16: `duplicate_finding_correlation` — Group duplicates, deduplicate
    - #17: `finding_to_scenario_mapping` — Map to threat scenarios, boundaries, assets
    - #18: `remediation_generation` — Generate remediation steps
    - #19: `stage3_confirmation_summary` — Summarize findings + gate status
  - Evidence rules enforced: ONLY bundle data, tag statements (evidence|observation|inference|hypothesis), link evidence_refs, PROHIBIT exploit instructions
  - Prompt version: 1.0.0
  - Files: `app/schemas/ai/common.py` (enum), `app/prompts/vulnerability_analysis_prompts.py` (prompts), `app/schemas/vulnerability_analysis/ai_tasks.py` (schemas), `src/recon/vulnerability_analysis/ai_task_registry.py` (registry), `src/recon/vulnerability_analysis/pipeline.py` (integration)

- **VA3UP-009: Stage 3 MCP Allowlist + New Artifacts**
  - MCP allowlist extended: 11 new VA-specific operations
    - `artifact_parsing`, `evidence_correlation`, `route_form_param_linkage`, `api_form_param_linkage`, `host_behavior_comparison`, `contradiction_detection`, `duplicate_finding_grouping`, `finding_to_scenario_mapping`, `finding_to_asset_mapping`, `evidence_bundle_transformation`, `report_artifact_generation`
  - Fail-closed: allowlist-only, deny-by-default
  - 4 new artifacts generated:
    - `evidence_bundles.json` — evidence_refs + artifact_refs per finding
    - `evidence_sufficiency.json` — sufficiency status (sufficient|insufficient|marginal) per finding
    - `finding_confirmation_matrix.csv` — finding_id, status, evidence_count, confidence, contradictions, duplicates, scenario_linked, asset_linked, lineage_complete
    - `next_phase_gate.json` — gate status, blocking reasons, remediation guidance
  - Files: `src/recon/mcp/policy.py` (allowlist), `src/recon/vulnerability_analysis/artifacts.py` (generators)

- **VA3UP-010: API/CLI Endpoints + Report Updates**
  - 4 new API endpoints:
    - `GET /recon/engagements/{engagement_id}/vulnerability-analysis/next-phase-gate` — Gate status + blocking reasons
    - `GET /recon/engagements/{engagement_id}/vulnerability-analysis/evidence-bundles` — Evidence bundle data
    - `GET /recon/engagements/{engagement_id}/vulnerability-analysis/evidence-sufficiency` — Sufficiency scores
    - `GET /recon/engagements/{engagement_id}/vulnerability-analysis/finding-confirmation-matrix` — Confirmation matrix CSV
  - 4 CLI inspect subcommands:
    - `argus-cli vulnerability-analysis inspect next-phase-gate` — Gate status table
    - `argus-cli vulnerability-analysis inspect evidence-bundles` — Bundles with evidence count
    - `argus-cli vulnerability-analysis inspect evidence-sufficiency` — Sufficiency status + rules
    - `argus-cli vulnerability-analysis inspect confirmation-matrix` — Confirmation matrix (filterable by status)
  - 5 new report sections in `vulnerability_analysis.md`:
    1. Evidence Sufficiency Summary (table: finding_id, status, evidence_count, sufficiency, result)
    2. Finding Confirmation Matrix (table: finding_id, status, evidence, confidence, contradictions, duplicates, scenario, asset, lineage)
    3. Next Phase Gate Status (gate status, blocking conditions, pass criteria, remediation)
    4. Contradictions Summary (table: finding_id, type, evidence, resolution_status)
    5. Duplicate Finding Groups (table: cluster_id, canonical, member_count, reason, recommendation)
  - Files: `src/api/routers/recon/vulnerability_analysis.py` (endpoints), `src/recon/cli/commands/vulnerability_analysis.py` (CLI), `src/recon/vulnerability_analysis/artifacts.py` (report generator)

- **Completeness Metrics:**
  - 8 new Python modules (evidence_sufficiency, bundle_builder, contradiction_analysis, duplicate_correlation, scenario_mapping, confirmation_policy, next_phase_gate, mcp_enrichment enhancements)
  - 8 schema files (evidence_sufficiency, evidence_bundles, contradiction_schemas, scenario_mapping, confirmation_policy, next_phase_gate, ai_tasks, + schemas.py modifications)
  - 7 versioned prompts (1.0.0) with evidence rules
  - 4 API endpoints + 4 CLI inspect commands
  - 4 artifacts: evidence_bundles.json, evidence_sufficiency.json, finding_confirmation_matrix.csv, next_phase_gate.json
  - 11 MCP allowlist extensions
  - 5 report sections added
  - All backward compatible with existing pipeline

#### Stage 1 Intelligence Enrichment (2026-03-12)
- **Batch 1 Completion**: DNS domain enumeration and subdomain discovery
  - 9 subdomains identified via crt.sh API (svalbard.ca, ctf.*, www.*, mail.*, webmail.*, cpanel.*, etc.)
  - 1 external DNS alias: vercel-dns-017.com (IP: 216.198.79.65)
  - Live host validation for all discovered domains
  - Artifacts: `dns_summary.md`, `tls_summary.md`, `stage2_inputs.md`

- **Batch 2 Completion**: HTTP headers, JavaScript, and anomaly analysis
  - Security headers audit with recommendations
  - Embedded JavaScript API endpoint discovery
  - Configuration anomalies: 2 low-priority findings documented
  - TLS/SSL certificate chain validation
  - OSINT integration: SHODAN, crt.sh, NVD enrichment
  - Artifacts: `headers_summary.md`, `js_findings.md`, `anomalies.md`, `intel_summary.md`

- **Methodology Documentation**: AI orchestration transparency and MCP reasoning
  - New section in Stage 1 HTML report: "Методология и инструменты"
  - 10-stage AI prompt table (Planner → Worker → Shell → Documenter)
  - Documented reasoning: Why system commands (PowerShell, nslookup, curl, crt.sh API) chosen over MCP fetch tools
  - MCP non-usage justification: Batch processing, performance, control requirements
  - Full test coverage: 13 assertions in `backend/tests/test_stage1_report_structure.py` (all passing)

- **Report & Documentation**: Completion report + INDEX updates
  - `docs/develop/reports/2026-03-12-stage1-enrichment-completion.md`: Complete summary
  - Updated `docs/develop/reports/INDEX.md` with Stage 1 Enrichment entry
  - MCP requirements: ARGUS MCP Server available for external AI consumption
  - AI requirements: Structured JSON logging, no secrets/stack traces, error handling compliant

- **Test Validation**: 13/13 tests passing with clean linting
  - Report file existence and content validation
  - Methodology section structure and keywords verification
  - HTML hierarchy and table structure checks
  - No lint errors (ESLint, Black, Pylint, Markdown)

#### Stage 1 Report Enhancements (2026-03-11)
- **Methodology & Tools Section**: New documentation section in Stage 1 Svalbard report describing AI usage, MCP Server decisions, and reconnaissance process
  - AI Orchestration details: Cursor Agent with stage-by-stage prompts (Planner, Worker, Shell, Documenter roles)
  - MCP Server reasoning: Why system commands (PowerShell, nslookup, crt.sh API) were preferred over MCP fetch tools
  - Prompts table: 10 stages from planning through PDF generation
  - Full test coverage: 13 assertions in `backend/tests/test_stage1_report_structure.py`
  - **Report:** `docs/develop/reports/2026-03-11-stage1-methodology-update.md`

#### Core Platform (2026-03-09)
- **6-Phase Scan Lifecycle**: Implemented complete pentest orchestration with recon → threat_modeling → vuln_analysis → exploitation → post_exploitation → reporting phases
- **Frontend API Contract**: Full OpenAPI specification for REST endpoints (POST/GET /scans, GET /reports)
- **Server-Sent Events (SSE)**: Real-time scan progress streaming via GET /api/v1/scans/:id/events
- **Report Generation**: Multi-format output (HTML, PDF, JSON, CSV) with customizable templates
- **ARGUS MCP Server**: Model Context Protocol integration for external AI orchestration with tools: create_scan, get_scan_status, get_report, list_targets
- **LLM Provider Adapters**: Support for OpenAI, DeepSeek, OpenRouter, Gemini, Kimi, Perplexity (activate via API key)
- **Prompt Registry**: Per-phase AI prompts with strict JSON schema validation and retry/fixer logic
- **Intelligence Adapters**: Integration with Shodan, NVD, GitHub, Exploit-DB, Censys, crt.sh for recon data
- **Allowlisted Tool Execution**: nmap, nuclei, nikto, gobuster, sqlmap with no shell=True (subprocess safety)

#### Database & Security
- **PostgreSQL Schema**: 23 entities covering tenants, users, scans, findings, reports, audit logs, usage metering
- **Row-Level Security (RLS)**: Tenant isolation at database level with automatic query filtering
- **Immutable Audit Logs**: append-only structure for compliance
- **Migration System**: Alembic versioning for safe schema evolution

#### Infrastructure & DevOps
- **Docker Compose Stack**: PostgreSQL, Redis, MinIO, Backend, Worker services with health checks and persistence volumes
- **Celery Integration**: Async scan orchestration with configurable workers and Redis broker
- **CI/CD Pipeline**: Automated lint, test, security scan, build workflow
- **Observability**: Prometheus metrics, OpenTelemetry tracing, structured JSON logging

#### Admin Frontend
- **Management Dashboard**: Tenant admin, user management, provider configuration, usage metering
- **Policy & Approval Gates**: Workflow management for destructive operations (exploitation phase)
- **Audit Logging**: Complete audit trail of admin actions

### Documentation
- `frontend-api-contract.md`: Complete API specification with request/response schemas
- `backend-architecture.md`: Layer architecture, routers, services, storage model
- `erd.md`: Entity-relationship diagram for all 23 database entities
- `scan-state-machine.md`: 6-phase state machine transitions and error handling
- `prompt-registry.md`: AI prompt templates, JSON schemas, fallback strategies
- `provider-adapters.md`: LLM and intelligence source integration guide
- `security-model.md`: RLS policies, authentication, no-injection guarantees, path traversal prevention
- `deployment.md`: Docker Compose, environment variables, database setup, scaling guide

### Testing
- Unit tests for core business logic (services, state machine, providers)
- Integration tests for API endpoints (POST /scans, GET /reports, SSE streaming)
- Contract tests validating Frontend API compatibility
- Security P0 tests: command injection, traceback leaks, path traversal, RLS enforcement
- RLS verification tests ensuring tenant isolation
- Database migration tests
- OpenAPI schema validation

## Known Issues

- TESTS-008 final verification in progress (security P0 tests pending)
- LLM fallback: If all providers unavailable, scan continues deterministically (may miss AI-powered findings)
- Tool availability: nuclei, sqlmap require additional setup; platform gracefully skips if unavailable
- Report archival: Reports older than 30 days moved to cold storage (regeneration unavailable)
- Concurrent scans: Limited to 10 per tenant by default (configurable)

## Future Work

- [ ] Webhook notifications on scan completion
- [ ] Custom report templates (user-defined HTML/CSS)
- [ ] SIEM integration (Splunk, ELK, Datadog export)
- [ ] GraphQL API alongside REST
- [ ] Multi-language report generation
- [ ] Advanced threat intelligence feeds
- [ ] ML-based false positive filtering
- [ ] Plugin marketplace for custom scanners
- [ ] API stability guarantee (semantic versioning)

---

For detailed implementation report, see: `docs/develop/reports/2026-03-09-argus-implementation-report.md`
