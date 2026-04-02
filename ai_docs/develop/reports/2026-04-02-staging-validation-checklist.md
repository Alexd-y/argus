# ARGUS ENH-V2 Staging Validation Checklist

## Pre-Deployment

- [ ] All env variables added to `infra/.env` and `infra/.env.example`
- [ ] `shodan>=1.31.0` added to `pyproject.toml` and `requirements.txt`
- [ ] Alembic migration 015 verified (chain 014→015)
- [ ] `pip install shodan` in Docker build

## Module Import Verification

- [ ] `src.llm.task_router` — LLMTask, call_llm_for_task
- [ ] `src.llm.cost_tracker` — ScanCostTracker, calc_cost
- [ ] `src.scoring.adversarial` — compute_adversarial_score, score_findings
- [ ] `src.intel.shodan_enricher` — enrich_target_host, cross_reference_findings
- [ ] `src.intel.perplexity_enricher` — enrich_cve, osint_domain
- [ ] `src.intel.enrichment_pipeline` — run_enrichment_pipeline
- [ ] `src.validation.exploitability` — validate_finding, validate_findings_batch
- [ ] `src.exploit.generator` — generate_poc, generate_pocs_batch
- [ ] `src.core.config` — report_language, max_cost_per_scan_usd, feature flags

## Database Migration

- [ ] Run `alembic upgrade head` on staging DB
- [ ] Verify `findings.adversarial_score` column exists (DOUBLE PRECISION, nullable)
- [ ] Verify `scans.cost_summary` column exists (JSONB, nullable)
- [ ] Test `alembic downgrade -1` and re-upgrade (idempotency check)

## Feature Flag Smoke Tests

- [ ] Set `SHODAN_ENRICHMENT_ENABLED=false` → verify Shodan step skipped
- [ ] Set `PERPLEXITY_INTEL_ENABLED=false` → verify Perplexity step skipped
- [ ] Set `ADVERSARIAL_SCORE_ENABLED=false` → verify scoring step skipped
- [ ] Set `EXPLOITABILITY_VALIDATION_ENABLED=false` → verify validation step skipped
- [ ] Set `POC_GENERATION_ENABLED=false` → verify PoC generation step skipped
- [ ] All flags `=true` → verify full pipeline runs end-to-end

## LLM Router Verification

- [ ] Set `LLM_PRIMARY_PROVIDER=deepseek` → verify DeepSeek used as primary
- [ ] Set `MAX_COST_PER_SCAN_USD=0.01` → verify ScanBudgetExceededError raised on second call
- [ ] Verify fallback works: disable primary provider key → secondary provider used

## Report Generation

- [ ] Generate Valhalla report → verify `cost_summary` section appears
- [ ] Verify `report_language=ru` produces Russian AI text
- [ ] Verify adversarial_score appears in findings table (sorted descending)

## Integration Test Suite

- [ ] Run `pytest tests/test_enrichment_pipeline.py -v` — all tests pass
- [ ] Run full test suite `pytest tests/ -v` — no regressions

## Rollback Plan

1. `alembic downgrade -1` (removes new columns)
2. Remove ENH-V2 env vars from `infra/.env`
3. Redeploy previous backend image
4. Feature flags default to `true` but modules won't break without them (graceful degradation)
