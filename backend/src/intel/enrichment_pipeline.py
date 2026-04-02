"""Unified enrichment pipeline — runs all enrichment modules in sequence.

Called after findings are collected but before report generation.
Orchestrates: Shodan → Adversarial Score → LLM Dedup → Perplexity OSINT → Validation → PoC.
"""

from __future__ import annotations

import logging
import os
from typing import Any

logger = logging.getLogger(__name__)


async def run_enrichment_pipeline(
    findings: list[dict[str, Any]],
    target_ip: str | None = None,
    target_domain: str | None = None,
    scan_id: str | None = None,
) -> dict[str, Any]:
    """Run all enrichment modules on findings.

    Returns enrichment report with stats and enriched findings.
    """
    stats: dict[str, Any] = {
        "shodan_enriched": False,
        "perplexity_enriched": False,
        "adversarial_scored": False,
        "llm_dedup_run": False,
        "findings_deduplicated": 0,
        "validation_run": False,
        "pocs_generated": 0,
        "findings_confirmed": 0,
        "findings_rejected": 0,
    }

    shodan_result = None

    # Step 1: Shodan enrichment
    if target_ip and os.environ.get("SHODAN_ENRICHMENT_ENABLED", "true").lower() == "true":
        try:
            from src.intel.shodan_enricher import (
                create_findings_from_shodan_vulns,
                cross_reference_findings,
                enrich_target_host,
            )

            shodan_result = await enrich_target_host(target_ip)
            if shodan_result:
                findings = cross_reference_findings(shodan_result, findings)
                existing_cves: set[str] = set()
                for f in findings:
                    for cve in f.get("cve_ids") or []:
                        existing_cves.add(cve)
                new_findings = create_findings_from_shodan_vulns(shodan_result, existing_cves)
                findings.extend(new_findings)
                stats["shodan_enriched"] = True
                logger.info(
                    "Shodan enrichment complete",
                    extra={
                        "event": "argus.enrichment.shodan_done",
                        "scan_id": scan_id,
                        "new_findings": len(new_findings),
                    },
                )
        except Exception as exc:
            logger.warning(
                "Shodan enrichment failed",
                extra={"event": "argus.enrichment.shodan_error", "error_type": type(exc).__name__},
            )

    # Step 2: Adversarial scoring
    if os.environ.get("ADVERSARIAL_SCORE_ENABLED", "true").lower() == "true":
        try:
            from src.scoring.adversarial import score_findings

            findings = score_findings(findings)
            stats["adversarial_scored"] = True
        except Exception as exc:
            logger.warning(
                "Adversarial scoring failed",
                extra={"event": "argus.enrichment.scoring_error", "error_type": type(exc).__name__},
            )

    # Step 2.5: LLM-based deduplication (Strix-style)
    if os.environ.get("LLM_DEDUP_ENABLED", "true").lower() == "true":
        try:
            from src.dedup.llm_dedup import check_duplicates_batch

            unique, duplicates = await check_duplicates_batch(findings)
            findings = unique
            stats["llm_dedup_run"] = True
            stats["findings_deduplicated"] = len(duplicates)
            if duplicates:
                logger.info(
                    "LLM dedup removed %d duplicate findings",
                    len(duplicates),
                    extra={
                        "event": "argus.enrichment.dedup_done",
                        "scan_id": scan_id,
                        "duplicates": len(duplicates),
                    },
                )
        except Exception as exc:
            logger.warning(
                "LLM dedup failed",
                extra={"event": "argus.enrichment.dedup_error", "error_type": type(exc).__name__},
            )

    # Step 3: Perplexity CVE/OSINT enrichment
    if os.environ.get("PERPLEXITY_INTEL_ENABLED", "true").lower() == "true":
        try:
            from src.intel.perplexity_enricher import enrich_findings_with_cve_intel

            findings = await enrich_findings_with_cve_intel(findings)
            stats["perplexity_enriched"] = True
        except Exception as exc:
            logger.warning(
                "Perplexity enrichment failed",
                extra={"event": "argus.enrichment.perplexity_error", "error_type": type(exc).__name__},
            )

    # Step 4: Exploitability validation
    if os.environ.get("EXPLOITABILITY_VALIDATION_ENABLED", "true").lower() == "true":
        try:
            from src.validation.exploitability import validate_findings_batch

            results = await validate_findings_batch(findings)
            for finding, result in zip(findings, results):
                finding["validation_status"] = result.status
                finding["validation_confidence"] = result.confidence
                if result.poc_command:
                    finding.setdefault("proof_of_concept", {})["validation_poc"] = result.poc_command
                if result.exploit_public:
                    finding["exploit_public"] = True
                    finding["exploit_sources"] = result.exploit_sources
            stats["validation_run"] = True
            stats["findings_confirmed"] = sum(1 for r in results if r.status == "confirmed")
            stats["findings_rejected"] = sum(1 for r in results if r.status == "rejected")
        except Exception as exc:
            logger.warning(
                "Validation pipeline failed",
                extra={"event": "argus.enrichment.validation_error", "error_type": type(exc).__name__},
            )

    # Step 5: PoC generation (only for confirmed findings)
    if os.environ.get("POC_GENERATION_ENABLED", "true").lower() == "true":
        try:
            from src.exploit.generator import generate_pocs_batch

            confirmed = [f for f in findings if f.get("validation_status") == "confirmed"]
            pocs = await generate_pocs_batch(confirmed, target=target_domain or target_ip or "")
            poc_map = {p.finding_id: p for p in pocs}
            for finding in findings:
                fid = str(finding.get("finding_id") or finding.get("id") or "")
                if fid in poc_map:
                    poc_result = poc_map[fid]
                    finding.setdefault("proof_of_concept", {})["generated_poc"] = poc_result.poc_code
                    if poc_result.playwright_script:
                        finding["proof_of_concept"]["playwright_script"] = poc_result.playwright_script
            stats["pocs_generated"] = len(pocs)
        except Exception as exc:
            logger.warning(
                "PoC generation failed",
                extra={"event": "argus.enrichment.poc_error", "error_type": type(exc).__name__},
            )

    logger.info(
        "Enrichment pipeline complete",
        extra={"event": "argus.enrichment.pipeline_done", "scan_id": scan_id, "stats": stats},
    )

    return {
        "findings": findings,
        "shodan_result": shodan_result,
        "stats": stats,
    }
