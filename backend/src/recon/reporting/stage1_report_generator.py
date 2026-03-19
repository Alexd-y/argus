"""Stage 1 report generator — orchestrates parsers and builders for recon dir artifacts."""

import asyncio
import json
import logging
import re
import shutil
from collections.abc import Callable
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from src.core.llm_config import get_llm_client, get_llm_provider_info, has_any_llm_key
from src.recon.mcp.audit import build_mcp_trace_from_audit, mcp_audit_context, write_mcp_audit_meta
from src.recon.reporting.raw_outputs_builder import RAW_OUTPUTS_DIR, aggregate_raw_tool_outputs
from src.recon.reporting.stage1_contract import (
    STAGE1_BASELINE_ARTIFACTS,
    build_stage1_contract_snapshot,
)
from src.recon.stage1_storage import upload_stage1_artifacts

logger = logging.getLogger(__name__)

STAGE1_OUTPUTS = list(STAGE1_BASELINE_ARTIFACTS)


def _derive_target_domain(recon_dir: Path) -> str:
    """Extract target domain from scope.txt, targets.txt, or directory name."""
    scope_path = recon_dir / "00_scope" / "scope.txt"
    if scope_path.exists():
        try:
            text = scope_path.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"Target:\s*([^\s#\n]+)", text, re.I)
            if m:
                return m.group(1).strip()
        except OSError:
            pass
    targets_path = recon_dir / "00_scope" / "targets.txt"
    if targets_path.exists():
        try:
            text = targets_path.read_text(encoding="utf-8", errors="replace")
            m = re.search(r"Primary Domain\s*\n\s*([^\s#\n]+)", text, re.I)
            if m:
                return m.group(1).strip()
        except OSError:
            pass
    name = recon_dir.name
    if "-stage" in name.lower():
        return name.split("-")[0]
    return name or "unknown"


def _run_intel_adapters(domain: str) -> dict:
    """Fetch intel from all available adapters for the target domain.

    Returns aggregated dict: {target_domain, fetched_at, adapters: [...]}.
    """
    try:
        from src.recon.adapters.intel import get_available_intel_adapters
    except ImportError:
        logger.warning("Intel adapters not available", extra={"domain": domain})
        return {"target_domain": domain, "fetched_at": "", "adapters": []}

    adapters = get_available_intel_adapters()
    if not adapters:
        return {"target_domain": domain, "fetched_at": "", "adapters": []}

    async def _fetch_all() -> list[dict]:
        tasks = [a.fetch(domain) for a in adapters]
        return list(await asyncio.gather(*tasks, return_exceptions=True))

    try:
        results = asyncio.run(asyncio.wait_for(_fetch_all(), timeout=60.0))
    except Exception:
        logger.warning(
            "Intel fetch failed",
            extra={"domain": domain, "error_code": "intel_fetch_failed"},
        )
        return {"target_domain": domain, "fetched_at": "", "adapters": []}

    adapters_out: list[dict] = []
    for i, r in enumerate(results):
        if isinstance(r, Exception):
            adapters_out.append({
                "source": adapters[i].name if i < len(adapters) else "unknown",
                "findings": [],
                "skipped": True,
                "error_code": "adapter_fetch_failed",
                "error_category": "upstream_adapter_error",
                "raw": None,
            })
        else:
            adapters_out.append(r)

    return {
        "target_domain": domain,
        "fetched_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "adapters": adapters_out,
    }


def generate_stage1_report(
    recon_dir: str | Path,
    use_mcp: bool = True,
    fetch_func: Callable[[str], dict] | None = None,
    headers_fetch_func: Callable[[str], dict] | None = None,
    skip_intel: bool = False,
    artifacts_base: Path | None = None,
) -> list[Path]:
    """Generate Stage 1 reports from recon directory artifacts.

    Runs parsers on 00_scope, 01_domains, 02_subdomains, 03_dns, 04_live_hosts,
    invokes report builders, and writes outputs to the recon dir.

    Args:
        recon_dir: Path to recon directory (e.g. .../recon/svalbard-stage1/)
                   containing 00_scope, 01_domains, 02_subdomains, 03_dns, 04_live_hosts.
        use_mcp: When True, use MCP user-fetch for endpoint discovery (robots.txt,
                 sitemap.xml, security.txt, etc.). Fallback to httpx if MCP unavailable.
        fetch_func: Optional custom fetch(url) -> {status, content_type, exists, notes}.
                    When provided, used for endpoint inventory instead of MCP/httpx.
        headers_fetch_func: Optional custom fetch(url) -> {status_code, headers, url}.
                           When provided, used for headers summary instead of httpx.
        artifacts_base: Optional base path for artifacts/stage1/{scan_id}/ layout (REC-008).
                       When provided, copies recon_results.json, tech_profile.json, mcp_trace.jsonl,
                       anomalies_structured.json, raw_tool_outputs/* to artifacts_base/stage1/{scan_id}/.

    Returns:
        List of generated file paths.
    """
    recon_dir = Path(recon_dir)
    if not recon_dir.is_dir():
        logger.warning("Recon dir does not exist", extra={"path": str(recon_dir)})
        return []
    run_id = recon_dir.name
    job_id = f"{run_id}-stage1"
    stage_name = "recon_stage1"
    trace_id = f"{run_id}-{job_id}-mcp"

    dns_dir = recon_dir / "03_dns"
    live_dir = recon_dir / "04_live_hosts"

    generated: list[Path] = []
    with mcp_audit_context(
        stage=stage_name,
        run_id=run_id,
        job_id=job_id,
        recon_dir=recon_dir,
        trace_id=trace_id,
    ):

        # --- DNS summary ---
        try:
            from src.recon.reporting.dns_builder import build_dns_summary

            content = build_dns_summary(recon_dir)
            out_path = recon_dir / "dns_summary.md"
            out_path.write_text(content, encoding="utf-8")
            generated.append(out_path)
        except Exception:
            logger.warning("Skipped dns_summary", extra={"error_code": "dns_summary_failed"})

        # --- Subdomain classification ---
        try:
            from src.recon.reporting.subdomain_builder import build_subdomain_classification

            content = build_subdomain_classification(recon_dir)
            out_path = recon_dir / "subdomain_classification.csv"
            out_path.write_text(content, encoding="utf-8")
            generated.append(out_path)
        except Exception:
            logger.warning(
                "Skipped subdomain_classification",
                extra={"error_code": "subdomain_classification_failed"},
            )

        # --- Live hosts detailed ---
        try:
            from src.recon.reporting.live_host_builder import build_live_hosts_detailed

            resolved_path = dns_dir / "resolved.txt"
            cname_path = dns_dir / "cname_map.csv"
            http_probe_path = live_dir / "http_probe.csv"
            if http_probe_path.exists():
                content = build_live_hosts_detailed(
                    resolved_path=resolved_path,
                    cname_path=cname_path,
                    http_probe_path=http_probe_path,
                )
                out_path = recon_dir / "live_hosts_detailed.csv"
                out_path.write_text(content, encoding="utf-8")
                generated.append(out_path)
        except Exception:
            logger.warning(
                "Skipped live_hosts_detailed",
                extra={"error_code": "live_hosts_detailed_failed"},
            )

        # --- Tech profile ---
        try:
            from src.recon.reporting.tech_builder import build_tech_profile, build_tech_profile_json

            http_probe_path = live_dir / "http_probe.csv"
            content = build_tech_profile(http_probe_path=http_probe_path)
            out_path = recon_dir / "tech_profile.csv"
            out_path.write_text(content, encoding="utf-8")
            generated.append(out_path)

            entries = build_tech_profile_json(http_probe_path=http_probe_path)
            json_path = recon_dir / "tech_profile.json"
            json_path.write_text(
                json.dumps([e.model_dump(mode="json") for e in entries], indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            generated.append(json_path)
        except Exception:
            logger.warning("Skipped tech_profile", extra={"error_code": "tech_profile_failed"})

        # --- Recon results (REC-002) — aggregated ReconResults for recon_results.json ---
        try:
            from src.recon.reporting.recon_results_builder import build_recon_results

            recon_results = build_recon_results(recon_dir, run_id)
            out_path = recon_dir / "recon_results.json"
            out_path.write_text(
                recon_results.model_dump_json(indent=2, exclude_none=True),
                encoding="utf-8",
            )
            generated.append(out_path)
        except Exception:
            logger.warning(
                "Skipped recon_results",
                extra={"error_code": "recon_results_failed"},
            )

        # --- Headers / TLS / Endpoint inventory (use live hosts from http_probe) ---
        http_probe_path = live_dir / "http_probe.csv"
        stage1_live_hosts: list[str] = []
        if http_probe_path.exists():
            try:
                from src.recon.reporting.endpoint_builder import extract_live_hosts_from_http_probe

                stage1_live_hosts = extract_live_hosts_from_http_probe(http_probe_path)
            except Exception:
                pass

        try:
            from src.recon.reporting.headers_builder import build_headers_artifacts

            summary_content, detailed_csv = build_headers_artifacts(
                live_hosts=stage1_live_hosts,
                fetch_func=headers_fetch_func,
            )
            summary_path = recon_dir / "headers_summary.md"
            summary_path.write_text(summary_content, encoding="utf-8")
            generated.append(summary_path)
            detailed_path = recon_dir / "headers_detailed.csv"
            detailed_path.write_text(detailed_csv, encoding="utf-8")
            generated.append(detailed_path)
        except Exception:
            logger.warning("Skipped headers_summary", extra={"error_code": "headers_summary_failed"})

        try:
            from src.recon.reporting.headers_builder import build_tls_summary

            content = build_tls_summary(live_hosts=stage1_live_hosts)
            out_path = recon_dir / "tls_summary.md"
            out_path.write_text(content, encoding="utf-8")
            generated.append(out_path)
        except Exception:
            logger.warning("Skipped tls_summary", extra={"error_code": "tls_summary_failed"})

        try:
            from src.recon.reporting.endpoint_builder import build_endpoint_inventory

            content = build_endpoint_inventory(
                live_hosts=stage1_live_hosts if stage1_live_hosts else None,
                http_probe_path=http_probe_path if http_probe_path.exists() else None,
                fetch_func=fetch_func,
                use_mcp=use_mcp,
            )
            out_path = recon_dir / "endpoint_inventory.csv"
            out_path.write_text(content, encoding="utf-8")
            generated.append(out_path)
        except Exception:
            logger.warning(
                "Skipped endpoint_inventory",
                extra={"error_code": "endpoint_inventory_failed"},
            )

        # --- Stage 1 enrichment: routes/pages/forms/params/js/api + AI templates ---
        try:
            from src.recon.reporting.stage1_enrichment_builder import (
                build_stage1_enrichment_artifacts,
            )

            enrichment_outputs = build_stage1_enrichment_artifacts(
                recon_dir=recon_dir,
                live_hosts=stage1_live_hosts,
                endpoint_inventory_path=recon_dir / "endpoint_inventory.csv",
                fetch_func=fetch_func,
                use_mcp=use_mcp,
                trace_id=trace_id,
            )
            for filename, content in enrichment_outputs.items():
                out_path = recon_dir / filename
                out_path.write_text(content, encoding="utf-8")
                generated.append(out_path)
        except Exception:
            logger.warning("Skipped stage1 enrichment", extra={"error_code": "stage1_enrichment_failed"})

        # Resolve LLM client once for anomalies + stage2 (if keys present)
        call_llm: Callable[[str, dict], str] | None = None
        if has_any_llm_key():
            with suppress(Exception):
                call_llm = get_llm_client()

        # --- Anomalies + hypotheses + coverage gaps ---
        try:
            from src.recon.reporting.anomaly_builder import build_anomalies

            content, structured = build_anomalies(recon_dir, call_llm=call_llm)
            out_path = recon_dir / "anomalies.md"
            out_path.write_text(content, encoding="utf-8")
            generated.append(out_path)

            structured_path = recon_dir / "anomalies_structured.json"
            structured_path.write_text(
                json.dumps(structured, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            generated.append(structured_path)
        except Exception:
            logger.warning("Skipped anomalies", extra={"error_code": "anomalies_failed"})

        # --- Stage 2 inputs for Threat Modeling ---
        try:
            from src.recon.reporting.stage2_builder import build_stage2_inputs

            markdown_content, structured = build_stage2_inputs(recon_dir, call_llm=call_llm)
            out_path = recon_dir / "stage2_inputs.md"
            out_path.write_text(markdown_content, encoding="utf-8")
            generated.append(out_path)

            structured_path = recon_dir / "stage2_structured.json"
            structured_path.write_text(
                json.dumps(structured, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            generated.append(structured_path)
        except Exception:
            logger.warning("Skipped stage2_inputs", extra={"error_code": "stage2_inputs_failed"})

        # --- Intel/OSINT enrichment (when adapters available) ---
        try:
            if skip_intel:
                intel_data = {"target_domain": _derive_target_domain(recon_dir), "fetched_at": "", "adapters": []}
            else:
                target_domain = _derive_target_domain(recon_dir)
                intel_data = _run_intel_adapters(target_domain)
            if intel_data.get("adapters"):
                intel_path = recon_dir / "intel_findings.json"
                intel_path.write_text(
                    json.dumps(intel_data, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
                generated.append(intel_path)

                from src.recon.reporting.intel_builder import build_intel_summary

                summary_content = build_intel_summary(intel_data)
                summary_path = recon_dir / "intel_summary.md"
                summary_path.write_text(summary_content, encoding="utf-8")
                generated.append(summary_path)
        except Exception:
            logger.warning("Skipped intel enrichment", extra={"error_code": "intel_enrichment_failed"})

        # --- Tools & AI metadata for report ---
        tools_ai_metadata: dict = {}
        if call_llm:
            info = get_llm_provider_info()
            if info:
                tools_ai_metadata["ai_provider"] = info[0]
                tools_ai_metadata["ai_model"] = info[1]
                from src.recon.reporting.anomaly_builder import ANOMALY_PROMPT_TEMPLATE
                from src.recon.reporting.stage1_enrichment_builder import _AI_TEMPLATES
                from src.recon.reporting.stage2_builder import STAGE2_PROMPT_TEMPLATE
                tools_ai_metadata["prompts_used"] = [
                    {"name": "Anomaly interpretation", "description": ANOMALY_PROMPT_TEMPLATE},
                    {"name": "Stage 2 inputs", "description": STAGE2_PROMPT_TEMPLATE},
                    {
                        "name": "JS findings analysis",
                        "description": _AI_TEMPLATES["js_findings_analysis"]["prompt_template"],
                    },
                    {
                        "name": "Parameter input analysis",
                        "description": _AI_TEMPLATES["parameter_input_analysis"]["prompt_template"],
                    },
                    {
                        "name": "API surface inference",
                        "description": _AI_TEMPLATES["api_surface_inference"]["prompt_template"],
                    },
                    {
                        "name": "Headers/TLS posture summary",
                        "description": _AI_TEMPLATES["headers_tls_summary"]["prompt_template"],
                    },
                    {
                        "name": "Content similarity interpretation",
                        "description": _AI_TEMPLATES["content_similarity_interpretation"]["prompt_template"],
                    },
                    {
                        "name": "Anomaly interpretation (Stage1 validation)",
                        "description": _AI_TEMPLATES["anomaly_interpretation"]["prompt_template"],
                    },
                    {
                        "name": "Stage 2 preparation summary",
                        "description": _AI_TEMPLATES["stage2_preparation_summary"]["prompt_template"],
                    },
                    {
                        "name": "Stage 3 preparation summary",
                        "description": _AI_TEMPLATES["stage3_preparation_summary"]["prompt_template"],
                    },
                ]

        # --- HTML report (RPT-007) ---
        try:
            from src.recon.reporting.html_report_builder import build_html_report

            html_path = build_html_report(
                recon_dir,
                mcp_used_for_endpoints=use_mcp,
                tools_ai_metadata=tools_ai_metadata,
            )
            generated.append(html_path)
        except Exception:
            logger.warning("Skipped HTML report", extra={"error_code": "html_report_failed"})

        # --- Stage 1 baseline contract snapshot + MCP audit linkage artifacts ---
        contract_path = recon_dir / "stage1_contract_baseline.json"
        contract_path.write_text(
            build_stage1_contract_snapshot(run_id=run_id, job_id=job_id, trace_id=trace_id),
            encoding="utf-8",
        )
        generated.append(contract_path)

        audit_meta_path = write_mcp_audit_meta(
            recon_dir,
            stage=stage_name,
            run_id=run_id,
            job_id=job_id,
            trace_id=trace_id,
        )
        generated.append(audit_meta_path)

        audit_log_path = recon_dir / "mcp_invocation_audit.jsonl"
        if not audit_log_path.exists():
            audit_log_path.write_text("", encoding="utf-8")
        generated.append(audit_log_path)

        trace_path = build_mcp_trace_from_audit(recon_dir)
        if trace_path is not None:
            generated.append(trace_path)

    # REC-008/REC-009: aggregate raw tool outputs, optional artifacts layout, upload to MinIO
    aggregate_raw_tool_outputs(recon_dir, recon_dir)
    raw_dir = recon_dir / RAW_OUTPUTS_DIR
    if raw_dir.is_dir():
        generated.append(raw_dir)
        for p in raw_dir.iterdir():
            if p.is_file():
                generated.append(p)

    if artifacts_base is not None:
        artifacts_stage1_dir = artifacts_base / "stage1" / run_id
        artifacts_stage1_dir.mkdir(parents=True, exist_ok=True)
        _stage1_artifacts = (
            "recon_results.json",
            "tech_profile.json",
            "mcp_trace.jsonl",
            "anomalies_structured.json",
        )
        for name in _stage1_artifacts:
            src = recon_dir / name
            if src.is_file():
                shutil.copy2(src, artifacts_stage1_dir / name)
        if raw_dir.is_dir():
            dest_raw = artifacts_stage1_dir / RAW_OUTPUTS_DIR
            dest_raw.mkdir(exist_ok=True)
            for f in raw_dir.iterdir():
                if f.is_file():
                    shutil.copy2(f, dest_raw / f.name)

    upload_stage1_artifacts(
        artifacts_dir=recon_dir,
        scan_id=run_id,
        run_id=run_id,
        job_id=job_id,
    )

    logger.info(
        "Stage 1 report generated",
        extra={"recon_dir": str(recon_dir), "generated_count": len(generated)},
    )
    return generated
