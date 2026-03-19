"""Threat modeling module — Stage 2 dependency checks and TM workflow."""

from src.recon.threat_modeling.ai_task_registry import (
    THREAT_MODELING_AI_TASKS,
    export_threat_modeling_ai_schemas,
    get_threat_modeling_ai_task_definitions,
    validate_threat_modeling_ai_payload,
)
from src.recon.threat_modeling.artifacts import (
    generate_ai_reasoning_trace_json,
    generate_all_artifacts,
    generate_application_flows_json,
    generate_application_flows_md,
    generate_attacker_profiles_csv,
    generate_critical_assets_csv,
    generate_entry_points_csv,
    generate_evidence_gaps_md,
    generate_mcp_trace_json,
    generate_priority_hypotheses_json,
    generate_stage2_inputs_json,
    generate_testing_priorities_md,
    generate_threat_model_json,
    generate_threat_model_md,
    generate_threat_scenarios_csv,
    generate_trust_boundaries_csv,
    generate_trust_boundaries_md,
)
from src.recon.threat_modeling.stage2_parsers import (
    parse_application_flows_to_stage3,
    parse_critical_assets_to_stage3,
    parse_entry_points_to_stage3,
    parse_priority_hypotheses,
    parse_threat_scenarios_to_stage3,
    parse_trust_boundaries_to_stage3,
)
from src.recon.threat_modeling.dependency_check import (
    STAGE1_BASELINE_ARTIFACTS,
    Stage1ReadinessResult,
    check_stage1_readiness,
)
from src.recon.threat_modeling.input_loader import (
    load_threat_model_input_bundle,
    load_threat_model_input_bundle_from_artifacts,
)
from src.recon.threat_modeling.mcp_enrichment import enrich_with_mcp
from src.recon.threat_modeling.pipeline import (
    ThreatModelPipelineError,
    execute_threat_modeling_run,
)

__all__ = [
    "generate_all_artifacts",
    "generate_ai_reasoning_trace_json",
    "generate_application_flows_json",
    "generate_application_flows_md",
    "generate_attacker_profiles_csv",
    "generate_critical_assets_csv",
    "generate_entry_points_csv",
    "generate_evidence_gaps_md",
    "generate_mcp_trace_json",
    "generate_priority_hypotheses_json",
    "generate_stage2_inputs_json",
    "generate_testing_priorities_md",
    "generate_threat_model_json",
    "generate_threat_model_md",
    "generate_threat_scenarios_csv",
    "generate_trust_boundaries_csv",
    "generate_trust_boundaries_md",
    "parse_application_flows_to_stage3",
    "parse_critical_assets_to_stage3",
    "parse_entry_points_to_stage3",
    "parse_priority_hypotheses",
    "parse_threat_scenarios_to_stage3",
    "parse_trust_boundaries_to_stage3",
    "STAGE1_BASELINE_ARTIFACTS",
    "Stage1ReadinessResult",
    "THREAT_MODELING_AI_TASKS",
    "check_stage1_readiness",
    "enrich_with_mcp",
    "export_threat_modeling_ai_schemas",
    "get_threat_modeling_ai_task_definitions",
    "load_threat_model_input_bundle",
    "load_threat_model_input_bundle_from_artifacts",
    "ThreatModelPipelineError",
    "execute_threat_modeling_run",
    "validate_threat_modeling_ai_payload",
]
