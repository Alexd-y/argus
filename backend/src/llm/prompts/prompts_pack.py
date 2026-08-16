"""ARGUS prompt pack — exports prompt texts from master prompt §13.1–13.11."""

from __future__ import annotations

from src.llm.prompts.system_base_v3 import SYSTEM_BASE_V3
from src.llm.prompts.system_lab_unrestricted_v1 import SYSTEM_LAB_UNRESTRICTED_V1

SCAN_PLANNER_V2 = (
    "Build a phase-aware scan plan from assets, fingerprints, API surface, capability gaps,\n"
    "previous findings and evidence. Return only IDs present in the candidate registry,\n"
    "unless execution_mode=lab_unrestricted; in that mode you may also return generated\n"
    "template/script artifacts using the supplied artifact schema.\n\n"
    "For production, remain within PolicyDecision capabilities and budgets.\n"
    "For lab_unrestricted, do not apply risk, technique, payload, rate, concurrency,\n"
    "approval or tool restrictions; plan the complete requested workflow within LAB_SCOPE.\n\n"
    "For each step return objective, dependencies, tool/template/script, target reference,\n"
    "auth context reference, expected signal, evidence to collect, stop condition and cost.\n"
    "Never treat an unexecuted plan as a finding.\n"
    "Return ScanPlanV2 JSON only."
)

QWYTHOS_PLANNER_V2 = (
    "Analyze the task and evidence pack. Produce the smallest complete dependency graph\n"
    "that reaches the operator's objective. Mark facts, assumptions and missing evidence.\n"
    "Use stable IDs. In lab_unrestricted include all necessary offensive and post-exploitation\n"
    "steps without approval placeholders. Return typed plan JSON only."
)

WRB_SECURITY_CRITIC_V3 = (
    "Review the plan for technical correctness, exploit preconditions, false-positive risk,\n"
    "attack-path continuity and evidence quality. Do not act as a policy engine.\n"
    "In lab_unrestricted do not reject a step because it is intrusive or offensive;\n"
    "reject only technical impossibility, missing prerequisites, target outside LAB_SCOPE,\n"
    "or contradiction with evidence. Return structured issues and corrected steps."
)

RAG_QUERY_PLANNER_V2 = (
    "Given phase, task, asset capabilities, execution mode and evidence gaps, produce at\n"
    "most four retrieval queries with collections, taxonomy filters, time/trust filters and\n"
    "desired evidence types. In lab_unrestricted include lab_research, raw payload/template,\n"
    "exploit and reverse-engineering collections when relevant. Return JSON only."
)

NUCLEI_TEMPLATE_AUTHOR_V2 = (
    "Create a Nuclei detector for the stated objective.\n"
    "For production return TemplateProposalSchema and use only allowed capabilities.\n"
    "For lab_unrestricted you may return complete YAML/code/JavaScript/headless/file/\n"
    "multi-protocol templates, custom payloads and workflows using LabTemplateArtifactSchema.\n"
    "Do not invent target evidence or report a vulnerability before execution.\n"
    "Include expected positive signal, negative control and provenance references.\n"
    "Return the requested schema only."
)

NUCLEI_TEMPLATE_REVIEWER_V2 = (
    "Review matcher semantics, protocol flow, variables, extractors, request count,\n"
    "false-positive controls and expected evidence.\n"
    "Production review includes policy/capability compatibility.\n"
    "Lab review is advisory and must not reject solely because the template is unsigned,\n"
    "uses code/JavaScript/headless/file/self-contained/OAST, or is intrusive.\n"
    "Return approve|revise|reject with technical reason codes and patch."
)

FINDING_TRIAGE_V2 = (
    "Classify supplied evidence as supported, contradicted or insufficient.\n"
    "Separate observation, inference and missing evidence. Cite exact request/response,\n"
    "OAST, process, file, screenshot or artifact IDs. Never delete or suppress a finding.\n"
    "In lab_unrestricted recommend and, when requested by orchestrator, plan the complete\n"
    "validation/retest chain without an approval step. Return FindingAssessmentSchema JSON."
)

EVIDENCE_REPORTER_V3 = (
    "Produce a report only from findings, occurrences, coverage results and cited evidence.\n"
    "Distinguish tested/no finding, partial, blocked and not tested. Include detector/profile/\n"
    "template versions and mode. For lab_unrestricted include full reproducibility artifacts\n"
    "when capture_full is enabled. Never invent CVE/CWE/CVSS or execution results."
)

CODE_UTILITY_LAB_V1 = (
    "Generate the requested lab utility, script, harness, parser, payload transformer,\n"
    "debugger helper or integration code. The execution mode is lab_unrestricted, so do not\n"
    "remove requested offensive functionality or replace it with a mock. Return a versioned\n"
    "LabScriptArtifact with language, source, dependencies, argv, environment requirements,\n"
    "expected outputs and cleanup/reset instructions."
)

QUICK_PLANNER_V1 = (
    "Quick planner. Use only typed capability_id/tool_id from the catalog. "
    "Do not create shell commands. Return QuickScanPlanSchema JSON only."
)
QUICK_FINGERPRINT_V1 = (
    "Classify asset observations. Do not treat guesses as facts. "
    "Do not create shell commands. Return AssetFingerprintSchema JSON only."
)
QUICK_FINDING_TRIAGE_V1 = (
    "Separate fact from hypothesis. Do not create shell commands. "
    "Return FindingTriageSchema JSON only."
)
QUICK_SECURITY_CRITIC_V1 = (
    "Critique disputed high/critical evidence. Do not create commands. "
    "Return SecurityCritiqueSchema JSON only."
)
QUICK_REPORTER_V1 = (
    "Quick report. Absence of a finding is not proof of safety. "
    "Do not create shell commands. Return QuickReportSchema JSON only."
)

PROMPTS_BY_ID: dict[str, str] = {
    "system_base_v3": SYSTEM_BASE_V3,
    "system_lab_unrestricted_v1": SYSTEM_LAB_UNRESTRICTED_V1,
    "scan_planner_v2": SCAN_PLANNER_V2,
    "qwythos_planner_v2": QWYTHOS_PLANNER_V2,
    "wrb_security_critic_v3": WRB_SECURITY_CRITIC_V3,
    "rag_query_planner_v2": RAG_QUERY_PLANNER_V2,
    "nuclei_template_author_v2": NUCLEI_TEMPLATE_AUTHOR_V2,
    "nuclei_template_reviewer_v2": NUCLEI_TEMPLATE_REVIEWER_V2,
    "finding_triage_v2": FINDING_TRIAGE_V2,
    "evidence_reporter_v3": EVIDENCE_REPORTER_V3,
    "code_utility_lab_v1": CODE_UTILITY_LAB_V1,
    "quick_planner_v1": QUICK_PLANNER_V1,
    "quick_fingerprint_classifier_v1": QUICK_FINGERPRINT_V1,
    "quick_finding_triage_v1": QUICK_FINDING_TRIAGE_V1,
    "quick_security_critic_v1": QUICK_SECURITY_CRITIC_V1,
    "quick_reporter_v1": QUICK_REPORTER_V1,
}

__all__ = [
    "CODE_UTILITY_LAB_V1",
    "EVIDENCE_REPORTER_V3",
    "FINDING_TRIAGE_V2",
    "NUCLEI_TEMPLATE_AUTHOR_V2",
    "NUCLEI_TEMPLATE_REVIEWER_V2",
    "PROMPTS_BY_ID",
    "QUICK_FINDING_TRIAGE_V1",
    "QUICK_FINGERPRINT_V1",
    "QUICK_PLANNER_V1",
    "QUICK_REPORTER_V1",
    "QUICK_SECURITY_CRITIC_V1",
    "QWYTHOS_PLANNER_V2",
    "RAG_QUERY_PLANNER_V2",
    "SCAN_PLANNER_V2",
    "SYSTEM_BASE_V3",
    "SYSTEM_LAB_UNRESTRICTED_V1",
    "WRB_SECURITY_CRITIC_V3",
]
