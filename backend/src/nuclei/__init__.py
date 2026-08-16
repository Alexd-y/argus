"""Native Nuclei control plane — §9.

Public symbols are exported lazily so importing leaf modules
(e.g. ``legacy_metrics``) does not pull ``profile_compiler`` → VA →
orchestration and trigger circular imports.
"""

from __future__ import annotations

from typing import Any

__all__ = [
    "LabTemplateArtifact",
    "NucleiCompileRequest",
    "NucleiExecutionPlan",
    "NucleiExecutionPlanner",
    "NucleiProfileCompiler",
    "NucleiReleaseRecord",
    "NucleiTemplateAnalyzer",
    "NucleiTemplateManifest",
    "NucleiTemplateRegistry",
    "NucleiTemplateSelectionManifest",
    "NucleiUpdateController",
    "ScanProfile",
    "TemplateAnalysisResult",
    "TemplateProposal",
    "TemplateRegistryError",
    "TemplateSource",
    "digest_nuclei_template_ids",
    "load_scan_profile",
]

_LAZY_ATTRS: dict[str, tuple[str, str]] = {
    "LabTemplateArtifact": ("src.nuclei.schemas", "LabTemplateArtifact"),
    "NucleiCompileRequest": ("src.nuclei.schemas", "NucleiCompileRequest"),
    "NucleiExecutionPlan": ("src.nuclei.schemas", "NucleiExecutionPlan"),
    "NucleiExecutionPlanner": ("src.nuclei.execution_planner", "NucleiExecutionPlanner"),
    "NucleiProfileCompiler": ("src.nuclei.profile_compiler", "NucleiProfileCompiler"),
    "NucleiReleaseRecord": ("src.nuclei.schemas", "NucleiReleaseRecord"),
    "NucleiTemplateAnalyzer": ("src.nuclei.template_analyzer", "NucleiTemplateAnalyzer"),
    "NucleiTemplateManifest": ("src.nuclei.schemas", "NucleiTemplateManifest"),
    "NucleiTemplateRegistry": ("src.nuclei.template_registry", "NucleiTemplateRegistry"),
    "NucleiTemplateSelectionManifest": ("src.nuclei.schemas", "NucleiTemplateSelectionManifest"),
    "NucleiUpdateController": ("src.nuclei.update_controller", "NucleiUpdateController"),
    "ScanProfile": ("src.nuclei.schemas", "ScanProfile"),
    "TemplateAnalysisResult": ("src.nuclei.schemas", "TemplateAnalysisResult"),
    "TemplateProposal": ("src.nuclei.schemas", "TemplateProposal"),
    "TemplateRegistryError": ("src.nuclei.template_registry", "TemplateRegistryError"),
    "TemplateSource": ("src.nuclei.schemas", "TemplateSource"),
    "digest_nuclei_template_ids": ("src.nuclei.schemas", "digest_nuclei_template_ids"),
    "load_scan_profile": ("src.nuclei.profile_compiler", "load_scan_profile"),
}


def __getattr__(name: str) -> Any:
    target = _LAZY_ATTRS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_path, attr = target
    from importlib import import_module

    mod = import_module(module_path)
    value = getattr(mod, attr)
    globals()[name] = value
    return value
