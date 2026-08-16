"""NucleiExecutionPlanner — candidate → execution plan (§9.7)."""

from __future__ import annotations

from collections.abc import Sequence

from src.execution_mode.mode import ExecutionMode, parse_execution_mode
from src.nuclei.profile_compiler import load_scan_profile
from src.nuclei.schemas import (
    NucleiExecutionPlan,
    NucleiTemplateSelectionManifest,
    ScanProfile,
    digest_nuclei_template_ids,
)
from src.nuclei.template_analyzer import NucleiTemplateAnalyzer
from src.nuclei.template_registry import NucleiTemplateRegistry


class NucleiExecutionPlanner:
    """Build execution plans — LAB bypasses approval/risk budget; Quick uses production gates."""

    def __init__(
        self,
        registry: NucleiTemplateRegistry | None = None,
        analyzer: NucleiTemplateAnalyzer | None = None,
    ) -> None:
        self._registry = registry or NucleiTemplateRegistry()
        self._analyzer = analyzer or NucleiTemplateAnalyzer()

    @property
    def registry(self) -> NucleiTemplateRegistry:
        return self._registry

    def plan(
        self,
        candidates: Sequence[str] | NucleiTemplateSelectionManifest,
        profile: str | ScanProfile,
        mode: ExecutionMode | str,
        *,
        selector_manifest: NucleiTemplateSelectionManifest | None = None,
        risk_budget: float | None = None,
        approval_granted: bool = False,
    ) -> NucleiExecutionPlan:
        resolved_mode = parse_execution_mode(mode)
        resolved_profile = (
            profile if isinstance(profile, ScanProfile) else load_scan_profile(profile)
        )
        manifest = selector_manifest
        if isinstance(candidates, NucleiTemplateSelectionManifest):
            manifest = candidates
        if manifest is not None:
            expected = digest_nuclei_template_ids(manifest.template_ids)
            if manifest.digest_sha256 != expected:
                raise ValueError("selector_manifest_digest_mismatch")
            candidate_ids = tuple(
                dict.fromkeys(str(item).strip() for item in manifest.template_ids if str(item).strip())
            )
        else:
            candidate_ids = tuple(
                dict.fromkeys(str(item).strip() for item in candidates if str(item).strip())
            )

        match resolved_mode:
            case ExecutionMode.LAB_UNRESTRICTED:
                return NucleiExecutionPlan(
                    profile_id=resolved_profile.id,
                    mode=resolved_mode.value,
                    template_ids=candidate_ids,
                    requires_approval=False,
                    blocked_reasons=(),
                    risk_budget_remaining=risk_budget,
                )
            case ExecutionMode.PRODUCTION | ExecutionMode.QUICK:
                pass
            case _:
                raise ValueError(f"unsupported_execution_mode:{resolved_mode}")

        blocked: list[str] = []
        approved_ids: list[str] = []

        if resolved_profile.requires_approval and not approval_granted:
            blocked.append("profile_requires_approval")

        remaining_budget = risk_budget
        for template_id in candidate_ids:
            manifest = self._registry.get(template_id)
            if manifest is None:
                blocked.append(f"unknown_template:{template_id}")
                continue
            analysis = self._analyzer.analyze_manifest(manifest)
            if not analysis.production_allowed:
                blocked.append(f"production_denied:{template_id}")
                continue
            if remaining_budget is not None:
                cost = 1.0 if analysis.risk_level in ("intrusive", "code_execution") else 0.25
                if remaining_budget < cost:
                    blocked.append(f"risk_budget_exhausted:{template_id}")
                    continue
                remaining_budget -= cost
            approved_ids.append(template_id)

        return NucleiExecutionPlan(
            profile_id=resolved_profile.id,
            mode=resolved_mode.value,
            template_ids=tuple(approved_ids),
            requires_approval=resolved_profile.requires_approval,
            blocked_reasons=tuple(blocked),
            risk_budget_remaining=remaining_budget,
        )
