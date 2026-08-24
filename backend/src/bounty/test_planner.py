"""Test plan generator — produce phased testing plans from bounty scope and surfaces."""

from __future__ import annotations

from src.bounty.schemas import (
    BountyScope,
    BountyTestPlan,
    ClassifiedSurface,
    TestPlanPhase,
    VulnPriority,
)
from src.bounty.surface_classifier import SurfaceType
from src.bounty.vuln_prioritizer import prioritize_vulns


def generate_test_plan(
    scope: BountyScope,
    surfaces: list[ClassifiedSurface] | None = None,
    prioritized_vulns: list[VulnPriority] | None = None,
) -> BountyTestPlan:
    """Build a structured phased test plan from scope analysis."""
    if surfaces is None:
        from src.bounty.surface_classifier import classify_surfaces
        surfaces = classify_surfaces(scope.in_scope)
    if prioritized_vulns is None:
        prioritized_vulns = prioritize_vulns(scope)

    phases: list[TestPlanPhase] = []
    phase_num = 1

    phases.append(TestPlanPhase(
        phase=phase_num,
        name="Passive Recon & Fingerprinting",
        priority="FIRST",
        surfaces=["global"],
        steps=[
            "Run: argus scan create --target <target> --mode quick",
            "Map all in-scope subdomains via crt.sh / subfinder / DNS",
            "Screenshot all discovered assets",
            "Check Wayback Machine for old endpoints / leaked params",
            "Google dork: site:target.com (inurl:api | inurl:admin | ext:json)",
            "Search GitHub/GitLab for exposed secrets: org:targetcorp",
            "Check Shodan/Censys for exposed ports and services",
        ],
    ))
    phase_num += 1

    surface_priority_order = [
        SurfaceType.AUTH_SYSTEM,
        SurfaceType.API,
        SurfaceType.ADMIN_PANEL,
        SurfaceType.WEB_APP,
        SurfaceType.MOBILE,
        SurfaceType.CLOUD_INFRA,
        SurfaceType.SUBDOMAIN,
        SurfaceType.CDN_ASSETS,
    ]

    for surface_type in surface_priority_order:
        matching = [s for s in surfaces if s.surface_type == surface_type]
        if not matching:
            continue

        phase = TestPlanPhase(
            phase=phase_num,
            name=f"{surface_type.value.replace('_', ' ').title()} Testing",
            priority="HIGH" if surface_type in (
                SurfaceType.AUTH_SYSTEM, SurfaceType.API, SurfaceType.ADMIN_PANEL
            ) else "MEDIUM",
            surfaces=[s.surface_type.value for s in matching],
            steps=matching[0].test_steps,
            recommended_scan_options=matching[0].recommended_scan_options,
        )
        phases.append(phase)
        phase_num += 1

    vuln_checklist_steps = [
        f"[ ] {v.vuln} (OWASP {v.owasp}) — score {v.score}/10"
        for v in prioritized_vulns[:10]
    ]
    phases.append(TestPlanPhase(
        phase=phase_num,
        name="High-Value Vulnerability Checklist",
        priority="HIGH",
        steps=vuln_checklist_steps,
    ))

    return BountyTestPlan(
        program_name=scope.program_name,
        platform=scope.platform,
        reward_range=scope.reward_range,
        surfaces=surfaces,
        prioritized_vulns=prioritized_vulns,
        phases=phases,
        scope=scope,
    )
