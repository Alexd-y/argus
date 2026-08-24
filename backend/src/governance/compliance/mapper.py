"""Compliance Evidence Mapping — ISO 27001, SOC 2, PCI DSS, GDPR.

Maps findings, patches, and validation results to compliance controls.
Generates audit-ready evidence bundles per framework.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class Framework(str, Enum):
    ISO27001 = "iso27001"
    SOC2 = "soc2"
    PCI_DSS = "pci_dss"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    NIST_CSF = "nist_csf"


@dataclass
class ComplianceControl:
    id: str = ""
    framework: str = ""
    control_id: str = ""         # A.8.1, CC6.1, 6.5.1, Art.32, …
    control_name: str = ""
    description: str = ""
    evidence_required: str = ""


@dataclass
class ComplianceEvidence:
    id: str = ""
    tenant_id: str = ""
    finding_id: str = ""
    framework: str = ""
    control_id: str = ""
    evidence_type: str = ""      # patch_applied | validation_passed | risk_accepted | …
    evidence_description: str = ""
    evidence_hash: str = ""
    generated_at: str = ""
    validity_days: int = 365


# ISO 27001:2022 controls relevant to vulnerability management
ISO27001_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(framework="iso27001", control_id="A.8.8", control_name="Technical vulnerability management",
                      description="Vulnerabilities shall be identified, evaluated and addressed.",
                      evidence_required="Patch applied or risk accepted"),
    ComplianceControl(framework="iso27001", control_id="A.8.9", control_name="Configuration management",
                      description="Hardening and secure configuration.",
                      evidence_required="Hardening patch applied"),
    ComplianceControl(framework="iso27001", control_id="A.8.25", control_name="Secure development life cycle",
                      description="Security in development and maintenance.",
                      evidence_required="Security fix in code"),
    ComplianceControl(framework="iso27001", control_id="A.8.26", control_name="Application security requirements",
                      description="Security requirements for applications.",
                      evidence_required="Finding validated and patched"),
]

# SOC 2 Trust Services Criteria
SOC2_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(framework="soc2", control_id="CC6.1", control_name="Logical and physical access controls",
                      description="Controls over logical access to systems.",
                      evidence_required="Auth bypass fixed"),
    ComplianceControl(framework="soc2", control_id="CC7.1", control_name="System monitoring and alerts",
                      description="Monitor systems for anomalies.",
                      evidence_required="Alert correlated with code root cause"),
    ComplianceControl(framework="soc2", control_id="CC7.2", control_name="Incident detection and response",
                      description="Detect and respond to security incidents.",
                      evidence_required="Incident enriched with code context"),
]

# PCI DSS v4.0
PCI_DSS_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(framework="pci_dss", control_id="6.3.1", control_name="Security vulnerabilities identified",
                      description="Identify security vulnerabilities using appropriate methods.",
                      evidence_required="Finding identified by semantic SAST"),
    ComplianceControl(framework="pci_dss", control_id="6.3.2", control_name="Vulnerabilities ranked and fixed",
                      description="Rank and fix vulnerabilities based on risk.",
                      evidence_required="Risk score calculated, patch generated"),
]

# GDPR
GDPR_CONTROLS: list[ComplianceControl] = [
    ComplianceControl(framework="gdpr", control_id="Art.25", control_name="Data protection by design",
                      description="Appropriate technical measures for data protection.",
                      evidence_required="PII-related finding fixed"),
    ComplianceControl(framework="gdpr", control_id="Art.32", control_name="Security of processing",
                      description="Ensure ongoing confidentiality, integrity and resilience.",
                      evidence_required="Critical vulnerability remediated"),
]

FRAMEWORK_CONTROLS: dict[Framework, list[ComplianceControl]] = {
    Framework.ISO27001: ISO27001_CONTROLS,
    Framework.SOC2: SOC2_CONTROLS,
    Framework.PCI_DSS: PCI_DSS_CONTROLS,
    Framework.GDPR: GDPR_CONTROLS,
}


def _map_finding_to_controls(
    finding: dict[str, Any], framework: Framework,
) -> list[ComplianceControl]:
    """Map a security finding to relevant compliance controls."""
    all_controls = FRAMEWORK_CONTROLS.get(framework, [])
    cwe = str(finding.get("cwe", "")).upper()
    severity = str(finding.get("severity", "info")).lower()
    title = str(finding.get("title", "")).lower()

    relevant = []
    for ctrl in all_controls:
        if framework == Framework.ISO27001:
            if "vulnerability" in ctrl.control_id.lower() and severity in ("critical", "high", "medium") or "development" in ctrl.control_name.lower() and finding.get("file_path"):
                relevant.append(ctrl)
        elif framework == Framework.SOC2:
            if "access" in ctrl.control_name.lower() and any(kw in title for kw in ("auth", "bypass", "privilege")) or "incident" in ctrl.control_id.lower():
                relevant.append(ctrl)
        elif framework == Framework.PCI_DSS:
            relevant.append(ctrl)  # All PCI DSS vuln controls apply
        elif framework == Framework.GDPR:
            if any(kw in title for kw in ("pii", "data", "privacy", "personal")) or severity in ("critical", "high"):
                relevant.append(ctrl)

    if not relevant:
        relevant = all_controls[:1]
    return relevant


async def map_finding_to_compliance(
    finding: dict[str, Any],
    *,
    tenant_id: str = "",
    frameworks: list[Framework] | None = None,
) -> list[ComplianceEvidence]:
    """Map a finding to compliance frameworks and generate evidence records."""
    if frameworks is None:
        frameworks = [Framework.ISO27001, Framework.SOC2]

    evidence_records = []
    for fw in frameworks:
        controls = _map_finding_to_controls(finding, fw)
        for ctrl in controls:
            evidence = ComplianceEvidence(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                finding_id=finding.get("id", finding.get("finding_id", "")),
                framework=fw.value,
                control_id=ctrl.control_id,
                evidence_type=_determine_evidence_type(finding),
                evidence_description=f"Finding '{finding.get('title', 'N/A')[:100]}' "
                                     f"({finding.get('severity', 'unknown')}) maps to {ctrl.control_id} — {ctrl.control_name}",
                evidence_hash=hashlib.blake2b(
                    json.dumps({"finding_id": finding.get("id", ""), "control_id": ctrl.control_id, "fw": fw.value},
                               sort_keys=True).encode(), digest_size=16,
                ).hexdigest(),
                generated_at=datetime.now(UTC).isoformat(),
            )
            evidence_records.append(evidence)
    return evidence_records


def _determine_evidence_type(finding: dict[str, Any]) -> str:
    status = str(finding.get("patche_status", finding.get("status", ""))).lower()
    if "patched" in status or "validated" in status:
        return "patch_applied"
    if finding.get("exploitable"):
        return "risk_identified"
    return "finding_reported"


def build_audit_report(
    findings: list[dict[str, Any]],
    *,
    tenant_id: str = "",
    frameworks: list[Framework] | None = None,
) -> dict[str, Any]:
    """Build a compliance audit report from multiple findings."""
    import asyncio as _asyncio
    from concurrent.futures import ThreadPoolExecutor

    async def _collect():
        all_evidence = []
        for f in findings:
            evidence = await map_finding_to_compliance(f, tenant_id=tenant_id, frameworks=frameworks)
            all_evidence.extend(evidence)
        return all_evidence

    try:
        loop = _asyncio.get_running_loop()
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_asyncio.run, _collect())
            evidence = future.result(timeout=300)
    except RuntimeError:
        evidence = _asyncio.run(_collect())

    controls_covered = set()
    for e in evidence:
        controls_covered.add(f"{e.framework}:{e.control_id}")

    return {
        "report_id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "frameworks": [fw.value for fw in (frameworks or [Framework.ISO27001, Framework.SOC2])],
        "controls_covered": sorted(controls_covered),
        "total_controls": len(controls_covered),
        "findings_count": len(findings),
        "evidence": [
            {
                "finding_id": e.finding_id,
                "framework": e.framework,
                "control_id": e.control_id,
                "evidence_type": e.evidence_type,
                "hash": e.evidence_hash,
            }
            for e in evidence
        ],
    }
