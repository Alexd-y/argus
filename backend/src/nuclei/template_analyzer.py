"""NucleiTemplateAnalyzer — advisory capability/risk analysis (§9.3)."""

from __future__ import annotations

from src.nuclei.schemas import (
    NucleiTemplateManifest,
    TemplateAnalysisResult,
    TemplateProposal,
)

_HIGH_RISK_PROTOCOLS = frozenset(
    {"code", "javascript", "headless", "file", "network", "websocket"}
)
_INTRUSIVE_RISK_LEVELS = frozenset(
    {"intrusive", "code_execution", "destructive", "high"}
)


class NucleiTemplateAnalyzer:
    """Advisory analyzer — never blocks LAB execution."""

    def analyze_manifest(self, manifest: NucleiTemplateManifest) -> TemplateAnalysisResult:
        protocols = tuple(str(p) for p in manifest.protocols)
        capabilities = tuple(str(c) for c in manifest.capabilities)
        warnings: list[str] = []

        if manifest.requires_oast:
            warnings.append("requires_oast_callback")
        if manifest.risk_level in _INTRUSIVE_RISK_LEVELS:
            warnings.append(f"intrusive_risk:{manifest.risk_level}")
        if any(p in _HIGH_RISK_PROTOCOLS for p in protocols):
            warnings.append("high_risk_protocol_present")
        if not manifest.verified:
            warnings.append("unverified_source")
        if manifest.signature is None:
            warnings.append("unsigned_template")

        production_allowed = (
            manifest.verified
            and manifest.risk_level not in ("code_execution", "destructive")
            and not any(p in ("code", "javascript") for p in protocols)
        )

        return TemplateAnalysisResult(
            template_id=manifest.template_id,
            risk_level=manifest.risk_level,
            protocols=protocols,
            capabilities=capabilities,
            requires_oast=manifest.requires_oast,
            advisory_warnings=tuple(warnings),
            production_allowed=production_allowed,
            lab_allowed=True,
        )

    def analyze_proposal(self, proposal: TemplateProposal) -> TemplateAnalysisResult:
        protocol = str(proposal.protocol)
        warnings: list[str] = []
        if protocol in _HIGH_RISK_PROTOCOLS:
            warnings.append(f"high_risk_protocol:{protocol}")
        if proposal.risk_level in _INTRUSIVE_RISK_LEVELS:
            warnings.append(f"intrusive_risk:{proposal.risk_level}")
        if proposal.custom_payloads:
            warnings.append("custom_payloads_present")
        if proposal.uncertainties:
            warnings.extend(f"uncertainty:{u}" for u in proposal.uncertainties)

        production_allowed = (
            proposal.risk_level not in _INTRUSIVE_RISK_LEVELS
            and protocol not in ("code", "javascript", "headless")
        )

        template_id = proposal.proposal_id or f"proposal:{hash(proposal.intent) & 0xFFFFFFFF:08x}"
        return TemplateAnalysisResult(
            template_id=template_id,
            risk_level=proposal.risk_level,
            protocols=(protocol,),
            capabilities=tuple(proposal.payload_family_ids),
            requires_oast=False,
            advisory_warnings=tuple(warnings),
            production_allowed=production_allowed,
            lab_allowed=True,
        )
