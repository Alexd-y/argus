"""Phase 2/3 — a fully-populated snapshot must reach every readable format (RC-05..RC-13).

Builds a ``ReportDocumentV1`` where every ``render="all"`` field carries a distinctive,
non-empty value (including nested models and list items), renders it through all four
renderers, and asserts the declarative parity gate finds nothing missing. This is the
exhaustive guard the spec names ``test_render_parity_full_document``: if a renderer
stops emitting a field, a precise ``model.field`` blocker appears here.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from src.reports.renderers import render_html, render_json, render_markdown, render_xml
from src.reports.report_content_parity import content_parity_blockers
from src.reports.report_document import (
    ClientImpact,
    EngagementMetadata,
    ReportAttackStep,
    ReportClaim,
    ReportClosure,
    ReportConclusions,
    ReportCoverageItem,
    ReportDocumentV1,
    ReportEvidenceRef,
    ReportExploitChain,
    ReportFailure,
    ReportFinding,
    ReportMethodologyRef,
    ReportPoC,
    ReportRemediation,
    ReportSurfaceItem,
    ReportTestExecution,
    ReportToolRun,
    ReportValidationError,
)

_TS = datetime(2026, 1, 1, tzinfo=UTC)


def _full_finding() -> ReportFinding:
    # finding-level observed/potential/blast mirror the PoC (as _map_finding does in
    # production) so the value is present via the PoC rendering.
    return ReportFinding(
        finding_id="F-1",
        observation_id="zzObservationId",
        provenance="zzProvenanceFirstContact",
        title="zzFindTitle",
        severity="high",
        category="zzCategory",
        cwe="CWE-79",
        description="zzFindDesc",
        verification_status="confirmed",
        confidence=0.91,
        evidence_ids=["E-1"],
        tool_run_id="TR-1",
        validator_id="zzValidator",
        raw_artifact_ref="zzRawRef",
        owasp_category="A03:2021",
        cvss_version="3.1",
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        cvss_score=8.8,
        established_or_hypothesis="established",
        confirmation_class="xss",
        downgrade_reason="zzDowngrade",
        reviewer="zzFindReviewer",
        review_status="approved",
        asset="zzAsset",
        ip="10.2.2.2",
        port=8443,
        protocol="tcp",
        scheme="https",
        url="https://zz.example/vuln",
        path="/vuln-path",
        parameter="zzParam",
        component="zzComponent",
        observed_version="zzObsVer",
        wstg_test_ids=["WSTG-CLNT-01"],
        observed_impact="zzObsImpact",
        potential_impact="zzPotImpact",
        blast_radius="zzBlast",
        acceptance_criteria=["zzAccCrit"],
        retest_plan=["zzRetestStep"],
        priority_rationale="zzPrioRationaleFinding",
        poc=ReportPoC(
            tool="zzPocTool",
            payload="zzPayload",
            command="zzCommand",
            http_request="zzHttpReq",
            http_response="zzHttpResp",
            observation="zzObservation",
            oast_callback="zzOastCb",
            screenshot_ref="zzScreenshot",
            evidence_ids=["E-poc1"],
            reproducibility="confirmed",
            preconditions="zzPrecond",
            discriminator="zzDiscriminator",
            negative_control="zzNegControl",
            canary="zzPocCanary",
            timing="zzTiming",
            source="zzSource",
            attempts=3,
            observed_impact="zzObsImpact",
            potential_impact="zzPotImpact",
            blast_radius="zzBlast",
            cleanup="zzCleanup",
            client_repro="zzClientRepro",
        ),
        remediation=ReportRemediation(
            status="generated",
            established_or_hypothesis="established",
            temporary_containment="zzContain",
            permanent_fix="zzFix",
            preventive_measures="zzPrevent",
            component="zzRemComponent",
            rollout_order="zzRollout",
            rollback_risk="zzRollback",
            acceptance_criteria=["zzRemAccCrit"],
            retest_plan="zzRemRetest",
        ),
        closure=ReportClosure(
            permitted_status="zzPermitted",
            what_verified="zzVerified",
            what_not_verified="zzNotVerified",
            residual_risk="zzResidual",
            next_step="zzNextStep",
        ),
    )


def _full_document() -> ReportDocumentV1:
    doc = ReportDocumentV1(
        scan_id="zzScan-1",
        tenant_id="zzTenant-1",
        target="https://zz.example",
        scan_profile="zzProfileDeep",
        resolved_scan_mode="zzModeThorough",
        execution_mode="zzExecProd",
        quick_profile="zzQuickFast",
        nuclei_profile="zzNucleiFull",
        started_at="2026-01-01T00:00:00Z",
        completed_at="2026-01-02T00:00:00Z",
        scope_summary={"zzScopeKey": "zzScopeValue"},
        profile_limits={"zzLimitKey": "zzLimitValue"},
        tool_runs=[
            ReportToolRun(
                tool_run_id="TR-1",
                tool_name="zzToolName",
                status="success",
                parser_status="zzParserOk",
                raw_artifact_ref="zzToolRawRef",
                started_at="2026-01-01T01:00:00Z",
                finished_at="2026-01-01T02:00:00Z",
                exit_code=0,
                argv="zzArgvRedacted --flag",
                sandbox_id="zzSandbox",
                source_ip="10.9.9.9",
            )
        ],
        tested_capabilities=["zzCapTested"],
        not_assessed_capabilities=["zzCapNotAssessed"],
        coverage=[
            ReportCoverageItem(
                capability_id="zzCapCov",
                status="tested",
                reason_code="zzCovReason",
                evidence_ids=["E-cov"],
            )
        ],
        findings=[_full_finding()],
        evidence_references=[
            ReportEvidenceRef(
                evidence_id="E-1",
                kind="artifact",
                object_key="zzObjectKeyOpaque",
                description="zzEvidenceDesc",
                sha256="zzSha256Digest",
                size=1234,
                mime="application/zzmime",
                collected_at_utc="2026-01-01T03:00:00Z",
                collector="zzCollector",
                producer_tool_run_id="TR-1",
                redaction_applied=True,
                chain_hash="zzChainHash",
            )
        ],
        oast_references=[{"zzOastKey": "zzOastValue"}],
        failures=[
            ReportFailure(where="zzFailWhere", reason_code="zzFailReason", message="zzFailMsg")
        ],
        skipped_reasons=[{"zzSkipKey": "zzSkipValue"}],
        budget_usage={"zzBudgetKey": "zzBudgetValue"},
        limitations=["zzLimitationOne"],
        validation_errors=[
            ReportValidationError(finding_id="F-1", code="zzVErrCode", message="zzVErrMsg")
        ],
        prompt_model_versions={"zzPromptKey": "zzPromptValue"},
        registry_versions={"zzRegKey": "zzRegValue"},
        surface_inventory=[
            ReportSurfaceItem(
                host="zzHost",
                port=8080,
                service="zzService",
                version="zzSurfaceVer",
                technology="zzTechnology",
            )
        ],
        unconfirmed_observations=[
            ReportFinding(
                finding_id="U-1",
                title="zzUnconfTitle",
                severity="info",
                verification_status="observed",
                downgrade_reason="zzUnconfDowngrade",
            )
        ],
        test_executions=[
            ReportTestExecution(
                test_id="zzTest-1",
                control="zzControl",
                method="zzMethod",
                executed_at="2026-01-03T00:00:00Z",
                result="passed",
                evidence_ids=["E-te"],
            )
        ],
        attack_narrative=[
            ReportAttackStep(
                order_index=1,
                phase="zzNarrPhase",
                description="zzNarrDesc",
                tactic="zzNarrTactic",
                technique_id="T1190",
                claim_ids=["CL-n1"],
                evidence_ids=["E-n1"],
                timestamp="2026-01-04T00:00:00Z",
            )
        ],
        exploit_chains=[
            ReportExploitChain(
                chain_id="zzChain-1",
                kind="proven",
                title="zzChainTitle",
                steps=[
                    ReportAttackStep(
                        order_index=1,
                        phase="zzChainPhase",
                        description="zzChainStepDesc",
                        tactic="zzChainTactic",
                        technique_id="T1059",
                        claim_ids=["CL-c1"],
                        evidence_ids=["E-c1"],
                        timestamp="2026-01-05T00:00:00Z",
                    )
                ],
                preconditions="zzChainPre",
                outcome="zzChainOutcome",
                breaks_at="zzChainBreaks",
                to_verify=["zzChainVerify"],
            )
        ],
        methodology=[
            ReportMethodologyRef(
                framework="zzFramework", revision="zzRev1", applied=True, notes="zzMethodNotes"
            )
        ],
        engagement=EngagementMetadata(
            testing_windows=["zzWindow"],
            source_ips=["zzSrcIp-1"],
            user_agents=["zzUserAgent"],
            canaries=["zzCanary"],
            oast_domains=["zzOastDomain"],
            test_accounts=["zzAccount"],
            run_profile="zzRunProfile",
            execution_mode="zzEngExec",
            tool_catalog_version="zzCatalogVer",
            roe_restrictions=["zzRoe"],
            incidents=["zzIncident"],
            time_source="zzTimeSource",
        ),
        client_impact=ClientImpact(
            created_artifacts=["zzCreated"],
            removed=["zzRemoved"],
            not_removed=["zzNotRemoved"],
            data_exfiltration="zzExfil",
            availability_impact="zzAvail",
        ),
        conclusions=ReportConclusions(
            executive_summary="zzExecSummary",
            business_risk="zzBizRisk",
            closure_summary="zzClosureSummary",
            priority_plan=[{"rationale": "zzPrioPlanRationale", "finding_ids": ["F-1"]}],
        ),
        claims=[
            ReportClaim(
                claim_id="CL-1",
                claim_type="zzClaimType",
                text="zzClaimText",
                subject="zzClaimSubject",
                evidence_ids=["E-cl1"],
                derived_from=["CL-0"],
                limitations="zzClaimLimits",
                validator="zzClaimValidator",
                reviewer="zzClaimReviewer",
            )
        ],
        generation_status="ready",
        llm_analysis_status="completed",
        assessment_completeness="complete",
        evidence_integrity="verified",
        review_status="approved",
        verification_kit_ref="zzKitRef",
    )
    return doc.finalized(generated_at=_TS)


def test_declarative_parity_clean_on_full_document():
    doc = _full_document()
    canon = {
        "json": render_json(doc).encode(),
        "md": render_markdown(doc).encode(),
        "xml": render_xml(doc).encode(),
        "html": render_html(doc).encode(),
    }
    blockers = content_parity_blockers(canon, doc=doc)
    field_blockers = [b for b in blockers if b.startswith("parity:") and " value not rendered" in b]
    assert field_blockers == [], field_blockers


def test_md_html_section_headers_do_not_diverge():
    """C-28 — the new/renamed sections must keep MD and HTML section-header sets equal, or
    the content-parity gate fail-closed-blocks every report that has them (RC-07 headers)."""
    doc = _full_document()
    canon = {
        "json": render_json(doc).encode(),
        "md": render_markdown(doc).encode(),
        "html": render_html(doc).encode(),
    }
    blockers = content_parity_blockers(canon)
    assert not any("section headers differ" in b for b in blockers), blockers


@pytest.mark.parametrize("render", [render_markdown, render_xml, render_html])
def test_free_form_container_values_present(render):
    """RC-07 — the free-form top-level containers reach every readable format."""
    text = render(_full_document())
    for value in (
        "zzScopeValue",
        "zzLimitValue",
        "zzBudgetValue",
        "zzPromptValue",
        "zzRegValue",
        "zzOastValue",
        "zzSkipValue",
        "zzCapTested",
        "zzCapNotAssessed",
    ):
        assert value in text, (render.__name__, value)
