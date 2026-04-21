"""Unit tests for ARGUS pipeline contracts (ARG-001).

Covers ToolJob/ValidationJob/ExploitJob/FindingDTO/EvidenceDTO/PhaseTransition
construction, mutually-exclusive TargetSpec validation, JSON serialization
round-trip, and the 6-phase ordering rules.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

from src.orchestrator.schemas.loader import (
    PayloadStrategyV1,
    RiskRating,
    ValidationPlanV1,
    ValidatorSpecV1,
    ValidatorTool,
)
from src.pipeline.contracts import (
    ConfidenceLevel,
    EvidenceDTO,
    EvidenceKind,
    ExploitJob,
    FindingCategory,
    FindingDTO,
    FindingStatus,
    PhaseOutput,
    PhaseTransition,
    RemediationDTO,
    ReproducerSpecDTO,
    RiskLevel,
    SSVCDecision,
    ScanPhase,
    TargetSpec,
    ToolJob,
    ValidationJob,
)
from src.pipeline.contracts.tool_job import TargetKind

# 64 bytes -> 88 chars base64 with padding; this is a deterministic dummy signature
# generated locally to keep the test hermetic. It is NOT a valid Ed25519 signature
# of any real payload; the contract only enforces structural validity.
_FAKE_ED25519_SIG = base64.b64encode(b"\x01" * 64).decode("ascii")


def _make_tool_job(
    *,
    risk_level: RiskLevel = RiskLevel.LOW,
    requires_approval: bool = False,
    approval_id: str | None = None,
    target: TargetSpec | None = None,
    parameters: dict[str, str] | None = None,
) -> ToolJob:
    return ToolJob(
        id=uuid4(),
        tenant_id=uuid4(),
        scan_id=uuid4(),
        tool_id="nmap_tcp_top",
        phase=ScanPhase.RECON,
        risk_level=risk_level,
        target=target or TargetSpec(kind=TargetKind.IP, ip="10.0.0.1"),
        parameters=parameters if parameters is not None else {"ip": "10.0.0.1", "out_dir": "/out"},
        outputs_dir="/out",
        timeout_s=600,
        requires_approval=requires_approval,
        approval_id=approval_id,  # type: ignore[arg-type]
        correlation_id="trace-abc-001",
    )


class TestTargetSpec:
    def test_url_only(self) -> None:
        spec = TargetSpec(kind=TargetKind.URL, url="https://example.com/login")
        assert spec.value == "https://example.com/login"

    def test_host_only(self) -> None:
        spec = TargetSpec(kind=TargetKind.HOST, host="api.example.com")
        assert spec.value == "api.example.com"

    def test_ip_only(self) -> None:
        spec = TargetSpec(kind=TargetKind.IP, ip="10.0.0.1")
        assert spec.value == "10.0.0.1"

    def test_cidr_only(self) -> None:
        spec = TargetSpec(kind=TargetKind.CIDR, cidr="10.0.0.0/24")
        assert spec.value == "10.0.0.0/24"

    def test_domain_only(self) -> None:
        spec = TargetSpec(kind=TargetKind.DOMAIN, domain="example.com")
        assert spec.value == "example.com"

    def test_url_and_ip_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            TargetSpec(kind=TargetKind.URL, url="https://x", ip="1.2.3.4")
        assert "exactly one" in str(exc.value)

    def test_no_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            TargetSpec(kind=TargetKind.URL)

    def test_kind_mismatch_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            TargetSpec(kind=TargetKind.URL, host="example.com")
        assert "populated field is" in str(exc.value)


class TestToolJob:
    def test_happy_path(self) -> None:
        job = _make_tool_job()
        assert job.tool_id == "nmap_tcp_top"
        assert job.requires_approval is False

    def test_invalid_risk_level(self) -> None:
        with pytest.raises(ValidationError):
            ToolJob(
                id=uuid4(),
                tenant_id=uuid4(),
                scan_id=uuid4(),
                tool_id="nmap",
                phase=ScanPhase.RECON,
                risk_level="lethal",  # type: ignore[arg-type]
                target=TargetSpec(kind=TargetKind.IP, ip="1.2.3.4"),
                parameters={},
                outputs_dir="/out",
                timeout_s=60,
                correlation_id="t",
            )

    def test_invalid_phase(self) -> None:
        with pytest.raises(ValidationError):
            ToolJob(
                id=uuid4(),
                tenant_id=uuid4(),
                scan_id=uuid4(),
                tool_id="nmap",
                phase="invalid_phase",  # type: ignore[arg-type]
                risk_level=RiskLevel.LOW,
                target=TargetSpec(kind=TargetKind.IP, ip="1.2.3.4"),
                parameters={},
                outputs_dir="/out",
                timeout_s=60,
                correlation_id="t",
            )

    def test_invalid_tool_id(self) -> None:
        with pytest.raises(ValidationError) as exc:
            ToolJob(
                id=uuid4(),
                tenant_id=uuid4(),
                scan_id=uuid4(),
                tool_id="UPPERCASE",
                phase=ScanPhase.RECON,
                risk_level=RiskLevel.LOW,
                target=TargetSpec(kind=TargetKind.IP, ip="1.2.3.4"),
                parameters={},
                outputs_dir="/out",
                timeout_s=60,
                correlation_id="t",
            )
        assert "tool_id" in str(exc.value)

    def test_disallowed_param_key(self) -> None:
        with pytest.raises(ValidationError) as exc:
            ToolJob(
                id=uuid4(),
                tenant_id=uuid4(),
                scan_id=uuid4(),
                tool_id="nmap",
                phase=ScanPhase.RECON,
                risk_level=RiskLevel.LOW,
                target=TargetSpec(kind=TargetKind.IP, ip="1.2.3.4"),
                parameters={"secret": "hunter2"},
                outputs_dir="/out",
                timeout_s=60,
                correlation_id="t",
            )
        assert "allow-list" in str(exc.value)

    def test_high_risk_requires_approval(self) -> None:
        with pytest.raises(ValidationError) as exc:
            _make_tool_job(risk_level=RiskLevel.HIGH, requires_approval=False)
        assert "requires_approval=True" in str(exc.value)

    def test_approval_id_without_flag_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _make_tool_job(
                risk_level=RiskLevel.LOW,
                requires_approval=False,
                approval_id=str(uuid4()),
            )

    def test_inputs_dir_must_differ(self) -> None:
        with pytest.raises(ValidationError):
            ToolJob(
                id=uuid4(),
                tenant_id=uuid4(),
                scan_id=uuid4(),
                tool_id="nmap",
                phase=ScanPhase.RECON,
                risk_level=RiskLevel.LOW,
                target=TargetSpec(kind=TargetKind.IP, ip="1.2.3.4"),
                parameters={},
                inputs_dir="/io",
                outputs_dir="/io",
                timeout_s=60,
                correlation_id="t",
            )

    def test_serialization_round_trip(self) -> None:
        original = _make_tool_job()
        as_json = original.model_dump_json()
        restored = ToolJob.model_validate_json(as_json)
        assert restored == original

    def test_correlation_id_charset(self) -> None:
        with pytest.raises(ValidationError):
            ToolJob(
                id=uuid4(),
                tenant_id=uuid4(),
                scan_id=uuid4(),
                tool_id="nmap",
                phase=ScanPhase.RECON,
                risk_level=RiskLevel.LOW,
                target=TargetSpec(kind=TargetKind.IP, ip="1.2.3.4"),
                parameters={},
                outputs_dir="/out",
                timeout_s=60,
                correlation_id="bad id with spaces",
            )

    def test_requires_approval_without_id_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            _make_tool_job(
                risk_level=RiskLevel.HIGH,
                requires_approval=True,
                approval_id=None,
            )
        assert "approval_id is required" in str(exc.value)

    def test_param_key_invalid_format_rejected(self) -> None:
        # An UPPERCASE key is not snake_case and should be rejected before the
        # allow-list check.
        with pytest.raises(ValidationError) as exc:
            ToolJob(
                id=uuid4(),
                tenant_id=uuid4(),
                scan_id=uuid4(),
                tool_id="nmap",
                phase=ScanPhase.RECON,
                risk_level=RiskLevel.LOW,
                target=TargetSpec(kind=TargetKind.IP, ip="1.2.3.4"),
                parameters={"BAD_KEY": "x"},
                outputs_dir="/out",
                timeout_s=60,
                correlation_id="t",
            )
        assert "snake_case" in str(exc.value)

    def test_tool_job_accepts_authentication_placeholders(self) -> None:
        """Auth-related short placeholders (``u``, ``p``, ``mode``) must be allowed.

        Backlog/dev1_md §4.12 (evil-winrm ``-u {u} -p {p}``) and §4.13
        (hashcat ``-m {mode}``) declare these short placeholder names. The
        ``ToolJob.parameters`` allow-list MUST agree with the templating
        allow-list, otherwise the YAMLs load but no real ``ToolJob`` can ever
        supply the keys -- silently disabling those tools.
        """
        job = _make_tool_job(
            parameters={
                "host": "10.0.0.1",
                "u": "admin",
                "p": "P@ssw0rd!",
                "mode": "1000",
                "out_dir": "/out/scan",
            },
        )
        assert job.parameters["u"] == "admin"
        assert job.parameters["mode"] == "1000"


def _make_validation_plan(*, risk: RiskRating = RiskRating.HIGH) -> ValidationPlanV1:
    return ValidationPlanV1(
        hypothesis="Boolean-blind SQLi suspected on /search?q=",
        risk=risk,
        payload_strategy=PayloadStrategyV1(
            registry_family="sqli.boolean.diff.v3",
            mutation_classes=[],
            raw_payloads_allowed=False,
        ),
        validator=ValidatorSpecV1(
            tool=ValidatorTool.SAFE_VALIDATOR,
            inputs={"endpoint": "/search", "param": "q"},
            success_signals=["response_diff > threshold"],
            stop_conditions=["http_500", "rate_limited"],
        ),
        approval_required=False,
        evidence_to_collect=["raw_output", "diff"],
        remediation_focus=["use parameterized queries"],
    )


class TestValidationJob:
    def _hex(self, length: int = 24) -> str:
        return "0" * length  # all-zero lowercase hex

    def test_happy_path(self) -> None:
        job = ValidationJob(
            id=uuid4(),
            tenant_id=uuid4(),
            scan_id=uuid4(),
            finding_id=uuid4(),
            phase=ScanPhase.VULN_ANALYSIS,
            canary_token=self._hex(),
            validation_plan=_make_validation_plan(),
            evidence_required=[EvidenceKind.RAW_OUTPUT, EvidenceKind.OAST_CALLBACK],
            correlation_id="trace-vj-1",
        )
        assert len(job.canary_token) == 24

    def test_canary_too_short(self) -> None:
        with pytest.raises(ValidationError):
            ValidationJob(
                id=uuid4(),
                tenant_id=uuid4(),
                scan_id=uuid4(),
                finding_id=uuid4(),
                phase=ScanPhase.VULN_ANALYSIS,
                canary_token="short",
                validation_plan=_make_validation_plan(),
                evidence_required=[EvidenceKind.RAW_OUTPUT],
                correlation_id="t",
            )

    def test_canary_non_hex(self) -> None:
        with pytest.raises(ValidationError):
            ValidationJob(
                id=uuid4(),
                tenant_id=uuid4(),
                scan_id=uuid4(),
                finding_id=uuid4(),
                phase=ScanPhase.VULN_ANALYSIS,
                canary_token="ZZZZZZZZZZZZZZZZZZZZZZZZ",
                validation_plan=_make_validation_plan(),
                evidence_required=[EvidenceKind.RAW_OUTPUT],
                correlation_id="t",
            )

    def test_phase_must_be_validation_eligible(self) -> None:
        with pytest.raises(ValidationError) as exc:
            ValidationJob(
                id=uuid4(),
                tenant_id=uuid4(),
                scan_id=uuid4(),
                finding_id=uuid4(),
                phase=ScanPhase.RECON,
                canary_token=self._hex(),
                validation_plan=_make_validation_plan(),
                evidence_required=[EvidenceKind.RAW_OUTPUT],
                correlation_id="t",
            )
        assert "validation-eligible" in str(exc.value)

    def test_evidence_required_no_duplicates(self) -> None:
        with pytest.raises(ValidationError):
            ValidationJob(
                id=uuid4(),
                tenant_id=uuid4(),
                scan_id=uuid4(),
                finding_id=uuid4(),
                phase=ScanPhase.VULN_ANALYSIS,
                canary_token=self._hex(),
                validation_plan=_make_validation_plan(),
                evidence_required=[
                    EvidenceKind.RAW_OUTPUT,
                    EvidenceKind.RAW_OUTPUT,
                ],
                correlation_id="t",
            )

    def test_serialization_round_trip(self) -> None:
        original = ValidationJob(
            id=uuid4(),
            tenant_id=uuid4(),
            scan_id=uuid4(),
            finding_id=uuid4(),
            phase=ScanPhase.VULN_ANALYSIS,
            canary_token=self._hex(32),
            validation_plan=_make_validation_plan(),
            evidence_required=[EvidenceKind.RAW_OUTPUT],
            correlation_id="trace-vj-2",
        )
        restored = ValidationJob.model_validate_json(original.model_dump_json())
        assert restored == original


class TestExploitJob:
    def test_destructive_requires_signature(self) -> None:
        # An ExploitJob without a structurally-valid signature is rejected even if
        # non_destructive=True; signature validity is enforced at construction.
        parent = _make_tool_job(
            risk_level=RiskLevel.DESTRUCTIVE,
            requires_approval=True,
            approval_id=str(uuid4()),
        )
        with pytest.raises(ValidationError):
            ExploitJob(
                id=uuid4(),
                tenant_id=parent.tenant_id,
                scan_id=parent.scan_id,
                parent_tool_job_id=parent.id,
                parent_tool_job=parent,
                approval_signature="too_short",
                approver_public_key_id="argus-tenant-1:v1",
                non_destructive=False,
                proof_of_concept_template_id="sqli.boolean.diff.v3",
                correlation_id="trace-ej-1",
            )

    def test_happy_path_non_destructive(self) -> None:
        parent = _make_tool_job(
            risk_level=RiskLevel.HIGH,
            requires_approval=True,
            approval_id=str(uuid4()),
        )
        job = ExploitJob(
            id=uuid4(),
            tenant_id=parent.tenant_id,
            scan_id=parent.scan_id,
            parent_tool_job_id=parent.id,
            parent_tool_job=parent,
            approval_signature=_FAKE_ED25519_SIG,
            approver_public_key_id="argus-tenant-1:v1",
            non_destructive=True,
            proof_of_concept_template_id="sqli.boolean.diff.v3",
            correlation_id="trace-ej-2",
        )
        assert job.non_destructive is True

    def test_happy_path_destructive_with_signature(self) -> None:
        parent = _make_tool_job(
            risk_level=RiskLevel.DESTRUCTIVE,
            requires_approval=True,
            approval_id=str(uuid4()),
        )
        job = ExploitJob(
            id=uuid4(),
            tenant_id=parent.tenant_id,
            scan_id=parent.scan_id,
            parent_tool_job_id=parent.id,
            parent_tool_job=parent,
            approval_signature=_FAKE_ED25519_SIG,
            approver_public_key_id="argus-tenant-1:v1",
            non_destructive=False,
            proof_of_concept_template_id="rce.oast.dns.v1",
            correlation_id="trace-ej-3",
        )
        assert job.non_destructive is False

    def test_parent_must_require_approval(self) -> None:
        parent = _make_tool_job(
            risk_level=RiskLevel.LOW,
            requires_approval=False,
        )
        with pytest.raises(ValidationError):
            ExploitJob(
                id=uuid4(),
                tenant_id=parent.tenant_id,
                scan_id=parent.scan_id,
                parent_tool_job_id=parent.id,
                parent_tool_job=parent,
                approval_signature=_FAKE_ED25519_SIG,
                approver_public_key_id="argus-tenant-1:v1",
                non_destructive=True,
                proof_of_concept_template_id="sqli.boolean.diff.v3",
                correlation_id="trace-ej-4",
            )

    def test_parent_id_mismatch(self) -> None:
        parent = _make_tool_job(
            risk_level=RiskLevel.HIGH,
            requires_approval=True,
            approval_id=str(uuid4()),
        )
        with pytest.raises(ValidationError):
            ExploitJob(
                id=uuid4(),
                tenant_id=parent.tenant_id,
                scan_id=parent.scan_id,
                parent_tool_job_id=uuid4(),  # different from parent.id
                parent_tool_job=parent,
                approval_signature=_FAKE_ED25519_SIG,
                approver_public_key_id="argus-tenant-1:v1",
                non_destructive=True,
                proof_of_concept_template_id="sqli.boolean.diff.v3",
                correlation_id="trace-ej-5",
            )

    def test_invalid_poc_template_id(self) -> None:
        parent = _make_tool_job(
            risk_level=RiskLevel.HIGH,
            requires_approval=True,
            approval_id=str(uuid4()),
        )
        with pytest.raises(ValidationError):
            ExploitJob(
                id=uuid4(),
                tenant_id=parent.tenant_id,
                scan_id=parent.scan_id,
                parent_tool_job_id=parent.id,
                parent_tool_job=parent,
                approval_signature=_FAKE_ED25519_SIG,
                approver_public_key_id="argus-tenant-1:v1",
                non_destructive=True,
                proof_of_concept_template_id="not-a-valid-id",
                correlation_id="trace-ej-6",
            )

    def test_tenant_id_mismatch(self) -> None:
        parent = _make_tool_job(
            risk_level=RiskLevel.HIGH,
            requires_approval=True,
            approval_id=str(uuid4()),
        )
        with pytest.raises(ValidationError) as exc:
            ExploitJob(
                id=uuid4(),
                tenant_id=uuid4(),  # different from parent
                scan_id=parent.scan_id,
                parent_tool_job_id=parent.id,
                parent_tool_job=parent,
                approval_signature=_FAKE_ED25519_SIG,
                approver_public_key_id="argus-tenant-1:v1",
                non_destructive=True,
                proof_of_concept_template_id="sqli.boolean.diff.v3",
                correlation_id="trace-ej-7",
            )
        assert "tenant_id mismatch" in str(exc.value)

    def test_scan_id_mismatch(self) -> None:
        parent = _make_tool_job(
            risk_level=RiskLevel.HIGH,
            requires_approval=True,
            approval_id=str(uuid4()),
        )
        with pytest.raises(ValidationError) as exc:
            ExploitJob(
                id=uuid4(),
                tenant_id=parent.tenant_id,
                scan_id=uuid4(),  # different from parent
                parent_tool_job_id=parent.id,
                parent_tool_job=parent,
                approval_signature=_FAKE_ED25519_SIG,
                approver_public_key_id="argus-tenant-1:v1",
                non_destructive=True,
                proof_of_concept_template_id="sqli.boolean.diff.v3",
                correlation_id="trace-ej-8",
            )
        assert "scan_id mismatch" in str(exc.value)

    def test_signature_wrong_byte_length(self) -> None:
        # 90 base64 chars decoding to a non-64-byte payload — pad with extra '=' to
        # satisfy regex while decoding to a wrong size.
        bogus_sig = base64.b64encode(b"\x02" * 65).decode("ascii")  # 88 chars, 65 bytes
        parent = _make_tool_job(
            risk_level=RiskLevel.HIGH,
            requires_approval=True,
            approval_id=str(uuid4()),
        )
        with pytest.raises(ValidationError) as exc:
            ExploitJob(
                id=uuid4(),
                tenant_id=parent.tenant_id,
                scan_id=parent.scan_id,
                parent_tool_job_id=parent.id,
                parent_tool_job=parent,
                approval_signature=bogus_sig,
                approver_public_key_id="argus-tenant-1:v1",
                non_destructive=True,
                proof_of_concept_template_id="sqli.boolean.diff.v3",
                correlation_id="trace-ej-9",
            )
        assert "Ed25519 requires 64" in str(exc.value)

    def test_signature_bad_base64_chars(self) -> None:
        # Construct a signature that matches the regex (length-wise) but has chars
        # that fail strict base64 decoding. Hard to do without breaking the regex;
        # so feed an 88-char string with a single unmatched padding to fail decode.
        bad_sig = "A" * 87 + "*"  # '*' is not in base64 alphabet -> regex rejects first
        parent = _make_tool_job(
            risk_level=RiskLevel.HIGH,
            requires_approval=True,
            approval_id=str(uuid4()),
        )
        with pytest.raises(ValidationError):
            ExploitJob(
                id=uuid4(),
                tenant_id=parent.tenant_id,
                scan_id=parent.scan_id,
                parent_tool_job_id=parent.id,
                parent_tool_job=parent,
                approval_signature=bad_sig,
                approver_public_key_id="argus-tenant-1:v1",
                non_destructive=True,
                proof_of_concept_template_id="sqli.boolean.diff.v3",
                correlation_id="trace-ej-10",
            )

    def test_approver_key_id_invalid_chars(self) -> None:
        parent = _make_tool_job(
            risk_level=RiskLevel.HIGH,
            requires_approval=True,
            approval_id=str(uuid4()),
        )
        with pytest.raises(ValidationError) as exc:
            ExploitJob(
                id=uuid4(),
                tenant_id=parent.tenant_id,
                scan_id=parent.scan_id,
                parent_tool_job_id=parent.id,
                parent_tool_job=parent,
                approval_signature=_FAKE_ED25519_SIG,
                approver_public_key_id="bad key with spaces!",
                non_destructive=True,
                proof_of_concept_template_id="sqli.boolean.diff.v3",
                correlation_id="trace-ej-11",
            )
        assert "approver_public_key_id" in str(exc.value)


class TestFindingDTO:
    def _base_finding_kwargs(self) -> dict[str, object]:
        return {
            "id": uuid4(),
            "tenant_id": uuid4(),
            "scan_id": uuid4(),
            "asset_id": uuid4(),
            "tool_run_id": uuid4(),
            "category": FindingCategory.SQLI,
            "cwe": [89],
            "cvss_v3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cvss_v3_score": 9.8,
            "ssvc_decision": SSVCDecision.ACT,
            "owasp_wstg": ["WSTG-INPV-05"],
            "mitre_attack": ["T1190"],
            "confidence": ConfidenceLevel.CONFIRMED,
            "status": FindingStatus.NEW,
        }

    def test_happy_path(self) -> None:
        f = FindingDTO(**self._base_finding_kwargs())  # type: ignore[arg-type]
        assert f.cvss_v3_score == pytest.approx(9.8)

    def test_negative_cvss_rejected(self) -> None:
        kwargs = self._base_finding_kwargs()
        kwargs["cvss_v3_score"] = -0.1
        with pytest.raises(ValidationError):
            FindingDTO(**kwargs)  # type: ignore[arg-type]

    def test_cvss_above_max_rejected(self) -> None:
        kwargs = self._base_finding_kwargs()
        kwargs["cvss_v3_score"] = 10.5
        with pytest.raises(ValidationError):
            FindingDTO(**kwargs)  # type: ignore[arg-type]

    def test_at_least_one_cwe(self) -> None:
        kwargs = self._base_finding_kwargs()
        kwargs["cwe"] = []
        with pytest.raises(ValidationError):
            FindingDTO(**kwargs)  # type: ignore[arg-type]

    def test_negative_cwe_rejected(self) -> None:
        kwargs = self._base_finding_kwargs()
        kwargs["cwe"] = [-1]
        with pytest.raises(ValidationError):
            FindingDTO(**kwargs)  # type: ignore[arg-type]

    def test_invalid_confidence(self) -> None:
        kwargs = self._base_finding_kwargs()
        kwargs["confidence"] = "guess"
        with pytest.raises(ValidationError):
            FindingDTO(**kwargs)  # type: ignore[arg-type]

    def test_last_seen_before_first_seen(self) -> None:
        kwargs = self._base_finding_kwargs()
        kwargs["first_seen"] = datetime.now(tz=timezone.utc)
        kwargs["last_seen"] = datetime.now(tz=timezone.utc) - timedelta(days=1)
        with pytest.raises(ValidationError):
            FindingDTO(**kwargs)  # type: ignore[arg-type]

    def test_evidence_ids_no_dupes(self) -> None:
        dup = uuid4()
        kwargs = self._base_finding_kwargs()
        kwargs["evidence_ids"] = [dup, dup]
        with pytest.raises(ValidationError):
            FindingDTO(**kwargs)  # type: ignore[arg-type]

    def test_invalid_cvss_vector(self) -> None:
        kwargs = self._base_finding_kwargs()
        kwargs["cvss_v3_vector"] = "garbage"
        with pytest.raises(ValidationError):
            FindingDTO(**kwargs)  # type: ignore[arg-type]

    def test_optional_blocks_round_trip(self) -> None:
        kwargs = self._base_finding_kwargs()
        kwargs["reproducer"] = ReproducerSpecDTO(
            method="GET",
            target="https://example.com/search?q=ARGUS_CANARY",
            request_template="GET /search?q={canary} HTTP/1.1\\nHost: example.com",
            expected_signal="response contains canary echo",
            canary_token="abcdef0123456789",
        )
        kwargs["remediation"] = RemediationDTO(
            summary="Use parameterized queries",
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
        )
        original = FindingDTO(**kwargs)  # type: ignore[arg-type]
        restored = FindingDTO.model_validate_json(original.model_dump_json())
        assert restored == original


class TestEvidenceDTO:
    def test_happy_path(self) -> None:
        ev = EvidenceDTO(
            id=uuid4(),
            finding_id=uuid4(),
            tool_run_id=uuid4(),
            kind=EvidenceKind.RAW_OUTPUT,
            s3_key="argus-stage3/scan-1/run-1/raw.txt",
            sha256="a" * 64,
        )
        assert ev.kind is EvidenceKind.RAW_OUTPUT

    def test_empty_s3_key_rejected(self) -> None:
        with pytest.raises(ValidationError):
            EvidenceDTO(
                id=uuid4(),
                finding_id=uuid4(),
                tool_run_id=uuid4(),
                kind=EvidenceKind.RAW_OUTPUT,
                s3_key="",
                sha256="a" * 64,
            )

    def test_uppercase_sha256_rejected(self) -> None:
        with pytest.raises(ValidationError):
            EvidenceDTO(
                id=uuid4(),
                finding_id=uuid4(),
                tool_run_id=uuid4(),
                kind=EvidenceKind.RAW_OUTPUT,
                s3_key="argus-stage3/foo",
                sha256="A" * 64,
            )

    def test_short_sha256_rejected(self) -> None:
        with pytest.raises(ValidationError):
            EvidenceDTO(
                id=uuid4(),
                finding_id=uuid4(),
                tool_run_id=uuid4(),
                kind=EvidenceKind.RAW_OUTPUT,
                s3_key="argus-stage3/foo",
                sha256="abcd",
            )

    def test_s3_key_illegal_chars_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            EvidenceDTO(
                id=uuid4(),
                finding_id=uuid4(),
                tool_run_id=uuid4(),
                kind=EvidenceKind.RAW_OUTPUT,
                s3_key="bad path with spaces & symbols",
                sha256="a" * 64,
            )
        assert "s3_key" in str(exc.value)


class TestPhaseTransition:
    @pytest.mark.parametrize(
        ("source", "destination", "expected"),
        [
            (ScanPhase.RECON, ScanPhase.THREAT_MODELING, True),
            (ScanPhase.THREAT_MODELING, ScanPhase.VULN_ANALYSIS, True),
            (ScanPhase.VULN_ANALYSIS, ScanPhase.EXPLOITATION, True),
            (ScanPhase.EXPLOITATION, ScanPhase.POST_EXPLOITATION, True),
            (ScanPhase.POST_EXPLOITATION, ScanPhase.REPORTING, True),
            (ScanPhase.RECON, ScanPhase.RECON, True),
            (ScanPhase.RECON, ScanPhase.REPORTING, True),
            (ScanPhase.VULN_ANALYSIS, ScanPhase.REPORTING, True),
            (ScanPhase.RECON, ScanPhase.VULN_ANALYSIS, False),
            (ScanPhase.RECON, ScanPhase.EXPLOITATION, False),
            (ScanPhase.THREAT_MODELING, ScanPhase.RECON, False),
            (ScanPhase.REPORTING, ScanPhase.RECON, False),
            (ScanPhase.EXPLOITATION, ScanPhase.VULN_ANALYSIS, False),
        ],
    )
    def test_is_allowed(
        self,
        source: ScanPhase,
        destination: ScanPhase,
        expected: bool,
    ) -> None:
        assert (
            PhaseTransition(source=source, destination=destination).is_allowed() is expected
        )


class TestPhaseOutput:
    def test_success_payload(self) -> None:
        out = PhaseOutput(
            tenant_id=uuid4(),
            scan_id=uuid4(),
            phase=ScanPhase.RECON,
            success=True,
            payload={"assets": ["1.2.3.4"]},
            next_phase=ScanPhase.THREAT_MODELING,
            correlation_id="trace-1",
        )
        assert out.next_phase is ScanPhase.THREAT_MODELING

    def test_illegal_transition_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc:
            PhaseOutput(
                tenant_id=uuid4(),
                scan_id=uuid4(),
                phase=ScanPhase.RECON,
                success=True,
                next_phase=ScanPhase.EXPLOITATION,
                correlation_id="t",
            )
        assert "illegal phase transition" in str(exc.value)

    def test_failure_requires_error_code(self) -> None:
        with pytest.raises(ValidationError):
            PhaseOutput(
                tenant_id=uuid4(),
                scan_id=uuid4(),
                phase=ScanPhase.RECON,
                success=False,
                correlation_id="t",
            )

    def test_success_with_error_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PhaseOutput(
                tenant_id=uuid4(),
                scan_id=uuid4(),
                phase=ScanPhase.RECON,
                success=True,
                error_code="X",
                correlation_id="t",
            )
