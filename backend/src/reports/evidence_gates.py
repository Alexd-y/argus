from typing import Literal

from pydantic import BaseModel

EvidenceGate = Literal["validated", "observed", "candidate", "inconclusive"]


class EvidenceQuality(BaseModel):
    evidence_gate: EvidenceGate = "candidate"
    required_evidence_count: int = 0
    current_evidence_count: int = 0
    missing_evidence: list[str] = []


class XssPocValidation(BaseModel):
    reflection_context: str | None = None
    payload_entered: str | None = None
    payload_reflected: str | None = None
    verified_via_browser: bool | None = None
    browser_alert_text: str | None = None
    affected_parameter: str | None = None
    negative_control: str | None = None


class CsrfPocValidation(BaseModel):
    raw_html_form: str | None = None
    raw_post: str | None = None
    cookies: dict | None = None
    origin_referer: str | None = None
    csrftoken_status: Literal["missing", "weak", "absent", "present"] | None = None
    state_changing: bool | None = None
    negative_control: str | None = None


class CmdiPocValidation(BaseModel):
    harmless_marker: str | None = None
    controlled_output: str | None = None
    server_proof: str | None = None
    negative_control: str | None = None


def validate_xss_evidence(proof_of_concept: dict) -> EvidenceQuality:
    poc = proof_of_concept.get("proof_of_concept", proof_of_concept)
    xss = poc.get("xss", {})

    required = [
        ("reflection_context", "reflection_context"),
        ("payload_entered", "payload_entered"),
        ("payload_reflected", "payload_reflected"),
        ("verified_via_browser", "verified_via_browser"),
        ("browser_alert_text", "browser_alert_text"),
        ("affected_parameter", "affected_parameter"),
        ("negative_control", "negative_control"),
    ]

    found = []
    for field_name, model_field in required:
        value = xss.get(model_field, poc.get(model_field))
        if value is not None:
            found.append(field_name)

    quality = EvidenceQuality(
        required_evidence_count=len(required),
        current_evidence_count=len(found),
        missing_evidence=[name for name, _ in required if name not in found]
    )
    quality.evidence_gate = calculate_evidence_gate(quality)
    return quality


def validate_csrf_evidence(proof_of_concept: dict) -> EvidenceQuality:
    poc = proof_of_concept.get("proof_of_concept", proof_of_concept)
    csrf = poc.get("csrf", {})

    required = [
        ("raw_html_form", "raw_html_form"),
        ("raw_post", "raw_post"),
        ("cookies", "cookies"),
        ("origin_referer", "origin_referer"),
        ("csrftoken_status", "csrftoken_status"),
        ("state_changing", "state_changing"),
        ("negative_control", "negative_control"),
    ]

    found = []
    for field_name, model_field in required:
        value = csrf.get(model_field, poc.get(model_field))
        if value is not None:
            found.append(field_name)

    quality = EvidenceQuality(
        required_evidence_count=len(required),
        current_evidence_count=len(found),
        missing_evidence=[name for name, _ in required if name not in found]
    )
    quality.evidence_gate = calculate_evidence_gate(quality)
    return quality


def validate_cmdi_evidence(proof_of_concept: dict) -> EvidenceQuality:
    poc = proof_of_concept.get("proof_of_concept", proof_of_concept)
    cmdi = poc.get("command_injection", {})

    required = [
        ("harmless_marker", "harmless_marker"),
        ("controlled_output", "controlled_output"),
        ("server_proof", "server_proof"),
        ("negative_control", "negative_control"),
    ]

    found = []
    for field_name, model_field in required:
        value = cmdi.get(model_field, poc.get(model_field))
        if value is not None:
            found.append(field_name)

    quality = EvidenceQuality(
        required_evidence_count=len(required),
        current_evidence_count=len(found),
        missing_evidence=[name for name, _ in required if name not in found]
    )
    quality.evidence_gate = calculate_evidence_gate(quality)
    return quality


def calculate_evidence_gate(quality: EvidenceQuality) -> EvidenceGate:
    if quality.current_evidence_count >= quality.required_evidence_count:
        return "validated"
    if quality.current_evidence_count >= quality.required_evidence_count * 0.7:
        return "observed"
    if quality.current_evidence_count > 0:
        return "candidate"
    return "inconclusive"


def get_missing_artifact_message(
    artifact_key: str,
    section: str,
    tool: str,
    recovery_command: str
) -> str:
    return f"Not assessed: missing artifact {artifact_key}\nAffected section: {section}\nTool: {tool}\nRecommendation: {recovery_command}"
