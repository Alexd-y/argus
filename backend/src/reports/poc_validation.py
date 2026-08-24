from typing import Literal

from pydantic import BaseModel


class XssValidationResult(BaseModel):
    reflection_context: str | None = None
    payload_entered: str | None = None
    payload_reflected: str | None = None
    verified_via_browser: bool | None = None
    browser_alert_text: str | None = None
    affected_parameter: str | None = None
    negative_control: str | None = None

    def is_validated(self) -> bool:
        required = [
            self.reflection_context,
            self.payload_entered,
            self.payload_reflected,
            self.verified_via_browser is not None,
            self.browser_alert_text,
            self.affected_parameter,
            self.negative_control,
        ]
        return all(required)


class CsrfValidationResult(BaseModel):
    raw_html_form: str | None = None
    raw_post: str | None = None
    cookies: dict | None = None
    origin_referer: str | None = None
    csrftoken_status: Literal["missing", "weak", "absent", "present"] | None = None
    state_changing: bool | None = None
    negative_control: str | None = None

    def is_validated(self) -> bool:
        required = [
            self.raw_html_form,
            self.raw_post,
            self.cookies,
            self.origin_referer,
            self.csrftoken_status,
            self.state_changing is not None,
            self.negative_control,
        ]
        return all(required)


class CmdiValidationResult(BaseModel):
    harmless_marker: str | None = None
    controlled_output: str | None = None
    server_proof: str | None = None
    negative_control: str | None = None

    def is_validated(self) -> bool:
        required = [
            self.harmless_marker,
            self.controlled_output,
            self.server_proof,
            self.negative_control,
        ]
        return all(required)


def validate_xss_poc(proof_of_concept: dict) -> XssValidationResult:
    poc_obj = proof_of_concept.get("proof_of_concept", proof_of_concept)
    xss_obj = poc_obj.get("xss", {})
    return XssValidationResult(
        reflection_context=xss_obj.get("reflection_context") or poc_obj.get("reflection_context"),
        payload_entered=xss_obj.get("payload_entered") or poc_obj.get("payload_entered"),
        payload_reflected=xss_obj.get("payload_reflected") or poc_obj.get("payload_reflected"),
        verified_via_browser=xss_obj.get("verified_via_browser") or poc_obj.get("verified_via_browser"),
        browser_alert_text=xss_obj.get("browser_alert_text") or poc_obj.get("browser_alert_text"),
        affected_parameter=xss_obj.get("affected_parameter") or poc_obj.get("affected_parameter"),
        negative_control=xss_obj.get("negative_control") or poc_obj.get("negative_control"),
    )


def validate_csrf(proof_of_concept: dict) -> CsrfValidationResult:
    poc_obj = proof_of_concept.get("proof_of_concept", proof_of_concept)
    csrf_obj = poc_obj.get("csrf", {})
    return CsrfValidationResult(
        raw_html_form=csrf_obj.get("raw_html_form") or poc_obj.get("raw_html_form"),
        raw_post=csrf_obj.get("raw_post") or poc_obj.get("raw_post"),
        cookies=csrf_obj.get("cookies") or poc_obj.get("cookies"),
        origin_referer=csrf_obj.get("origin_referer") or poc_obj.get("origin_referer"),
        csrftoken_status=csrf_obj.get("csrftoken_status") or poc_obj.get("csrftoken_status"),
        state_changing=csrf_obj.get("state_changing") or poc_obj.get("state_changing"),
        negative_control=csrf_obj.get("negative_control") or poc_obj.get("negative_control"),
    )


def validate_cmdi(proof_of_concept: dict) -> CmdiValidationResult:
    poc_obj = proof_of_concept.get("proof_of_concept", proof_of_concept)
    cmdi_obj = poc_obj.get("command_injection", {})
    return CmdiValidationResult(
        harmless_marker=cmdi_obj.get("harmless_marker") or poc_obj.get("harmless_marker"),
        controlled_output=cmdi_obj.get("controlled_output") or poc_obj.get("controlled_output"),
        server_proof=cmdi_obj.get("server_proof") or poc_obj.get("server_proof"),
        negative_control=cmdi_obj.get("negative_control") or poc_obj.get("negative_control"),
    )
