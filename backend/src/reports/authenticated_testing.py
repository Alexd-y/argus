from typing import Literal, Optional
from pydantic import BaseModel

__all__ = [
    "SessionTesting",
    "TokenTesting",
    "MfaTesting",
    "AuthorizationTesting",
    "AuthTestingContextV2",
    "build_auth_testing_context",
    "build_idor_tests",
    "detect_session_testing",
    "detect_token_testing",
    "detect_mfa_testing",
    "detect_authorization_testing",
]


class SessionTesting(BaseModel):
    session_fixation: bool = False
    session_hijacking: bool = False
    session_timeout: int = 0
    session_cookie_secure: bool = False
    session_cookie_httponly: bool = False


class TokenTesting(BaseModel):
    jwt_algorithm: str = "HS256"
    jwt_key_strength: int = 256
    jwt_expiration: int = 3600
    jwt_rotation: bool = False
    token_leakage: bool = False


class MfaTesting(BaseModel):
    mfa_bypass: bool = False
    otp_prediction: bool = False
    sms_interception: bool = False
    backup_codes: bool = False


class AuthorizationTesting(BaseModel):
    idor_horizontal: bool = False
    idor_vertical: bool = False
    privilege_escalation: bool = False
    broken_access_control: bool = False


class AuthTestingContextV2(BaseModel):
    session: Optional[SessionTesting] = None
    token: Optional[TokenTesting] = None
    mfa: Optional[MfaTesting] = None
    authorization: Optional[AuthorizationTesting] = None
    testing_methodology: str = "OWASP WSTG + PTES"
    tools_used: list[str] = []


def build_auth_testing_context(scenario: str, findings: list[dict]) -> AuthTestingContextV2:
    context = AuthTestingContextV2(
        testing_methodology="OWASP WSTG + PTES",
        tools_used=["nuclei", "sqlmap", "dalfox"],
    )
    context.session = context.session or SessionTesting()
    context.token = context.token or TokenTesting()
    context.mfa = context.mfa or MfaTesting()
    context.authorization = context.authorization or AuthorizationTesting()
    
    for finding in findings:
        if finding.get("type") == "session_hijacking":
            context.session.session_hijacking = True
        if finding.get("type") == "jwt_weak":
            context.token.jwt_key_strength = 128
            context.token.jwt_expiration = 86400
        if finding.get("type") == "mfa_bypass":
            context.mfa.mfa_bypass = True
        if finding.get("type") == "idor":
            if finding.get("level") == "horizontal":
                context.authorization.idor_horizontal = True
            elif finding.get("level") == "vertical":
                context.authorization.idor_vertical = True
        if finding.get("type") == "privilege_escalation":
            context.authorization.privilege_escalation = True
        if finding.get("type") == "broken_access":
            context.authorization.broken_access_control = True
    
    return context


def build_idor_tests(endpoint: str, target_field: str) -> dict:
    return {
        "endpoint": endpoint,
        "original_value": "user-001",
        "modified_value": "user-002",
        "test_method": "change_id_in_request",
        "expected_result": "access_denied_or_data_mismatch",
        "actual_result": "pending",
    }


def detect_session_testing(findings: list[dict]) -> SessionTesting:
    session = SessionTesting()
    for finding in findings:
        if finding.get("type") == "session_fixation":
            session.session_fixation = True
        if finding.get("type") == "session_hijacking":
            session.session_hijacking = True
    return session


def detect_token_testing(findings: list[dict]) -> TokenTesting:
    token = TokenTesting()
    for finding in findings:
        if finding.get("type") == "jwt_weak":
            token.jwt_key_strength = 128
            token.jwt_expiration = 86400
    return token


def detect_mfa_testing(findings: list[dict]) -> MfaTesting:
    mfa = MfaTesting()
    for finding in findings:
        if finding.get("type") == "mfa_bypass":
            mfa.mfa_bypass = True
    return mfa


def detect_authorization_testing(findings: list[dict]) -> AuthorizationTesting:
    auth = AuthorizationTesting()
    for finding in findings:
        if finding.get("type") == "idor":
            auth.idor_horizontal = True
        if finding.get("type") == "privilege_escalation":
            auth.privilege_escalation = True
        if finding.get("type") == "broken_access":
            auth.broken_access_control = True
    return auth
