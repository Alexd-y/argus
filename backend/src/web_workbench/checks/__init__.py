"""Web Workbench — native security check modules (behavioral parity).

Each check reuses the platform's existing detection primitives (oracles,
payload registry, evidence) rather than reimplementing them. WB-P6a ships the
authorization analyzer (owner/attacker/anon diff → BAC/IDOR) over the shared
:class:`~src.playbooks.oracles.AuthzOracle`.
"""

from src.web_workbench.checks.authorization_analyzer import (
    AuthorizationError,
    AuthorizationFinding,
    AuthzClass,
    CapturedExchange,
    analyze_authorization,
    detect_object_id,
    evaluate_pair,
)
from src.web_workbench.checks.client_dependency import (
    DependencyFinding,
    DependencySeverity,
    DetectedLibrary,
    dependency_finding_to_dto,
    dependency_findings_to_dtos,
    detect_libraries,
    match_vulnerabilities,
    scan,
)
from src.web_workbench.checks.jwt_editor import (
    DecodedJwt,
    JwtError,
    JwtFinding,
    analyze_jwt,
    decode_jwt,
    is_jwt,
    jwt_finding_to_dto,
    jwt_findings_to_dtos,
)
from src.web_workbench.checks.nosqli import (
    NosqlFinding,
    analyze as analyze_nosql,
    detect_error_signature,
    detect_operator_injection,
    nosql_finding_to_dto,
    nosql_findings_to_dtos,
)
from src.web_workbench.checks.severity import CheckSeverity, cvss_for
from src.web_workbench.checks.wordpress import (
    WordpressFinding,
    analyze as analyze_wordpress,
    detect_fingerprint,
    detect_version,
    wordpress_finding_to_dto,
    wordpress_findings_to_dtos,
)

__all__ = [
    "AuthorizationError",
    "AuthorizationFinding",
    "AuthzClass",
    "CapturedExchange",
    "CheckSeverity",
    "DecodedJwt",
    "DependencyFinding",
    "DependencySeverity",
    "DetectedLibrary",
    "JwtError",
    "JwtFinding",
    "NosqlFinding",
    "WordpressFinding",
    "analyze_authorization",
    "analyze_jwt",
    "analyze_nosql",
    "analyze_wordpress",
    "cvss_for",
    "decode_jwt",
    "dependency_finding_to_dto",
    "dependency_findings_to_dtos",
    "detect_error_signature",
    "detect_fingerprint",
    "detect_libraries",
    "detect_object_id",
    "detect_operator_injection",
    "detect_version",
    "evaluate_pair",
    "is_jwt",
    "jwt_finding_to_dto",
    "jwt_findings_to_dtos",
    "match_vulnerabilities",
    "nosql_finding_to_dto",
    "nosql_findings_to_dtos",
    "scan",
    "wordpress_finding_to_dto",
    "wordpress_findings_to_dtos",
]
