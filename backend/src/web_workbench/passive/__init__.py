"""Web Workbench — passive HTTP audit over captured traffic (WB-P5a).

Native, offline, send-free passive scanner. Distinct from the active Nuclei
pipeline (extend, not duplicate); findings reuse the platform taxonomy for a
clean bridge to ``FindingDTO`` in WB-P5b.
"""

from src.web_workbench.passive.analyzer import (
    PassiveFinding,
    PassiveSeverity,
    analyze,
    check_cookies,
    check_cors,
    check_info_disclosure,
    check_reflected_input,
    check_security_headers,
)
from src.web_workbench.passive.finding_bridge import (
    passive_finding_to_dto,
    passive_findings_to_dtos,
)

__all__ = [
    "PassiveFinding",
    "PassiveSeverity",
    "analyze",
    "check_cookies",
    "check_cors",
    "check_info_disclosure",
    "check_reflected_input",
    "check_security_headers",
    "passive_finding_to_dto",
    "passive_findings_to_dtos",
]
