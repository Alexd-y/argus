"""Pydantic schemas exposed via the ARGUS MCP server (Backlog/dev1_md §13).

Every MCP tool / resource / prompt argument and result is a strongly-typed
Pydantic model declared here. The schemas are intentionally narrower than the
internal HTTP API contracts so that an LLM client cannot, by chance, pass an
internal-only field (e.g. ``options.advanced.proxy``) and trigger an
unintended code path.
"""

from src.mcp.schemas.approval import (
    ApprovalDecideInput,
    ApprovalDecideResult,
    ApprovalListInput,
    ApprovalListResult,
    ApprovalSummary,
    ApprovalDecisionAction,
)
from src.mcp.schemas.common import PaginationInput, ToolResultStatus
from src.mcp.schemas.finding import (
    FindingDetail,
    FindingFilter,
    FindingGetInput,
    FindingListInput,
    FindingListResult,
    FindingMarkFalsePositiveInput,
    FindingMarkResult,
    FindingSummary,
    Severity,
)
from src.mcp.schemas.policy import (
    PolicyEvaluateInput,
    PolicyEvaluateResult,
    PolicyEvaluationOutcome,
    PolicyRiskLevel,
    ScopeVerifyInput,
    ScopeVerifyResult,
)
from src.mcp.schemas.report import (
    ReportDownloadInput,
    ReportDownloadResult,
    ReportFormat,
    ReportGenerateInput,
    ReportGenerateResult,
    ReportTier,
)
from src.mcp.schemas.scan import (
    ScanCancelInput,
    ScanCancelResult,
    ScanCreateInput,
    ScanCreateResult,
    ScanProfile,
    ScanScopeInput,
    ScanStatus,
    ScanStatusInput,
    ScanStatusResult,
)
from src.mcp.schemas.tool_run import (
    ToolCatalogEntry,
    ToolCatalogListInput,
    ToolCatalogListResult,
    ToolRiskLevel,
    ToolRunStatus,
    ToolRunStatusInput,
    ToolRunStatusResult,
    ToolRunTriggerInput,
    ToolRunTriggerResult,
)

__all__ = [
    "ApprovalDecideInput",
    "ApprovalDecideResult",
    "ApprovalDecisionAction",
    "ApprovalListInput",
    "ApprovalListResult",
    "ApprovalSummary",
    "FindingDetail",
    "FindingFilter",
    "FindingGetInput",
    "FindingListInput",
    "FindingListResult",
    "FindingMarkFalsePositiveInput",
    "FindingMarkResult",
    "FindingSummary",
    "PaginationInput",
    "PolicyEvaluateInput",
    "PolicyEvaluateResult",
    "PolicyEvaluationOutcome",
    "PolicyRiskLevel",
    "ReportDownloadInput",
    "ReportDownloadResult",
    "ReportFormat",
    "ReportGenerateInput",
    "ReportGenerateResult",
    "ReportTier",
    "ScanCancelInput",
    "ScanCancelResult",
    "ScanCreateInput",
    "ScanCreateResult",
    "ScanProfile",
    "ScanScopeInput",
    "ScanStatus",
    "ScanStatusInput",
    "ScanStatusResult",
    "ScopeVerifyInput",
    "ScopeVerifyResult",
    "Severity",
    "ToolCatalogEntry",
    "ToolCatalogListInput",
    "ToolCatalogListResult",
    "ToolResultStatus",
    "ToolRiskLevel",
    "ToolRunStatus",
    "ToolRunStatusInput",
    "ToolRunStatusResult",
    "ToolRunTriggerInput",
    "ToolRunTriggerResult",
]
