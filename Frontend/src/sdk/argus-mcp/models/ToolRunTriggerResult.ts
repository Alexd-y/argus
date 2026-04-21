/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ToolRiskLevel } from './ToolRiskLevel';
import type { ToolRunStatus } from './ToolRunStatus';
/**
 * Result of ``tool.run.trigger``.
 *
 * For HIGH / DESTRUCTIVE tools the MCP server NEVER kicks off the actual
 * run; instead it records an :class:`ApprovalRequest`, logs an audit
 * event, and returns ``status=approval_pending`` with the request id so
 * an operator can sign it.
 */
export type ToolRunTriggerResult = {
  approval_request_id?: (string | null);
  audit_event_id?: (string | null);
  requires_approval?: boolean;
  risk_level: ToolRiskLevel;
  status: ToolRunStatus;
  tool_id: string;
  tool_run_id?: (string | null);
};

