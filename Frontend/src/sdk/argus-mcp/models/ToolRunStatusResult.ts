/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ToolRunStatus } from './ToolRunStatus';
/**
 * Result of ``tool.run.status``.
 */
export type ToolRunStatusResult = {
  approval_request_id?: (string | null);
  finding_count?: number;
  finished_at?: (string | null);
  started_at?: (string | null);
  status: ToolRunStatus;
  tool_id: string;
  tool_run_id: string;
};

