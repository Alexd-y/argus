/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Compact representation of an approval row for list views.
 */
export type ApprovalSummary = {
  action: string;
  created_at: string;
  expires_at: string;
  request_id: string;
  requires_dual_control?: boolean;
  signatures_present: number;
  status: string;
  target: string;
  tool_id: string;
};

