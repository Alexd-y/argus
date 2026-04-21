/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ToolResultStatus } from './ToolResultStatus';
/**
 * Result of ``findings.mark_false_positive``.
 */
export type FindingMarkResult = {
  audit_event_id?: (string | null);
  finding_id: string;
  status: ToolResultStatus;
};

