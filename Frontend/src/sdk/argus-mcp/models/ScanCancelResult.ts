/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ScanStatus } from './ScanStatus';
import type { ToolResultStatus } from './ToolResultStatus';
/**
 * Result of ``scan.cancel``.
 */
export type ScanCancelResult = {
  audit_event_id?: (string | null);
  new_state: ScanStatus;
  scan_id: string;
  status: ToolResultStatus;
};

