/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * ``scan.cancel(scan_id, reason)`` arguments.
 */
export type ScanCancelInput = {
  /**
   * Operator-provided reason for cancellation (recorded in audit log).
   */
  reason: string;
  scan_id: string;
};

