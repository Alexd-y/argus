/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ScanProfile } from './ScanProfile';
import type { ScanStatus } from './ScanStatus';
/**
 * Result of ``scan.create``.
 */
export type ScanCreateResult = {
  audit_event_id?: (string | null);
  profile: ScanProfile;
  requires_approval?: boolean;
  scan_id: string;
  status: ScanStatus;
  target: string;
};

