/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ScanStatus } from './ScanStatus';
/**
 * Result of ``scan.status``.
 */
export type ScanStatusResult = {
  /**
   * Severity → count snapshot (e.g. {'critical': 2, 'high': 5}).
   */
  finding_counts?: Record<string, number>;
  finished_at?: (string | null);
  progress_percent: number;
  scan_id: string;
  started_at?: (string | null);
  status: ScanStatus;
  target: string;
};

