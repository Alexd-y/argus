/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ReportFormat } from './ReportFormat';
import type { ReportTier } from './ReportTier';
/**
 * Result of ``report.generate``.
 */
export type ReportGenerateResult = {
  audit_event_id?: (string | null);
  format: ReportFormat;
  queued?: boolean;
  report_id: string;
  scan_id: string;
  tier: ReportTier;
};

