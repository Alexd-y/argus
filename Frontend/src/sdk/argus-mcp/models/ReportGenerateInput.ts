/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ReportFormat } from './ReportFormat';
import type { ReportTier } from './ReportTier';
/**
 * ``report.generate(scan_id, tier, format)`` arguments.
 */
export type ReportGenerateInput = {
  format?: ReportFormat;
  scan_id: string;
  tier?: ReportTier;
};

