/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { Severity } from './Severity';
/**
 * Compact representation of a finding for list views.
 */
export type FindingSummary = {
  confidence?: string;
  created_at?: (string | null);
  cwe?: (string | null);
  false_positive?: boolean;
  finding_id: string;
  owasp_category?: (string | null);
  severity: Severity;
  title: string;
};

