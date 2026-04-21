/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { Severity } from './Severity';
/**
 * Optional filters for ``findings.list``.
 */
export type FindingFilter = {
  /**
   * One of ``confirmed``, ``likely``, ``possible``, ``advisory``.
   */
  confidence?: (string | null);
  /**
   * Filter by CWE id (e.g. ``CWE-79``).
   */
  cwe?: (string | null);
  include_false_positive?: boolean;
  /**
   * OWASP Top 10:2025 short id (``A01``…``A10``).
   */
  owasp_category?: (string | null);
  severity?: (Severity | null);
};

