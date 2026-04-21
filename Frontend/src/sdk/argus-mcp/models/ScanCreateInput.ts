/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ScanProfile } from './ScanProfile';
import type { ScanScopeInput } from './ScanScopeInput';
/**
 * ``scan.create(target, scope, profile)`` arguments.
 */
export type ScanCreateInput = {
  /**
   * Operator-provided justification; required for HIGH-risk profiles.
   */
  justification?: (string | null);
  profile?: ScanProfile;
  scope?: ScanScopeInput;
  /**
   * URL or domain to scan (must already be in the tenant's allow-list).
   */
  target: string;
};

