/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Result of ``scope.verify``.
 */
export type ScopeVerifyResult = {
  allowed: boolean;
  audit_event_id?: (string | null);
  failure_summary?: (string | null);
  matched_rule_index?: (number | null);
  target: string;
};

