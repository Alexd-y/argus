/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PolicyEvaluationOutcome } from './PolicyEvaluationOutcome';
import type { PolicyRiskLevel } from './PolicyRiskLevel';
/**
 * Result of ``policy.evaluate``.
 */
export type PolicyEvaluateResult = {
  audit_event_id?: (string | null);
  failure_summary?: (string | null);
  outcome: PolicyEvaluationOutcome;
  requires_approval?: boolean;
  risk_level: PolicyRiskLevel;
};

