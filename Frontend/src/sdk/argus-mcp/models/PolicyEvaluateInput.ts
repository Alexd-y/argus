/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PolicyRiskLevel } from './PolicyRiskLevel';
/**
 * ``policy.evaluate(tool_id, target, risk_level)`` arguments.
 */
export type PolicyEvaluateInput = {
  estimated_cost_cents?: number;
  payload_family?: (string | null);
  risk_level?: PolicyRiskLevel;
  target: string;
  tool_id: string;
};

