/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Closed taxonomy of action risk levels.
 *
 * Mirrors :class:`src.pipeline.contracts.tool_job.RiskLevel` so the MCP
 * tool can pass the value straight through to :class:`PolicyEngine`.
 */
export type PolicyRiskLevel = 'passive' | 'low' | 'medium' | 'high' | 'destructive';
