/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ToolRiskLevel } from './ToolRiskLevel';
/**
 * One catalog row exposed via MCP.
 *
 * The entry intentionally omits ``command_template``, ``image``, and other
 * sandbox-internal fields — the LLM never needs them to reason about
 * capabilities, and they would leak the templating contract to a
 * potentially-untrusted client.
 */
export type ToolCatalogEntry = {
  category: string;
  cwe_hints?: Array<number>;
  description?: string;
  phase: string;
  requires_approval: boolean;
  risk_level: ToolRiskLevel;
  tool_id: string;
};

