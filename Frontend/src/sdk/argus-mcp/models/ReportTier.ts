/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Closed taxonomy of report tiers exposed via MCP.
 *
 * Mirrors the ARGUS Midgard / Asgard / Valhalla cascade. Tier selection
 * is gated by the tenant plan inside :class:`PolicyEngine`; the MCP layer
 * only echoes the requested tier and reports the policy decision.
 */
export type ReportTier = 'midgard' | 'asgard' | 'valhalla';
