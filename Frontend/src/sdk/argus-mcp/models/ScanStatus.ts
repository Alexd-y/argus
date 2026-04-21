/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Closed taxonomy of high-level scan lifecycle states.
 *
 * Mirrors the ``scans.status`` column but is intentionally smaller: the
 * MCP layer never exposes internal pipeline phases (``recon`` /
 * ``vuln_analysis`` / ``exploitation``) — those leak implementation
 * structure to the LLM.
 */
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
