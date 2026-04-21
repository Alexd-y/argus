/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Public-facing scan profile names exposed to MCP clients.
 *
 * Maps 1-to-1 to ``Settings.scan_mode`` (``quick`` / ``standard`` / ``deep``)
 * so that ``scan.create`` arguments stay in sync with the rest of the
 * backend. The MCP client cannot pick a deeper profile than its tenant
 * plan allows; that gate sits in :class:`PolicyEngine`.
 */
export type ScanProfile = 'quick' | 'standard' | 'deep';
