/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Optional scope hints supplied when creating a scan.
 *
 * The MCP server's :class:`ScopeEngine` integration ignores anything the
 * client cannot explicitly substantiate — these hints only narrow the
 * automatic discovery (e.g. ``include_subdomains=False`` to avoid spending
 * budget on unrelated apex domains).
 */
export type ScanScopeInput = {
  follow_redirects?: boolean;
  include_subdomains?: boolean;
  max_depth?: number;
};

