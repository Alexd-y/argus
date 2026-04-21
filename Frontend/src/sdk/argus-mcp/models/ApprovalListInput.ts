/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PaginationInput } from './PaginationInput';
/**
 * ``approvals.list(tenant_id, status)`` arguments.
 *
 * Note
 * ----
 * The ``tenant_id`` argument is informational only — the MCP server always
 * filters by the *authenticated* tenant (extracted from the bearer token /
 * ``X-Tenant-ID`` header). A mismatch raises
 * :class:`src.mcp.exceptions.TenantMismatchError`.
 */
export type ApprovalListInput = {
  pagination?: PaginationInput;
  /**
   * One of ``pending``, ``granted``, ``denied``, ``revoked``, ``expired``.
   */
  status?: (string | null);
  /**
   * Optional caller-supplied tenant identifier (must match the authenticated tenant; otherwise a TenantMismatchError is raised).
   */
  tenant_id?: (string | null);
  tool_id?: (string | null);
};

