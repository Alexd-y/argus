/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * ``scope.verify(target, tenant_id)`` arguments.
 */
export type ScopeVerifyInput = {
  port?: (number | null);
  target: string;
  /**
   * Optional caller-supplied tenant identifier (must match the authenticated tenant; otherwise a TenantMismatchError is raised).
   */
  tenant_id?: (string | null);
};

