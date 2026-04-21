/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Common pagination parameters.
 *
 * The MCP server enforces an explicit upper bound (``limit <= 200``) so a
 * client cannot accidentally drain the entire findings table in a single
 * call. Larger result sets must paginate.
 */
export type PaginationInput = {
  limit?: number;
  offset?: number;
};

