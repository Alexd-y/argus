/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PaginationInput } from './PaginationInput';
import type { ToolRiskLevel } from './ToolRiskLevel';
/**
 * ``tool.catalog.list(filter)`` arguments.
 */
export type ToolCatalogListInput = {
  /**
   * Filter by tool category (e.g. ``web_va``, ``recon_passive``).
   */
  category?: (string | null);
  pagination?: PaginationInput;
  requires_approval?: (boolean | null);
  risk_level?: (ToolRiskLevel | null);
};

