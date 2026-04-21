/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { FindingFilter } from './FindingFilter';
import type { PaginationInput } from './PaginationInput';
/**
 * ``findings.list(scan_id, filter)`` arguments.
 */
export type FindingListInput = {
  filters?: FindingFilter;
  pagination?: PaginationInput;
  scan_id: string;
};

