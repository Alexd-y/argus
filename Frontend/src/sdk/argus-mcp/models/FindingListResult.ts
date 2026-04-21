/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { FindingSummary } from './FindingSummary';
/**
 * Result of ``findings.list``.
 */
export type FindingListResult = {
  items?: Array<FindingSummary>;
  next_offset?: (number | null);
  total: number;
};

