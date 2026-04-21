/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Closed taxonomy for tool result status flags.
 *
 * Used by tools that return a small acknowledgement payload (e.g.
 * ``scan.cancel``, ``findings.mark_false_positive``). Avoid free-form
 * strings so callers can switch on the value without a string-compare.
 */
export type ToolResultStatus = 'ok' | 'success' | 'unchanged' | 'noop' | 'queued' | 'denied';
