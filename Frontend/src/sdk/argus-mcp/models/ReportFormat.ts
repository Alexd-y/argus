/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Closed taxonomy of report output formats.
 *
 * The MCP server intentionally does NOT expose ``valhalla_sections_csv``
 * (a debug helper) — only the canonical formats listed here.
 */
export type ReportFormat = 'html' | 'pdf' | 'json' | 'csv' | 'sarif' | 'junit';
