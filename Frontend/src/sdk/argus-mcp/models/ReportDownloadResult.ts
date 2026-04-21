/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ReportFormat } from './ReportFormat';
/**
 * Result of ``report.download``.
 *
 * The MCP server NEVER streams raw bytes back over the JSON-RPC channel;
 * callers receive a *short-lived* presigned URL plus a SHA-256 of the
 * final artifact for tamper detection.
 */
export type ReportDownloadResult = {
  audit_event_id?: (string | null);
  expires_at?: (string | null);
  format: ReportFormat;
  presigned_url?: (string | null);
  report_id: string;
  /**
   * SHA-256 hex of the report artifact bytes.
   */
  sha256?: (string | null);
};

