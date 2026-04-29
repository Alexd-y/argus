/**
 * ARGUS Reports API - GET /reports?target=X, GET /reports/:id, GET /reports/:id/download.
 */

import { apiFetch, apiUrl } from "./api";
import type { Report } from "./types";

/** useReport: show when /report is opened without ?target= or ?id= */
export const REPORT_PAGE_REQUIRES_TARGET_OR_ID =
  "No target or report ID provided";

/**
 * Short, user-safe description for report load errors.
 * Does not echo raw API bodies or system messages.
 */
export function getPublicReportUiMessage(
  errorText: string | null | undefined,
): string {
  if (errorText == null || String(errorText).trim() === "") {
    return "Try again later or return to the scanner.";
  }
  const t = errorText.trim();
  if (t === REPORT_PAGE_REQUIRES_TARGET_OR_ID) {
    return "Open this page from the scanner after a scan, or add a target or report ID to the link.";
  }
  const low = t.toLowerCase();
  if (low.includes("not found") || t === "Report not found") {
    return "This report is missing or the link is no longer valid.";
  }
  if (/^request failed \(\d+\)$/i.test(t) || /\bfetch\b/i.test(t)) {
    return "We could not reach the server. Check your connection and try again.";
  }
  return "We could not load the report. Try again or return to the scanner.";
}

export function reportErrorKind(
  errorText: string | null | undefined,
  hasTargetOrId: boolean,
): "missing" | "not_found" | "other" {
  if (!hasTargetOrId) {
    return "missing";
  }
  if (errorText == null) {
    return "other";
  }
  const t = errorText.trim().toLowerCase();
  if (t.includes("not found") || t === "report not found") {
    return "not_found";
  }
  return "other";
}

export async function getReportByTarget(target: string): Promise<Report> {
  const params = new URLSearchParams({ target });
  const reports = await apiFetch<Report[]>(`/reports?${params.toString()}`);
  if (!Array.isArray(reports) || reports.length === 0) {
    throw new Error("Report not found");
  }
  return reports[0];
}

export async function getReportById(reportId: string): Promise<Report> {
  return apiFetch<Report>(`/reports/${encodeURIComponent(reportId)}`);
}

export type ReportDownloadFormat =
  | "pdf"
  | "html"
  | "json"
  | "csv"
  | "valhalla_sections.csv";

export type GetReportDownloadUrlOptions = {
  /**
   * When true, append `regenerate=true` so the backend skips ReportObject / MinIO
   * cache and rebuilds the export (GET /reports/:id/download).
   */
  readonly regenerate?: boolean;
  /**
   * When true, request `redirect=true` (302 to presigned URL if supported).
   */
  readonly redirect?: boolean;
};

/**
 * Returns download URL for report (opens in new tab or triggers download).
 */
export function getReportDownloadUrl(
  reportId: string,
  format: ReportDownloadFormat = "pdf",
  options?: GetReportDownloadUrlOptions,
): string {
  const params = new URLSearchParams({ format });
  if (options?.regenerate) {
    params.set("regenerate", "true");
  }
  if (options?.redirect) {
    params.set("redirect", "true");
  }
  return apiUrl(
    `/reports/${encodeURIComponent(reportId)}/download?${params.toString()}`,
  );
}
