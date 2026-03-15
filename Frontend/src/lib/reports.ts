/**
 * ARGUS Reports API - GET /reports?target=X, GET /reports/:id, GET /reports/:id/download.
 */

import { apiFetch, apiUrl } from "./api";
import type { Report } from "./types";

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

/**
 * Returns download URL for report (opens in new tab or triggers download).
 */
export function getReportDownloadUrl(
  reportId: string,
  format: "pdf" | "html" | "json" | "csv" = "pdf"
): string {
  return apiUrl(`/reports/${encodeURIComponent(reportId)}/download?format=${format}`);
}
