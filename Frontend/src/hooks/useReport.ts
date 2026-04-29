"use client";

import { useState, useEffect, useCallback } from "react";
import {
  getReportByTarget,
  getReportById,
  getReportsByTarget,
  findValhallaReportRow,
  isReportGenerationReady,
  resolveValhallaHtmlReportDownloadUrl,
  REPORT_PAGE_REQUIRES_TARGET_OR_ID,
} from "@/lib/reports";
import { getSafeErrorMessage } from "@/lib/api";
import type { Report } from "@/lib/types";

export interface UseReportResult {
  report: Report | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
  /** Absolute URL for Valhalla HTML download when the Valhalla artifact is ready; otherwise null. */
  valhallaHtmlDownloadUrl: string | null;
}

export function useReport(target: string | null, id: string | null): UseReportResult {
  const [report, setReport] = useState<Report | null>(null);
  const [valhallaHtmlDownloadUrl, setValhallaHtmlDownloadUrl] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchReport = useCallback(async () => {
    if (!target && !id) {
      setLoading(false);
      setError(REPORT_PAGE_REQUIRES_TARGET_OR_ID);
      setValhallaHtmlDownloadUrl(null);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      let rows: Report[];
      let base: Report;

      if (id) {
        base = await getReportById(id);
        try {
          rows = await getReportsByTarget(base.target);
        } catch {
          rows = [base];
        }
      } else {
        rows = await getReportsByTarget(target!);
        base = rows[0];
      }

      const detail = await getReportById(base.report_id);
      const merged: Report = {
        ...base,
        ...detail,
        scan_id: detail.scan_id ?? base.scan_id ?? null,
      };

      const valhallaRow = findValhallaReportRow(rows);
      const ready = Boolean(
        valhallaRow && isReportGenerationReady(valhallaRow.generation_status),
      );
      const url = ready
        ? resolveValhallaHtmlReportDownloadUrl({
            scanId: merged.scan_id,
            valhallaReportId: valhallaRow?.report_id,
          })
        : null;

      setReport(merged);
      setValhallaHtmlDownloadUrl(url);
    } catch (err) {
      setReport(null);
      setValhallaHtmlDownloadUrl(null);
      setError(getSafeErrorMessage(err, "Failed to load report"));
    } finally {
      setLoading(false);
    }
  }, [target, id]);

  useEffect(() => {
    fetchReport();
  }, [fetchReport]);

  return {
    report,
    loading,
    error,
    refetch: fetchReport,
    valhallaHtmlDownloadUrl,
  };
}
