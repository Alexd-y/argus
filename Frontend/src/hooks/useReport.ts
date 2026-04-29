"use client";

import { useState, useEffect, useCallback } from "react";
import {
  getReportByTarget,
  getReportById,
  REPORT_PAGE_REQUIRES_TARGET_OR_ID,
} from "@/lib/reports";
import { getSafeErrorMessage } from "@/lib/api";
import type { Report } from "@/lib/types";

export interface UseReportResult {
  report: Report | null;
  loading: boolean;
  error: string | null;
  refetch: () => void;
}

export function useReport(target: string | null, id: string | null): UseReportResult {
  const [report, setReport] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchReport = useCallback(async () => {
    if (!target && !id) {
      setLoading(false);
      setError(REPORT_PAGE_REQUIRES_TARGET_OR_ID);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const data = id
        ? await getReportById(id)
        : await getReportByTarget(target!);
      setReport(data);
    } catch (err) {
      setReport(null);
      setError(getSafeErrorMessage(err, "Failed to load report"));
    } finally {
      setLoading(false);
    }
  }, [target, id]);

  useEffect(() => {
    fetchReport();
  }, [fetchReport]);

  return { report, loading, error, refetch: fetchReport };
}
