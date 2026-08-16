"use client";

import { useEffect, useState } from "react";

import { labApi } from "@/lib/lab/labApi";
import type { CoverageStatus, ScanCoverageResponse } from "@/lib/lab/types";

const STATUS_STYLES: Record<CoverageStatus, string> = {
  planned: "bg-neutral-800 text-neutral-400",
  running: "bg-indigo-900/50 text-indigo-300",
  covered_no_finding: "bg-green-900/50 text-green-400",
  covered_with_finding: "bg-amber-900/50 text-amber-300",
  partial: "bg-yellow-900/50 text-yellow-300",
  blocked: "bg-red-900/50 text-red-400",
  not_applicable: "bg-neutral-800 text-neutral-500",
  not_tested: "bg-neutral-800 text-neutral-600",
};

interface CoverageStatusViewProps {
  scanId: string;
}

export function CoverageStatusView({ scanId }: CoverageStatusViewProps) {
  const [data, setData] = useState<ScanCoverageResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    void labApi
      .getCoverage(scanId)
      .then((next) => {
        if (!cancelled) setData(next);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "coverage_failed");
      });
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  if (error) {
    return <p className="text-xs text-red-400">{error}</p>;
  }
  if (!data) {
    return <p className="text-xs text-neutral-500">Loading coverage…</p>;
  }

  const rows =
    data.results.length > 0
      ? data.results
      : data.requirements.map((req) => ({
          requirement_id: req.id,
          tenant_id: req.tenant_id,
          scan_id: req.scan_id,
          asset_id: req.asset_id,
          capability_id: req.capability_id,
          status: "not_tested" as CoverageStatus,
          blocked_reason: null,
          finding_id: null,
        }));

  return (
    <div className="overflow-x-auto" data-testid="coverage-status-view">
      <table className="min-w-full text-xs">
        <thead>
          <tr className="text-left text-neutral-500">
            <th className="px-2 py-1">capability</th>
            <th className="px-2 py-1">asset</th>
            <th className="px-2 py-1">status</th>
            <th className="px-2 py-1">blocked reason</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={`${row.asset_id}:${row.capability_id}`} className="border-t border-neutral-800">
              <td className="px-2 py-1 font-mono text-neutral-200">{row.capability_id}</td>
              <td className="px-2 py-1 font-mono text-neutral-400">{row.asset_id}</td>
              <td className="px-2 py-1">
                <span className={`rounded px-2 py-0.5 ${STATUS_STYLES[row.status]}`}>
                  {row.status.replace(/_/g, " ")}
                </span>
              </td>
              <td className="px-2 py-1 text-neutral-400">{row.blocked_reason ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
