"use client";

import { useEffect, useMemo, useState } from "react";

import { labApi } from "@/lib/lab/labApi";
import type { CoverageStatus, ScanCoverageResponse } from "@/lib/lab/types";

const CELL_STYLES: Record<CoverageStatus, string> = {
  planned: "bg-neutral-800 text-neutral-500",
  running: "bg-indigo-800 text-indigo-200",
  covered_no_finding: "bg-emerald-800 text-emerald-200",
  covered_with_finding: "bg-amber-700 text-amber-100",
  partial: "bg-yellow-800 text-yellow-200",
  blocked: "bg-red-900 text-red-200",
  not_applicable: "bg-neutral-900 text-neutral-600",
  not_tested: "bg-neutral-950 text-neutral-500 ring-1 ring-inset ring-neutral-700",
};

function coverageCellLabel(status: CoverageStatus): string {
  switch (status) {
    case "planned":
      return "planned";
    case "running":
      return "running";
    case "covered_no_finding":
      return "OK";
    case "covered_with_finding":
      return "finding";
    case "partial":
      return "partial";
    case "blocked":
      return "blocked";
    case "not_applicable":
      return "n/a";
    case "not_tested":
      return "NT";
    default: {
      const _exhaustive: never = status;
      return _exhaustive;
    }
  }
}

function statusOf(
  data: ScanCoverageResponse,
  assetId: string,
  capabilityId: string,
): CoverageStatus {
  const result = data.results.find(
    (row) => row.asset_id === assetId && row.capability_id === capabilityId,
  );
  if (result) return result.status;
  const req = data.requirements.find(
    (row) => row.asset_id === assetId && row.capability_id === capabilityId,
  );
  return req ? "planned" : "not_tested";
}

interface CoverageHeatmapProps {
  scanId: string;
  coverage?: ScanCoverageResponse;
}

/** Asset × capability heatmap. ``not_tested`` is visually distinct from ``covered_no_finding``. */
export function CoverageHeatmap({ scanId, coverage }: CoverageHeatmapProps) {
  const [data, setData] = useState<ScanCoverageResponse | null>(coverage ?? null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (coverage) {
      setData(coverage);
      return;
    }
    let cancelled = false;
    void labApi
      .getCoverage(scanId)
      .then((next) => {
        if (!cancelled) setData(next);
      })
      .catch(() => {
        if (!cancelled) setError("coverage_unavailable");
      });
    return () => {
      cancelled = true;
    };
  }, [scanId, coverage]);

  const axes = useMemo(() => {
    if (!data) return { assets: [] as string[], caps: [] as string[] };
    const assets = new Set<string>();
    const caps = new Set<string>();
    for (const req of data.requirements) {
      assets.add(req.asset_id);
      caps.add(req.capability_id);
    }
    for (const result of data.results) {
      assets.add(result.asset_id);
      caps.add(result.capability_id);
    }
    return { assets: [...assets], caps: [...caps] };
  }, [data]);

  if (error) {
    return (
      <p className="text-xs text-neutral-500" data-testid="coverage-heatmap-error">
        Coverage heatmap unavailable
      </p>
    );
  }
  if (!data || (axes.assets.length === 0 && axes.caps.length === 0)) {
    return (
      <p className="text-xs text-neutral-600" data-testid="coverage-heatmap-empty">
        No coverage cells yet
      </p>
    );
  }

  return (
    <div className="overflow-x-auto" data-testid="coverage-heatmap">
      <table className="min-w-full border-collapse text-xs">
        <thead>
          <tr>
            <th className="border border-neutral-800 px-2 py-1 text-left text-neutral-500">
              asset × capability
            </th>
            {axes.caps.map((cap) => (
              <th
                key={cap}
                className="border border-neutral-800 px-2 py-1 font-mono text-neutral-400"
              >
                {cap}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {axes.assets.map((asset) => (
            <tr key={asset}>
              <th className="border border-neutral-800 px-2 py-1 text-left font-mono text-neutral-400">
                {asset}
              </th>
              {axes.caps.map((cap) => {
                const status = statusOf(data, asset, cap);
                return (
                  <td
                    key={`${asset}:${cap}`}
                    data-status={status}
                    title={`${asset} / ${cap}: ${status}`}
                    className={`border border-neutral-800 px-2 py-1 text-center ${CELL_STYLES[status]}`}
                  >
                    {coverageCellLabel(status)}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
