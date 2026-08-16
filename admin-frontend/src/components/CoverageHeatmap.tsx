"use client";

import { useEffect, useMemo, useState } from "react";

import type { CoverageResult, CoverageStatus, ScanCoverageResponse } from "@/lib/scanApi";
import { COVERAGE_UNTESTED_NOT_SAFE, coverageReasonLabel, scanApi } from "@/lib/scanApi";

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

function resultOf(
  data: ScanCoverageResponse,
  assetId: string,
  capabilityId: string
): CoverageResult | undefined {
  return data.results.find(
    (r) => r.asset_id === assetId && r.capability_id === capabilityId
  );
}

function statusOf(
  data: ScanCoverageResponse,
  assetId: string,
  capabilityId: string
): CoverageStatus {
  const result = resultOf(data, assetId, capabilityId);
  if (result) return result.status;
  const req = data.requirements.find(
    (r) => r.asset_id === assetId && r.capability_id === capabilityId
  );
  return req ? "planned" : "not_tested";
}

interface CoverageHeatmapProps {
  scanId: string;
}

/** Asset × capability heatmap. ``not_tested`` is visually distinct from ``covered_no_finding``. */
export function CoverageHeatmap({ scanId }: CoverageHeatmapProps) {
  const [data, setData] = useState<ScanCoverageResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const next = await scanApi.getCoverage(scanId);
        if (!cancelled) setData(next);
      } catch {
        if (!cancelled) setError("coverage_unavailable");
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, [scanId]);

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
                const result = resultOf(data, asset, cap);
                const reason = coverageReasonLabel(result?.reason_code);
                const title =
                  result?.reason_code
                    ? `${asset} / ${cap}: ${status} (${reason})`
                    : `${asset} / ${cap}: ${status}`;
                return (
                  <td
                    key={`${asset}:${cap}`}
                    data-status={status}
                    data-reason={result?.reason_code ?? ""}
                    title={title}
                    className={`border border-neutral-800 px-2 py-1 text-center ${CELL_STYLES[status]}`}
                  >
                    {status === "not_tested" ? "NT" : status === "covered_no_finding" ? "OK" : status.replace(/_/g, " ")}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-2 text-xs text-amber-200/80" data-testid="coverage-untested-warning">
        NT = not tested. {COVERAGE_UNTESTED_NOT_SAFE}
      </p>
    </div>
  );
}
