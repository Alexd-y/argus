"use client";

import { useEffect, useState } from "react";

import { DataTable } from "@/components/DataTable";
import type { CoverageResult, CoverageStatus, ScanCoverageResponse } from "@/lib/scanApi";
import {
  COVERAGE_UNTESTED_NOT_SAFE,
  coverageReasonLabel,
  scanApi,
} from "@/lib/scanApi";

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

function StatusBadge({ status }: { status: CoverageStatus }) {
  return (
    <span className={`rounded px-2 py-0.5 text-xs ${STATUS_STYLES[status] ?? STATUS_STYLES.not_tested}`}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

interface CoverageRow extends Record<string, unknown> {
  capability_id: string;
  asset_id: string;
  status: CoverageStatus;
  finding_id: string;
  blocked_reason: string;
  reason_code: string;
}

/** Show every capability row — never filter by production risk / policy labels (§17). */
function buildRows(data: ScanCoverageResponse): CoverageRow[] {
  const resultByReq = new Map(
    data.results.map((r) => [r.requirement_id, r])
  );

  if (data.requirements.length === 0 && data.results.length === 0) {
    return [];
  }

  if (data.requirements.length === 0) {
    return data.results.map((r: CoverageResult) => ({
      capability_id: r.capability_id,
      asset_id: r.asset_id,
      status: r.status,
      finding_id: r.finding_id ?? "—",
      blocked_reason: r.blocked_reason ?? "—",
      reason_code: r.reason_code ?? "",
    }));
  }

  return data.requirements.map((req) => {
    const result = resultByReq.get(req.id);
    return {
      capability_id: req.capability_id,
      asset_id: req.asset_id,
      status: result?.status ?? ("not_tested" as CoverageStatus),
      finding_id: result?.finding_id ?? "—",
      blocked_reason: result?.blocked_reason ?? "—",
      reason_code: result?.reason_code ?? "",
    };
  });
}

interface CoverageStatusViewProps {
  scanId: string;
}

export function CoverageStatusView({ scanId }: CoverageStatusViewProps) {
  const [data, setData] = useState<ScanCoverageResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await scanApi.getCoverage(scanId);
        if (!cancelled) setData(response);
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Failed to load coverage");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    void load();
    const interval = setInterval(load, 15000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [scanId]);

  const rows = data ? buildRows(data) : [];
  const covered = rows.filter((r) =>
    ["covered_no_finding", "covered_with_finding", "partial"].includes(r.status)
  ).length;

  return (
    <div className="rounded border border-neutral-800 bg-neutral-950 p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-medium text-neutral-300">Coverage Status</h2>
        {data && rows.length > 0 && (
          <span className="text-xs text-neutral-500">
            {covered}/{rows.length} covered
          </span>
        )}
      </div>
      <p className="mb-3 text-xs text-amber-200/80">{COVERAGE_UNTESTED_NOT_SAFE}</p>

      {loading && !data && (
        <p className="text-xs text-neutral-600">Loading coverage...</p>
      )}
      {error && (
        <p className="text-xs text-red-400">{error}</p>
      )}
      {!loading && !error && rows.length === 0 && (
        <p className="text-xs text-neutral-600">No coverage data yet.</p>
      )}
      {rows.length > 0 && (
        <DataTable<CoverageRow>
          columns={[
            { key: "capability_id", label: "Capability" },
            { key: "asset_id", label: "Asset", render: (r) => (
              <code className="text-xs">{String(r.asset_id).slice(0, 8)}…</code>
            )},
            {
              key: "status",
              label: "Status",
              render: (r) => <StatusBadge status={r.status} />,
            },
            { key: "finding_id", label: "Finding" },
            {
              key: "reason_code",
              label: "Reason",
              render: (r) => (
                <span className="text-xs text-neutral-400">
                  {coverageReasonLabel(
                    typeof r.reason_code === "string" ? r.reason_code : null
                  )}
                </span>
              ),
            },
            { key: "blocked_reason", label: "Blocked" },
          ]}
          data={rows}
          emptyMessage="No coverage rows"
        />
      )}
    </div>
  );
}
