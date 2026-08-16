"use client";

import { useEffect, useState } from "react";

import { DataTable } from "@/components/DataTable";
import type { DiffStatus, ScanDiffEntry } from "@/lib/scanApi";
import { scanApi } from "@/lib/scanApi";

const DIFF_STYLES: Record<DiffStatus, string> = {
  new: "bg-green-900/50 text-green-400",
  unchanged: "bg-neutral-800 text-neutral-400",
  changed: "bg-amber-900/50 text-amber-300",
  resolved_candidate: "bg-indigo-900/50 text-indigo-300",
  resolved: "bg-blue-900/50 text-blue-300",
  regressed: "bg-red-900/50 text-red-400",
  not_tested: "bg-neutral-800 text-neutral-600",
};

function DiffBadge({ status }: { status: DiffStatus }) {
  return (
    <span className={`rounded px-2 py-0.5 text-xs ${DIFF_STYLES[status] ?? DIFF_STYLES.not_tested}`}>
      {status.replace(/_/g, " ")}
    </span>
  );
}

interface DiffRow extends Record<string, unknown> {
  finding_key: string;
  status: DiffStatus;
  baseline_state: string;
  current_state: string;
}

interface ScanDiffViewProps {
  scanId: string;
  baselineId: string;
}

export function ScanDiffView({ scanId, baselineId }: ScanDiffViewProps) {
  const [entries, setEntries] = useState<ScanDiffEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!baselineId.trim()) {
      setEntries([]);
      setError(null);
      return;
    }

    let cancelled = false;

    const load = async () => {
      setLoading(true);
      setError(null);
      try {
        const response = await scanApi.getDiff(scanId, baselineId.trim());
        if (!cancelled) setEntries(response.entries);
      } catch (e) {
        if (!cancelled) {
          setEntries([]);
          setError(e instanceof Error ? e.message : "Failed to load diff");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };

    void load();
    return () => {
      cancelled = true;
    };
  }, [scanId, baselineId]);

  const rows: DiffRow[] = entries.map((e) => ({
    finding_key: e.finding_key,
    status: e.status,
    baseline_state: e.baseline_state ?? "—",
    current_state: e.current_state ?? "—",
  }));

  const summary = entries.reduce(
    (acc, e) => {
      acc[e.status] = (acc[e.status] ?? 0) + 1;
      return acc;
    },
    {} as Record<string, number>
  );

  return (
    <div className="rounded border border-neutral-800 bg-neutral-950 p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-medium text-neutral-300">Scan Diff</h2>
        {entries.length > 0 && (
          <div className="flex flex-wrap gap-2 text-xs text-neutral-500">
            {Object.entries(summary).map(([status, count]) => (
              <span key={status}>
                {status}: {count}
              </span>
            ))}
          </div>
        )}
      </div>

      {!baselineId.trim() && (
        <p className="text-xs text-neutral-600">Enter a baseline scan ID to compare.</p>
      )}
      {loading && (
        <p className="text-xs text-neutral-600">Loading diff...</p>
      )}
      {error && (
        <p className="text-xs text-red-400">{error}</p>
      )}
      {baselineId.trim() && !loading && !error && rows.length === 0 && (
        <p className="text-xs text-neutral-600">No diff entries.</p>
      )}
      {rows.length > 0 && (
        <DataTable<DiffRow>
          columns={[
            {
              key: "finding_key",
              label: "Finding",
              render: (r) => (
                <code className="text-xs">{String(r.finding_key).slice(0, 12)}…</code>
              ),
            },
            {
              key: "status",
              label: "Status",
              render: (r) => <DiffBadge status={r.status} />,
            },
            { key: "baseline_state", label: "Baseline" },
            { key: "current_state", label: "Current" },
          ]}
          data={rows}
          emptyMessage="No diff entries"
        />
      )}
    </div>
  );
}
