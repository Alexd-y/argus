"use client";

import { useEffect, useState } from "react";

import { labApi } from "@/lib/lab/labApi";
import type { DiffStatus, ScanDiffEntry } from "@/lib/lab/types";

const DIFF_STYLES: Record<DiffStatus, string> = {
  new: "bg-green-900/50 text-green-400",
  unchanged: "bg-neutral-800 text-neutral-400",
  changed: "bg-amber-900/50 text-amber-300",
  resolved_candidate: "bg-indigo-900/50 text-indigo-300",
  resolved: "bg-blue-900/50 text-blue-300",
  regressed: "bg-red-900/50 text-red-400",
  not_tested: "bg-neutral-800 text-neutral-600",
};

interface ScanDiffViewProps {
  scanId: string;
  baselineId: string;
}

export function ScanDiffView({ scanId, baselineId }: ScanDiffViewProps) {
  const [entries, setEntries] = useState<ScanDiffEntry[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!baselineId.trim()) {
      setEntries([]);
      setError(null);
      return;
    }
    let cancelled = false;
    void labApi
      .getDiff(scanId, baselineId.trim())
      .then((response) => {
        if (!cancelled) setEntries(response.entries);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "diff_failed");
      });
    return () => {
      cancelled = true;
    };
  }, [scanId, baselineId]);

  if (!baselineId.trim()) {
    return (
      <p className="text-xs text-neutral-600" data-testid="scan-diff-empty">
        Enter a baseline scan id to diff
      </p>
    );
  }
  if (error) {
    return (
      <p className="text-xs text-red-400" data-testid="scan-diff-error">
        {error}
      </p>
    );
  }

  return (
    <div className="overflow-x-auto" data-testid="scan-diff-view">
      <table className="min-w-full text-xs">
        <thead>
          <tr className="text-left text-neutral-500">
            <th className="px-2 py-1">finding</th>
            <th className="px-2 py-1">status</th>
            <th className="px-2 py-1">baseline</th>
            <th className="px-2 py-1">current</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((entry) => (
            <tr key={entry.finding_key} className="border-t border-neutral-800">
              <td className="px-2 py-1 font-mono text-neutral-200">{entry.finding_key}</td>
              <td className="px-2 py-1">
                <span className={`rounded px-2 py-0.5 ${DIFF_STYLES[entry.status]}`}>
                  {entry.status.replace(/_/g, " ")}
                </span>
              </td>
              <td className="px-2 py-1 text-neutral-400">{entry.baseline_state ?? "—"}</td>
              <td className="px-2 py-1 text-neutral-400">{entry.current_state ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
