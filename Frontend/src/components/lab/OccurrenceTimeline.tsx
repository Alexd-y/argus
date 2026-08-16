"use client";

import { useEffect, useMemo, useState } from "react";

import { labApi } from "@/lib/lab/labApi";
import type { FindingOccurrence } from "@/lib/lab/types";

interface OccurrenceTimelineProps {
  scanId: string;
  occurrences?: FindingOccurrence[];
}

function formatTs(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toISOString();
}

export function OccurrenceTimeline({ scanId, occurrences }: OccurrenceTimelineProps) {
  const [rows, setRows] = useState<FindingOccurrence[]>(occurrences ?? []);
  const [error, setError] = useState<string | null>(null);
  const [retestKey, setRetestKey] = useState<string | null>(null);

  useEffect(() => {
    if (occurrences) {
      setRows(occurrences);
      return;
    }
    let cancelled = false;
    void labApi
      .getOccurrences(scanId)
      .then((response) => {
        if (!cancelled) setRows(response.occurrences);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "occurrences_failed");
      });
    return () => {
      cancelled = true;
    };
  }, [scanId, occurrences]);

  const ordered = useMemo(
    () =>
      [...rows].sort(
        (left, right) =>
          new Date(left.first_seen_at).getTime() - new Date(right.first_seen_at).getTime(),
      ),
    [rows],
  );

  async function retest(findingKey: string) {
    setRetestKey(findingKey);
    try {
      await labApi.retestFinding(findingKey, scanId, "still_present");
    } catch (err) {
      setError(err instanceof Error ? err.message : "retest_failed");
    } finally {
      setRetestKey(null);
    }
  }

  if (error) {
    return (
      <p className="text-xs text-red-400" data-testid="occurrence-timeline-error">
        {error}
      </p>
    );
  }
  if (ordered.length === 0) {
    return (
      <p className="text-xs text-neutral-600" data-testid="occurrence-timeline-empty">
        No occurrences for this scan
      </p>
    );
  }

  return (
    <ol className="space-y-2" data-testid="occurrence-timeline">
      {ordered.map((item) => (
        <li
          key={item.occurrence_key}
          className="rounded border border-neutral-800 bg-neutral-950 px-3 py-2 text-xs"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-mono text-neutral-200">{item.detector_id}</span>
            <span className="text-neutral-500">{formatTs(item.first_seen_at)}</span>
          </div>
          <div className="mt-1 text-neutral-400">
            scanner={item.scanner} last_seen={formatTs(item.last_seen_at)}
          </div>
          <button
            type="button"
            className="mt-2 rounded border border-amber-700 px-2 py-0.5 text-amber-200 disabled:opacity-40"
            disabled={retestKey === item.finding_key}
            onClick={() => void retest(item.finding_key)}
            data-testid={`occurrence-retest-${item.finding_key.slice(0, 8)}`}
          >
            Retest
          </button>
        </li>
      ))}
    </ol>
  );
}
