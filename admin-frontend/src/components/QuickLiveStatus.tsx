"use client";

import { useCallback, useEffect, useMemo, useState } from "react";

import type { ScanDetailResponse, ScanFinding } from "@/lib/scanApi";
import { scanApi } from "@/lib/scanApi";
import type { QuickScanPlanView } from "@/lib/quickApi";
import { fetchScanPlan, formatDurationSeconds } from "@/lib/quickApi";

export interface QuickBudgetSnapshot {
  usedSeconds?: number;
  remainingSeconds?: number;
  wallClockSeconds?: number;
  usedRatio?: number;
}

interface QuickLiveStatusProps {
  scanId: string;
  stage?: string | null;
  sseBudget?: QuickBudgetSnapshot | null;
  ssePlanVersion?: number | null;
  sseDegraded?: string[];
  sseFindingsCount?: number | null;
  onCancelled?: () => void;
}

function parseIso(value: string | null | undefined): number | null {
  if (!value) return null;
  const ms = new Date(value).getTime();
  return Number.isNaN(ms) ? null : ms;
}

function countByStatus(tasks: QuickScanPlanView["tasks"]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const task of tasks) {
    const key = (task.status || "queued").toLowerCase();
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

function uniqueAssets(tasks: QuickScanPlanView["tasks"]): string[] {
  const seen = new Set<string>();
  for (const task of tasks) {
    if (task.target_ref) seen.add(task.target_ref);
  }
  return [...seen];
}

export function QuickLiveStatus({
  scanId,
  stage,
  sseBudget = null,
  ssePlanVersion = null,
  sseDegraded = [],
  sseFindingsCount = null,
  onCancelled,
}: QuickLiveStatusProps) {
  const [detail, setDetail] = useState<ScanDetailResponse | null>(null);
  const [plan, setPlan] = useState<QuickScanPlanView | null>(null);
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [error, setError] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState(false);
  const [cancelError, setCancelError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [nextDetail, nextFindings] = await Promise.all([
        scanApi.getScan(scanId),
        scanApi.getFindings(scanId).catch(() => [] as ScanFinding[]),
      ]);
      setDetail(nextDetail);
      setFindings(nextFindings);
      try {
        setPlan(await fetchScanPlan(scanId));
      } catch {
        setPlan(null);
      }
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load Quick status");
    }
  }, [scanId]);

  useEffect(() => {
    void load();
    const poll = setInterval(() => void load(), 5000);
    const tick = setInterval(() => setNowMs(Date.now()), 1000);
    return () => {
      clearInterval(poll);
      clearInterval(tick);
    };
  }, [load]);

  const deadlineMs = parseIso(plan?.deadline_at ?? detail?.deadline_at);
  const createdMs = parseIso(detail?.created_at);
  const elapsedSec = createdMs ? Math.max(0, (nowMs - createdMs) / 1000) : 0;
  const remainingSec =
    sseBudget?.remainingSeconds ??
    (deadlineMs ? Math.max(0, (deadlineMs - nowMs) / 1000) : null);
  const wallClock =
    sseBudget?.wallClockSeconds ??
    plan?.budget.wall_clock_budget_seconds ??
    detail?.budget?.wall_clock_budget_seconds ??
    null;
  const usedSec =
    sseBudget?.usedSeconds ??
    (wallClock != null && remainingSec != null
      ? Math.min(wallClock, Math.max(0, wallClock - remainingSec))
      : elapsedSec);
  const usedRatio =
    sseBudget?.usedRatio ??
    (wallClock && wallClock > 0 ? Math.min(1, usedSec / wallClock) : 0);

  const currentStage = stage || detail?.stage || detail?.phase || "—";
  const planVersion = ssePlanVersion ?? plan?.plan_version ?? 0;
  const taskCounts = useMemo(
    () => countByStatus(plan?.tasks ?? []),
    [plan]
  );
  const assets = uniqueAssets(plan?.tasks ?? []);
  const terminal =
    detail?.status === "completed" ||
    detail?.status === "failed" ||
    detail?.status === "cancelled";

  const handleCancel = async () => {
    setCancelling(true);
    setCancelError(null);
    try {
      await scanApi.cancelScan(scanId);
      onCancelled?.();
      await load();
    } catch (e) {
      setCancelError(e instanceof Error ? e.message : "Cancel failed");
    } finally {
      setCancelling(false);
    }
  };

  return (
    <section
      className="rounded border border-cyan-900/50 bg-neutral-900 p-4"
      data-testid="quick-live-status"
    >
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-medium text-cyan-200">Quick live status</h2>
        {!terminal && (
          <button
            type="button"
            onClick={() => void handleCancel()}
            disabled={cancelling}
            className="rounded border border-red-900/60 bg-red-950/40 px-3 py-1 text-xs text-red-300 hover:bg-red-950/70 disabled:opacity-50"
          >
            {cancelling ? "Cancelling…" : "Cancel scan"}
          </button>
        )}
      </div>

      {error && <p className="mb-2 text-xs text-red-400">{error}</p>}
      {cancelError && <p className="mb-2 text-xs text-red-400">{cancelError}</p>}

      <dl className="mb-3 grid gap-2 text-xs sm:grid-cols-2">
        <div className="rounded border border-neutral-800 bg-neutral-950 px-3 py-2">
          <dt className="text-neutral-500">Deadline</dt>
          <dd className="mt-0.5 font-mono text-neutral-200">
            {deadlineMs ? new Date(deadlineMs).toLocaleString() : "—"}
          </dd>
        </div>
        <div className="rounded border border-neutral-800 bg-neutral-950 px-3 py-2">
          <dt className="text-neutral-500">Elapsed</dt>
          <dd className="mt-0.5 font-mono text-neutral-200">
            {formatDurationSeconds(elapsedSec)}
            {remainingSec != null && (
              <span className="ml-2 text-neutral-500">
                remaining {formatDurationSeconds(remainingSec)}
              </span>
            )}
          </dd>
        </div>
        <div className="rounded border border-neutral-800 bg-neutral-950 px-3 py-2">
          <dt className="text-neutral-500">Stage</dt>
          <dd className="mt-0.5 text-neutral-200">{currentStage.replace(/_/g, " ")}</dd>
        </div>
        <div className="rounded border border-neutral-800 bg-neutral-950 px-3 py-2">
          <dt className="text-neutral-500">Plan revision</dt>
          <dd className="mt-0.5 font-mono text-neutral-200">
            v{planVersion}
            {plan?.revision_reason ? (
              <span className="ml-2 font-sans text-neutral-500">{plan.revision_reason}</span>
            ) : null}
          </dd>
        </div>
      </dl>

      <div className="mb-3">
        <div className="mb-1 flex justify-between text-xs text-neutral-500">
          <span>Budget used</span>
          <span className="font-mono">
            {formatDurationSeconds(usedSec)}
            {wallClock != null ? ` / ${formatDurationSeconds(wallClock)}` : ""}
          </span>
        </div>
        <div className="h-2 w-full rounded-full bg-neutral-800">
          <div
            className={`h-2 rounded-full ${usedRatio >= 0.9 ? "bg-amber-500" : "bg-cyan-600"}`}
            style={{ width: `${Math.round(usedRatio * 100)}%` }}
          />
        </div>
      </div>

      <div className="mb-3 grid gap-2 text-xs sm:grid-cols-2">
        <div className="rounded border border-neutral-800 bg-neutral-950 px-3 py-2">
          <p className="mb-1 text-neutral-500">Tasks</p>
          <p className="font-mono text-neutral-300">
            {plan?.tasks.length ?? 0} total
            {Object.entries(taskCounts).map(([status, count]) => (
              <span key={status} className="ml-2 text-neutral-500">
                {status}:{count}
              </span>
            ))}
          </p>
        </div>
        <div className="rounded border border-neutral-800 bg-neutral-950 px-3 py-2">
          <p className="mb-1 text-neutral-500">Assets</p>
          <p className="font-mono text-neutral-300">
            {assets.length > 0 ? assets.slice(0, 6).join(", ") : "—"}
            {assets.length > 6 ? ` +${assets.length - 6}` : ""}
          </p>
        </div>
      </div>

      <div className="mb-3">
        <p className="mb-1 text-xs text-neutral-500">
          Preliminary findings
          {sseFindingsCount != null ? ` (${sseFindingsCount} via stream)` : ""}
        </p>
        {findings.length === 0 ? (
          <p className="text-xs text-neutral-600">None yet — not evidence of safety.</p>
        ) : (
          <ul className="space-y-1 text-xs">
            {findings.slice(0, 8).map((finding, index) => (
              <li
                key={finding.finding_id ?? `${finding.title}-${index}`}
                className="flex gap-2 text-neutral-300"
              >
                <span className="w-16 shrink-0 uppercase text-amber-400">
                  {finding.severity}
                </span>
                <span className="truncate">{finding.title}</span>
                <span className="shrink-0 text-neutral-500">
                  {finding.confidence ?? "—"}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {sseDegraded.length > 0 && (
        <div className="rounded border border-amber-900/40 bg-amber-950/20 px-3 py-2 text-xs text-amber-200">
          <p className="mb-1 font-medium">Degraded components</p>
          <ul className="list-disc pl-4">
            {sseDegraded.map((name) => (
              <li key={name}>{name}</li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
