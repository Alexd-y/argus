"use client";

import { useCallback, useEffect, useRef, useState, useTransition } from "react";
import { getHealthDashboard, type HealthDashboard } from "./dashboard-actions";

function StatusDot({ ok, label }: { ok: boolean; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span
        className={`inline-block size-2.5 rounded-full ${ok ? "bg-[var(--success)]" : "bg-[var(--error)]"}`}
        aria-label={ok ? `${label} healthy` : `${label} unhealthy`}
      />
      <span className="text-sm text-[var(--text-secondary)]">{label}</span>
    </div>
  );
}

export function DashboardHealthCard() {
  const [health, setHealth] = useState<HealthDashboard | null>(null);
  const [error, setError] = useState("");
  const [pending, startTransition] = useTransition();
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const refresh = useCallback(() => {
    startTransition(async () => {
      try {
        const data = await getHealthDashboard();
        setHealth(data);
        setError("");
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load health status");
      }
    });
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    intervalRef.current = setInterval(refresh, 30_000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [refresh]);

  const status = health?.status ?? "degraded";
  const badgeClass =
    status === "ok"
      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
      : "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20";

  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-[var(--text-primary)]">
          System Health
        </h2>
        {health && (
          <span className={`rounded px-2 py-0.5 text-xs font-medium ${badgeClass}`}>
            {status === "ok" ? "Operational" : "Degraded"}
          </span>
        )}
      </div>
      {error && !health && (
        <div role="alert" className="mt-3 rounded border border-red-900/40 bg-red-950/30 px-3 py-2 text-sm text-red-200">
          {error}
        </div>
      )}
      {health ? (
        <div className="mt-3 grid grid-cols-3 gap-4">
          <StatusDot ok={health.database} label="Database" />
          <StatusDot ok={health.redis} label="Redis" />
          <StatusDot ok={health.storage} label="Storage" />
        </div>
      ) : (
        !error && (
          <div className="mt-3 grid grid-cols-3 gap-4">
            {["Database", "Redis", "Storage"].map((l) => (
              <div key={l} className="flex items-center gap-2">
                <span className="inline-block size-2.5 animate-pulse rounded-full bg-[var(--bg-tertiary)]" />
                <span className="text-sm text-[var(--text-muted)]">{l}</span>
              </div>
            ))}
          </div>
        )
      )}
    </div>
  );
}