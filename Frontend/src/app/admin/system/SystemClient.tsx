"use client";

import { useCallback, useEffect, useState, useTransition } from "react";

import type { EmergencyStatus, HealthDashboard, AuditLogEntry } from "@/app/admin/dashboard-actions";
import {
  getEmergencyStatus,
  getHealthDashboard,
  getRecentAuditLogs,
} from "@/app/admin/dashboard-actions";

function HealthDot({ ok, label }: { ok: boolean; label: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className={`inline-block size-2.5 rounded-full ${ok ? "bg-emerald-400" : "bg-red-400"}`} />
      <span className="text-sm text-[var(--text-secondary)]">{label}</span>
      <span className={`text-xs font-medium ${ok ? "text-emerald-300" : "text-red-300"}`}>
        {ok ? "OK" : "Down"}
      </span>
    </div>
  );
}

function SystemStatCard({
  label,
  value,
  sub,
  accent,
  isLoading,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent: string;
  isLoading: boolean;
}) {
  return (
    <div className={`rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-4 ${accent}`}>
      <div className="text-xs font-medium uppercase tracking-wide text-[var(--text-muted)]">{label}</div>
      {isLoading ? (
        <div className="mt-2 h-8 w-16 animate-pulse rounded bg-[var(--bg-tertiary)]" />
      ) : (
        <div className="mt-2 text-2xl font-bold text-[var(--text-primary)]">{value}</div>
      )}
      {sub ? (
        <div className="mt-1 text-xs text-[var(--text-secondary)]">
          {isLoading ? <span className="inline-block h-3 w-24 animate-pulse rounded bg-[var(--bg-tertiary)]" /> : sub}
        </div>
      ) : null}
    </div>
  );
}

const EVENT_TYPE_COLORS: Record<string, string> = {
  "emergency.stop_all": "bg-red-400",
  "emergency.resume_all": "bg-emerald-400",
  "emergency.throttle": "bg-amber-400",
  "scan.": "bg-blue-400",
  "auth.": "bg-purple-400",
};

function getEventDotColor(action: string): string {
  for (const [prefix, color] of Object.entries(EVENT_TYPE_COLORS)) {
    if (action.startsWith(prefix)) return color;
  }
  return "bg-zinc-400";
}

function formatTimeAgo(iso: string): string {
  try {
    const d = new Date(iso);
    const now = Date.now();
    const diff = now - d.getTime();
    if (diff < 60_000) return "just now";
    if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
    if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
    return `${Math.floor(diff / 86_400_000)}d ago`;
  } catch {
    return iso;
  }
}

function SystemBody() {
  const [isPending, startTransition] = useTransition();
  const [health, setHealth] = useState<HealthDashboard | null>(null);
  const [emergency, setEmergency] = useState<EmergencyStatus | null>(null);
  const [auditLogs, setAuditLogs] = useState<AuditLogEntry[]>([]);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(() => {
    startTransition(async () => {
      try {
        const [h, e, a] = await Promise.all([
          getHealthDashboard(),
          getEmergencyStatus(),
          getRecentAuditLogs(20),
        ]);
        setHealth(h);
        setEmergency(e);
        setAuditLogs(a);
        setError(null);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load system data");
      }
    });
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  if (error && !health) {
    return (
      <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-[var(--border)] bg-[var(--bg-secondary)] px-6 py-12 text-center">
        <div className="flex size-12 items-center justify-center rounded-full bg-red-500/10">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-red-400">
            <circle cx="12" cy="12" r="10" /><path d="M15 9l-6 6M9 9l6 6" />
          </svg>
        </div>
        <h3 className="text-sm font-medium text-[var(--text-primary)]">Failed to load system data</h3>
        <p className="max-w-sm text-xs text-[var(--text-muted)]">{error}</p>
        <button
          type="button"
          className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-1.5 text-sm text-[var(--text-secondary)] transition-colors hover:bg-[var(--bg-tertiary)]"
          onClick={refresh}
        >
          Retry
        </button>
      </div>
    );
  }

  const isLoading = !health;

  const throttleCount = emergency
    ? Object.values(emergency.tenant_throttles).filter(Boolean).length
    : 0;

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">System</h1>
          <p className="mt-0.5 text-sm text-[var(--text-secondary)]">
            Platform-wide controls and status. Super-admin only.
          </p>
        </div>
        <button
          type="button"
          className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-1.5 text-sm text-[var(--text-secondary)] transition-colors hover:bg-[var(--bg-tertiary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
          disabled={isPending}
          onClick={refresh}
        >
          {isPending ? "Refreshing\u2026" : "Refresh"}
        </button>
      </header>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <SystemStatCard
          label="Platform Status"
          value={emergency?.global_stop_active ? "Stopped" : "Running"}
          sub={emergency?.global_stop_active ? "Emergency stop active" : "All systems normal"}
          accent={emergency?.global_stop_active ? "border-l-4 border-l-red-500" : "border-l-4 border-l-emerald-500"}
          isLoading={isLoading}
        />
        <SystemStatCard
          label="Health"
          value={health?.status === "ok" ? "OK" : health?.status === "degraded" ? "Degraded" : "\u2014"}
          sub={health ? `${[health.database, health.redis, health.storage].filter(Boolean).length}/3 services up` : undefined}
          accent="border-l-4 border-l-[var(--accent)]"
          isLoading={isLoading}
        />
        <SystemStatCard
          label="Active Throttles"
          value={throttleCount}
          sub={throttleCount === 0 ? "No active throttles" : `${throttleCount} tenant${throttleCount > 1 ? "s" : ""} throttled`}
          accent="border-l-4 border-l-amber-500"
          isLoading={isLoading}
        />
        <SystemStatCard
          label="Recent Events"
          value={auditLogs.length}
          sub="Last 20 audit entries"
          accent="border-l-4 border-l-[var(--accent)]"
          isLoading={isLoading}
        />
      </div>

      {emergency?.global_stop_active ? (
        <div className="rounded-lg border border-red-500/30 bg-red-950/30 px-4 py-3 text-sm text-red-200" role="alert">
          <span className="font-medium">Emergency stop is active.</span> All scan operations are suspended. Go to{" "}
          <a href="/admin/operations" className="text-[var(--accent)] hover:underline">
            Operations
          </a>{" "}
          to resume.
        </div>
      ) : null}

      <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)]">
        <div className="border-b border-[var(--border)] px-4 py-3">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">Infrastructure Health</h2>
          <p className="mt-0.5 text-xs text-[var(--text-muted)]">Core service connectivity status</p>
        </div>
        {!health ? (
          <div className="flex items-center justify-center py-8">
            <div className="h-6 w-6 animate-spin rounded-full border-2 border-[var(--border)] border-t-[var(--accent)]" />
          </div>
        ) : (
          <div className="grid gap-3 p-4 sm:grid-cols-3">
            <div className="flex items-center gap-3 rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-3">
              <span className={`inline-block size-3 rounded-full ${health.database ? "bg-emerald-400" : "bg-red-400"}`} />
              <div>
                <div className="text-sm font-medium text-[var(--text-primary)]">Database</div>
                <div className={`text-xs ${health.database ? "text-emerald-300" : "text-red-300"}`}>
                  {health.database ? "Connected" : "Disconnected"}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3 rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-3">
              <span className={`inline-block size-3 rounded-full ${health.redis ? "bg-emerald-400" : "bg-red-400"}`} />
              <div>
                <div className="text-sm font-medium text-[var(--text-primary)]">Redis</div>
                <div className={`text-xs ${health.redis ? "text-emerald-300" : "text-red-300"}`}>
                  {health.redis ? "Connected" : "Disconnected"}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3 rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-3">
              <span className={`inline-block size-3 rounded-full ${health.storage ? "bg-emerald-400" : "bg-red-400"}`} />
              <div>
                <div className="text-sm font-medium text-[var(--text-primary)]">Storage</div>
                <div className={`text-xs ${health.storage ? "text-emerald-300" : "text-red-300"}`}>
                  {health.storage ? "Available" : "Unavailable"}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)]">
        <div className="border-b border-[var(--border)] px-4 py-3">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">Recent System Events</h2>
          <p className="mt-0.5 text-xs text-[var(--text-muted)]">Latest 20 audit log entries across all tenants</p>
        </div>
        {isLoading ? (
          <div className="flex items-center justify-center py-8">
            <div className="h-6 w-6 animate-spin rounded-full border-2 border-[var(--border)] border-t-[var(--accent)]" />
          </div>
        ) : auditLogs.length === 0 ? (
          <div className="flex flex-col items-center gap-2 px-6 py-8 text-center">
            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-[var(--text-muted)]">
              <path d="M12 8v4l3 3M3 12a9 9 0 1018 0 9 9 0 00-18 0z" />
            </svg>
            <p className="text-sm text-[var(--text-muted)]">No recent events</p>
          </div>
        ) : (
          <div className="divide-y divide-[var(--border)] max-h-80 overflow-y-auto">
            {auditLogs.map((entry) => (
              <div key={entry.id} className="flex items-start gap-3 px-4 py-2.5">
                <span className={`mt-1.5 inline-block size-2 shrink-0 rounded-full ${getEventDotColor(entry.action)}`} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-medium text-[var(--text-primary)]">{entry.action}</span>
                    {entry.resource_type ? (
                      <span className="text-[10px] text-[var(--text-muted)]">
                        {entry.resource_type}{entry.resource_id ? ` ${entry.resource_id.slice(0, 8)}\u2026` : ""}
                      </span>
                    ) : null}
                  </div>
                  <div className="text-[10px] text-[var(--text-muted)]">
                    {entry.tenant_id ? `tenant ${entry.tenant_id.slice(0, 8)}\u2026` : "global"}
                    {" \u00B7 "}
                    {formatTimeAgo(entry.created_at)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
        <div className="border-t border-[var(--border)] px-4 py-2">
          <a
            href="/admin/audit-logs"
            className="text-xs text-[var(--accent)] hover:underline"
          >
            View all audit logs &rarr;
          </a>
        </div>
      </div>

      <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)]">
        <div className="border-b border-[var(--border)] px-4 py-3">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">Quick Links</h2>
          <p className="mt-0.5 text-xs text-[var(--text-muted)]">Navigate to related admin surfaces</p>
        </div>
        <div className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-3">
          <a
            href="/admin/operations"
            className="flex items-center gap-3 rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-3 transition-colors hover:bg-[var(--bg-tertiary)]"
          >
            <span className="flex size-8 items-center justify-center rounded-full bg-red-500/10 text-sm">
              {"\u26D4"}
            </span>
            <div>
              <div className="text-sm font-medium text-[var(--text-primary)]">Operations</div>
              <div className="text-[10px] text-[var(--text-muted)]">Kill switch & throttle controls</div>
            </div>
          </a>
          <a
            href="/admin/llm"
            className="flex items-center gap-3 rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-3 transition-colors hover:bg-[var(--bg-tertiary)]"
          >
            <span className="flex size-8 items-center justify-center rounded-full bg-purple-500/10 text-sm">
              {"\uD83E\uDDE0"}
            </span>
            <div>
              <div className="text-sm font-medium text-[var(--text-primary)]">LLM Providers</div>
              <div className="text-[10px] text-[var(--text-muted)]">Provider config & WhiteRabbitNeo</div>
            </div>
          </a>
          <a
            href="/admin/settings"
            className="flex items-center gap-3 rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-3 transition-colors hover:bg-[var(--bg-tertiary)]"
          >
            <span className="flex size-8 items-center justify-center rounded-full bg-blue-500/10 text-sm">
              {"\u2699\uFE0F"}
            </span>
            <div>
              <div className="text-sm font-medium text-[var(--text-primary)]">Settings</div>
              <div className="text-[10px] text-[var(--text-muted)]">Profile, MFA & sessions</div>
            </div>
          </a>
          <a
            href="/admin/tenants"
            className="flex items-center gap-3 rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-3 transition-colors hover:bg-[var(--bg-tertiary)]"
          >
            <span className="flex size-8 items-center justify-center rounded-full bg-emerald-500/10 text-sm">
              {"\uD83C\uDFE0"}
            </span>
            <div>
              <div className="text-sm font-medium text-[var(--text-primary)]">Tenants</div>
              <div className="text-[10px] text-[var(--text-muted)]">Tenant management</div>
            </div>
          </a>
          <a
            href="/admin/audit-logs"
            className="flex items-center gap-3 rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-3 transition-colors hover:bg-[var(--bg-tertiary)]"
          >
            <span className="flex size-8 items-center justify-center rounded-full bg-amber-500/10 text-sm">
              {"\uD83D\uDCDC"}
            </span>
            <div>
              <div className="text-sm font-medium text-[var(--text-primary)]">Audit Log</div>
              <div className="text-[10px] text-[var(--text-muted)]">Full event history</div>
            </div>
          </a>
          <a
            href="/admin/webhooks/dlq"
            className="flex items-center gap-3 rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-3 transition-colors hover:bg-[var(--bg-tertiary)]"
          >
            <span className="flex size-8 items-center justify-center rounded-full bg-indigo-500/10 text-sm">
              {"\uD83D\uDCE0"}
            </span>
            <div>
              <div className="text-sm font-medium text-[var(--text-primary)]">Webhooks DLQ</div>
              <div className="text-[10px] text-[var(--text-muted)]">Dead-letter queue triage</div>
            </div>
          </a>
        </div>
      </div>
    </div>
  );
}

export function SystemClient() {
  return <SystemBody />;
}