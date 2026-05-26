"use client";

import { useEffect, useState, useTransition } from "react";
import Link from "next/link";
import { getRecentAuditLogs, type AuditLogEntry } from "./dashboard-actions";

function formatRelativeTime(iso: string): string {
  try {
    const d = new Date(iso);
    const now = Date.now();
    const diff = now - d.getTime();
    const min = Math.floor(diff / 60_000);
    if (min < 1) return "just now";
    if (min < 60) return `${min}m ago`;
    const hr = Math.floor(min / 60);
    if (hr < 24) return `${hr}h ago`;
    const day = Math.floor(hr / 24);
    return `${day}d ago`;
  } catch {
    return iso;
  }
}

function formatAction(action: string): string {
  const map: Record<string, string> = {
    tenant_create: "Tenant created",
    tenant_update: "Tenant updated",
    tenant_delete: "Tenant deleted",
    scan_launched: "Scan launched",
    scan_completed: "Scan completed",
    scan_cancelled: "Scan cancelled",
    finding_triaged: "Finding triaged",
    finding_acked: "Finding acknowledged",
    finding_resolved: "Finding resolved",
    finding_dismissed: "Finding dismissed",
    emergency_stop: "Emergency stop activated",
    emergency_resume: "Emergency stop deactivated",
    admin_login: "Admin login",
    admin_logout: "Admin logout",
    password_change: "Password changed",
  };
  return map[action] ?? action.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

function actionColor(action: string): string {
  if (action.startsWith("tenant_")) return "bg-[var(--accent)]";
  if (action.startsWith("scan_")) return "bg-blue-500";
  if (action.startsWith("finding_")) return "bg-amber-500";
  if (action.startsWith("emergency_")) return "bg-[var(--error)]";
  return "bg-[var(--text-muted)]";
}

export function DashboardActivityFeed() {
  const [entries, setEntries] = useState<AuditLogEntry[]>([]);
  const [error, setError] = useState("");
  const [pending, startTransition] = useTransition();

  useEffect(() => {
    startTransition(async () => {
      try {
        const logs = await getRecentAuditLogs(15);
        setEntries(logs);
        setError("");
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load activity");
      }
    });
  }, []);

  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-[var(--text-primary)]">
          Recent Activity
        </h2>
        <Link
          href="/admin/audit-logs"
          className="text-xs text-[var(--accent)] hover:underline"
        >
          View all
        </Link>
      </div>
      {error && (
        <div role="alert" className="rounded border border-red-900/40 bg-red-950/30 px-3 py-2 text-sm text-red-200">
          {error}
        </div>
      )}
      {pending && entries.length === 0 ? (
        <div className="space-y-2">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="h-10 animate-pulse rounded bg-[var(--bg-tertiary)]" />
          ))}
        </div>
      ) : entries.length === 0 ? (
        <div className="py-6 text-center text-sm text-[var(--text-muted)]">
          No recent activity
        </div>
      ) : (
        <div className="space-y-2 max-h-[400px] overflow-y-auto" role="log">
          {entries.map((entry) => (
            <div
              key={entry.id}
              className="flex items-start gap-3 rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2"
            >
              <span
                className={`mt-1 inline-block size-2 shrink-0 rounded-full ${actionColor(entry.action)}`}
              />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-[var(--text-primary)]">
                    {formatAction(entry.action)}
                  </span>
                  {entry.resource_type && (
                    <span className="rounded bg-[var(--bg-tertiary)] px-1.5 py-0.5 text-[10px] text-[var(--text-muted)]">
                      {entry.resource_type}
                    </span>
                  )}
                </div>
                <div className="mt-0.5 text-xs text-[var(--text-muted)]">
                  {formatRelativeTime(entry.created_at)}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}