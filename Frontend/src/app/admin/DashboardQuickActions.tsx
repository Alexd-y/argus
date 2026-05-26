"use client";

import Link from "next/link";
import type { AdminRole } from "@/services/admin/adminRoles";

const actions = [
  { href: "/admin/tenants", label: "Tenants", icon: "🏢" },
  { href: "/admin/scans", label: "Scans", icon: "🔍" },
  { href: "/admin/findings", label: "Findings", icon: "🛡️" },
  { href: "/admin/audit-logs", label: "Audit Log", icon: "📋" },
  { href: "/admin/operations", label: "Operations", icon: "🚨" },
  { href: "/admin/schedules", label: "Schedules", icon: "📅" },
] as const;

const superAdminActions = [
  { href: "/admin/system", label: "System", icon: "⚙️" },
  { href: "/admin/settings", label: "Settings", icon: "🔑" },
] as const;

function QuickActionLink({ href, icon, label }: { href: string; icon: string; label: string }) {
  return (
    <Link
      href={href}
      className="flex items-center gap-2 rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2.5 text-sm text-[var(--text-secondary)] transition hover:bg-[var(--bg-tertiary)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
    >
      <span aria-hidden="true">{icon}</span>
      <span>{label}</span>
    </Link>
  );
}

export function DashboardQuickActions({ role }: { role: AdminRole | null }) {
  const allActions = role === "super-admin" ? [...actions, ...superAdminActions] : [...actions];

  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
      <h2 className="mb-3 text-sm font-semibold text-[var(--text-primary)]">
        Quick Actions
      </h2>
      <div className="grid grid-cols-2 gap-2">
        {allActions.map((a) => (
          <QuickActionLink key={a.href} href={a.href} icon={a.icon} label={a.label} />
        ))}
      </div>
    </div>
  );
}