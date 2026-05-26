"use client";

import { useEffect, useState, useTransition } from "react";
import type { AdminRole } from "@/services/admin/adminRoles";
import {
  getDashboardTenants,
  getDashboardFindingsCount,
  getDashboardScans,
  getEmergencyStatus,
  type AdminTenant,
} from "./dashboard-actions";

type StatCard = {
  label: string;
  value: string | number;
  detail: string;
  loading: boolean;
};

function StatCard({ label, value, detail, loading }: StatCard) {
  return (
    <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
      <div className="text-xs font-medium uppercase tracking-wide text-[var(--text-muted)]">
        {label}
      </div>
      {loading ? (
        <div className="mt-2 h-8 w-16 animate-pulse rounded bg-[var(--bg-tertiary)]" />
      ) : (
        <div className="mt-2 text-2xl font-bold text-[var(--text-primary)]">{value}</div>
      )}
      <div className="mt-1 text-xs text-[var(--text-secondary)]">
        {loading ? (
          <span className="inline-block h-3 w-24 animate-pulse rounded bg-[var(--bg-tertiary)]" />
        ) : (
          detail
        )}
      </div>
    </div>
  );
}

export function DashboardStatsCards({ role }: { role: AdminRole | null }) {
  const [tenantCount, setTenantCount] = useState<number | null>(null);
  const [scanTotal, setScanTotal] = useState<number | null>(null);
  const [findingsTotal, setFindingsTotal] = useState<number | null>(null);
  const [globalStop, setGlobalStop] = useState<boolean | null>(null);
  const [pending, startTransition] = useTransition();

  useEffect(() => {
    startTransition(async () => {
      try {
        const tenants: AdminTenant[] = await getDashboardTenants();
        setTenantCount(tenants.length);

        if (tenants.length > 0) {
          const scans = await getDashboardScans(tenants[0].id);
          setScanTotal(scans.total);
        }

        const findings = await getDashboardFindingsCount();
        setFindingsTotal(findings.total);

        try {
          const emerg = await getEmergencyStatus();
          setGlobalStop(emerg.global_stop_active);
        } catch {
          setGlobalStop(null);
        }
      } catch {
        setTenantCount((p) => p ?? 0);
        setScanTotal((p) => p ?? 0);
        setFindingsTotal((p) => p ?? 0);
      }
    });
  }, []);

  const stopDetail =
    globalStop === true
      ? "Global stop active"
      : globalStop === false
        ? "System running"
        : "";

  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      <StatCard
        label="Tenants"
        value={tenantCount ?? "—"}
        detail={tenantCount !== null ? `${tenantCount} registered` : ""}
        loading={tenantCount === null}
      />
      <StatCard
        label="Scans"
        value={scanTotal ?? "—"}
        detail={scanTotal !== null ? "total scans" : ""}
        loading={scanTotal === null}
      />
      <StatCard
        label="Findings"
        value={findingsTotal ?? "—"}
        detail={findingsTotal !== null ? "open findings" : ""}
        loading={findingsTotal === null}
      />
      <StatCard
        label="System"
        value={globalStop === true ? "Stopped" : globalStop === false ? "Active" : "—"}
        detail={stopDetail}
        loading={globalStop === null && pending}
      />
    </div>
  );
}