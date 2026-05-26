"use client";

import { useCallback, useEffect, useState } from "react";
import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import { useAdminAuth } from "@/services/admin/useAdminAuth";
import { DashboardStatsCards } from "./DashboardStatsCards";
import { DashboardHealthCard } from "./DashboardHealthCard";
import { DashboardActivityFeed } from "./DashboardActivityFeed";
import { DashboardQuickActions } from "./DashboardQuickActions";
import { DashboardLLMStatus } from "./DashboardLLMStatus";

function DashboardBody() {
  const { role } = useAdminAuth({ minimumRole: "operator" });

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">
            Dashboard
          </h1>
          <p className="text-sm text-[var(--text-secondary)]">
            System overview and recent activity
          </p>
        </div>
        {role && (
          <span className="rounded bg-[var(--bg-tertiary)] px-2 py-0.5 text-xs text-[var(--text-muted)]">
            {role}
          </span>
        )}
      </div>

      <DashboardHealthCard />
      <DashboardStatsCards role={role} />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <DashboardActivityFeed />
        <div className="space-y-6">
          <DashboardLLMStatus />
          <DashboardQuickActions role={role} />
        </div>
      </div>
    </div>
  );
}

export default function AdminDashboardPage() {
  return (
    <AdminRouteGuard minimumRole="operator">
      <DashboardBody />
    </AdminRouteGuard>
  );
}