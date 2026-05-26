"use client";

import { useState } from "react";
import { AdminLlmClient } from "./AdminLlmClient";
import { WrbDashboardClient } from "./WrbDashboardClient";

const TABS = [
  { key: "providers", label: "Cloud Providers", icon: "\u2601" },
  { key: "wrb", label: "WhiteRabbitNeo", icon: "\uD83D\uDC30" },
] as const;

type TabKey = (typeof TABS)[number]["key"];

export function AdminLlmTabs() {
  const [tab, setTab] = useState<TabKey>("providers");

  return (
    <div className="space-y-6">
      <div className="flex gap-1 border-b border-[var(--border)]">
        {TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium transition-colors ${
              tab === t.key
                ? "border-b-2 border-[var(--accent)] text-[var(--accent)]"
                : "text-[var(--text-muted)] hover:text-[var(--text-primary)]"
            }`}
            onClick={() => setTab(t.key)}
          >
            <span aria-hidden="true">{t.icon}</span>
            {t.label}
          </button>
        ))}
      </div>
      {tab === "providers" ? <AdminLlmClient /> : null}
      {tab === "wrb" ? <WrbDashboardClient /> : null}
    </div>
  );
}