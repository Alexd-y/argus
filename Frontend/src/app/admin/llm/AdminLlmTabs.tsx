"use client";

import { useState } from "react";
import { AdminLlmClient } from "./AdminLlmClient";
import { WrbDashboardClient } from "./WrbDashboardClient";

const TABS = [
  { key: "providers", label: "Cloud Providers" },
  { key: "wrb", label: "WhiteRabbitNeo" },
] as const;

type TabKey = (typeof TABS)[number]["key"];

export function AdminLlmTabs() {
  const [tab, setTab] = useState<TabKey>("providers");

  return (
    <div className="space-y-4">
      <div className="flex gap-1 border-b border-[var(--border)]">
        {TABS.map((t) => (
          <button
            key={t.key}
            type="button"
            className={`px-3 py-2 text-sm transition ${
              tab === t.key
                ? "border-b-2 border-[var(--accent)] text-[var(--accent)]"
                : "text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            }`}
            onClick={() => setTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>
      {tab === "providers" ? <AdminLlmClient /> : null}
      {tab === "wrb" ? <WrbDashboardClient /> : null}
    </div>
  );
}