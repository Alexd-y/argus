"use client";

import { useEffect, useMemo, useState } from "react";

import type {
  QuickProfileCatalogItem,
  QuickProfileName,
  QuickSeverityFloor,
} from "@/lib/quickApi";
import { fetchQuickProfiles, formatDurationSeconds } from "@/lib/quickApi";

const INCLUDED_CLASSES = [
  "Network / DNS / exposed services",
  "Web / CMS / API fingerprint",
  "TLS and auth surface",
  "High-signal CVE and misconfig (Nuclei quick-default)",
];

const EXCLUDED_CLASSES = [
  "Brute force / password spray",
  "Exhaustive fuzz / clusterbomb",
  "Destructive checks",
  "Heavy reverse engineering",
  "Exploitation / post-exploitation",
];

const SEVERITY_FLOORS: QuickSeverityFloor[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

const PROFILE_PURPOSE: Record<QuickProfileName, string> = {
  compact: "Fast triage — 5 minutes, tight budget, highest-signal checks only",
  balanced: "Default Quick profile — 15 minutes, production-like policy, no LAB lease",
  extended: "Wider Quick pass — 30 minutes, still not a full or LAB scan",
};

/** Display-only fallback if GET /quick/profiles is unavailable. */
const FALLBACK_PROFILES: QuickProfileCatalogItem[] = [
  {
    name: "compact",
    wall_clock_budget_seconds: 300,
    ai_budget_seconds: 30,
    reserve_for_validation_percent: 15,
    max_targets: 25,
    max_urls_per_host: 40,
    crawl_depth: 1,
    severity_floor: "medium",
    enable_ai: true,
    enable_oast: true,
    enable_headless_on_signal: false,
    request_budget: 4000,
    per_host_budget: 400,
    concurrency_budget: 4,
  },
  {
    name: "balanced",
    wall_clock_budget_seconds: 900,
    ai_budget_seconds: 90,
    reserve_for_validation_percent: 20,
    max_targets: 100,
    max_urls_per_host: 100,
    crawl_depth: 2,
    severity_floor: "medium",
    enable_ai: true,
    enable_oast: true,
    enable_headless_on_signal: true,
    request_budget: 12000,
    per_host_budget: 800,
    concurrency_budget: 6,
  },
  {
    name: "extended",
    wall_clock_budget_seconds: 1800,
    ai_budget_seconds: 180,
    reserve_for_validation_percent: 25,
    max_targets: 250,
    max_urls_per_host: 200,
    crawl_depth: 3,
    severity_floor: "medium",
    enable_ai: true,
    enable_oast: true,
    enable_headless_on_signal: true,
    request_budget: 24000,
    per_host_budget: 1600,
    concurrency_budget: 8,
  },
];

export interface QuickModeCardValue {
  profile: QuickProfileName;
  severityFloor: QuickSeverityFloor;
  enableOast: boolean;
  enableAi: boolean;
  cloudLlmAllowed: boolean;
  authenticatedContextId: string;
}

interface QuickModeCardProps {
  value: QuickModeCardValue;
  onChange: (next: QuickModeCardValue) => void;
  allowCloudAi?: boolean;
  targetCount?: number;
  disabled?: boolean;
}

function catalogFor(
  profiles: QuickProfileCatalogItem[],
  name: QuickProfileName
): QuickProfileCatalogItem {
  return (
    profiles.find((item) => item.name === name) ??
    FALLBACK_PROFILES.find((item) => item.name === name) ??
    FALLBACK_PROFILES[1]
  );
}

export function QuickModeCard({
  value,
  onChange,
  allowCloudAi = false,
  targetCount = 1,
  disabled = false,
}: QuickModeCardProps) {
  const [profiles, setProfiles] = useState<QuickProfileCatalogItem[]>(FALLBACK_PROFILES);
  const [catalogError, setCatalogError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const items = await fetchQuickProfiles();
        if (!cancelled && items.length > 0) setProfiles(items);
      } catch {
        if (!cancelled) setCatalogError("Using local profile defaults — catalog unavailable");
      }
    };
    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  const selected = useMemo(
    () => catalogFor(profiles, value.profile),
    [profiles, value.profile]
  );

  const overTargetCap = targetCount > selected.max_targets;
  const patch = (partial: Partial<QuickModeCardValue>) => {
    if (disabled) return;
    onChange({ ...value, ...partial });
  };

  return (
    <section
      className="rounded border border-cyan-900/60 bg-neutral-900 p-4"
      data-testid="quick-mode-card"
    >
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h2 className="text-sm font-medium text-cyan-200">Quick execution profile</h2>
        <span className="rounded border border-cyan-800 bg-cyan-950/40 px-2 py-0.5 text-xs uppercase tracking-wide text-cyan-300">
          not LAB
        </span>
      </div>
      <p className="mb-3 text-xs text-neutral-400">
        Time-boxed, production-like policy. No LAB lease, no exploitation, no silent
        fallback to a full scan.
      </p>

      <fieldset disabled={disabled} className="mb-3">
        <legend className="mb-2 text-xs text-neutral-500">Profile</legend>
        <div className="grid gap-2 sm:grid-cols-3">
          {profiles.map((item) => {
            const active = value.profile === item.name;
            return (
              <label
                key={item.name}
                className={`cursor-pointer rounded border p-3 ${
                  active
                    ? "border-cyan-600 bg-cyan-950/30"
                    : "border-neutral-800 bg-neutral-950 hover:border-neutral-700"
                } ${disabled ? "cursor-not-allowed opacity-60" : ""}`}
              >
                <input
                  type="radio"
                  name="quick_profile"
                  className="sr-only"
                  checked={active}
                  disabled={disabled}
                  onChange={() => patch({ profile: item.name })}
                />
                <span className="block text-sm font-medium capitalize text-white">
                  {item.name}
                </span>
                <span className="mt-1 block text-xs text-neutral-400">
                  {formatDurationSeconds(item.wall_clock_budget_seconds)} wall-clock
                </span>
                <span className="mt-1 block text-xs text-neutral-500">
                  {PROFILE_PURPOSE[item.name] ?? item.name}
                </span>
              </label>
            );
          })}
        </div>
      </fieldset>

      <dl className="mb-3 grid gap-2 text-xs sm:grid-cols-3">
        <div className="rounded border border-neutral-800 bg-neutral-950 px-3 py-2">
          <dt className="text-neutral-500">Expected duration</dt>
          <dd className="mt-0.5 font-mono text-neutral-200">
            {formatDurationSeconds(selected.wall_clock_budget_seconds)}
          </dd>
        </div>
        <div className="rounded border border-neutral-800 bg-neutral-950 px-3 py-2">
          <dt className="text-neutral-500">AI budget</dt>
          <dd className="mt-0.5 font-mono text-neutral-200">
            {formatDurationSeconds(selected.ai_budget_seconds)}
          </dd>
        </div>
        <div className="rounded border border-neutral-800 bg-neutral-950 px-3 py-2">
          <dt className="text-neutral-500">Validation reserve</dt>
          <dd className="mt-0.5 font-mono text-neutral-200">
            {selected.reserve_for_validation_percent}%
          </dd>
        </div>
      </dl>

      <div className="mb-3 grid gap-3 sm:grid-cols-2">
        <div>
          <p className="mb-1 text-xs font-medium text-neutral-400">Included classes</p>
          <ul className="space-y-0.5 text-xs text-neutral-300">
            {INCLUDED_CLASSES.map((item) => (
              <li key={item}>+ {item}</li>
            ))}
          </ul>
        </div>
        <div>
          <p className="mb-1 text-xs font-medium text-neutral-400">Excluded classes</p>
          <ul className="space-y-0.5 text-xs text-neutral-500">
            {EXCLUDED_CLASSES.map((item) => (
              <li key={item}>− {item}</li>
            ))}
          </ul>
        </div>
      </div>

      <div className="mb-3 grid gap-3 sm:grid-cols-2">
        <label className="text-xs text-neutral-500">
          Severity floor
          <select
            value={value.severityFloor}
            disabled={disabled}
            onChange={(e) =>
              patch({ severityFloor: e.target.value as QuickSeverityFloor })
            }
            className="mt-1 w-full rounded border border-neutral-700 bg-neutral-950 px-3 py-2 text-sm text-white"
          >
            {SEVERITY_FLOORS.map((floor) => (
              <option key={floor} value={floor}>
                {floor}
              </option>
            ))}
          </select>
        </label>
        <label className="text-xs text-neutral-500">
          Auth context (secret-store ref)
          <input
            type="text"
            value={value.authenticatedContextId}
            disabled={disabled}
            onChange={(e) => patch({ authenticatedContextId: e.target.value })}
            placeholder="optional UUID — never a password"
            autoComplete="off"
            className="mt-1 w-full rounded border border-neutral-700 bg-neutral-950 px-3 py-2 font-mono text-xs text-white"
          />
        </label>
      </div>

      <div className="mb-3 flex flex-wrap gap-4 text-sm text-neutral-300">
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={value.enableOast}
            disabled={disabled}
            onChange={(e) => patch({ enableOast: e.target.checked })}
          />
          OAST callbacks
        </label>
        <label className="flex items-center gap-2">
          <input
            type="checkbox"
            checked={value.enableAi}
            disabled={disabled}
            onChange={(e) => patch({ enableAi: e.target.checked })}
          />
          Local AI assist
        </label>
        {allowCloudAi && (
          <label className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={value.cloudLlmAllowed}
              disabled={disabled}
              onChange={(e) => patch({ cloudLlmAllowed: e.target.checked })}
            />
            Cloud AI
          </label>
        )}
      </div>

      <div
        className="rounded border border-amber-900/50 bg-amber-950/20 px-3 py-2 text-xs text-amber-200"
        data-testid="quick-budget-warning"
      >
        Hard wall-clock deadline. Skipped classes are not proven safe. Max{" "}
        {selected.max_targets} targets / {selected.max_urls_per_host} URLs per host
        at crawl depth {selected.crawl_depth}.
        {overTargetCap && (
          <span className="mt-1 block text-amber-300">
            Target count ({targetCount}) exceeds this profile cap.
          </span>
        )}
      </div>
      {catalogError && (
        <p className="mt-2 text-xs text-neutral-500">{catalogError}</p>
      )}
    </section>
  );
}
