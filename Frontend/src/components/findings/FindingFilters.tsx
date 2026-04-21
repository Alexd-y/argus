"use client";

/**
 * ARG-044 — Finding list filter bar (severity + KEV + SSVC outcome).
 *
 * Designed as a *controlled* component: the parent owns the filter
 * state. We expose a simple `FindingFilters` value object plus a
 * single `onChange` callback so the bar plays nice with React Server
 * Components / `useSearchParams` integrations.
 *
 * The SSVC outcome filter is the new ARG-044 addition; it lets
 * operators narrow the report view to exactly the four CISA SSVC v2.1
 * decisions (or any combination thereof).
 */

import * as React from "react";

import { SSVC_DECISIONS, SsvcDecision } from "./SsvcBadge";

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export const FINDING_SEVERITIES: ReadonlyArray<FindingSeverity> = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;

export interface FindingFiltersValue {
  /** Selected severities; empty set means "no filter — show all". */
  readonly severities: ReadonlySet<FindingSeverity>;
  /** Selected SSVC outcomes; empty set means "no filter — show all". */
  readonly ssvcOutcomes: ReadonlySet<SsvcDecision>;
  /** Show only KEV-listed (CISA Known Exploited Vulnerabilities) entries. */
  readonly kevOnly: boolean;
  /** Free-text search applied to title / description / cwe by the parent. */
  readonly query: string;
}

export const EMPTY_FINDING_FILTERS: FindingFiltersValue = {
  severities: new Set<FindingSeverity>(),
  ssvcOutcomes: new Set<SsvcDecision>(),
  kevOnly: false,
  query: "",
};

export interface FindingFiltersProps {
  readonly value: FindingFiltersValue;
  readonly onChange: (next: FindingFiltersValue) => void;
  readonly className?: string;
}

function toggle<T>(set: ReadonlySet<T>, key: T): Set<T> {
  const next = new Set<T>(set);
  if (next.has(key)) {
    next.delete(key);
  } else {
    next.add(key);
  }
  return next;
}

const SEV_PRESENTATION: Readonly<
  Record<FindingSeverity, { readonly label: string; readonly chip: string }>
> = {
  critical: { label: "Critical", chip: "bg-red-600 text-white border-red-400" },
  high: { label: "High", chip: "bg-orange-600 text-white border-orange-400" },
  medium: { label: "Medium", chip: "bg-amber-500 text-neutral-900 border-amber-300" },
  low: { label: "Low", chip: "bg-emerald-600 text-white border-emerald-400" },
  info: { label: "Info", chip: "bg-sky-700 text-white border-sky-400" },
};

const SSVC_PRESENTATION: Readonly<Record<SsvcDecision, { readonly chip: string }>> = {
  Act: { chip: "bg-red-600 text-white border-red-400" },
  Attend: { chip: "bg-orange-600 text-white border-orange-400" },
  "Track*": { chip: "bg-blue-700 text-white border-blue-500" },
  Track: { chip: "bg-slate-600 text-slate-100 border-slate-400" },
};

export function FindingFilters(props: FindingFiltersProps): React.ReactElement {
  const { value, onChange, className } = props;

  const handleSeverity = React.useCallback(
    (sev: FindingSeverity) => {
      onChange({ ...value, severities: toggle(value.severities, sev) });
    },
    [value, onChange],
  );

  const handleSsvc = React.useCallback(
    (decision: SsvcDecision) => {
      onChange({ ...value, ssvcOutcomes: toggle(value.ssvcOutcomes, decision) });
    },
    [value, onChange],
  );

  const handleKev = React.useCallback(
    (next: boolean) => {
      onChange({ ...value, kevOnly: next });
    },
    [value, onChange],
  );

  const handleQuery = React.useCallback(
    (next: string) => {
      onChange({ ...value, query: next });
    },
    [value, onChange],
  );

  const handleReset = React.useCallback(() => {
    onChange({ ...EMPTY_FINDING_FILTERS });
  }, [onChange]);

  return (
    <div
      data-testid="finding-filters"
      className={[
        "flex flex-col gap-3 rounded border border-neutral-800 bg-neutral-900 p-3 text-xs",
        className ?? "",
      ]
        .filter(Boolean)
        .join(" ")}
      role="region"
      aria-label="Finding filters"
    >
      <div className="flex flex-wrap items-center gap-2">
        <label className="text-neutral-400 uppercase tracking-wider">Search</label>
        <input
          aria-label="Search findings"
          type="text"
          value={value.query}
          onChange={(event) => handleQuery(event.target.value)}
          placeholder="title / description / CWE"
          className="grow rounded border border-neutral-700 bg-neutral-950 px-2 py-1 text-neutral-100 focus:border-purple-500 focus:outline-none"
        />
        <button
          type="button"
          onClick={handleReset}
          className="rounded border border-neutral-700 px-2 py-1 text-neutral-300 hover:border-neutral-500 hover:text-white"
          data-testid="finding-filters-reset"
        >
          Reset
        </button>
      </div>

      <fieldset className="flex flex-wrap items-center gap-2">
        <legend className="mr-1 text-neutral-400 uppercase tracking-wider">Severity</legend>
        {FINDING_SEVERITIES.map((sev) => {
          const isOn = value.severities.has(sev);
          const cfg = SEV_PRESENTATION[sev];
          return (
            <button
              key={sev}
              type="button"
              data-testid={`severity-${sev}`}
              data-active={isOn}
              aria-pressed={isOn}
              onClick={() => handleSeverity(sev)}
              className={[
                "rounded border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                isOn ? cfg.chip : "bg-neutral-800 text-neutral-400 border-neutral-700",
              ].join(" ")}
            >
              {cfg.label}
            </button>
          );
        })}
      </fieldset>

      <fieldset className="flex flex-wrap items-center gap-2">
        <legend className="mr-1 text-neutral-400 uppercase tracking-wider">
          SSVC outcome
        </legend>
        {SSVC_DECISIONS.map((decision) => {
          const isOn = value.ssvcOutcomes.has(decision);
          const cfg = SSVC_PRESENTATION[decision];
          return (
            <button
              key={decision}
              type="button"
              data-testid={`ssvc-${decision}`}
              data-active={isOn}
              aria-pressed={isOn}
              onClick={() => handleSsvc(decision)}
              className={[
                "rounded border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider",
                isOn ? cfg.chip : "bg-neutral-800 text-neutral-400 border-neutral-700",
              ].join(" ")}
            >
              {decision}
            </button>
          );
        })}
      </fieldset>

      <div className="flex items-center gap-2">
        <label className="flex items-center gap-2 text-neutral-300">
          <input
            type="checkbox"
            data-testid="finding-filters-kev-only"
            checked={value.kevOnly}
            onChange={(event) => handleKev(event.target.checked)}
            className="h-3 w-3 accent-red-500"
          />
          KEV-listed only
        </label>
      </div>
    </div>
  );
}

/**
 * Pure helper: apply a {@link FindingFiltersValue} to a list of finding
 * records. Records are expected to expose ``severity``,
 * ``ssvc_decision``, ``kev_listed`` and any of ``title`` / ``description`` /
 * ``cwe`` for the search query.
 */
export function applyFindingFilters<
  TFinding extends {
    readonly severity?: string | null;
    readonly ssvc_decision?: string | null;
    readonly kev_listed?: boolean | null;
    readonly title?: string | null;
    readonly description?: string | null;
    readonly cwe?: string | null;
  },
>(records: ReadonlyArray<TFinding>, filters: FindingFiltersValue): TFinding[] {
  const query = filters.query.trim().toLowerCase();
  const sev = filters.severities;
  const out: TFinding[] = [];
  for (const r of records) {
    if (filters.kevOnly && !r.kev_listed) continue;
    if (sev.size > 0) {
      const sevKey = (r.severity ?? "").toLowerCase() as FindingSeverity;
      if (!sev.has(sevKey)) continue;
    }
    if (filters.ssvcOutcomes.size > 0) {
      const sd = r.ssvc_decision as SsvcDecision | undefined;
      if (!sd || !filters.ssvcOutcomes.has(sd)) continue;
    }
    if (query) {
      const haystack = [r.title, r.description, r.cwe]
        .filter((s): s is string => Boolean(s))
        .join(" ")
        .toLowerCase();
      if (!haystack.includes(query)) continue;
    }
    out.push(r);
  }
  return out;
}

export default FindingFilters;
