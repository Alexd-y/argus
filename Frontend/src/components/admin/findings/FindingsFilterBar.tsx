"use client";

/**
 * `FindingsFilterBar` — accessible, URL-bound filter controls for the global
 * cross-tenant findings triage page (T20).
 *
 * Why native form controls instead of shadcn/ui:
 *   The repo ships no design-system deps (see `ExportFormatToggle.tsx`); using
 *   native `<input>` / `<select>` keeps the bundle slim and gives screen
 *   readers, keyboard users and high-contrast modes the right semantics for
 *   free.
 *
 * Status filter (S1-2):
 *   The backend currently exposes `false_positive: bool|undefined`, not the
 *   full multi-select status taxonomy. The bar therefore renders a single
 *   tri-state segmented control ("Все" / "Открытые" / "False positive")
 *   that maps straight to the backend's wire param. The unsupported
 *   `fixed`, `wontfix`, `risk_accepted`, `under_investigation` chips were
 *   removed — silently no-op'd UI was the original review failure
 *   (ISS-T20-005 tracks restoring them when the triage workflow lands).
 *
 * Target field (S1-1):
 *   Free-text search maps to backend `q` (title/url/host substring), not the
 *   nominal `target` column — the placeholder reflects this so operators
 *   know they can search for either.
 *
 * Debouncing (S1-4):
 *   The bar emits `onChange` immediately on every keystroke for instant
 *   visual feedback; the parent (`AdminFindingsClient`) debounces the
 *   text/date subset before passing it to React Query so we don't fire a
 *   server action per character.
 *
 * KEV / SSVC chips:
 *   The backend currently returns `kev_listed: null` and `ssvc_action: null`
 *   for every row (Phase-1 state — no intel-table JOIN yet). When the parent
 *   reports `kevAvailable === false` / `ssvcAvailable === false` the chips
 *   render as disabled with a clearly labelled "Reserved — Phase 2" tooltip
 *   so operators don't think they're broken.
 */

import { useId, type ChangeEvent } from "react";

import {
  FINDING_SEVERITIES,
  SSVC_ACTIONS,
  isFindingSeverity,
  isFindingStatusMode,
  isSsvcAction,
  type FindingSeverity,
  type FindingStatusMode,
  type SsvcAction,
} from "@/lib/adminFindings";
import type { AdminRole } from "@/services/admin/adminRoles";

import { TenantSelector, type TenantOption } from "./TenantSelector";

const SEVERITY_LABEL: Readonly<Record<FindingSeverity, string>> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const STATUS_MODE_LABEL: Readonly<Record<FindingStatusMode, string>> = {
  all: "Все",
  open: "Открытые",
  false_positive: "False positive",
};

const STATUS_MODE_HINT: Readonly<Record<FindingStatusMode, string>> = {
  all: "Показать findings обоих видов",
  open: "Скрыть findings, помеченные как false positive",
  false_positive: "Только findings, помеченные как false positive",
};

const STATUS_MODE_VALUES: ReadonlyArray<FindingStatusMode> = [
  "all",
  "open",
  "false_positive",
];

const SSVC_LABEL: Readonly<Record<SsvcAction, string>> = {
  act: "Act",
  attend: "Attend",
  "track-star": "Track*",
  track: "Track",
};

export type FindingsFilterValues = {
  readonly severity: ReadonlyArray<FindingSeverity>;
  readonly statusMode: FindingStatusMode;
  readonly target: string;
  readonly since: string;
  readonly until: string;
  readonly tenantId: string;
  readonly kevListed: boolean | null;
  readonly ssvcAction: SsvcAction | null;
};

export const EMPTY_FILTER_VALUES: FindingsFilterValues = {
  severity: [],
  statusMode: "all",
  target: "",
  since: "",
  until: "",
  tenantId: "",
  kevListed: null,
  ssvcAction: null,
};

export type FindingsFilterBarProps = {
  readonly value: FindingsFilterValues;
  readonly onChange: (next: FindingsFilterValues) => void;
  readonly onReset: () => void;
  readonly role: AdminRole | null;
  readonly tenants: ReadonlyArray<TenantOption>;
  /** When false, KEV chip is gated as "Reserved — Phase 2". */
  readonly kevAvailable: boolean;
  /** When false, SSVC select is gated as "Reserved — Phase 2". */
  readonly ssvcAvailable: boolean;
  readonly disabled?: boolean;
  readonly slotEnd?: React.ReactNode;
};

function toggleArrayValue<T extends string>(
  arr: ReadonlyArray<T>,
  value: T,
): T[] {
  return arr.includes(value) ? arr.filter((v) => v !== value) : [...arr, value];
}

export function FindingsFilterBar({
  value,
  onChange,
  onReset,
  role,
  tenants,
  kevAvailable,
  ssvcAvailable,
  disabled = false,
  slotEnd,
}: FindingsFilterBarProps): React.ReactElement {
  const groupId = useId();
  const targetId = `${groupId}-target`;
  const sinceId = `${groupId}-since`;
  const untilId = `${groupId}-until`;
  const ssvcId = `${groupId}-ssvc`;

  const isSuperAdmin = role === "super-admin";

  const handleSeverityToggle = (sev: FindingSeverity) => {
    onChange({
      ...value,
      severity: toggleArrayValue<FindingSeverity>(value.severity, sev),
    });
  };

  const handleStatusModeChange = (next: FindingStatusMode) => {
    onChange({ ...value, statusMode: next });
  };

  const handleTargetChange = (e: ChangeEvent<HTMLInputElement>) => {
    onChange({ ...value, target: e.target.value });
  };

  const handleSinceChange = (e: ChangeEvent<HTMLInputElement>) => {
    onChange({ ...value, since: e.target.value });
  };

  const handleUntilChange = (e: ChangeEvent<HTMLInputElement>) => {
    onChange({ ...value, until: e.target.value });
  };

  const handleKevToggle = (e: ChangeEvent<HTMLInputElement>) => {
    onChange({ ...value, kevListed: e.target.checked ? true : null });
  };

  const handleSsvcChange = (e: ChangeEvent<HTMLSelectElement>) => {
    const v = e.target.value;
    onChange({ ...value, ssvcAction: isSsvcAction(v) ? v : null });
  };

  const handleTenantChange = (tenantId: string) => {
    onChange({ ...value, tenantId });
  };

  return (
    <section
      aria-label="Filter findings"
      data-testid="findings-filter-bar"
      className="flex flex-col gap-3 rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-3 text-sm"
    >
      <div className="flex flex-wrap items-end gap-3">
        {isSuperAdmin ? (
          <TenantSelector
            value={value.tenantId}
            tenants={tenants}
            onChange={handleTenantChange}
            disabled={disabled}
          />
        ) : null}

        <div className="flex flex-col gap-1">
          <span
            id={`${groupId}-severity-label`}
            className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]"
          >
            Severity
          </span>
          <div
            role="group"
            aria-labelledby={`${groupId}-severity-label`}
            className="flex flex-wrap gap-1"
          >
            {FINDING_SEVERITIES.map((sev) => {
              const checked = value.severity.includes(sev);
              return (
                <label
                  key={sev}
                  className={`inline-flex cursor-pointer items-center gap-1 rounded border px-2 py-1 text-xs transition focus-within:ring-2 focus-within:ring-[var(--accent)] ${
                    checked
                      ? "border-[var(--accent)] bg-[var(--accent)] text-[var(--bg-primary)]"
                      : "border-[var(--border)] bg-[var(--bg-primary)] text-[var(--text-secondary)] hover:border-[var(--accent)]"
                  }`}
                >
                  <input
                    type="checkbox"
                    className="sr-only"
                    checked={checked}
                    aria-checked={checked}
                    disabled={disabled}
                    onChange={() => handleSeverityToggle(sev)}
                    data-testid={`filter-severity-${sev}`}
                  />
                  <span aria-hidden>•</span>
                  <span>{SEVERITY_LABEL[sev]}</span>
                </label>
              );
            })}
          </div>
        </div>

        <div className="flex flex-col gap-1">
          <span
            id={`${groupId}-status-label`}
            className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]"
          >
            Status
          </span>
          <div
            role="radiogroup"
            aria-labelledby={`${groupId}-status-label`}
            className="inline-flex overflow-hidden rounded border border-[var(--border)]"
          >
            {STATUS_MODE_VALUES.map((mode) => {
              const checked = value.statusMode === mode;
              return (
                <label
                  key={mode}
                  className={`inline-flex cursor-pointer items-center gap-1 border-l border-[var(--border)] px-2 py-1 text-xs transition first:border-l-0 focus-within:ring-2 focus-within:ring-[var(--accent)] ${
                    checked
                      ? "bg-[var(--accent)] text-[var(--bg-primary)]"
                      : "bg-[var(--bg-primary)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
                  }`}
                  title={STATUS_MODE_HINT[mode]}
                >
                  <input
                    type="radio"
                    name={`${groupId}-status`}
                    value={mode}
                    className="sr-only"
                    checked={checked}
                    aria-checked={checked}
                    disabled={disabled}
                    onChange={() => handleStatusModeChange(mode)}
                    data-testid={`filter-status-${mode}`}
                  />
                  <span>{STATUS_MODE_LABEL[mode]}</span>
                </label>
              );
            })}
          </div>
        </div>
      </div>

      <div className="flex flex-wrap items-end gap-3">
        <div className="flex flex-col gap-1">
          <label
            htmlFor={targetId}
            className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]"
          >
            Target / поиск
          </label>
          <input
            id={targetId}
            type="search"
            value={value.target}
            onChange={handleTargetChange}
            disabled={disabled}
            placeholder="Поиск по title, host или URL"
            aria-describedby={`${groupId}-target-hint`}
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
            data-testid="filter-target"
          />
          <span
            id={`${groupId}-target-hint`}
            className="text-[10px] text-[var(--text-muted)]"
          >
            Substring-поиск по полям заголовка и адреса (backend `q`).
          </span>
        </div>
        <div className="flex flex-col gap-1">
          <label
            htmlFor={sinceId}
            className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]"
          >
            Since
          </label>
          <input
            id={sinceId}
            type="date"
            value={value.since}
            onChange={handleSinceChange}
            disabled={disabled}
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
            data-testid="filter-since"
          />
        </div>
        <div className="flex flex-col gap-1">
          <label
            htmlFor={untilId}
            className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]"
          >
            Until
          </label>
          <input
            id={untilId}
            type="date"
            value={value.until}
            onChange={handleUntilChange}
            disabled={disabled}
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
            data-testid="filter-until"
          />
        </div>

        <div className="flex flex-col gap-1">
          <span className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
            KEV
          </span>
          <label
            className={`inline-flex items-center gap-2 rounded border px-2 py-1.5 text-xs ${
              kevAvailable
                ? "border-[var(--border)] bg-[var(--bg-primary)] text-[var(--text-primary)]"
                : "cursor-not-allowed border-dashed border-[var(--border)] bg-[var(--bg-tertiary)] text-[var(--text-muted)]"
            }`}
            title={
              kevAvailable
                ? "Только findings из CISA KEV"
                : "Reserved — Phase 2 (intel JOIN не активен)"
            }
            data-testid="filter-kev"
          >
            <input
              type="checkbox"
              checked={value.kevListed === true}
              aria-checked={value.kevListed === true}
              aria-disabled={!kevAvailable}
              disabled={disabled || !kevAvailable}
              onChange={handleKevToggle}
              data-testid="filter-kev-input"
              className="h-3.5 w-3.5 accent-[var(--accent)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
            />
            <span aria-hidden>{kevAvailable ? "Только KEV" : "Reserved — Phase 2"}</span>
            {!kevAvailable ? <span className="sr-only">Reserved — Phase 2</span> : null}
          </label>
        </div>

        <div className="flex flex-col gap-1">
          <label
            htmlFor={ssvcId}
            className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]"
          >
            SSVC
          </label>
          <select
            id={ssvcId}
            value={value.ssvcAction ?? ""}
            onChange={handleSsvcChange}
            disabled={disabled || !ssvcAvailable}
            aria-disabled={!ssvcAvailable}
            title={ssvcAvailable ? undefined : "Reserved — Phase 2 (intel JOIN не активен)"}
            className={`rounded border px-2 py-1.5 text-sm ${
              ssvcAvailable
                ? "border-[var(--border)] bg-[var(--bg-primary)] text-[var(--text-primary)]"
                : "cursor-not-allowed border-dashed border-[var(--border)] bg-[var(--bg-tertiary)] text-[var(--text-muted)]"
            }`}
            data-testid="filter-ssvc"
          >
            <option value="">{ssvcAvailable ? "Любой" : "Reserved — Phase 2"}</option>
            {SSVC_ACTIONS.map((s) => (
              <option key={s} value={s}>
                {SSVC_LABEL[s]}
              </option>
            ))}
          </select>
        </div>

        <button
          type="button"
          onClick={onReset}
          disabled={disabled}
          className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-1.5 text-sm text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
          data-testid="filter-reset"
        >
          Сбросить фильтры
        </button>
        <div className="ml-auto flex items-center gap-2">{slotEnd}</div>
      </div>
    </section>
  );
}

/**
 * Parse a list of raw query-string values, dropping anything outside the
 * closed taxonomy. Lets the page hydrate from `URLSearchParams` without
 * trusting the URL.
 */
export function sanitizeFilterValues(raw: {
  readonly severity?: ReadonlyArray<string>;
  readonly statusMode?: string | null;
  readonly target?: string;
  readonly since?: string;
  readonly until?: string;
  readonly tenantId?: string;
  readonly kevListed?: string | null;
  readonly ssvcAction?: string | null;
}): FindingsFilterValues {
  const severity = (raw.severity ?? []).filter(isFindingSeverity);
  const statusMode = isFindingStatusMode(raw.statusMode) ? raw.statusMode : "all";
  const ssvcAction =
    raw.ssvcAction && isSsvcAction(raw.ssvcAction) ? raw.ssvcAction : null;
  let kevListed: boolean | null = null;
  if (raw.kevListed === "true") kevListed = true;
  else if (raw.kevListed === "false") kevListed = false;
  return {
    severity,
    statusMode,
    target: raw.target ?? "",
    since: raw.since ?? "",
    until: raw.until ?? "",
    tenantId: raw.tenantId ?? "",
    kevListed,
    ssvcAction,
  };
}
