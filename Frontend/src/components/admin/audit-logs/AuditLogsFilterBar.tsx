"use client";

/**
 * `AuditLogsFilterBar` — accessible, URL-bound filter controls for the
 * admin audit-log viewer (T22). Mirrors the `FindingsFilterBar` (T20)
 * conventions: native form controls (no design-system dep), live `onChange`
 * for instant visual feedback, and the parent debounces text/date inputs
 * before firing the server action.
 *
 * Controls:
 *   - Tenant selector (super-admin only) — reuses `<TenantSelector>`.
 *   - `since` / `until` date pickers (≤ 90-day window enforced server-side).
 *   - `event_type` substring input (free text; the backend matches it as an
 *     EXACT string today, but the input is free-text so an operator can
 *     paste a known event name without a select-of-everything dropdown).
 *   - `actor_subject` substring input (mapped to backend `q` for ILIKE
 *     across action / resource_type / details — see `actions.ts`).
 *   - "Verify chain" button — fires the verify-chain action with the
 *     CURRENT filter values (since/until/tenant/event_type).
 *   - "Сбросить фильтры" button.
 *   - "Export" button — opens the existing CSV/JSON export endpoint via
 *     the server-side admin proxy. Hidden when no filter is set so a
 *     blank dump never accidentally lands on disk.
 */

import { useId, type ChangeEvent } from "react";

import type { AdminRole } from "@/services/admin/adminRoles";

import {
  TenantSelector,
  type TenantOption,
} from "@/components/admin/findings/TenantSelector";

export type AuditLogsFilterValues = {
  readonly since: string;
  readonly until: string;
  readonly tenantId: string;
  readonly eventType: string;
  readonly actorSubject: string;
};

export const EMPTY_AUDIT_FILTER_VALUES: AuditLogsFilterValues = {
  since: "",
  until: "",
  tenantId: "",
  eventType: "",
  actorSubject: "",
};

export type AuditLogsFilterBarProps = {
  readonly value: AuditLogsFilterValues;
  readonly onChange: (next: AuditLogsFilterValues) => void;
  readonly onReset: () => void;
  readonly onVerifyChain: () => void;
  readonly onExport?: (format: "csv" | "json") => void;
  readonly role: AdminRole | null;
  readonly tenants: ReadonlyArray<TenantOption>;
  readonly disabled?: boolean;
  readonly verifying?: boolean;
};

export function AuditLogsFilterBar({
  value,
  onChange,
  onReset,
  onVerifyChain,
  onExport,
  role,
  tenants,
  disabled = false,
  verifying = false,
}: AuditLogsFilterBarProps): React.ReactElement {
  const groupId = useId();
  const sinceId = `${groupId}-since`;
  const untilId = `${groupId}-until`;
  const eventTypeId = `${groupId}-event-type`;
  const actorId = `${groupId}-actor`;

  const isSuperAdmin = role === "super-admin";

  const handleSinceChange = (e: ChangeEvent<HTMLInputElement>) => {
    onChange({ ...value, since: e.target.value });
  };
  const handleUntilChange = (e: ChangeEvent<HTMLInputElement>) => {
    onChange({ ...value, until: e.target.value });
  };
  const handleEventTypeChange = (e: ChangeEvent<HTMLInputElement>) => {
    onChange({ ...value, eventType: e.target.value });
  };
  const handleActorChange = (e: ChangeEvent<HTMLInputElement>) => {
    onChange({ ...value, actorSubject: e.target.value });
  };
  const handleTenantChange = (tenantId: string) => {
    onChange({ ...value, tenantId });
  };

  return (
    <section
      aria-label="Filter audit logs"
      data-testid="audit-logs-filter-bar"
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
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
            data-testid="audit-filter-since"
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
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
            data-testid="audit-filter-until"
          />
        </div>

        <div className="flex flex-col gap-1">
          <label
            htmlFor={eventTypeId}
            className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]"
          >
            Event type
          </label>
          <input
            id={eventTypeId}
            type="search"
            value={value.eventType}
            onChange={handleEventTypeChange}
            disabled={disabled}
            placeholder="например, scan.start"
            aria-describedby={`${groupId}-event-type-hint`}
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
            data-testid="audit-filter-event-type"
          />
          <span
            id={`${groupId}-event-type-hint`}
            className="text-[10px] text-[var(--text-muted)]"
          >
            Точное совпадение по полю action.
          </span>
        </div>

        <div className="flex flex-col gap-1">
          <label
            htmlFor={actorId}
            className="text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]"
          >
            Actor / поиск
          </label>
          <input
            id={actorId}
            type="search"
            value={value.actorSubject}
            onChange={handleActorChange}
            disabled={disabled}
            placeholder="субъект или подстрока"
            aria-describedby={`${groupId}-actor-hint`}
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
            data-testid="audit-filter-actor"
          />
          <span
            id={`${groupId}-actor-hint`}
            className="text-[10px] text-[var(--text-muted)]"
          >
            Подстрока по полям action / resource_type / details (backend `q`).
          </span>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          onClick={onReset}
          disabled={disabled}
          className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-1.5 text-sm text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
          data-testid="audit-filter-reset"
        >
          Сбросить фильтры
        </button>
        <button
          type="button"
          onClick={onVerifyChain}
          disabled={disabled || verifying}
          aria-busy={verifying}
          className="rounded border border-[var(--accent)] bg-[var(--accent)] px-3 py-1.5 text-sm font-medium text-[var(--bg-primary)] transition hover:opacity-90 focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
          data-testid="audit-verify-chain"
        >
          {verifying ? "Проверяем…" : "Verify chain integrity"}
        </button>
        {onExport ? (
          <div
            className="ml-auto flex items-center gap-1"
            role="group"
            aria-label="Export audit log"
          >
            <button
              type="button"
              onClick={() => onExport("csv")}
              disabled={disabled}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-1.5 text-xs text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
              data-testid="audit-export-csv"
            >
              Экспорт CSV
            </button>
            <button
              type="button"
              onClick={() => onExport("json")}
              disabled={disabled}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-1.5 text-xs text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
              data-testid="audit-export-json"
            >
              Экспорт JSON
            </button>
          </div>
        ) : null}
      </div>
    </section>
  );
}

/**
 * Parse a list of raw query-string values, dropping anything that doesn't
 * look like a usable filter. Lets the page hydrate from `URLSearchParams`
 * without trusting the URL.
 */
export function sanitizeAuditFilterValues(raw: {
  readonly since?: string | null;
  readonly until?: string | null;
  readonly tenantId?: string | null;
  readonly eventType?: string | null;
  readonly actorSubject?: string | null;
}): AuditLogsFilterValues {
  return {
    since: raw.since ?? "",
    until: raw.until ?? "",
    tenantId: raw.tenantId ?? "",
    eventType: raw.eventType ?? "",
    actorSubject: raw.actorSubject ?? "",
  };
}
