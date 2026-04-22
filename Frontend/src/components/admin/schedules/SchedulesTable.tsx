"use client";

/**
 * `SchedulesTable` — read-only-ish table of scan schedules with row-level
 * actions (T35, ARG-056).
 *
 * "Read-only-ish" because the `enabled` toggle fires `updateScheduleAction`
 * directly from the row — operators routinely flip schedules on/off
 * without entering the editor dialog. Other mutations (rename, cron edit,
 * delete, run-now) open dedicated modals via `onEdit` / `onDelete` /
 * `onRunNow` callbacks owned by the parent client.
 *
 * Empty / loading state:
 *   - When `schedules` is an empty array AND `isLoading` is false, render
 *     a friendly empty-state with a `role="status"` so AT users hear it.
 *   - When `isLoading` is true, render a skeleton row count placeholder.
 *
 * Tenant column visibility:
 *   The `tenant_id` column is hidden for `admin` role (their session is
 *   already scoped to one tenant). super-admin sees it as a truncated UUID
 *   (`shortUuid`) — full UUID never echoes to the DOM (PII safety).
 */

import { useMemo } from "react";

import {
  shortUuid,
  type Schedule,
} from "@/lib/adminSchedules";

export type SchedulesTableProps = {
  readonly schedules: ReadonlyArray<Schedule>;
  readonly isLoading: boolean;
  readonly showTenantColumn: boolean;
  readonly canMutate: boolean;
  readonly onEdit: (schedule: Schedule) => void;
  readonly onDelete: (schedule: Schedule) => void;
  readonly onRunNow: (schedule: Schedule) => void;
  readonly onToggleEnabled: (schedule: Schedule, next: boolean) => void;
  /** Test override — used by the action buttons' busy state. */
  readonly busyScheduleIds?: ReadonlyArray<string>;
};

function formatIso(iso: string | null): string {
  if (iso === null || iso === "") return "—";
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    const yyyy = d.getUTCFullYear();
    const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
    const dd = String(d.getUTCDate()).padStart(2, "0");
    const hh = String(d.getUTCHours()).padStart(2, "0");
    const mi = String(d.getUTCMinutes()).padStart(2, "0");
    return `${yyyy}-${mm}-${dd} ${hh}:${mi} UTC`;
  } catch {
    return iso;
  }
}

export function SchedulesTable({
  schedules,
  isLoading,
  showTenantColumn,
  canMutate,
  onEdit,
  onDelete,
  onRunNow,
  onToggleEnabled,
  busyScheduleIds = [],
}: SchedulesTableProps): React.ReactElement {
  const busySet = useMemo(() => new Set(busyScheduleIds), [busyScheduleIds]);

  if (!isLoading && schedules.length === 0) {
    return (
      <div
        role="status"
        className="rounded border border-dashed border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-8 text-center text-sm text-[var(--text-muted)]"
        data-testid="schedules-empty-state"
      >
        Расписаний пока нет. Нажмите «Создать расписание», чтобы добавить
        первое.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table
        className="w-full min-w-[720px] table-auto text-left text-xs text-[var(--text-primary)]"
        data-testid="schedules-table"
      >
        <thead className="bg-[var(--bg-secondary)] text-[11px] uppercase text-[var(--text-muted)]">
          <tr>
            <th scope="col" className="px-3 py-2">
              Имя
            </th>
            {showTenantColumn ? (
              <th scope="col" className="px-3 py-2">
                Tenant
              </th>
            ) : null}
            <th scope="col" className="px-3 py-2">
              Cron
            </th>
            <th scope="col" className="px-3 py-2">
              Target
            </th>
            <th scope="col" className="px-3 py-2">
              Режим
            </th>
            <th scope="col" className="px-3 py-2">
              Включено
            </th>
            <th scope="col" className="px-3 py-2">
              Следующий запуск (UTC)
            </th>
            <th scope="col" className="px-3 py-2">
              Последний запуск (UTC)
            </th>
            <th scope="col" className="px-3 py-2 text-right">
              Действия
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--border)]">
          {isLoading && schedules.length === 0
            ? Array.from({ length: 3 }).map((_, idx) => (
                <tr key={`skeleton-${idx}`} data-testid="schedules-row-skeleton">
                  <td
                    colSpan={showTenantColumn ? 9 : 8}
                    className="px-3 py-2 text-[var(--text-muted)]"
                  >
                    Загрузка…
                  </td>
                </tr>
              ))
            : schedules.map((s) => {
                const busy = busySet.has(s.id);
                return (
                  <tr
                    key={s.id}
                    data-testid={`schedule-row-${s.id}`}
                    className="hover:bg-[var(--bg-tertiary)]"
                  >
                    <td className="px-3 py-2 font-mono">{s.name}</td>
                    {showTenantColumn ? (
                      <td
                        className="px-3 py-2 font-mono text-[var(--text-secondary)]"
                        title={s.tenant_id}
                      >
                        {shortUuid(s.tenant_id)}
                      </td>
                    ) : null}
                    <td className="px-3 py-2 font-mono">{s.cron_expression}</td>
                    <td
                      className="max-w-xs truncate px-3 py-2 font-mono text-[var(--text-secondary)]"
                      title={s.target_url}
                    >
                      {s.target_url}
                    </td>
                    <td className="px-3 py-2">{s.scan_mode}</td>
                    <td className="px-3 py-2">
                      <label
                        className="inline-flex cursor-pointer items-center gap-2"
                        htmlFor={`schedule-enable-toggle-${s.id}`}
                      >
                        <input
                          id={`schedule-enable-toggle-${s.id}`}
                          type="checkbox"
                          checked={s.enabled}
                          onChange={(e) => onToggleEnabled(s, e.target.checked)}
                          disabled={!canMutate || busy}
                          className="h-4 w-4 rounded border border-[var(--border)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
                          data-testid={`schedule-enable-toggle-${s.id}`}
                          aria-label={
                            s.enabled
                              ? `Отключить расписание ${s.name}`
                              : `Включить расписание ${s.name}`
                          }
                        />
                        <span
                          className={`text-[11px] ${
                            s.enabled
                              ? "text-emerald-300"
                              : "text-[var(--text-muted)]"
                          }`}
                        >
                          {s.enabled ? "ON" : "OFF"}
                        </span>
                      </label>
                    </td>
                    <td className="px-3 py-2 font-mono text-[var(--text-secondary)]">
                      {formatIso(s.next_run_at)}
                    </td>
                    <td className="px-3 py-2 font-mono text-[var(--text-secondary)]">
                      {formatIso(s.last_run_at)}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <div className="inline-flex gap-1">
                        <button
                          type="button"
                          onClick={() => onEdit(s)}
                          disabled={!canMutate || busy}
                          className="rounded border border-[var(--border)] px-2 py-0.5 text-[11px] hover:bg-[var(--bg-tertiary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
                          data-testid={`schedule-edit-${s.id}`}
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          onClick={() => onRunNow(s)}
                          disabled={!canMutate || busy || !s.enabled}
                          title={
                            !s.enabled
                              ? "Расписание отключено"
                              : "Запустить вне очереди"
                          }
                          // keep: outline trigger uses lighter amber-500
                          // tones as a visual cue. The warning-action fill
                          // (`--warning-strong`) lives on the confirm CTA
                          // inside RunNowDialog — see design-tokens.md §3.5.
                          className="rounded border border-amber-500/60 px-2 py-0.5 text-[11px] text-amber-200 hover:bg-amber-500/10 focus-visible:ring-2 focus-visible:ring-amber-400 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
                          data-testid={`schedule-run-now-${s.id}`}
                        >
                          Run now
                        </button>
                        <button
                          type="button"
                          onClick={() => onDelete(s)}
                          disabled={!canMutate || busy}
                          className="rounded border border-red-500/60 px-2 py-0.5 text-[11px] text-red-200 hover:bg-red-500/10 focus-visible:ring-2 focus-visible:ring-red-400 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
                          data-testid={`schedule-delete-${s.id}`}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
        </tbody>
      </table>
    </div>
  );
}
