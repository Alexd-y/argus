"use client";

/**
 * `DlqTable` — read-only table of webhook DLQ entries with row-level
 * actions (T41, ARG-053). All mutations route through the dedicated
 * `ReplayDialog` / `AbandonDialog` modals owned by `WebhookDlqClient`.
 *
 * Empty / loading state:
 *   - When `entries` is an empty array AND `isLoading` is false, render
 *     a friendly empty-state with `data-testid="dlq-empty-state"`.
 *   - When `isLoading` is true, render skeleton placeholder rows.
 *
 * Tenant column visibility:
 *   The `tenant_id` column is hidden for `admin` (their session is
 *   already tenant-scoped). super-admin sees it as a truncated UUID
 *   (`shortUuid`) — full UUID never echoes to the DOM (PII safety).
 *
 * Hash safety:
 *   `target_url_hash` is a SHA-256 fingerprint — the raw URL is NEVER
 *   persisted (see `backend/src/db/models/WebhookDlqEntry`). We render
 *   the first 12 hex chars (`shortTargetHash`) with the full hash in
 *   `title` for hover-to-copy.
 */

import { useMemo } from "react";

import {
  WEBHOOK_DLQ_TRIAGE_STATUS_LABELS_RU,
  shortTargetHash,
  shortUuid,
  type WebhookDlqEntryItem,
  type WebhookDlqTriageStatus,
} from "@/lib/adminWebhookDlq";

const ID_PREVIEW_CHARS = 12;

export type DlqTableProps = {
  readonly entries: ReadonlyArray<WebhookDlqEntryItem>;
  readonly isLoading: boolean;
  readonly showTenantColumn: boolean;
  readonly canMutate: boolean;
  readonly busyEntryIds?: ReadonlyArray<string>;
  readonly onReplay: (entry: WebhookDlqEntryItem) => void;
  readonly onAbandon: (entry: WebhookDlqEntryItem) => void;
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

function shortEventId(value: string): string {
  if (value.length <= ID_PREVIEW_CHARS) return value;
  return `${value.slice(0, ID_PREVIEW_CHARS)}…`;
}

function statusBadgeClass(status: WebhookDlqTriageStatus): string {
  switch (status) {
    // keep: amber-500 chip for `pending` is triage-status categorisation
    // (paired with emerald `replayed` + zinc `abandoned`). It is a state
    // indicator, not a warning-action fill — `--warning-strong` applies
    // to confirm CTAs only (see design-tokens.md §3.5).
    case "pending":
      return "border border-amber-400/60 bg-amber-500/10 text-amber-100";
    case "replayed":
      return "border border-emerald-400/60 bg-emerald-500/10 text-emerald-100";
    case "abandoned":
      return "border border-zinc-400/60 bg-zinc-500/10 text-zinc-100";
  }
}

export function DlqTable({
  entries,
  isLoading,
  showTenantColumn,
  canMutate,
  busyEntryIds = [],
  onReplay,
  onAbandon,
}: DlqTableProps): React.ReactElement {
  const busySet = useMemo(() => new Set(busyEntryIds), [busyEntryIds]);

  if (!isLoading && entries.length === 0) {
    return (
      <div
        role="status"
        className="rounded border border-dashed border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-8 text-center text-sm text-[var(--text-muted)]"
        data-testid="dlq-empty-state"
      >
        Сообщений в DLQ нет — все webhook&rsquo;и доставлены.
      </div>
    );
  }

  const colCount = showTenantColumn ? 10 : 9;

  return (
    <div className="overflow-x-auto">
      <table
        className="w-full min-w-[960px] table-auto text-left text-xs text-[var(--text-primary)]"
        data-testid="dlq-table"
      >
        <thead className="bg-[var(--bg-secondary)] text-[11px] uppercase text-[var(--text-muted)]">
          <tr>
            <th scope="col" className="px-3 py-2">
              Создано (UTC)
            </th>
            {showTenantColumn ? (
              <th scope="col" className="px-3 py-2">
                Tenant
              </th>
            ) : null}
            <th scope="col" className="px-3 py-2">
              Adapter
            </th>
            <th scope="col" className="px-3 py-2">
              Event
            </th>
            <th scope="col" className="px-3 py-2">
              Target hash
            </th>
            <th scope="col" className="px-3 py-2 text-right">
              Попыток
            </th>
            <th scope="col" className="px-3 py-2">
              Последняя ошибка
            </th>
            <th scope="col" className="px-3 py-2">
              Статус
            </th>
            <th scope="col" className="px-3 py-2">
              Replayed / Abandoned (UTC)
            </th>
            <th scope="col" className="px-3 py-2 text-right">
              Действия
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-[var(--border)]">
          {isLoading && entries.length === 0
            ? Array.from({ length: 3 }).map((_, idx) => (
                <tr key={`dlq-skeleton-${idx}`} data-testid="dlq-row-skeleton">
                  <td
                    colSpan={colCount}
                    className="px-3 py-2 text-[var(--text-muted)]"
                  >
                    Загрузка…
                  </td>
                </tr>
              ))
            : entries.map((entry) => {
                const busy = busySet.has(entry.id);
                const terminal = entry.triage_status !== "pending";
                const replayDisabled = !canMutate || busy || terminal;
                const abandonDisabled = !canMutate || busy || terminal;
                const terminalAt =
                  entry.replayed_at ??
                  entry.abandoned_at ??
                  null;
                return (
                  <tr
                    key={entry.id}
                    data-testid={`dlq-row-${entry.id}`}
                    className="hover:bg-[var(--bg-tertiary)]"
                  >
                    <td
                      className="px-3 py-2 font-mono text-[var(--text-secondary)]"
                      title={entry.created_at}
                    >
                      {formatIso(entry.created_at)}
                    </td>
                    {showTenantColumn ? (
                      <td
                        className="px-3 py-2 font-mono text-[var(--text-secondary)]"
                        title={entry.tenant_id}
                      >
                        {shortUuid(entry.tenant_id)}
                      </td>
                    ) : null}
                    <td className="px-3 py-2">
                      <span className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-1.5 py-0.5 font-mono text-[11px] text-[var(--text-secondary)]">
                        {entry.adapter_name}
                      </span>
                      <div className="mt-1 text-[10px] text-[var(--text-muted)]">
                        {entry.event_type}
                      </div>
                    </td>
                    <td
                      className="max-w-[180px] truncate px-3 py-2 font-mono text-[var(--text-secondary)]"
                      title={entry.event_id}
                    >
                      {shortEventId(entry.event_id)}
                    </td>
                    <td
                      className="px-3 py-2 font-mono text-[var(--text-muted)]"
                      title={`${entry.target_url_hash} (первые 12 символов SHA-256; URL не сохраняется)`}
                    >
                      {shortTargetHash(entry.target_url_hash)}
                    </td>
                    <td className="px-3 py-2 text-right font-mono">
                      {entry.attempt_count}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className="rounded border border-red-500/60 bg-red-500/10 px-1.5 py-0.5 font-mono text-[11px] text-red-200"
                        title={
                          entry.last_status_code === null
                            ? entry.last_error_code
                            : `${entry.last_error_code} · HTTP ${entry.last_status_code}`
                        }
                      >
                        {entry.last_error_code}
                      </span>
                      {entry.last_status_code !== null ? (
                        <div className="mt-1 text-[10px] text-[var(--text-muted)]">
                          HTTP {entry.last_status_code}
                        </div>
                      ) : null}
                    </td>
                    <td className="px-3 py-2">
                      <span
                        className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] ${statusBadgeClass(
                          entry.triage_status,
                        )}`}
                        data-testid={`dlq-status-badge-${entry.id}`}
                      >
                        {WEBHOOK_DLQ_TRIAGE_STATUS_LABELS_RU[entry.triage_status]}
                      </span>
                    </td>
                    <td
                      className="px-3 py-2 font-mono text-[var(--text-secondary)]"
                      title={terminalAt ?? undefined}
                    >
                      {formatIso(terminalAt)}
                    </td>
                    <td className="px-3 py-2 text-right">
                      <div className="inline-flex gap-1">
                        <button
                          type="button"
                          onClick={() => onReplay(entry)}
                          disabled={replayDisabled}
                          aria-disabled={replayDisabled}
                          title={
                            terminal
                              ? "Запись уже в терминальном состоянии"
                              : !canMutate
                                ? "Только администратор может выполнять это действие"
                                : "Повторить отправку webhook"
                          }
                          aria-label={`Повторить отправку для записи ${entry.event_id}`}
                          className="rounded border border-emerald-500/60 px-2 py-0.5 text-[11px] text-emerald-200 hover:bg-emerald-500/10 focus-visible:ring-2 focus-visible:ring-emerald-400 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
                          data-testid={`dlq-replay-button-${entry.id}`}
                        >
                          Повторить
                        </button>
                        <button
                          type="button"
                          onClick={() => onAbandon(entry)}
                          disabled={abandonDisabled}
                          aria-disabled={abandonDisabled}
                          title={
                            terminal
                              ? "Запись уже в терминальном состоянии"
                              : !canMutate
                                ? "Только администратор может выполнять это действие"
                                : "Отметить как abandoned"
                          }
                          aria-label={`Отметить как abandoned запись ${entry.event_id}`}
                          className="rounded border border-zinc-400/60 px-2 py-0.5 text-[11px] text-zinc-200 hover:bg-zinc-500/10 focus-visible:ring-2 focus-visible:ring-zinc-300 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
                          data-testid={`dlq-abandon-button-${entry.id}`}
                        >
                          Abandon
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
