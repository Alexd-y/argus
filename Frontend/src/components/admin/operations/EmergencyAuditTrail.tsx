"use client";

/**
 * `EmergencyAuditTrail` — read-only audit log for emergency events
 * (T30, ARG-053).
 *
 * Surface:
 *   ┌── Header: "Audit trail" + "Last refreshed at HH:MM:SS" + [Обновить] ──┐
 *   │ ts        | event_type (badge) | operator_hash | tenant_hash | reason │
 *   │ ...                                                                    │
 *   │ click on row OR [details] → expand JSON details inline                 │
 *   └────────────────────────────────────────────────────────────────────────┘
 *
 * PII safety (per task constraint):
 *   The backend already hashes `operator_subject` and `tenant_id` (T31).
 *   The UI MUST display them as-is — no reverse-lookup, no
 *   "humanisation". Reason is rendered verbatim but truncated to 80
 *   chars in the table; the full body is shown only inside the
 *   expanded JSON pane so a wide reason cannot push the table off-screen.
 *
 * Mount + polling:
 *   A `useEffect` triggers an immediate `refetch()` on mount so a parent
 *   that remounts us via `key={...}` (e.g. `GlobalKillSwitchClient`
 *   bumping `auditNonce` after STOP/RESUME, T30 ARG-053 acceptance
 *   criterion (e)) sees the freshly created row WITHOUT waiting for the
 *   first 30 s poll tick. Steady-state refresh is `setInterval(pollMs)`
 *   (default 30 s); cleanup on unmount. `reqIdRef` ensures the on-mount
 *   fetch and a concurrent poll tick cannot stale-overwrite each other.
 *
 * A11y:
 *   - Empty state has `role="status"` (informational, not an error).
 *   - The expand button uses `aria-expanded` + `aria-controls`.
 *   - Time/relative strings are passed via `<time dateTime>` so AT users
 *     hear an ISO instant rather than the localised string.
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import type { listEmergencyAuditTrailAction } from "@/app/admin/operations/actions";
import {
  throttleActionErrorMessage,
  type EmergencyAuditEventType,
  type EmergencyAuditItem,
  type EmergencyAuditListResponse,
} from "@/lib/adminOperations";

const DEFAULT_POLL_MS = 30_000;
const REASON_TRUNCATE_AT = 80;

const EVENT_BADGE_LABEL: Readonly<Record<EmergencyAuditEventType, string>> = {
  "emergency.stop_all": "STOP ALL",
  "emergency.resume_all": "RESUME ALL",
  "emergency.throttle": "THROTTLE",
};

const EVENT_BADGE_CLASS: Readonly<Record<EmergencyAuditEventType, string>> = {
  "emergency.stop_all":
    "border-red-500/60 bg-red-500/10 text-red-200",
  "emergency.resume_all":
    "border-emerald-500/60 bg-emerald-500/10 text-emerald-200",
  // keep: amber-500 chip for `emergency.throttle` is event categorisation
  // (paired with red for stop_all + emerald for resume_all). It is a
  // status-coding cue, not a warning-action fill — `--warning-strong`
  // applies to confirm CTAs only (see design-tokens.md §3.5).
  "emergency.throttle":
    "border-amber-500/60 bg-amber-500/10 text-amber-200",
};

export type EmergencyAuditTrailProps = {
  readonly initial: EmergencyAuditListResponse | null;
  readonly auditAction: typeof listEmergencyAuditTrailAction;
  /** super-admin = null = cross-tenant; admin = own tenant. */
  readonly tenantId?: string | null;
  /** Refetch interval; defaults to 30_000 ms; tests pass 100. */
  readonly pollMs?: number;
};

function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function truncate(value: string, max: number): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max - 1)}…`;
}

function shortenHash(value: string | null | undefined): string {
  if (!value) return "—";
  if (value.length <= 16) return value;
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}

export function EmergencyAuditTrail({
  initial,
  auditAction,
  tenantId = null,
  pollMs = DEFAULT_POLL_MS,
}: EmergencyAuditTrailProps): React.ReactElement {
  const [items, setItems] = useState<ReadonlyArray<EmergencyAuditItem>>(
    initial?.items ?? [],
  );
  const [error, setError] = useState<string | null>(null);
  const [isFetching, setIsFetching] = useState(false);
  const [lastFetchedAt, setLastFetchedAt] = useState<number | null>(
    initial ? Date.now() : null,
  );
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Monotonic request id — polling + manual refresh interleave; only the
  // latest request is allowed to land in state. Same pattern as
  // PerTenantThrottleClient.refetchStatus.
  const reqIdRef = useRef(0);

  const refetch = useCallback(async () => {
    const myReqId = ++reqIdRef.current;
    setIsFetching(true);
    setError(null);
    try {
      const next = await auditAction({
        tenantId: tenantId ?? null,
        limit: 25,
      });
      if (myReqId !== reqIdRef.current) return;
      setItems(next.items);
      setLastFetchedAt(Date.now());
    } catch (err) {
      if (myReqId !== reqIdRef.current) return;
      setError(throttleActionErrorMessage(err));
    } finally {
      if (myReqId === reqIdRef.current) {
        setIsFetching(false);
      }
    }
  }, [auditAction, tenantId]);

  // On-mount refetch (T30 ARG-053): the SSR snapshot in `initial` is
  // stale by definition after a parent-driven remount (the
  // `key={auditNonce}` bump on STOP/RESUME). Pull fresh state on mount
  // so the new audit row is visible immediately instead of after the
  // first poll tick. `refetch` is `useCallback` with stable deps so this
  // fires once per (re)mount, not on every render.
  useEffect(() => {
    void refetch();
  }, [refetch]);

  // Polling interval — re-bound when `pollMs` or `tenantId` changes so
  // tests can override the cadence cheaply.
  useEffect(() => {
    if (pollMs <= 0) return;
    const id = window.setInterval(() => {
      void refetch();
    }, pollMs);
    return () => {
      window.clearInterval(id);
    };
  }, [pollMs, refetch]);

  const handleManualRefresh = () => {
    void refetch();
  };

  const lastFetchedLabel = useMemo(() => {
    if (lastFetchedAt === null) return "ещё не загружено";
    return formatTimestamp(new Date(lastFetchedAt).toISOString());
  }, [lastFetchedAt]);

  const toggleExpanded = (id: string) => {
    setExpandedId((cur) => (cur === id ? null : id));
  };

  return (
    <section
      className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-3"
      aria-label="Emergency audit trail"
      data-testid="emergency-audit-trail"
    >
      <header className="mb-2 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">
            Emergency audit trail
          </h3>
          <p
            className="text-[11px] text-[var(--text-muted)]"
            data-testid="emergency-audit-last-fetched"
          >
            Последнее обновление: {lastFetchedLabel}
            {isFetching ? " · обновление…" : ""}
          </p>
        </div>
        <button
          type="button"
          onClick={handleManualRefresh}
          disabled={isFetching}
          className="rounded border border-[var(--border)] px-2 py-1 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
          data-testid="emergency-audit-refresh"
        >
          Обновить
        </button>
      </header>

      {error ? (
        <div
          role="alert"
          className="mb-2 rounded border border-red-500/60 bg-red-500/10 px-2 py-1 text-xs text-red-200"
          data-testid="emergency-audit-error"
        >
          {error}
        </div>
      ) : null}

      {items.length === 0 ? (
        <p
          role="status"
          className="rounded border border-dashed border-[var(--border)] px-3 py-4 text-center text-sm text-[var(--text-muted)]"
          data-testid="emergency-audit-empty"
        >
          Записи отсутствуют.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr className="border-b border-[var(--border)] text-left text-[var(--text-muted)]">
                <th scope="col" className="px-2 py-1.5">
                  Время
                </th>
                <th scope="col" className="px-2 py-1.5">
                  Событие
                </th>
                <th scope="col" className="px-2 py-1.5">
                  Operator
                </th>
                <th scope="col" className="px-2 py-1.5">
                  Tenant
                </th>
                <th scope="col" className="px-2 py-1.5">
                  Причина
                </th>
                <th scope="col" className="px-2 py-1.5 text-right">
                  Детали
                </th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <AuditRow
                  key={item.audit_id}
                  item={item}
                  expanded={expandedId === item.audit_id}
                  onToggle={() => toggleExpanded(item.audit_id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function AuditRow({
  item,
  expanded,
  onToggle,
}: {
  item: EmergencyAuditItem;
  expanded: boolean;
  onToggle: () => void;
}): React.ReactElement {
  const detailsId = `emergency-audit-details-${item.audit_id}`;
  const reason = item.reason ?? "";
  const truncatedReason = truncate(reason, REASON_TRUNCATE_AT);

  return (
    <>
      <tr
        className="cursor-pointer border-b border-[var(--border)] hover:bg-[var(--bg-primary)]/40"
        data-testid={`emergency-audit-row-${item.audit_id}`}
        onClick={onToggle}
      >
        <td className="px-2 py-1.5 align-top">
          <time
            dateTime={item.created_at}
            className="font-mono text-[11px] text-[var(--text-secondary)]"
          >
            {formatTimestamp(item.created_at)}
          </time>
        </td>
        <td className="px-2 py-1.5 align-top">
          <span
            className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${EVENT_BADGE_CLASS[item.event_type]}`}
            data-testid={`emergency-audit-event-${item.audit_id}`}
          >
            {EVENT_BADGE_LABEL[item.event_type]}
          </span>
        </td>
        <td className="px-2 py-1.5 align-top">
          <code className="font-mono text-[11px] text-[var(--text-secondary)]">
            {shortenHash(item.operator_subject_hash)}
          </code>
        </td>
        <td className="px-2 py-1.5 align-top">
          <code className="font-mono text-[11px] text-[var(--text-secondary)]">
            {shortenHash(item.tenant_id_hash)}
          </code>
        </td>
        <td className="px-2 py-1.5 align-top text-[var(--text-primary)]">
          {truncatedReason || "—"}
        </td>
        <td className="px-2 py-1.5 text-right align-top">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              onToggle();
            }}
            aria-expanded={expanded}
            aria-controls={detailsId}
            className="rounded border border-[var(--border)] px-2 py-0.5 text-[11px] text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
            data-testid={`emergency-audit-details-toggle-${item.audit_id}`}
          >
            {expanded ? "Скрыть" : "Показать"}
          </button>
        </td>
      </tr>
      {expanded ? (
        <tr
          className="border-b border-[var(--border)]"
          data-testid={`emergency-audit-details-${item.audit_id}`}
        >
          <td colSpan={6} className="bg-[var(--bg-primary)]/40 px-2 py-2">
            <pre
              id={detailsId}
              className="overflow-x-auto whitespace-pre-wrap break-words text-[11px] text-[var(--text-secondary)]"
            >
              {JSON.stringify(
                {
                  audit_id: item.audit_id,
                  event_type: item.event_type,
                  created_at: item.created_at,
                  operator_subject_hash: item.operator_subject_hash,
                  tenant_id_hash: item.tenant_id_hash,
                  reason: item.reason,
                  details: item.details ?? null,
                },
                null,
                2,
              )}
            </pre>
          </td>
        </tr>
      ) : null}
    </>
  );
}
