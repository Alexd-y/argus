"use client";

/**
 * `AuditLogsTable` — virtualised, keyboard-navigable read-only table for the
 * admin audit-log viewer (T22).
 *
 * Patterns mirror `FindingsTable` (T20):
 *   - `@tanstack/react-virtual` keeps DOM size proportional to the visible
 *     window so 1000+ rows render in O(visible) cost.
 *   - Severity uses colour + icon + text (colour-blind safe).
 *   - Drawer with focus trap, Escape-to-close and focus-restore on close.
 *   - Pre-formatted `details` rendered inside `<pre><code>` (NEVER
 *     `dangerouslySetInnerHTML`, NEVER eval) — closed taxonomy: read only.
 *
 * Chain-aware indicator:
 *   - Rows whose `details` carry the SHA-256 chain markers
 *     (`_event_hash` / `_prev_event_hash`) get a small "🔗 chain" badge so
 *     operators can immediately spot which entries participate in the
 *     verifiable chain that T25 replays.
 */

import {
  useCallback,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type Ref,
} from "react";
import { useVirtualizer } from "@tanstack/react-virtual";

import {
  hasChainMarkers,
  prettyPrintDetails,
  type AuditLogItem,
  type AuditSeverity,
} from "@/lib/adminAuditLogs";

const ROW_HEIGHT_PX = 44;
const OVERSCAN = 8;

// keep: severity-coding ladder (critical/high/medium/low/info). The
// `medium` row uses yellow-500 as part of the 5-tone palette, paired
// with red/orange/blue/slate. It is a status indicator, not a
// warning-action fill — `--warning-strong` is reserved for confirm
// CTAs (see ai_docs/architecture/design-tokens.md §3.5).
const SEVERITY_PRESENTATION: Readonly<
  Record<
    AuditSeverity,
    { readonly label: string; readonly icon: string; readonly className: string }
  >
> = {
  critical: {
    label: "Critical",
    icon: "■",
    className: "border-red-500 bg-red-500/15 text-red-200",
  },
  high: {
    label: "High",
    icon: "◆",
    className: "border-orange-500 bg-orange-500/15 text-orange-200",
  },
  medium: {
    label: "Medium",
    icon: "▲",
    className: "border-yellow-500 bg-yellow-500/15 text-yellow-200",
  },
  low: {
    label: "Low",
    icon: "●",
    className: "border-blue-500 bg-blue-500/15 text-blue-200",
  },
  info: {
    label: "Info",
    icon: "○",
    className: "border-slate-500 bg-slate-500/15 text-slate-200",
  },
};

const UNKNOWN_SEVERITY = {
  label: "—",
  icon: "·",
  className: "border-[var(--border)] bg-transparent text-[var(--text-muted)]",
};

function formatDt(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

function shortId(id: string | null): string {
  if (!id) return "—";
  return id.length <= 12 ? id : `${id.slice(0, 8)}…`;
}

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

function getFocusable(container: HTMLElement | null): HTMLElement[] {
  if (!container) return [];
  return Array.from(
    container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
  ).filter(
    (el) =>
      !el.hasAttribute("disabled") &&
      el.getAttribute("aria-hidden") !== "true",
  );
}

export type AuditLogsTableProps = {
  readonly items: ReadonlyArray<AuditLogItem>;
  readonly loading: boolean;
  readonly fetchingMore: boolean;
  readonly errorMessage: string | null;
  readonly onLoadMore?: () => void;
  readonly hasMore: boolean;
  readonly showTenantColumn: boolean;
  readonly heightPx?: number;
  /** When set, the row with that id is highlighted (used for drift jump). */
  readonly highlightId?: string | null;
  /**
   * Imperative handle for the parent (e.g. the chain-verify banner) to scroll
   * to a specific row. Uses React 19's ref-as-prop convention so we avoid
   * `forwardRef` (which the React Compiler cannot reason about cleanly).
   */
  readonly ref?: Ref<AuditLogsTableHandle>;
};

/** Imperative handle exposed to the parent (used for "scroll to drift"). */
export type AuditLogsTableHandle = {
  scrollToId: (id: string) => boolean;
};

const COLUMNS_BASE = 6;

export function AuditLogsTable({
  items,
  loading,
  fetchingMore,
  errorMessage,
  onLoadMore,
  hasMore,
  showTenantColumn,
  heightPx = 560,
  highlightId = null,
  ref,
}: AuditLogsTableProps): React.ReactElement {
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const drawerRef = useRef<HTMLDivElement | null>(null);
  const drawerCloseRef = useRef<HTMLButtonElement | null>(null);
  const previouslyFocusedRef = useRef<HTMLElement | null>(null);
  const [activeIndex, setActiveIndex] = useState(0);
  const [drawerItem, setDrawerItem] = useState<AuditLogItem | null>(null);

  // Items arrive newest-first from the backend; use as-is.
  const sorted = items;
  const totalRows = sorted.length;
  const totalColumns = COLUMNS_BASE + (showTenantColumn ? 1 : 0);

  // useVirtualizer returns un-memoisable callbacks; opting out of compiler
  // memoisation matches the pattern used by `FindingsTable` (T20).
  // eslint-disable-next-line react-hooks/incompatible-library
  const rowVirtualizer = useVirtualizer({
    count: totalRows,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT_PX,
    overscan: OVERSCAN,
  });

  // Expose imperative scroll-to-id for the chain-verify drift jump.
  useImperativeHandle(
    ref,
    () => ({
      scrollToId: (id: string) => {
        const idx = sorted.findIndex((x) => x.id === id);
        if (idx < 0) return false;
        rowVirtualizer.scrollToIndex(idx, { align: "center" });
        setActiveIndex(idx);
        return true;
      },
    }),
    [sorted, rowVirtualizer],
  );

  useEffect(() => {
    if (activeIndex >= totalRows && totalRows > 0) {
      setActiveIndex(totalRows - 1);
    } else if (totalRows === 0 && activeIndex !== 0) {
      setActiveIndex(0);
    }
  }, [activeIndex, totalRows]);

  const virtualItems = rowVirtualizer.getVirtualItems();
  const lastVisibleIndex =
    virtualItems.length > 0 ? virtualItems[virtualItems.length - 1].index : -1;

  useEffect(() => {
    if (!hasMore || !onLoadMore || fetchingMore || loading) return;
    if (lastVisibleIndex < 0) return;
    if (lastVisibleIndex >= totalRows - 5) {
      onLoadMore();
    }
  }, [hasMore, onLoadMore, fetchingMore, loading, totalRows, lastVisibleIndex]);

  const openDrawer = useCallback((item: AuditLogItem) => {
    previouslyFocusedRef.current =
      typeof document !== "undefined"
        ? (document.activeElement as HTMLElement | null)
        : null;
    setDrawerItem(item);
  }, []);

  const closeDrawer = useCallback(() => {
    setDrawerItem(null);
    const restoreTo = previouslyFocusedRef.current;
    previouslyFocusedRef.current = null;
    if (
      restoreTo &&
      typeof restoreTo.focus === "function" &&
      typeof document !== "undefined" &&
      document.contains(restoreTo)
    ) {
      restoreTo.focus();
    }
  }, []);

  useEffect(() => {
    if (drawerItem == null) return;
    const id = window.setTimeout(() => {
      drawerCloseRef.current?.focus();
    }, 0);
    return () => window.clearTimeout(id);
  }, [drawerItem]);

  const handleTableKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (totalRows === 0) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      const next = Math.min(activeIndex + 1, totalRows - 1);
      setActiveIndex(next);
      rowVirtualizer.scrollToIndex(next);
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      const next = Math.max(activeIndex - 1, 0);
      setActiveIndex(next);
      rowVirtualizer.scrollToIndex(next);
    } else if (e.key === "Home") {
      e.preventDefault();
      setActiveIndex(0);
      rowVirtualizer.scrollToIndex(0);
    } else if (e.key === "End") {
      e.preventDefault();
      setActiveIndex(totalRows - 1);
      rowVirtualizer.scrollToIndex(totalRows - 1);
    } else if (e.key === "Enter" && sorted[activeIndex]) {
      e.preventDefault();
      openDrawer(sorted[activeIndex]);
    }
  };

  const handleDrawerKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") {
      e.preventDefault();
      closeDrawer();
      return;
    }
    if (e.key !== "Tab") return;
    const focusables = getFocusable(drawerRef.current);
    if (focusables.length === 0) {
      e.preventDefault();
      return;
    }
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    const active =
      typeof document !== "undefined"
        ? (document.activeElement as HTMLElement | null)
        : null;
    if (e.shiftKey) {
      if (active === first || !drawerRef.current?.contains(active)) {
        e.preventDefault();
        last.focus();
      }
    } else {
      if (active === last) {
        e.preventDefault();
        first.focus();
      }
    }
  };

  const showEmpty = !loading && totalRows === 0 && !errorMessage;

  const gridTemplate = showTenantColumn
    ? "minmax(96px,1fr) minmax(140px,160px) minmax(160px,2fr) minmax(160px,1fr) minmax(120px,1fr) minmax(80px,80px) minmax(180px,1fr)"
    : "minmax(96px,1fr) minmax(140px,160px) minmax(160px,2fr) minmax(160px,1fr) minmax(80px,80px) minmax(180px,1fr)";

  const renderHeaderRow = () => (
    <div
      role="row"
      aria-rowindex={1}
      className="sticky top-0 z-10 grid bg-[var(--bg-secondary)] text-xs font-medium uppercase tracking-wider text-[var(--text-muted)] shadow-[0_1px_0_var(--border)]"
      style={{ gridTemplateColumns: gridTemplate }}
    >
      <span role="columnheader" className="px-3 py-2">
        Severity
      </span>
      <span role="columnheader" className="px-3 py-2">
        Timestamp
      </span>
      <span role="columnheader" className="px-3 py-2">
        Event
      </span>
      <span role="columnheader" className="px-3 py-2">
        Actor
      </span>
      {showTenantColumn ? (
        <span role="columnheader" className="px-3 py-2">
          Tenant
        </span>
      ) : null}
      <span role="columnheader" className="px-3 py-2">
        Chain
      </span>
      <span role="columnheader" className="px-3 py-2">
        Details
      </span>
    </div>
  );

  const renderRow = (item: AuditLogItem, index: number, top: number) => {
    const sev =
      item.severity != null
        ? SEVERITY_PRESENTATION[item.severity]
        : UNKNOWN_SEVERITY;
    const isActive = index === activeIndex;
    const isHighlighted = highlightId != null && item.id === highlightId;
    const chainAware = hasChainMarkers(item.details);
    return (
      <div
        key={item.id}
        role="row"
        aria-rowindex={index + 2}
        aria-selected={isActive}
        data-row-index={index}
        data-testid={`audit-row-${item.id}`}
        data-chain-aware={chainAware ? "true" : "false"}
        onClick={() => {
          setActiveIndex(index);
          openDrawer(item);
        }}
        className={`absolute left-0 right-0 grid cursor-pointer items-center border-b border-[var(--border)] text-xs hover:bg-[var(--bg-secondary)]/60 ${
          isActive ? "bg-[var(--bg-tertiary)]" : ""
        } ${isHighlighted ? "ring-2 ring-red-500" : ""}`}
        style={{
          height: `${ROW_HEIGHT_PX}px`,
          transform: `translateY(${top}px)`,
          gridTemplateColumns: gridTemplate,
        }}
      >
        <span role="cell" className="px-3 py-1.5">
          <span
            className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium ${sev.className}`}
            aria-label={`Severity ${sev.label}`}
          >
            <span aria-hidden>{sev.icon}</span>
            <span>{sev.label}</span>
          </span>
        </span>
        <span role="cell" className="px-3 py-1.5 text-[var(--text-muted)]">
          {formatDt(item.created_at)}
        </span>
        <span
          role="cell"
          className="truncate px-3 py-1.5 font-mono text-[11px] text-[var(--text-primary)]"
          title={item.event_type || undefined}
        >
          {item.event_type || "—"}
        </span>
        <span
          role="cell"
          className="truncate px-3 py-1.5 text-[var(--text-secondary)]"
          title={item.actor_subject ?? undefined}
        >
          {item.actor_subject ?? "—"}
        </span>
        {showTenantColumn ? (
          <span
            role="cell"
            className="truncate px-3 py-1.5 font-mono text-[11px] text-[var(--text-secondary)]"
            title={item.tenant_id ?? undefined}
          >
            {shortId(item.tenant_id)}
          </span>
        ) : null}
        <span role="cell" className="px-3 py-1.5">
          {chainAware ? (
            <span
              className="inline-flex items-center gap-1 rounded border border-emerald-600/50 bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-medium text-emerald-300"
              data-testid={`audit-chain-badge-${item.id}`}
              aria-label="Chain-aware audit entry"
              title="Содержит SHA-256 маркеры цепочки"
            >
              <span aria-hidden>🔗</span>
              chain
            </span>
          ) : (
            <span
              className="text-[10px] text-[var(--text-muted)]"
              aria-label="No chain markers"
            >
              —
            </span>
          )}
        </span>
        <span
          role="cell"
          className="truncate px-3 py-1.5 font-mono text-[10px] text-[var(--text-muted)]"
        >
          {item.details ? "View JSON" : "—"}
        </span>
      </div>
    );
  };

  return (
    <div className="relative">
      <div
        role="table"
        aria-rowcount={totalRows + 1}
        aria-colcount={totalColumns}
        aria-label="Audit log"
        aria-busy={loading || fetchingMore}
        tabIndex={0}
        onKeyDown={handleTableKeyDown}
        className="rounded border border-[var(--border)] bg-[var(--bg-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
        data-testid="audit-logs-table"
      >
        {renderHeaderRow()}

        <div
          ref={scrollRef}
          style={{ height: `${heightPx}px`, overflow: "auto" }}
          data-testid="audit-logs-table-scroll"
        >
          {loading && totalRows === 0 ? (
            // The skeleton lives inside `role="table"`; ARIA forbids arbitrary
            // children there, so we surface it as a rowgroup of placeholder
            // rows. `aria-busy` on the table already tells AT to ignore them.
            <ul
              role="rowgroup"
              aria-label="Загрузка audit log"
              className="m-0 list-none p-0"
            >
              {Array.from({ length: 8 }).map((_, i) => (
                <li
                  key={i}
                  role="row"
                  aria-hidden="true"
                  data-testid="audit-skeleton-row"
                  className="h-11 animate-pulse border-b border-[var(--border)] bg-[var(--bg-secondary)]/40"
                />
              ))}
            </ul>
          ) : showEmpty ? (
            <p
              role="status"
              data-testid="audit-empty"
              className="px-4 py-12 text-center text-sm text-[var(--text-muted)]"
            >
              Нет записей audit log в выбранном диапазоне.
            </p>
          ) : errorMessage ? (
            <p
              role="alert"
              data-testid="audit-error"
              className="px-4 py-12 text-center text-sm text-red-400"
            >
              {errorMessage}
            </p>
          ) : (
            <div
              style={{
                position: "relative",
                height: `${rowVirtualizer.getTotalSize()}px`,
                width: "100%",
              }}
            >
              {virtualItems.map((vi) => {
                const item = sorted[vi.index];
                if (!item) return null;
                return renderRow(item, vi.index, vi.start);
              })}
            </div>
          )}
        </div>
      </div>

      {drawerItem ? (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="audit-drawer-title"
          ref={drawerRef}
          onKeyDown={handleDrawerKeyDown}
          data-testid="audit-drawer"
          className="fixed inset-y-0 right-0 z-50 flex w-full max-w-2xl flex-col gap-3 overflow-y-auto border-l border-[var(--border)] bg-[var(--bg-primary)] p-4 shadow-xl"
        >
          <div className="flex items-start justify-between gap-3">
            <div className="flex min-w-0 flex-col gap-1">
              <h3
                id="audit-drawer-title"
                className="truncate text-sm font-semibold text-[var(--text-primary)]"
                title={drawerItem.event_type || undefined}
              >
                {drawerItem.event_type || "audit event"}
              </h3>
              <p className="truncate font-mono text-[11px] text-[var(--text-muted)]">
                {drawerItem.id}
              </p>
            </div>
            <button
              ref={drawerCloseRef}
              type="button"
              onClick={closeDrawer}
              className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-1.5 text-xs text-[var(--text-secondary)] transition hover:border-[var(--accent)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
              data-testid="audit-drawer-close"
              aria-label="Закрыть"
            >
              Закрыть
            </button>
          </div>

          <dl className="grid grid-cols-[120px_1fr] gap-x-3 gap-y-1 text-xs">
            <dt className="text-[var(--text-muted)]">Timestamp</dt>
            <dd className="text-[var(--text-primary)]">
              {formatDt(drawerItem.created_at)}
            </dd>
            <dt className="text-[var(--text-muted)]">Severity</dt>
            <dd className="text-[var(--text-primary)]">
              {drawerItem.severity ?? "—"}
            </dd>
            <dt className="text-[var(--text-muted)]">Actor</dt>
            <dd className="break-all text-[var(--text-primary)]">
              {drawerItem.actor_subject ?? "—"}
            </dd>
            <dt className="text-[var(--text-muted)]">Tenant</dt>
            <dd className="break-all font-mono text-[var(--text-primary)]">
              {drawerItem.tenant_id ?? "—"}
            </dd>
            <dt className="text-[var(--text-muted)]">Resource</dt>
            <dd className="break-all text-[var(--text-primary)]">
              {drawerItem.resource_type ?? "—"}
              {drawerItem.resource_id ? ` / ${drawerItem.resource_id}` : ""}
            </dd>
            <dt className="text-[var(--text-muted)]">Chain-aware</dt>
            <dd className="text-[var(--text-primary)]">
              {hasChainMarkers(drawerItem.details) ? "yes" : "no"}
            </dd>
          </dl>

          <DetailsBlock details={drawerItem.details} />
        </div>
      ) : null}
    </div>
  );
}

/**
 * Details JSON renderer. The audit `details` is JSONB from the backend
 * and may contain operator-supplied strings, so it is rendered as
 * pre-formatted text inside `<pre><code>` — never as HTML.
 */
function DetailsBlock({
  details,
}: {
  details: unknown;
}): React.ReactElement {
  const formatted = useMemo(() => prettyPrintDetails(details), [details]);
  return (
    <details
      className="mt-1 rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-2"
      data-testid="audit-drawer-details"
      open
    >
      <summary className="cursor-pointer text-xs font-medium text-[var(--text-secondary)]">
        Полный details JSON
      </summary>
      <pre className="mt-2 max-h-[60vh] overflow-auto rounded bg-[var(--bg-primary)] p-2 text-[11px] leading-relaxed">
        <code>{formatted}</code>
      </pre>
    </details>
  );
}

AuditLogsTable.displayName = "AuditLogsTable";
