"use client";

/**
 * `FindingsTable` — virtualised, keyboard-navigable triage table for the
 * cross-tenant admin findings view (T20).
 *
 * Why `@tanstack/react-virtual`: ARGUS aggregates thousands of findings across
 * tenants; rendering them all at once costs hundreds of milliseconds and
 * hammers the GC. The hook keeps DOM cost proportional to the visible window
 * (≤50 rows even for 5000 items) without pulling in a full table framework.
 *
 * A11y:
 *   - `role="table"` + `aria-rowcount` so AT can announce position correctly
 *     even though only a window is mounted.
 *   - Each row exposes `aria-rowindex` (1-based) and is reachable via Tab; the
 *     table itself catches Arrow Up/Down, Home, End and Enter so operators can
 *     navigate without a mouse.
 *   - Severity is encoded as colour AND short text + a leading icon (●/◆/■/▲)
 *     so the cue survives colour-blind palettes.
 *
 * Drawer (S2-1 focus management):
 *   - On open, focus moves to the close button so AT users land on a known
 *     anchor and the next Tab cycles inside the dialog.
 *   - Tab / Shift-Tab cycle through the focusable controls inside the drawer
 *     so focus is trapped while the modal is open (light-weight focus trap;
 *     no portal).
 *   - On close, the previously-focused element regains focus (or the row
 *     that opened the drawer, whichever is more useful for AT users).
 *
 * Export (S1-5):
 *   - Export is per-finding and lives inside the drawer. The previous global
 *     button silently exported the scan of an arbitrary visible finding,
 *     which mis-scoped the artefact when results came from multiple scans.
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
} from "react";
import { useVirtualizer } from "@tanstack/react-virtual";

import { ExportFormatToggle } from "@/components/admin/ExportFormatToggle";
import {
  type AdminFindingItem,
  type FindingSeverity,
  sortFindings,
} from "@/lib/adminFindings";
import {
  downloadFindingsExport,
  type ExportFormat,
} from "@/lib/findingsExport";

const ROW_HEIGHT_PX = 44;
const OVERSCAN = 8;

const SEVERITY_PRESENTATION: Readonly<Record<FindingSeverity, {
  readonly label: string;
  readonly icon: string;
  readonly className: string;
}>> = {
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

function formatDt(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString();
}

function formatScore(score: number | null): string {
  return score == null ? "—" : score.toFixed(1);
}

function formatEpss(score: number | null): string {
  if (score == null) return "—";
  return `${(score * 100).toFixed(1)}%`;
}

function shortId(id: string): string {
  return id.length <= 12 ? id : `${id.slice(0, 8)}…`;
}

function formatSsvc(ssvc: AdminFindingItem["ssvc_action"]): string {
  if (!ssvc) return "—";
  return ssvc.charAt(0).toUpperCase() + ssvc.slice(1);
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

export type FindingsTableProps = {
  readonly items: ReadonlyArray<AdminFindingItem>;
  readonly loading: boolean;
  readonly fetchingMore: boolean;
  readonly errorMessage: string | null;
  readonly onRowOpen?: (item: AdminFindingItem) => void;
  readonly onLoadMore?: () => void;
  readonly hasMore: boolean;
  readonly showTenantColumn: boolean;
  /** Container height in px. Defaults to a sensible value if not provided. */
  readonly heightPx?: number;
  /**
   * Tenant the operator is currently scoped to (super-admin URL choice or
   * server-resolved binding). Forwarded to the per-row export so the
   * `X-Tenant-ID` header matches the row's actual scope.
   */
  readonly effectiveTenantId?: string | null;
};

const COLUMNS_BASE = 7;

export function FindingsTable({
  items,
  loading,
  fetchingMore,
  errorMessage,
  onRowOpen,
  onLoadMore,
  hasMore,
  showTenantColumn,
  heightPx = 560,
  effectiveTenantId = null,
}: FindingsTableProps): React.ReactElement {
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const drawerRef = useRef<HTMLDivElement | null>(null);
  const drawerCloseRef = useRef<HTMLButtonElement | null>(null);
  const previouslyFocusedRef = useRef<HTMLElement | null>(null);
  const [activeIndex, setActiveIndex] = useState(0);
  const [drawerItem, setDrawerItem] = useState<AdminFindingItem | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState(false);

  const sorted = useMemo(() => sortFindings(items), [items]);

  const totalRows = sorted.length;
  const totalColumns = COLUMNS_BASE + (showTenantColumn ? 1 : 0);

  const rowVirtualizer = useVirtualizer({
    count: totalRows,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT_PX,
    overscan: OVERSCAN,
  });

  // Keep the active row clamped to the available range when the dataset shrinks.
  useEffect(() => {
    if (activeIndex >= totalRows && totalRows > 0) {
      setActiveIndex(totalRows - 1);
    } else if (totalRows === 0 && activeIndex !== 0) {
      setActiveIndex(0);
    }
  }, [activeIndex, totalRows]);

  const virtualItems = rowVirtualizer.getVirtualItems();
  const lastVisibleIndex = virtualItems.length > 0
    ? virtualItems[virtualItems.length - 1].index
    : -1;

  // Trigger infinite scroll when we approach the end of the rendered window.
  // We depend on the index of the last visible row (a primitive) rather than
  // the virtual-item array itself so the dep list stays statically checkable.
  useEffect(() => {
    if (!hasMore || !onLoadMore || fetchingMore || loading) return;
    if (lastVisibleIndex < 0) return;
    if (lastVisibleIndex >= totalRows - 5) {
      onLoadMore();
    }
  }, [
    hasMore,
    onLoadMore,
    fetchingMore,
    loading,
    totalRows,
    lastVisibleIndex,
  ]);

  const openDrawer = useCallback(
    (item: AdminFindingItem) => {
      previouslyFocusedRef.current =
        (typeof document !== "undefined"
          ? (document.activeElement as HTMLElement | null)
          : null) ?? null;
      setExportError(null);
      setDrawerItem(item);
      onRowOpen?.(item);
    },
    [onRowOpen],
  );

  const closeDrawer = useCallback(() => {
    setDrawerItem(null);
    setExportError(null);
    setIsExporting(false);
    // Restore focus to the element that triggered the open (typically the
    // row), giving keyboard users a stable anchor to keep navigating.
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

  // Auto-focus the close button when the drawer mounts, so screen readers
  // and keyboard users land on a known control.
  useEffect(() => {
    if (drawerItem == null) return;
    const id = window.setTimeout(() => {
      drawerCloseRef.current?.focus();
    }, 0);
    return () => window.clearTimeout(id);
  }, [drawerItem]);

  const handleExport = useCallback(
    async (format: ExportFormat) => {
      if (!drawerItem) return;
      setExportError(null);
      setIsExporting(true);
      try {
        await downloadFindingsExport(drawerItem.scan_id, format, {
          tenantId: effectiveTenantId ?? drawerItem.tenant_id,
        });
      } catch {
        setExportError(
          "Не удалось скачать экспорт. Повторите попытку.",
        );
      } finally {
        setIsExporting(false);
      }
    },
    [drawerItem, effectiveTenantId],
  );

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
    // Focus trap: keep Tab cycling inside the dialog while it's open.
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

  const renderHeaderRow = () => (
    <div
      role="row"
      aria-rowindex={1}
      className="sticky top-0 z-10 grid bg-[var(--bg-secondary)] text-xs font-medium uppercase tracking-wider text-[var(--text-muted)] shadow-[0_1px_0_var(--border)]"
      style={{
        gridTemplateColumns: showTenantColumn
          ? "minmax(96px,1fr) minmax(96px,1fr) minmax(80px,80px) minmax(80px,80px) minmax(80px,80px) minmax(120px,1fr) minmax(160px,2fr) minmax(160px,1fr) minmax(120px,140px)"
          : "minmax(96px,1fr) minmax(80px,80px) minmax(80px,80px) minmax(80px,80px) minmax(120px,1fr) minmax(160px,2fr) minmax(160px,1fr) minmax(120px,140px)",
      }}
    >
      <span role="columnheader" className="px-3 py-2">
        Severity
      </span>
      {showTenantColumn ? (
        <span role="columnheader" className="px-3 py-2">
          Tenant
        </span>
      ) : null}
      <span role="columnheader" className="px-3 py-2">
        SSVC
      </span>
      <span role="columnheader" className="px-3 py-2">
        CVSS
      </span>
      <span role="columnheader" className="px-3 py-2">
        EPSS
      </span>
      <span role="columnheader" className="px-3 py-2">
        Target
      </span>
      <span role="columnheader" className="px-3 py-2">
        Title
      </span>
      <span role="columnheader" className="px-3 py-2">
        CVEs
      </span>
      <span role="columnheader" className="px-3 py-2">
        Updated
      </span>
    </div>
  );

  const renderRow = (item: AdminFindingItem, index: number, top: number) => {
    const sev = SEVERITY_PRESENTATION[item.severity];
    const isActive = index === activeIndex;
    return (
      <div
        key={item.id}
        role="row"
        aria-rowindex={index + 2}
        aria-selected={isActive}
        data-row-index={index}
        data-testid={`findings-row-${item.id}`}
        onClick={() => {
          setActiveIndex(index);
          openDrawer(item);
        }}
        className={`absolute left-0 right-0 grid cursor-pointer items-center border-b border-[var(--border)] text-xs hover:bg-[var(--bg-secondary)]/60 ${
          isActive ? "bg-[var(--bg-tertiary)]" : ""
        }`}
        style={{
          height: `${ROW_HEIGHT_PX}px`,
          transform: `translateY(${top}px)`,
          gridTemplateColumns: showTenantColumn
            ? "minmax(96px,1fr) minmax(96px,1fr) minmax(80px,80px) minmax(80px,80px) minmax(80px,80px) minmax(120px,1fr) minmax(160px,2fr) minmax(160px,1fr) minmax(120px,140px)"
            : "minmax(96px,1fr) minmax(80px,80px) minmax(80px,80px) minmax(80px,80px) minmax(120px,1fr) minmax(160px,2fr) minmax(160px,1fr) minmax(120px,140px)",
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
          {item.kev_listed === true ? (
            <span
              className="ml-1 inline-flex items-center rounded bg-red-500/20 px-1.5 py-0.5 text-[10px] font-medium text-red-200"
              data-testid={`kev-badge-${item.id}`}
              aria-label="Listed in CISA KEV"
            >
              KEV
            </span>
          ) : item.kev_listed === false ? null : (
            <span
              className="ml-1 inline-flex items-center rounded border border-dashed border-[var(--border)] px-1.5 py-0.5 text-[10px] text-[var(--text-muted)]"
              aria-label="KEV статус неизвестен"
              data-testid={`kev-unknown-${item.id}`}
            >
              KEV: ?
            </span>
          )}
        </span>
        {showTenantColumn ? (
          <span
            role="cell"
            className="truncate px-3 py-1.5 font-mono text-[11px] text-[var(--text-secondary)]"
            title={item.tenant_id}
          >
            {shortId(item.tenant_id)}
          </span>
        ) : null}
        <span role="cell" className="px-3 py-1.5 text-[var(--text-secondary)]">
          {formatSsvc(item.ssvc_action)}
        </span>
        <span role="cell" className="px-3 py-1.5">
          {formatScore(item.cvss_score)}
        </span>
        <span role="cell" className="px-3 py-1.5">
          {formatEpss(item.epss_score)}
        </span>
        <span
          role="cell"
          className="truncate px-3 py-1.5 text-[var(--text-secondary)]"
          title={item.target ?? ""}
        >
          {item.target ?? "—"}
        </span>
        <span
          role="cell"
          className="truncate px-3 py-1.5 text-[var(--text-primary)]"
          title={item.title}
        >
          {item.title}
        </span>
        <span role="cell" className="truncate px-3 py-1.5">
          {item.cve_ids && item.cve_ids.length > 0 ? (
            <span className="flex flex-wrap gap-1">
              {item.cve_ids.slice(0, 3).map((cve) => (
                <span
                  key={cve}
                  className="rounded bg-[var(--bg-tertiary)] px-1.5 py-0.5 text-[10px] font-mono text-[var(--text-secondary)]"
                >
                  {cve}
                </span>
              ))}
              {item.cve_ids.length > 3 ? (
                <span className="text-[10px] text-[var(--text-muted)]">
                  +{item.cve_ids.length - 3}
                </span>
              ) : null}
            </span>
          ) : (
            <span className="text-[var(--text-muted)]">—</span>
          )}
        </span>
        <span role="cell" className="px-3 py-1.5 text-[var(--text-muted)]">
          {formatDt(item.updated_at)}
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
        aria-label="Findings"
        aria-busy={loading || fetchingMore}
        tabIndex={0}
        onKeyDown={handleTableKeyDown}
        className="rounded border border-[var(--border)] bg-[var(--bg-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
        data-testid="findings-table"
      >
        {renderHeaderRow()}

        <div
          ref={scrollRef}
          style={{ height: `${heightPx}px`, overflow: "auto" }}
          data-testid="findings-table-scroll"
        >
          {loading && totalRows === 0 ? (
            <ul aria-label="Загрузка findings" className="m-0 list-none p-0">
              {Array.from({ length: 8 }).map((_, i) => (
                <li
                  key={i}
                  data-testid="findings-skeleton-row"
                  className="h-11 animate-pulse border-b border-[var(--border)] bg-[var(--bg-secondary)]/40"
                />
              ))}
            </ul>
          ) : showEmpty ? (
            <p
              role="status"
              data-testid="findings-empty"
              className="px-4 py-12 text-center text-sm text-[var(--text-muted)]"
            >
              Нет findings, удовлетворяющих фильтрам.
            </p>
          ) : errorMessage ? (
            <p
              role="alert"
              data-testid="findings-error"
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
              {virtualItems.map((virtualRow) => {
                const item = sorted[virtualRow.index];
                if (!item) return null;
                return renderRow(item, virtualRow.index, virtualRow.start);
              })}
            </div>
          )}
        </div>
        {fetchingMore ? (
          <div
            role="status"
            data-testid="findings-loading-more"
            className="border-t border-[var(--border)] px-3 py-2 text-center text-xs text-[var(--text-muted)]"
          >
            Загрузка следующей страницы…
          </div>
        ) : null}
      </div>

      {drawerItem ? (
        <div
          className="fixed inset-0 z-40 flex justify-end bg-black/40"
          role="presentation"
          onClick={closeDrawer}
          data-testid="findings-drawer-backdrop"
        >
          <div
            ref={drawerRef}
            className="h-full w-full max-w-lg overflow-y-auto border-l border-[var(--border)] bg-[var(--bg-primary)] p-4 shadow-xl"
            role="dialog"
            aria-modal="true"
            aria-label={`Finding ${drawerItem.title}`}
            aria-labelledby="findings-drawer-title"
            data-testid="findings-drawer"
            tabIndex={-1}
            onKeyDown={handleDrawerKeyDown}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-2">
              <h2
                id="findings-drawer-title"
                className="text-base font-semibold text-[var(--text-primary)]"
              >
                {drawerItem.title}
              </h2>
              <button
                ref={drawerCloseRef}
                type="button"
                onClick={closeDrawer}
                className="rounded border border-[var(--border)] px-2 py-1 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
                data-testid="findings-drawer-close"
              >
                Закрыть
              </button>
            </div>
            <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm text-[var(--text-secondary)]">
              <dt className="text-[var(--text-muted)]">Finding ID</dt>
              <dd className="font-mono text-xs text-[var(--text-primary)]">
                {drawerItem.id}
              </dd>
              <dt className="text-[var(--text-muted)]">Tenant</dt>
              <dd className="font-mono text-xs text-[var(--text-primary)]">
                {drawerItem.tenant_id}
              </dd>
              <dt className="text-[var(--text-muted)]">Scan</dt>
              <dd className="font-mono text-xs text-[var(--text-primary)]">
                {drawerItem.scan_id}
              </dd>
              <dt className="text-[var(--text-muted)]">Severity</dt>
              <dd>{SEVERITY_PRESENTATION[drawerItem.severity].label}</dd>
              <dt className="text-[var(--text-muted)]">CVSS</dt>
              <dd>{formatScore(drawerItem.cvss_score)}</dd>
              <dt className="text-[var(--text-muted)]">EPSS</dt>
              <dd>{formatEpss(drawerItem.epss_score)}</dd>
              <dt className="text-[var(--text-muted)]">SSVC</dt>
              <dd>{formatSsvc(drawerItem.ssvc_action)}</dd>
              <dt className="text-[var(--text-muted)]">KEV</dt>
              <dd>
                {drawerItem.kev_listed === true
                  ? "Yes"
                  : drawerItem.kev_listed === false
                  ? "No"
                  : "Unknown"}
              </dd>
              <dt className="text-[var(--text-muted)]">Updated</dt>
              <dd>{formatDt(drawerItem.updated_at)}</dd>
            </dl>
            <section
              className="mt-5 border-t border-[var(--border)] pt-3"
              aria-label="Экспорт scan"
              data-testid="findings-drawer-export"
            >
              <h3 className="mb-1 text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
                Экспорт scan
              </h3>
              <p className="mb-2 text-[11px] text-[var(--text-muted)]">
                Скачивает SARIF / JUnit XML для scan этого finding
                (scan_id <code className="font-mono">{drawerItem.scan_id}</code>).
              </p>
              <ExportFormatToggle
                scanId={drawerItem.scan_id}
                onDownload={handleExport}
                disabled={isExporting}
              />
              {exportError ? (
                <p
                  role="alert"
                  className="mt-2 text-xs text-red-400"
                  data-testid="findings-drawer-export-error"
                >
                  {exportError}
                </p>
              ) : null}
            </section>
            <p className="mt-4 text-xs text-[var(--text-muted)]">
              Расширенная карточка finding появится в T21 — здесь будут детали
              артефактов и комментарии.
            </p>
          </div>
        </div>
      ) : null}
    </div>
  );
}
