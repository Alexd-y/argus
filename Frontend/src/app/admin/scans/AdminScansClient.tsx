"use client";

import { useRouter } from "next/navigation";
import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useState,
  useTransition,
} from "react";

import { listTenants, type AdminTenant } from "@/app/admin/tenants/actions";
import { getSafeErrorMessage } from "@/lib/api";
import {
  downloadFindingsExport,
  type ExportFormat,
} from "@/lib/findingsExport";
import { isTerminalScanStatus } from "@/lib/adminScans";

import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import { ExportFormatToggle } from "@/components/admin/ExportFormatToggle";
import { PerScanKillSwitchDialog } from "@/components/admin/operations/PerScanKillSwitchDialog";

import {
  bulkCancelAdminScans,
  getAdminScanDetail,
  listAdminScans,
  type AdminScanDetail,
  type AdminScanListItem,
  type AdminScanSort,
} from "./actions";

const PAGE_SIZE = 25;

function errMsg(e: unknown): string {
  return getSafeErrorMessage(e, "Something went wrong. Please try again.");
}

function formatDt(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function shortId(id: string): string {
  if (id.length <= 12) return id;
  return `${id.slice(0, 8)}…`;
}

function AdminScansBody() {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const cancelDialogId = useId();

  const [tenants, setTenants] = useState<AdminTenant[]>([]);
  const [tenantId, setTenantId] = useState<string>("");
  const [sort, setSort] = useState<AdminScanSort>("created_at_desc");
  const [offset, setOffset] = useState(0);
  const [rows, setRows] = useState<AdminScanListItem[]>([]);
  const [total, setTotal] = useState(0);

  const [listError, setListError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionInfo, setActionInfo] = useState<string | null>(null);

  const [selected, setSelected] = useState<Record<string, boolean>>({});

  const [detailOpen, setDetailOpen] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detail, setDetail] = useState<AdminScanDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);

  const [killTarget, setKillTarget] = useState<AdminScanListItem | null>(null);

  const selectedIds = useMemo(
    () => Object.keys(selected).filter((k) => selected[k]),
    [selected],
  );

  const loadTenants = useCallback(() => {
    startTransition(async () => {
      try {
        const t = await listTenants({ limit: 200, offset: 0 });
        setTenants(t);
        setTenantId((cur) => {
          if (cur && t.some((x) => x.id === cur)) return cur;
          return t[0]?.id ?? "";
        });
      } catch (e) {
        setListError(errMsg(e));
        setTenants([]);
        setTenantId("");
      }
    });
  }, []);

  const loadScans = useCallback(() => {
    if (!tenantId) {
      setRows([]);
      setTotal(0);
      return;
    }
    setListError(null);
    startTransition(async () => {
      try {
        const res = await listAdminScans({
          tenantId,
          offset,
          limit: PAGE_SIZE,
          sort,
        });
        setRows(res.scans);
        setTotal(res.total);
        setSelected({});
        router.refresh();
      } catch (e) {
        setListError(errMsg(e));
        setRows([]);
        setTotal(0);
      }
    });
  }, [tenantId, offset, sort, router]);

  useEffect(() => {
    loadTenants();
  }, [loadTenants]);

  useEffect(() => {
    loadScans();
  }, [loadScans]);

  const toggleSortCreated = () => {
    setSort((s) => (s === "created_at_desc" ? "created_at_asc" : "created_at_desc"));
    setOffset(0);
  };

  const toggleAllPage = (checked: boolean) => {
    const next: Record<string, boolean> = { ...selected };
    for (const r of rows) {
      next[r.id] = checked;
    }
    setSelected(next);
  };

  const openDetail = (scanId: string) => {
    if (!tenantId) return;
    setDetailOpen(true);
    setDetail(null);
    setDetailError(null);
    setDetailLoading(true);
    startTransition(async () => {
      try {
        const d = await getAdminScanDetail(tenantId, scanId);
        setDetail(d);
      } catch (e) {
        setDetailError(errMsg(e));
      } finally {
        setDetailLoading(false);
      }
    });
  };

  const closeDetail = () => {
    setDetailOpen(false);
    setDetail(null);
    setDetailError(null);
  };

  const requestBulkCancel = () => {
    setActionError(null);
    setActionInfo(null);
    if (!tenantId || selectedIds.length === 0) return;
    const dlg = document.getElementById(cancelDialogId) as HTMLDialogElement | null;
    dlg?.showModal();
  };

  const confirmBulkCancel = () => {
    if (!tenantId || selectedIds.length === 0) return;
    setActionError(null);
    setActionInfo(null);
    const dlg = document.getElementById(cancelDialogId) as HTMLDialogElement | null;
    dlg?.close();
    startTransition(async () => {
      try {
        const res = await bulkCancelAdminScans(tenantId, selectedIds);
        setActionInfo(
          `Cancelled ${res.cancelled_count}, skipped (terminal) ${res.skipped_terminal_count}, not found ${res.not_found_count}.`,
        );
        await loadScans();
      } catch (e) {
        setActionError(errMsg(e));
      }
    });
  };

  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const pageIndex = Math.floor(offset / PAGE_SIZE) + 1;

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">Scan history</h1>
          <p className="text-sm text-[var(--text-secondary)]">
            Tenant-scoped list, sortable by creation time. Bulk cancel uses the admin API; keys stay
            on the server.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label className="text-xs text-[var(--text-muted)]" htmlFor="admin-scan-tenant">
            Tenant
          </label>
          <select
            id="admin-scan-tenant"
            data-testid="scans-tenant-select"
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
            value={tenantId}
            onChange={(e) => {
              setTenantId(e.target.value);
              setOffset(0);
              setSelected({});
            }}
            disabled={isPending && tenants.length === 0}
          >
            {tenants.length === 0 ? (
              <option value="">—</option>
            ) : (
              tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))
            )}
          </select>
        </div>
      </div>

      {listError ? (
        <div
          className="rounded border border-red-900/40 bg-red-950/30 px-3 py-2 text-sm text-red-200"
          role="alert"
        >
          {listError}
        </div>
      ) : null}
      {actionError ? (
        <div
          className="rounded border border-red-900/40 bg-red-950/30 px-3 py-2 text-sm text-red-200"
          role="alert"
        >
          {actionError}
        </div>
      ) : null}
      {actionInfo ? (
        <div className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)]">
          {actionInfo}
        </div>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          className="rounded bg-[var(--accent)] px-3 py-1.5 text-sm font-medium text-white disabled:opacity-50"
          disabled={selectedIds.length === 0 || !tenantId || isPending}
          onClick={requestBulkCancel}
        >
          Bulk cancel ({selectedIds.length})
        </button>
        <span className="text-xs text-[var(--text-muted)]">
          {total} scan{total === 1 ? "" : "s"} total
        </span>
      </div>

      <div className="overflow-x-auto rounded border border-[var(--border)]" data-testid="scans-table-wrapper">
        <table className="min-w-full text-left text-sm" data-testid="scans-table">
          <thead className="border-b border-[var(--border)] bg-[var(--bg-secondary)] text-[var(--text-secondary)]">
            <tr>
              <th className="px-3 py-2">
                <input
                  type="checkbox"
                  aria-label="Select all on page"
                  checked={rows.length > 0 && rows.every((r) => selected[r.id])}
                  onChange={(e) => toggleAllPage(e.target.checked)}
                  disabled={rows.length === 0 || isPending}
                />
              </th>
              <th className="px-3 py-2">ID</th>
              <th className="px-3 py-2">Target</th>
              <th className="px-3 py-2">Status</th>
              <th className="px-3 py-2">Phase</th>
              <th className="px-3 py-2">Progress</th>
              <th className="px-3 py-2">Mode</th>
              <th className="px-3 py-2">
                <button
                  type="button"
                  className="inline-flex items-center gap-1 font-medium text-[var(--accent)] hover:underline"
                  onClick={toggleSortCreated}
                  disabled={!tenantId}
                >
                  Created
                  {sort === "created_at_desc" ? " ↓" : " ↑"}
                </button>
              </th>
              <th className="px-3 py-2"> </th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[var(--border)] text-[var(--text-primary)]">
            {!tenantId ? (
              <tr>
                <td colSpan={9} className="px-3 py-8 text-center text-[var(--text-muted)]">
                  Select a tenant to load scans.
                </td>
              </tr>
            ) : rows.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-3 py-8 text-center text-[var(--text-muted)]">
                  No scans in this page range.
                </td>
              </tr>
            ) : (
              rows.map((r) => (
                <tr
                  key={r.id}
                  className="hover:bg-[var(--bg-secondary)]/60"
                  data-testid={`scans-row-${r.id}`}
                >
                  <td className="px-3 py-2">
                    <input
                      type="checkbox"
                      aria-label={`Select scan ${r.id}`}
                      checked={!!selected[r.id]}
                      onChange={(e) =>
                        setSelected((s) => ({ ...s, [r.id]: e.target.checked }))
                      }
                    />
                  </td>
                  <td className="px-3 py-2 font-mono text-xs">{shortId(r.id)}</td>
                  <td className="max-w-[200px] truncate px-3 py-2" title={r.target}>
                    {r.target}
                  </td>
                  <td className="px-3 py-2">{r.status}</td>
                  <td className="px-3 py-2">{r.phase}</td>
                  <td className="px-3 py-2">{r.progress}</td>
                  <td className="px-3 py-2">{r.scan_mode}</td>
                  <td className="whitespace-nowrap px-3 py-2 text-[var(--text-secondary)]">
                    {formatDt(r.created_at)}
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-3">
                      <button
                        type="button"
                        className="text-[var(--accent)] hover:underline"
                        data-testid={`scans-row-details-${r.id}`}
                        onClick={() => openDetail(r.id)}
                      >
                        Details
                      </button>
                      {(() => {
                        const terminal = isTerminalScanStatus(r.status);
                        return (
                          <button
                            type="button"
                            className="text-red-300 hover:text-red-200 hover:underline disabled:cursor-not-allowed disabled:text-[var(--text-muted)] disabled:no-underline"
                            data-testid={`scans-row-kill-${r.id}`}
                            disabled={terminal}
                            aria-disabled={terminal}
                            title={
                              terminal
                                ? "Scan is already in a terminal status."
                                : "Kill this scan (типизированное подтверждение)"
                            }
                            onClick={() => {
                              if (terminal) return;
                              setActionError(null);
                              setActionInfo(null);
                              setKillTarget(r);
                            }}
                          >
                            Kill scan
                          </button>
                        );
                      })()}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between gap-2 text-sm">
        <button
          type="button"
          className="rounded border border-[var(--border)] px-3 py-1.5 disabled:opacity-50"
          disabled={offset <= 0 || !tenantId || isPending}
          onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
        >
          Previous
        </button>
        <span className="text-[var(--text-muted)]">
          Page {pageIndex} / {pageCount}
        </span>
        <button
          type="button"
          className="rounded border border-[var(--border)] px-3 py-1.5 disabled:opacity-50"
          disabled={offset + PAGE_SIZE >= total || !tenantId || isPending}
          onClick={() => setOffset((o) => o + PAGE_SIZE)}
        >
          Next
        </button>
      </div>

      {killTarget && tenantId ? (
        <PerScanKillSwitchDialog
          open={killTarget !== null}
          onOpenChange={(open) => {
            if (!open) setKillTarget(null);
          }}
          scan={{
            id: killTarget.id,
            target_url: killTarget.target,
            status: killTarget.status,
            tenant_id: tenantId,
          }}
          onSuccess={(result) => {
            setKillTarget(null);
            const verb =
              result.status === "cancelled"
                ? "Cancelled"
                : result.status === "skipped_terminal"
                  ? "Already terminal — skipped"
                  : "Not found";
            setActionInfo(`${verb} scan ${result.scanId.slice(0, 8)}…`);
            void loadScans();
          }}
        />
      ) : null}

      <dialog
        id={cancelDialogId}
        className="max-w-md rounded border border-[var(--border)] bg-[var(--bg-primary)] p-4 text-[var(--text-primary)] shadow-lg backdrop:bg-black/60"
      >
        <p className="text-sm">
          Cancel {selectedIds.length} selected scan(s) for this tenant? Non-running scans are
          skipped.
        </p>
        <div className="mt-4 flex justify-end gap-2">
          <button
            type="button"
            className="rounded border border-[var(--border)] px-3 py-1.5 text-sm"
            onClick={() =>
              (document.getElementById(cancelDialogId) as HTMLDialogElement)?.close()
            }
          >
            Back
          </button>
          <button
            type="button"
            className="rounded bg-[var(--accent)] px-3 py-1.5 text-sm font-medium text-white"
            onClick={confirmBulkCancel}
          >
            Confirm cancel
          </button>
        </div>
      </dialog>

      {detailOpen ? (
        <div
          className="fixed inset-0 z-40 flex justify-end bg-black/40"
          role="presentation"
          onClick={closeDetail}
        >
          <div
            className="h-full w-full max-w-lg overflow-y-auto border-l border-[var(--border)] bg-[var(--bg-primary)] p-4 shadow-xl"
            role="dialog"
            aria-modal="true"
            aria-label="Scan details"
            data-testid="scans-detail-drawer"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-2">
              <h2 className="text-base font-semibold text-[var(--text-primary)]">Scan details</h2>
              <button
                type="button"
                className="text-sm text-[var(--accent)] hover:underline"
                data-testid="scans-detail-close"
                onClick={closeDetail}
              >
                Close
              </button>
            </div>
            {detailLoading ? (
              <p className="mt-4 text-sm text-[var(--text-muted)]">Loading…</p>
            ) : null}
            {detailError ? (
              <p className="mt-4 text-sm text-red-300" role="alert">
                {detailError}
              </p>
            ) : null}
            {detail ? (
              <div className="mt-4 space-y-4 text-sm">
                <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[var(--text-secondary)]">
                  <dt className="text-[var(--text-muted)]">ID</dt>
                  <dd className="font-mono text-xs text-[var(--text-primary)]">{detail.id}</dd>
                  <dt className="text-[var(--text-muted)]">Target</dt>
                  <dd className="break-all text-[var(--text-primary)]">{detail.target}</dd>
                  <dt className="text-[var(--text-muted)]">Status</dt>
                  <dd>{detail.status}</dd>
                  <dt className="text-[var(--text-muted)]">Phase</dt>
                  <dd>{detail.phase}</dd>
                  <dt className="text-[var(--text-muted)]">Progress</dt>
                  <dd>{detail.progress}</dd>
                </dl>
                <ExportFormatToggle
                  scanId={detail.id}
                  onDownload={async (format: ExportFormat) => {
                    await downloadFindingsExport(detail.id, format, {
                      tenantId,
                    });
                  }}
                />
                <div>
                  <h3 className="mb-2 font-medium text-[var(--text-primary)]">Tool metrics</h3>
                  {detail.tool_metrics.length === 0 ? (
                    <p className="text-[var(--text-muted)]">No tool run rows recorded.</p>
                  ) : (
                    <div className="overflow-x-auto rounded border border-[var(--border)]">
                      <table className="min-w-full text-left text-xs">
                        <thead className="bg-[var(--bg-secondary)] text-[var(--text-secondary)]">
                          <tr>
                            <th className="px-2 py-1">Tool</th>
                            <th className="px-2 py-1">Status</th>
                            <th className="px-2 py-1">Duration (s)</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-[var(--border)]">
                          {detail.tool_metrics.map((m, ti) => (
                            <tr key={`${m.tool_name}-${ti}`}>
                              <td className="px-2 py-1">{m.tool_name}</td>
                              <td className="px-2 py-1">{m.status}</td>
                              <td className="px-2 py-1">
                                {m.duration_sec != null ? m.duration_sec.toFixed(1) : "—"}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
                <div>
                  <h3 className="mb-2 font-medium text-[var(--text-primary)]">Error summary</h3>
                  {detail.error_summary.length === 0 ? (
                    <p className="text-[var(--text-muted)]">No error events.</p>
                  ) : (
                    <ul className="space-y-2">
                      {detail.error_summary.map((e, i) => (
                        <li
                          key={`${e.at}-${i}`}
                          className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-2 py-1.5"
                        >
                          <div className="text-xs text-[var(--text-muted)]">
                            {formatDt(e.at)}
                            {e.phase ? ` · ${e.phase}` : ""}
                          </div>
                          <div className="text-[var(--text-primary)]">{e.message}</div>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function AdminScansClient() {
  return (
    <AdminRouteGuard minimumRole="admin">
      <AdminScansBody />
    </AdminRouteGuard>
  );
}
