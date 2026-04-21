"use client";

/**
 * `AdminFindingsClient` — orchestrator for the cross-tenant findings triage
 * page (T20).
 *
 * Responsibilities:
 *   - Read role from `useAdminAuth()` and refuse the page (via `AdminRouteGuard`)
 *     for anything below `admin`.
 *   - Hydrate filter state from `URLSearchParams`, persist edits back as a
 *     shallow `router.replace` so the URL is shareable.
 *   - Drive `@tanstack/react-query`'s `useInfiniteQuery` against `listAdminFindings`,
 *     stitching paginated cursors into a single sorted list.
 *   - Fetch the tenant directory once via the server action so super-admins get
 *     a typed dropdown (free-text fallback when the directory is empty).
 *   - Render `FindingsFilterBar`, `FindingsTable` and the export popover that
 *     reuses `ExportFormatToggle` from T23.
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useState,
  useTransition,
} from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";

import { listTenants, type AdminTenant } from "@/app/admin/tenants/actions";
import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import { ExportFormatToggle } from "@/components/admin/ExportFormatToggle";
import {
  adminFindingsErrorMessage,
  listAdminFindings,
  type AdminFindingItem,
  type AdminFindingsListResponse,
  type FindingSeverity,
  type FindingStatus,
  type ListAdminFindingsParams,
  type SsvcAction,
} from "@/lib/adminFindings";
import {
  downloadFindingsExport,
  type ExportFormat,
} from "@/lib/findingsExport";
import { useAdminAuth } from "@/services/admin/useAdminAuth";

import {
  EMPTY_FILTER_VALUES,
  FindingsFilterBar,
  sanitizeFilterValues,
  type FindingsFilterValues,
} from "@/components/admin/findings/FindingsFilterBar";
import { FindingsTable } from "@/components/admin/findings/FindingsTable";
import type { TenantOption } from "@/components/admin/findings/TenantSelector";

import { AdminFindingsQueryProvider } from "./AdminFindingsQueryProvider";

const PAGE_LIMIT = 50;

function readFiltersFromUrl(sp: URLSearchParams): FindingsFilterValues {
  return sanitizeFilterValues({
    severity: sp.getAll("severity"),
    status: sp.getAll("status"),
    target: sp.get("target") ?? "",
    since: sp.get("since") ?? "",
    until: sp.get("until") ?? "",
    tenantId: sp.get("tenant_id") ?? "",
    kevListed: sp.get("kev_listed"),
    ssvcAction: sp.get("ssvc_action"),
  });
}

function writeFiltersToUrl(filters: FindingsFilterValues): URLSearchParams {
  const sp = new URLSearchParams();
  for (const sev of filters.severity) sp.append("severity", sev);
  for (const st of filters.status) sp.append("status", st);
  if (filters.target.trim()) sp.set("target", filters.target.trim());
  if (filters.since) sp.set("since", filters.since);
  if (filters.until) sp.set("until", filters.until);
  if (filters.tenantId.trim()) sp.set("tenant_id", filters.tenantId.trim());
  if (filters.kevListed === true) sp.set("kev_listed", "true");
  if (filters.kevListed === false) sp.set("kev_listed", "false");
  if (filters.ssvcAction) sp.set("ssvc_action", filters.ssvcAction);
  return sp;
}

function filtersToParams(
  filters: FindingsFilterValues,
  effectiveTenantId: string | null,
): ListAdminFindingsParams {
  const severity: ReadonlyArray<FindingSeverity> = filters.severity;
  const status: ReadonlyArray<FindingStatus> = filters.status;
  const ssvc: SsvcAction | null = filters.ssvcAction;
  return {
    tenantId: effectiveTenantId,
    severity,
    status,
    target: filters.target.trim() || null,
    since: filters.since || null,
    until: filters.until || null,
    kevListed: filters.kevListed,
    ssvcAction: ssvc,
    limit: PAGE_LIMIT,
  };
}

function detectFeatureAvailability(
  pages: ReadonlyArray<AdminFindingsListResponse> | undefined,
): { kev: boolean; ssvc: boolean } {
  if (!pages || pages.length === 0) {
    return { kev: false, ssvc: false };
  }
  let kev = false;
  let ssvc = false;
  for (const page of pages) {
    for (const item of page.items) {
      if (item.kev_listed !== null) kev = true;
      if (item.ssvc_action !== null) ssvc = true;
      if (kev && ssvc) return { kev, ssvc };
    }
  }
  return { kev, ssvc };
}

function AdminFindingsBody() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { role } = useAdminAuth({ minimumRole: "admin" });
  const [isPending, startTransition] = useTransition();

  const [filters, setFilters] = useState<FindingsFilterValues>(() =>
    readFiltersFromUrl(new URLSearchParams(searchParams?.toString() ?? "")),
  );
  const [exportOpen, setExportOpen] = useState(false);
  const [exportError, setExportError] = useState<string | null>(null);

  const isSuperAdmin = role === "super-admin";

  const tenantsQuery = useQuery<ReadonlyArray<AdminTenant>>({
    queryKey: ["admin", "tenants", "directory"],
    queryFn: async () => listTenants({ limit: 200, offset: 0 }),
    staleTime: 5 * 60_000,
    retry: 0,
  });

  const tenantOptions: ReadonlyArray<TenantOption> = useMemo(() => {
    const list = tenantsQuery.data ?? [];
    return list.map((t) => ({ id: t.id, name: t.name }));
  }, [tenantsQuery.data]);

  // Resolve the tenant the backend is actually scoped to. For super-admin we
  // honour the explicit URL choice (empty = cross-tenant). For admin/operator
  // we always pin to the first tenant we know about — the backend rejects
  // mismatches with 403, so this avoids needless errors when the URL is
  // hand-edited and keeps tenantId out of the filter UI completely.
  const effectiveTenantId: string | null = useMemo(() => {
    if (isSuperAdmin) {
      return filters.tenantId.trim() || null;
    }
    return tenantOptions[0]?.id ?? null;
  }, [filters.tenantId, isSuperAdmin, tenantOptions]);

  // Sync URL whenever filters change. We strip tenantId for non-super-admin
  // roles so the URL never advertises a tenant the operator can't switch.
  useEffect(() => {
    const sp = writeFiltersToUrl(
      isSuperAdmin ? filters : { ...filters, tenantId: "" },
    );
    const next = sp.toString();
    const current = (searchParams?.toString() ?? "")
      .split("&")
      .filter(Boolean)
      .sort()
      .join("&");
    const proposed = next.split("&").filter(Boolean).sort().join("&");
    if (current === proposed) return;
    startTransition(() => {
      router.replace(next ? `/admin/findings?${next}` : "/admin/findings", {
        scroll: false,
      });
    });
  }, [filters, isSuperAdmin, router, searchParams]);

  const queryKey = useMemo(
    () => [
      "admin",
      "findings",
      role,
      effectiveTenantId,
      filters.severity,
      filters.status,
      filters.target.trim(),
      filters.since,
      filters.until,
      filters.kevListed,
      filters.ssvcAction,
    ],
    [
      role,
      effectiveTenantId,
      filters.severity,
      filters.status,
      filters.target,
      filters.since,
      filters.until,
      filters.kevListed,
      filters.ssvcAction,
    ],
  );

  const findingsQuery = useInfiniteQuery<AdminFindingsListResponse>({
    queryKey,
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam, signal }) =>
      listAdminFindings(
        {
          ...filtersToParams(filters, effectiveTenantId),
          cursor: pageParam as string | null,
        },
        {
          signal,
          operatorRole: role,
          operatorTenantId: effectiveTenantId,
        },
      ),
    getNextPageParam: (lastPage) => lastPage.next_cursor,
    enabled: !isSuperAdmin ? Boolean(effectiveTenantId) : true,
  });

  const pages = findingsQuery.data?.pages;
  const items: ReadonlyArray<AdminFindingItem> = useMemo(() => {
    if (!pages) return [];
    return pages.flatMap((p) => p.items);
  }, [pages]);

  const featureAvailability = useMemo(
    () => detectFeatureAvailability(pages),
    [pages],
  );

  const handleResetFilters = useCallback(() => {
    setFilters({ ...EMPTY_FILTER_VALUES });
  }, []);

  const handleExportDownload = useCallback(
    async (format: ExportFormat) => {
      setExportError(null);
      const item = items[0];
      if (!item) {
        setExportError("Нет findings для экспорта.");
        return;
      }
      try {
        await downloadFindingsExport(item.scan_id, format, {
          tenantId: effectiveTenantId ?? undefined,
        });
      } catch {
        setExportError(
          "Не удалось скачать экспорт. Повторите попытку.",
        );
      }
    },
    [effectiveTenantId, items],
  );

  const errorMessage =
    findingsQuery.error != null
      ? adminFindingsErrorMessage(findingsQuery.error)
      : null;

  const totalDisplayed = items.length;
  const total =
    pages && pages.length > 0 ? pages[pages.length - 1].total : 0;
  const hasMore = Boolean(findingsQuery.hasNextPage);

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">
            Global findings triage
          </h1>
          <p className="text-sm text-[var(--text-secondary)]">
            Сортировка по приоритету SSVC; KEV и SSVC станут активными после
            подключения intel-таблиц (Phase 2).
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-[var(--text-muted)]">
          <span data-testid="findings-counter">
            {totalDisplayed} / {total}
          </span>
          {findingsQuery.isFetching ? <span>· загрузка…</span> : null}
        </div>
      </div>

      <FindingsFilterBar
        value={filters}
        onChange={setFilters}
        onReset={handleResetFilters}
        role={role}
        tenants={tenantOptions}
        kevAvailable={featureAvailability.kev}
        ssvcAvailable={featureAvailability.ssvc}
        disabled={findingsQuery.isFetching && pages == null}
        slotEnd={
          <div className="relative">
            <button
              type="button"
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-1.5 text-sm text-[var(--text-secondary)] hover:border-[var(--accent)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
              aria-expanded={exportOpen}
              aria-haspopup="dialog"
              data-testid="findings-export-toggle"
              onClick={() => setExportOpen((v) => !v)}
              disabled={items.length === 0}
            >
              Экспорт
            </button>
            {exportOpen ? (
              <div
                role="dialog"
                aria-label="Экспорт findings"
                data-testid="findings-export-popover"
                className="absolute right-0 top-full z-20 mt-1 w-80 rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-2 shadow-lg"
                onKeyDown={(e) => {
                  if (e.key === "Escape") setExportOpen(false);
                }}
              >
                <ExportFormatToggle
                  scanId={items[0]?.scan_id ?? ""}
                  onDownload={handleExportDownload}
                />
                {exportError ? (
                  <p
                    role="alert"
                    className="mt-2 text-xs text-red-400"
                    data-testid="findings-export-error"
                  >
                    {exportError}
                  </p>
                ) : null}
                <p className="mt-2 text-[11px] text-[var(--text-muted)]">
                  Экспорт работает на уровне scan; будет выгружен scan текущего
                  верхнего finding.
                </p>
              </div>
            ) : null}
          </div>
        }
      />

      {!isSuperAdmin && !effectiveTenantId ? (
        <p
          role="status"
          className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-4 text-sm text-[var(--text-muted)]"
        >
          Дождитесь загрузки tenant и обновите страницу.
        </p>
      ) : null}

      <FindingsTable
        items={items}
        loading={findingsQuery.isPending || isPending}
        fetchingMore={findingsQuery.isFetchingNextPage}
        errorMessage={errorMessage}
        onLoadMore={() => {
          if (findingsQuery.hasNextPage && !findingsQuery.isFetchingNextPage) {
            void findingsQuery.fetchNextPage();
          }
        }}
        hasMore={hasMore}
        showTenantColumn={isSuperAdmin}
      />
    </div>
  );
}

export function AdminFindingsClient() {
  return (
    <AdminRouteGuard minimumRole="admin">
      <AdminFindingsQueryProvider>
        <AdminFindingsBody />
      </AdminFindingsQueryProvider>
    </AdminRouteGuard>
  );
}
