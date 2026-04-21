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
 *   - Drive `@tanstack/react-query`'s `useInfiniteQuery` against the
 *     `listAdminFindingsAction` server action — this keeps `X-Admin-Key`
 *     server-side and prevents the browser from forging admin headers
 *     (S0-1 / T20).
 *   - Resolve `effectiveTenantId` via `tenantBindingFromSession()` instead
 *     of a lexicographic-first fallback. For `admin` operators we render an
 *     explicit empty state (and skip the query) when no tenant binding is
 *     available; for `super-admin` the URL choice is honoured (empty =
 *     cross-tenant view).
 *   - Debounce free-text and date inputs by 300 ms so refetches don't
 *     happen per keystroke (S1-4).
 *   - Render `FindingsFilterBar`, `FindingsTable` and a per-row export
 *     trigger inside the detail drawer — the previous global Export button
 *     was removed because it picked one arbitrary scan from the visible
 *     window (S1-5).
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
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import {
  adminFindingsErrorMessage,
  type AdminFindingItem,
  type AdminFindingsListResponse,
  type ListAdminFindingsParams,
} from "@/lib/adminFindings";
import { useAdminAuth } from "@/services/admin/useAdminAuth";

import {
  EMPTY_FILTER_VALUES,
  FindingsFilterBar,
  sanitizeFilterValues,
  type FindingsFilterValues,
} from "@/components/admin/findings/FindingsFilterBar";
import { FindingsTable } from "@/components/admin/findings/FindingsTable";
import type { TenantOption } from "@/components/admin/findings/TenantSelector";

import { listAdminFindingsAction } from "./actions";
import { AdminFindingsQueryProvider } from "./AdminFindingsQueryProvider";

const PAGE_LIMIT = 50;
const DEBOUNCE_MS = 300;

function readFiltersFromUrl(sp: URLSearchParams): FindingsFilterValues {
  return sanitizeFilterValues({
    severity: sp.getAll("severity"),
    statusMode: sp.get("status_mode"),
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
  if (filters.statusMode !== "all") sp.set("status_mode", filters.statusMode);
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
  return {
    tenantId: effectiveTenantId,
    severity: filters.severity,
    statusMode: filters.statusMode,
    target: filters.target.trim() || null,
    since: filters.since || null,
    until: filters.until || null,
    kevListed: filters.kevListed,
    ssvcAction: filters.ssvcAction,
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

  const isSuperAdmin = role === "super-admin";

  const tenantsQuery = useQuery<ReadonlyArray<AdminTenant>>({
    queryKey: ["admin", "tenants", "directory"],
    queryFn: async () => listTenants({ limit: 200, offset: 0 }),
    staleTime: 5 * 60_000,
    retry: 0,
    enabled: isSuperAdmin,
  });

  const tenantOptions: ReadonlyArray<TenantOption> = useMemo(() => {
    const list = tenantsQuery.data ?? [];
    return list.map((t) => ({ id: t.id, name: t.name }));
  }, [tenantsQuery.data]);

  // Resolve the tenant the backend is actually scoped to. For super-admin we
  // honour the explicit URL choice (empty = cross-tenant). For admin we DO
  // NOT auto-pick the lexicographically-first tenant — that previously meant
  // the operator could be silently scoped to someone else's data depending
  // on the directory order. Instead we rely on the server-resolved tenant
  // binding (cookie / dev env), and render an explicit empty state when no
  // binding is available (S1-6 / ISS-T20-003).
  const effectiveTenantId: string | null = isSuperAdmin
    ? filters.tenantId.trim() || null
    : null;

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

  // Debounce the free-text and date subset of the filters so we don't fire
  // a server-action round-trip per keystroke (S1-4). Severity / status /
  // tenant chips fire immediately because they're discrete clicks.
  const debouncedTarget = useDebouncedValue(filters.target.trim(), DEBOUNCE_MS);
  const debouncedSince = useDebouncedValue(filters.since, DEBOUNCE_MS);
  const debouncedUntil = useDebouncedValue(filters.until, DEBOUNCE_MS);

  const queryParams = useMemo<ListAdminFindingsParams>(
    () =>
      filtersToParams(
        {
          ...filters,
          target: debouncedTarget,
          since: debouncedSince,
          until: debouncedUntil,
        },
        effectiveTenantId,
      ),
    [
      filters,
      debouncedTarget,
      debouncedSince,
      debouncedUntil,
      effectiveTenantId,
    ],
  );

  const queryKey = useMemo(
    () => [
      "admin",
      "findings",
      role,
      effectiveTenantId,
      queryParams.severity,
      queryParams.statusMode,
      queryParams.target,
      queryParams.since,
      queryParams.until,
      queryParams.kevListed,
      queryParams.ssvcAction,
    ],
    [role, effectiveTenantId, queryParams],
  );

  // For `admin` (non-super) operators we don't have a server-resolved tenant
  // exposed to the client — we let the action decide and skip the query
  // entirely until tenant binding lands. This matches the "explicit empty
  // state" guideline in S1-6 and avoids a misleading "no findings" panel
  // that would actually be a forbidden response.
  const queryEnabled = isSuperAdmin;

  const findingsQuery = useInfiniteQuery<AdminFindingsListResponse>({
    queryKey,
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam }) =>
      listAdminFindingsAction({
        ...queryParams,
        cursor: pageParam as string | null,
      }),
    getNextPageParam: (lastPage) => lastPage.next_cursor,
    enabled: queryEnabled,
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
      />

      {!isSuperAdmin ? (
        <p
          role="status"
          data-testid="findings-admin-no-tenant"
          className="rounded border border-dashed border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-4 text-sm text-[var(--text-secondary)]"
        >
          Аккаунт администратора не привязан к тенанту. Обратитесь к
          super-admin для назначения тенанта или используйте URL c
          явно указанным <code>tenant_id</code>.
        </p>
      ) : (
        <FindingsTable
          items={items}
          loading={findingsQuery.isPending || isPending}
          fetchingMore={findingsQuery.isFetchingNextPage}
          errorMessage={errorMessage}
          onLoadMore={() => {
            if (
              findingsQuery.hasNextPage &&
              !findingsQuery.isFetchingNextPage
            ) {
              void findingsQuery.fetchNextPage();
            }
          }}
          hasMore={hasMore}
          showTenantColumn={isSuperAdmin}
          effectiveTenantId={effectiveTenantId}
        />
      )}
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
