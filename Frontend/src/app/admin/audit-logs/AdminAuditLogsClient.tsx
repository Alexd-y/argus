"use client";

/**
 * `AdminAuditLogsClient` — orchestrator for the admin audit-log viewer +
 * chain-integrity verification page (T22).
 *
 * Mirrors `AdminFindingsClient` (T20) so the architectural pattern stays
 * consistent across admin features:
 *   - Role gate via `<AdminRouteGuard minimumRole="admin">`.
 *   - Filters hydrate from `URLSearchParams` and persist back via shallow
 *     `router.replace` so the URL is shareable.
 *   - All data goes through `"use server"` actions; the browser never owns
 *     `X-Admin-Key`.
 *   - Free-text and date inputs are debounced (300 ms) so we don't fire
 *     a server-action round-trip per keystroke.
 *   - Tenant column / selector visible only for `super-admin`.
 *   - `admin` operators without a session-bound tenant get an explicit empty
 *     state instead of a misleading "no rows" panel — same pattern as T20.
 *
 * Chain integrity:
 *   - Dedicated `useMutation` so the verify-chain action is a one-shot fire,
 *     decoupled from the list query's React Query cache.
 *   - The latest verdict is held in component state and rendered by
 *     `<ChainVerifyResult>`. The "scroll to drift" affordance is wired
 *     through an imperative table handle so we don't have to leak the row
 *     virtualizer outside the table.
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  useTransition,
} from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useInfiniteQuery, useMutation, useQuery } from "@tanstack/react-query";

import { listTenants, type AdminTenant } from "@/app/admin/tenants/actions";
import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import {
  adminAuditLogsErrorMessage,
  type AuditChainVerifyResponse,
  type AuditLogItem,
  type AuditLogsListResponse,
  type ListAdminAuditLogsParams,
  type VerifyAuditChainParams,
} from "@/lib/adminAuditLogs";
import { useAdminAuth } from "@/services/admin/useAdminAuth";

import {
  AuditLogsFilterBar,
  EMPTY_AUDIT_FILTER_VALUES,
  sanitizeAuditFilterValues,
  type AuditLogsFilterValues,
} from "@/components/admin/audit-logs/AuditLogsFilterBar";
import {
  AuditLogsTable,
  type AuditLogsTableHandle,
} from "@/components/admin/audit-logs/AuditLogsTable";
import { ChainVerifyResult } from "@/components/admin/audit-logs/ChainVerifyResult";
import type { TenantOption } from "@/components/admin/findings/TenantSelector";

import {
  listAdminAuditLogsAction,
  verifyAuditChainAction,
} from "./actions";
import { AdminAuditLogsQueryProvider } from "./AdminAuditLogsQueryProvider";

const PAGE_LIMIT = 50;
const DEBOUNCE_MS = 300;

function readFiltersFromUrl(sp: URLSearchParams): AuditLogsFilterValues {
  return sanitizeAuditFilterValues({
    since: sp.get("since"),
    until: sp.get("until"),
    tenantId: sp.get("tenant_id"),
    eventType: sp.get("event_type"),
    actorSubject: sp.get("actor_subject"),
  });
}

function writeFiltersToUrl(filters: AuditLogsFilterValues): URLSearchParams {
  const sp = new URLSearchParams();
  if (filters.since) sp.set("since", filters.since);
  if (filters.until) sp.set("until", filters.until);
  if (filters.tenantId.trim()) sp.set("tenant_id", filters.tenantId.trim());
  if (filters.eventType.trim()) sp.set("event_type", filters.eventType.trim());
  if (filters.actorSubject.trim()) {
    sp.set("actor_subject", filters.actorSubject.trim());
  }
  return sp;
}

function filtersToListParams(
  filters: AuditLogsFilterValues,
  effectiveTenantId: string | null,
): ListAdminAuditLogsParams {
  return {
    tenantId: effectiveTenantId,
    eventType: filters.eventType.trim() || null,
    actorSubject: filters.actorSubject.trim() || null,
    since: filters.since || null,
    until: filters.until || null,
    limit: PAGE_LIMIT,
  };
}

function filtersToVerifyParams(
  filters: AuditLogsFilterValues,
  effectiveTenantId: string | null,
): VerifyAuditChainParams {
  return {
    tenantId: effectiveTenantId,
    eventType: filters.eventType.trim() || null,
    since: filters.since || null,
    until: filters.until || null,
  };
}

function buildExportUrl(
  filters: AuditLogsFilterValues,
  effectiveTenantId: string | null,
  format: "csv" | "json",
): string {
  const sp = new URLSearchParams();
  sp.set("format", format);
  if (filters.since) sp.set("since", filters.since);
  if (filters.until) sp.set("until", filters.until);
  if (filters.eventType.trim()) sp.set("event_type", filters.eventType.trim());
  if (filters.actorSubject.trim()) sp.set("q", filters.actorSubject.trim());
  if (effectiveTenantId) sp.set("tenant_id", effectiveTenantId);
  return `/admin/audit-logs/export?${sp.toString()}`;
}

function AdminAuditLogsBody() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { role } = useAdminAuth({ minimumRole: "admin" });
  const [isPending, startTransition] = useTransition();
  const tableHandleRef = useRef<AuditLogsTableHandle | null>(null);

  const [filters, setFilters] = useState<AuditLogsFilterValues>(() =>
    readFiltersFromUrl(new URLSearchParams(searchParams?.toString() ?? "")),
  );

  const [verifyResult, setVerifyResult] =
    useState<AuditChainVerifyResponse | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);

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

  const effectiveTenantId: string | null = isSuperAdmin
    ? filters.tenantId.trim() || null
    : null;

  // Sync URL with filter state. For non-super-admin operators we strip the
  // tenant id from the URL — they cannot widen scope and the URL would just
  // confuse later attempts to share the link.
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
      router.replace(
        next ? `/admin/audit-logs?${next}` : "/admin/audit-logs",
        { scroll: false },
      );
    });
  }, [filters, isSuperAdmin, router, searchParams]);

  const debouncedSince = useDebouncedValue(filters.since, DEBOUNCE_MS);
  const debouncedUntil = useDebouncedValue(filters.until, DEBOUNCE_MS);
  const debouncedEventType = useDebouncedValue(
    filters.eventType.trim(),
    DEBOUNCE_MS,
  );
  const debouncedActor = useDebouncedValue(
    filters.actorSubject.trim(),
    DEBOUNCE_MS,
  );

  const queryParams = useMemo<ListAdminAuditLogsParams>(
    () =>
      filtersToListParams(
        {
          ...filters,
          since: debouncedSince,
          until: debouncedUntil,
          eventType: debouncedEventType,
          actorSubject: debouncedActor,
        },
        effectiveTenantId,
      ),
    [
      filters,
      debouncedSince,
      debouncedUntil,
      debouncedEventType,
      debouncedActor,
      effectiveTenantId,
    ],
  );

  const queryKey = useMemo(
    () => [
      "admin",
      "audit-logs",
      role,
      effectiveTenantId,
      queryParams.since,
      queryParams.until,
      queryParams.eventType,
      queryParams.actorSubject,
    ],
    [role, effectiveTenantId, queryParams],
  );

  // Enable the query for both `admin` and `super-admin`. The action resolves
  // the effective tenant server-side from the session cookie / dev env;
  // the client can't observe the binding directly. Admin operators without
  // a bound tenant simply receive an empty page — UX-acceptable for the
  // audit viewer because the alternative (suppressing the query entirely
  // like T20 does for findings) would also hide the data for admins who
  // ARE bound. The drawer / chain-verify UX still remains useful even when
  // the empty state is shown.
  const queryEnabled = role === "admin" || role === "super-admin";

  const auditQuery = useInfiniteQuery<AuditLogsListResponse>({
    queryKey,
    initialPageParam: null as string | null,
    queryFn: async ({ pageParam }) =>
      listAdminAuditLogsAction({
        ...queryParams,
        cursor: pageParam as string | null,
      }),
    getNextPageParam: (lastPage) => lastPage.next_cursor,
    enabled: queryEnabled,
  });

  const verifyMutation = useMutation<
    AuditChainVerifyResponse,
    Error,
    VerifyAuditChainParams
  >({
    mutationFn: async (params) => verifyAuditChainAction(params),
    onMutate: () => {
      setVerifyError(null);
      setVerifyResult(null);
    },
    onSuccess: (data) => {
      setVerifyResult(data);
      setVerifyError(null);
    },
    onError: (err) => {
      setVerifyResult(null);
      setVerifyError(adminAuditLogsErrorMessage(err));
    },
  });

  const handleVerifyChain = useCallback(() => {
    verifyMutation.mutate(filtersToVerifyParams(filters, effectiveTenantId));
  }, [verifyMutation, filters, effectiveTenantId]);

  const handleResetFilters = useCallback(() => {
    setFilters({ ...EMPTY_AUDIT_FILTER_VALUES });
  }, []);

  const handleExport = useCallback(
    (format: "csv" | "json") => {
      if (typeof window === "undefined") return;
      const url = buildExportUrl(filters, effectiveTenantId, format);
      window.location.assign(url);
    },
    [filters, effectiveTenantId],
  );

  const pages = auditQuery.data?.pages;
  const items: ReadonlyArray<AuditLogItem> = useMemo(() => {
    if (!pages) return [];
    return pages.flatMap((p) => p.items);
  }, [pages]);

  const errorMessage =
    auditQuery.error != null
      ? adminAuditLogsErrorMessage(auditQuery.error)
      : null;

  const totalDisplayed = items.length;
  const total =
    pages && pages.length > 0 ? pages[pages.length - 1].total : 0;
  const hasMore = Boolean(auditQuery.hasNextPage);

  // Whether the drift event currently lives in the loaded set — controls
  // whether the "Прокрутить к записи" button is rendered.
  const driftEventId = verifyResult?.drift_event_id ?? null;
  const canJumpToDrift = useMemo(() => {
    if (!driftEventId) return false;
    return items.some((it) => it.id === driftEventId);
  }, [items, driftEventId]);

  const handleJumpToDrift = useCallback((eventId: string) => {
    tableHandleRef.current?.scrollToId(eventId);
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">
            Audit log
          </h1>
          <p className="text-sm text-[var(--text-secondary)]">
            История действий админ-консоли. Цепочка SHA-256 (T25) проверяется
            кнопкой «Verify chain integrity».
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-[var(--text-muted)]">
          <span data-testid="audit-counter">
            {totalDisplayed} / {total}
          </span>
          {auditQuery.isFetching ? <span>· загрузка…</span> : null}
        </div>
      </div>

      <AuditLogsFilterBar
        value={filters}
        onChange={setFilters}
        onReset={handleResetFilters}
        onVerifyChain={handleVerifyChain}
        onExport={handleExport}
        role={role}
        tenants={tenantOptions}
        disabled={
          (auditQuery.isFetching && pages == null) ||
          verifyMutation.isPending ||
          isPending
        }
        verifying={verifyMutation.isPending}
      />

      <ChainVerifyResult
        result={verifyResult}
        errorMessage={verifyError}
        verifying={verifyMutation.isPending}
        onJumpToDrift={handleJumpToDrift}
        canJumpToDrift={canJumpToDrift}
        onDismiss={() => {
          setVerifyResult(null);
          setVerifyError(null);
        }}
      />

      <AuditLogsTable
        ref={tableHandleRef}
        items={items}
        loading={auditQuery.isPending || isPending}
        fetchingMore={auditQuery.isFetchingNextPage}
        errorMessage={errorMessage}
        onLoadMore={() => {
          if (auditQuery.hasNextPage && !auditQuery.isFetchingNextPage) {
            void auditQuery.fetchNextPage();
          }
        }}
        hasMore={hasMore}
        showTenantColumn={isSuperAdmin}
        highlightId={driftEventId}
      />

      {role === "admin" && totalDisplayed === 0 && !auditQuery.isFetching ? (
        <p
          role="status"
          data-testid="audit-admin-tenant-hint"
          className="rounded border border-dashed border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-3 text-xs text-[var(--text-secondary)]"
        >
          Если ожидаемых записей нет — проверьте, что аккаунт администратора
          привязан к тенанту и фильтр по диапазону времени включает нужный
          период.
        </p>
      ) : null}
    </div>
  );
}

export function AdminAuditLogsClient() {
  return (
    <AdminRouteGuard minimumRole="admin">
      <AdminAuditLogsQueryProvider>
        <AdminAuditLogsBody />
      </AdminAuditLogsQueryProvider>
    </AdminRouteGuard>
  );
}
