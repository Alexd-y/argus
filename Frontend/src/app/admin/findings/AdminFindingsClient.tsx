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
import {
  useInfiniteQuery,
  useQuery,
  useQueryClient,
} from "@tanstack/react-query";

import { listTenants, type AdminTenant } from "@/app/admin/tenants/actions";
import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import { useDebouncedValue } from "@/hooks/useDebouncedValue";
import {
  adminFindingsErrorMessage,
  bulkActionErrorMessage,
  BulkFindingsActionError,
  MAX_BULK_FINDING_IDS,
  type AdminFindingItem,
  type AdminFindingsListResponse,
  type BulkActionResult,
  type BulkFindingTarget,
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
import {
  BulkActionsToolbar,
  DEFAULT_BULK_AVAILABILITY,
  type BulkActionAvailability,
  type BulkActionKind,
} from "@/components/admin/findings/BulkActionsToolbar";
import {
  BulkActionDialog,
  type BulkActionPayload,
} from "@/components/admin/findings/BulkActionDialog";

import {
  bulkMarkFalsePositiveFindingsAction,
  bulkSuppressFindingsAction,
  listAdminFindingsAction,
} from "./actions";
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

/**
 * Banner messages emitted by `runBulkAction` after the server-action call
 * resolves. Kept as a closed taxonomy on the UI side so the renderer can
 * map state → colour without parsing free-form strings.
 */
type BulkActionBanner =
  | {
      readonly tone: "success";
      readonly message: string;
    }
  | {
      readonly tone: "warning";
      readonly message: string;
    }
  | {
      readonly tone: "error";
      readonly message: string;
    };

function buildSuccessBanner(
  result: BulkActionResult,
  totalRequested: number,
): BulkActionBanner {
  // "Partial" is anything where at least one id wasn't applied — could be
  // permission drift between selection and execution, an item that was
  // already suppressed, or a backend-side validation rejection. We surface
  // the count + the closed-taxonomy hint so operators can re-triage.
  const failedCount = result.failed_ids.length;
  const partial =
    result.affected_count < totalRequested ||
    failedCount > 0 ||
    result.skipped_count > 0;
  if (!partial) {
    return {
      tone: "success",
      message: `Применено к ${result.affected_count} findings.`,
    };
  }
  return {
    tone: "warning",
    message: `Применено к ${result.affected_count} из ${totalRequested}; пропущено уже обработанных ${result.skipped_count}, не применено к ${failedCount}.`,
  };
}

function bannerToneClass(tone: BulkActionBanner["tone"]): string {
  if (tone === "success") {
    return "border-emerald-500/60 bg-emerald-500/10 text-emerald-200";
  }
  if (tone === "warning") {
    // keep: result banner is a 3-tone family (success/warning/error)
    // using soft `*-500/10` tints. The yellow-500 entry is paired with
    // emerald + red as a status palette, not a warning-action fill.
    // `--warning-strong` is reserved for confirm CTAs (see
    // ai_docs/architecture/design-tokens.md §3.5).
    return "border-yellow-500/60 bg-yellow-500/10 text-yellow-200";
  }
  return "border-red-500/60 bg-red-500/10 text-red-200";
}

function AdminFindingsBody() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const { role } = useAdminAuth({ minimumRole: "admin" });
  const [isPending, startTransition] = useTransition();
  const queryClient = useQueryClient();

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

  // ── Bulk selection (T21) ──────────────────────────────────────────────
  // Use a `Set<string>` to keep add/remove O(1) for very large selections.
  // We persist ids across pagination loads so the operator can keep
  // building a multi-page selection — but we prune ids that fall out of
  // the materialised list (e.g. status changed after a refetch); leaving
  // them in would let the server reject the bulk call wholesale.
  const [selectedIds, setSelectedIds] = useState<ReadonlySet<string>>(
    () => new Set(),
  );
  const [activeBulkAction, setActiveBulkAction] =
    useState<BulkActionKind | null>(null);
  const [bulkSubmitting, setBulkSubmitting] = useState<boolean>(false);
  const [bulkDialogError, setBulkDialogError] = useState<string | null>(null);
  const [bulkBanner, setBulkBanner] = useState<BulkActionBanner | null>(null);

  // Build a tenant lookup for selected ids — required because both
  // suppress and mark-FP server actions take `BulkFindingTarget[]` (id +
  // tenant_id) so we can fan out per-tenant when super-admins select
  // across boundaries.
  const itemTenantById = useMemo(() => {
    const map = new Map<string, string>();
    for (const item of items) map.set(item.id, item.tenant_id);
    return map;
  }, [items]);

  // Prune ids that no longer exist in the loaded pages. We keep ids
  // we haven't materialised yet (e.g. selected on page 1, currently on
  // page 2) — but only as long as the loaded page set still references
  // them. The simple rule: if items.length grew but a previously-known
  // id is gone, drop it. Implemented by intersecting against the union
  // of historically-seen ids (cheap because Set ops are O(N)).
  useEffect(() => {
    if (selectedIds.size === 0) return;
    let changed = false;
    const next = new Set<string>();
    for (const id of selectedIds) {
      if (itemTenantById.has(id)) {
        next.add(id);
      } else {
        changed = true;
      }
    }
    if (changed) setSelectedIds(next);
  }, [itemTenantById, selectedIds]);

  const handleToggleSelection = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const handleToggleAll = useCallback(
    (visibleIds: ReadonlyArray<string>) => {
      setSelectedIds((prev) => {
        const allSelected =
          visibleIds.length > 0 && visibleIds.every((id) => prev.has(id));
        const next = new Set(prev);
        if (allSelected) {
          for (const id of visibleIds) next.delete(id);
        } else {
          for (const id of visibleIds) next.add(id);
        }
        return next;
      });
    },
    [],
  );

  const handleClearSelection = useCallback(() => {
    setSelectedIds(new Set());
    setBulkBanner(null);
  }, []);

  const openBulkDialog = useCallback((kind: BulkActionKind) => {
    setBulkDialogError(null);
    setActiveBulkAction(kind);
  }, []);

  const closeBulkDialog = useCallback(() => {
    if (bulkSubmitting) return;
    setActiveBulkAction(null);
    setBulkDialogError(null);
  }, [bulkSubmitting]);

  const bulkAvailability: BulkActionAvailability = DEFAULT_BULK_AVAILABILITY;

  // Selection mode is on for both admin and super-admin. Operator role
  // can never reach this body (AdminRouteGuard rejects below admin) —
  // the explicit `false` for operator below is defensive belt-and-braces
  // in case the guard is ever loosened upstream.
  const selectionMode = role === "admin" || role === "super-admin";

  // Admin without a server-side tenant binding sees the empty state
  // already (no FindingsTable at all). For super-admin, the bulk
  // toolbar should always be available — fan-out across tenants is
  // handled by the server action.
  const bulkDisabledReason: string | null = null;

  const runBulkAction = useCallback(
    async (payload: BulkActionPayload): Promise<void> => {
      const ids = Array.from(selectedIds);
      if (ids.length === 0) {
        setBulkDialogError("Выберите хотя бы один finding.");
        return;
      }
      if (ids.length > MAX_BULK_FINDING_IDS) {
        setBulkDialogError(
          `Можно подавить не более ${MAX_BULK_FINDING_IDS} findings за раз.`,
        );
        return;
      }
      const targets: BulkFindingTarget[] = [];
      for (const id of ids) {
        const tenant = itemTenantById.get(id);
        if (!tenant) {
          setBulkDialogError(
            "Часть выбранных findings больше недоступна. Обновите список.",
          );
          return;
        }
        targets.push({ id, tenant_id: tenant });
      }
      setBulkSubmitting(true);
      setBulkDialogError(null);
      try {
        let result: BulkActionResult;
        if (payload.kind === "suppress") {
          result = await bulkSuppressFindingsAction({
            targets,
            reason: payload.reason,
            comment: payload.comment,
          });
        } else {
          result = await bulkMarkFalsePositiveFindingsAction({
            targets,
            comment: payload.comment,
          });
        }
        setBulkBanner(buildSuccessBanner(result, targets.length));
        setSelectedIds(new Set());
        setActiveBulkAction(null);
        // React Query: drop every cached findings list query so the
        // operator sees the post-mutation truth on the next render.
        await queryClient.invalidateQueries({
          queryKey: ["admin", "findings"],
        });
      } catch (err) {
        if (err instanceof BulkFindingsActionError) {
          setBulkDialogError(bulkActionErrorMessage(err));
        } else {
          setBulkDialogError(bulkActionErrorMessage(err));
        }
      } finally {
        setBulkSubmitting(false);
      }
    },
    [itemTenantById, queryClient, selectedIds],
  );

  const handleResetFilters = useCallback(() => {
    setFilters({ ...EMPTY_FILTER_VALUES });
    setSelectedIds(new Set());
    setBulkBanner(null);
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

      {bulkBanner ? (
        <div
          role="status"
          aria-live="polite"
          data-testid="bulk-action-banner"
          data-tone={bulkBanner.tone}
          className={`rounded border px-3 py-2 text-sm ${bannerToneClass(bulkBanner.tone)}`}
        >
          {bulkBanner.message}
        </div>
      ) : null}

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
        <>
          <BulkActionsToolbar
            selectedCount={selectedIds.size}
            availability={bulkAvailability}
            disabled={bulkSubmitting}
            disabledReason={bulkDisabledReason}
            onAction={openBulkDialog}
            onClearSelection={handleClearSelection}
          />
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
            selectionMode={selectionMode}
            selectedIds={selectedIds}
            onToggleSelection={handleToggleSelection}
            onToggleAll={handleToggleAll}
            onClearSelection={handleClearSelection}
          />
        </>
      )}

      {activeBulkAction ? (
        <BulkActionDialog
          kind={activeBulkAction}
          selectedCount={selectedIds.size}
          submitting={bulkSubmitting}
          errorMessage={bulkDialogError}
          onConfirm={(payload) => {
            void runBulkAction(payload);
          }}
          onClose={closeBulkDialog}
        />
      ) : null}
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
