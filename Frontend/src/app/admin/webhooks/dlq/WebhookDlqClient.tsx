"use client";

/**
 * `WebhookDlqClient` — operator-facing webhook DLQ triage dashboard
 * (T41, ARG-053).
 *
 * Layout:
 *   ┌─ Header (title, subtitle, refresh button) ─────────────────────┐
 *   │                                                                 │
 *   │  [Status / action banners (info / error)]                       │
 *   │                                                                 │
 *   │  [Tenant selector]      (super-admin only)                      │
 *   │  [Status / Adapter / Created-after / Created-before filters]    │
 *   │  [Pagination — page-size + Prev/Next]                           │
 *   │                                                                 │
 *   │  ┌─ DlqTable ────────────────────────────────────────────────┐  │
 *   │  │  rows w/ Replay + Abandon row actions (admin+)            │  │
 *   │  └──────────────────────────────────────────────────────────┘  │
 *   │                                                                 │
 *   │  [Audit trail link → /admin/audit-logs?event_type=webhook_dlq.*]│
 *   └─────────────────────────────────────────────────────────────────┘
 *
 * Polling:
 *   The list refreshes every 30 s by default (`pollMs`). The interval
 *   reuses the same `reqIdRef` monotonic-id pattern as
 *   `SchedulesClient` so a slow response can NEVER overwrite a newer
 *   snapshot triggered by an immediate refetch (e.g. after replay /
 *   abandon success). `vi.useFakeTimers()` wins for tests.
 *
 * Optimistic state:
 *   None. Replay/abandon dialogs always wait for the server response
 *   before closing, then trigger a refetch.
 *
 * RBAC:
 *   - operator: page-blocked at `page.tsx` via AdminRouteGuard. The
 *     backend returns 403 for ALL DLQ endpoints when the role is
 *     operator, so we never even render the table for them.
 *   - admin: read/write within session tenant. Tenant selector hidden;
 *     the tenant column on the table is hidden too.
 *   - super-admin: read/write any tenant. Selector visible, tenant
 *     column visible. When no tenant is selected, list-all is
 *     attempted (`tenantId=null`).
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  useTransition,
} from "react";

import {
  abandonWebhookDlqAction,
  listWebhookDlqAction,
  replayWebhookDlqAction,
} from "@/app/admin/webhooks/dlq/actions";
import { DlqTable } from "@/app/admin/webhooks/dlq/DlqTable";
import { ReplayDialog } from "@/app/admin/webhooks/dlq/ReplayDialog";
import { AbandonDialog } from "@/app/admin/webhooks/dlq/AbandonDialog";
import { listTenants, type AdminTenant } from "@/app/admin/tenants/actions";
import {
  WEBHOOK_DLQ_LIMIT_DEFAULT,
  WEBHOOK_DLQ_TRIAGE_STATUSES,
  webhookDlqActionErrorMessage,
  type WebhookDlqAbandonResponse,
  type WebhookDlqEntryItem,
  type WebhookDlqListResponse,
  type WebhookDlqReplayResponse,
  type WebhookDlqTriageStatus,
} from "@/lib/adminWebhookDlq";

export type WebhookDlqClientSession = {
  readonly role: "admin" | "super-admin";
  readonly tenantId: string | null;
};

export type WebhookDlqClientProps = {
  readonly initialList: WebhookDlqListResponse | null;
  readonly session: WebhookDlqClientSession;
  readonly pollMs?: number;
  /** Test override — defaults to canonical `listWebhookDlqAction`. */
  readonly listAction?: typeof listWebhookDlqAction;
  /** Test override — defaults to canonical `replayWebhookDlqAction`. */
  readonly replayAction?: typeof replayWebhookDlqAction;
  /** Test override — defaults to canonical `abandonWebhookDlqAction`. */
  readonly abandonAction?: typeof abandonWebhookDlqAction;
  /** Test override — defaults to canonical tenant directory action. */
  readonly listTenantsAction?: typeof listTenants;
};

const DEFAULT_POLL_MS = 30_000;
const PAGE_SIZE_OPTIONS: ReadonlyArray<number> = [10, 25, 50, 100];
const ADAPTER_INPUT_DEBOUNCE_MS = 300;

type FilterState = {
  readonly status: WebhookDlqTriageStatus | "all";
  readonly adapter: string;
  readonly createdAfter: string;
  readonly createdBefore: string;
  readonly limit: number;
  readonly offset: number;
};

const INITIAL_FILTERS: FilterState = {
  status: "all",
  adapter: "",
  createdAfter: "",
  createdBefore: "",
  limit: WEBHOOK_DLQ_LIMIT_DEFAULT,
  offset: 0,
};

export function WebhookDlqClient({
  initialList,
  session,
  pollMs = DEFAULT_POLL_MS,
  listAction = listWebhookDlqAction,
  replayAction = replayWebhookDlqAction,
  abandonAction = abandonWebhookDlqAction,
  listTenantsAction = listTenants,
}: WebhookDlqClientProps): React.ReactElement {
  const isSuperAdmin = session.role === "super-admin";
  const canMutate = true;

  const [entries, setEntries] = useState<ReadonlyArray<WebhookDlqEntryItem>>(
    () => initialList?.items ?? [],
  );
  const [total, setTotal] = useState<number>(initialList?.total ?? 0);
  const [isLoading, setIsLoading] = useState<boolean>(initialList === null);
  const [listError, setListError] = useState<string | null>(null);
  const [actionInfo, setActionInfo] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const [tenants, setTenants] = useState<ReadonlyArray<AdminTenant>>([]);
  const [tenantsLoaded, setTenantsLoaded] = useState(false);
  const [selectedTenantId, setSelectedTenantId] = useState<string>(
    () => session.tenantId ?? "",
  );

  const [filters, setFilters] = useState<FilterState>(INITIAL_FILTERS);
  const [adapterDraft, setAdapterDraft] = useState<string>("");

  const [replayEntry, setReplayEntry] = useState<WebhookDlqEntryItem | null>(
    null,
  );
  const [abandonEntry, setAbandonEntry] = useState<WebhookDlqEntryItem | null>(
    null,
  );

  const [, startTransition] = useTransition();
  const reqIdRef = useRef(0);

  const tenantOptions = useMemo(
    () => tenants.map((t) => ({ id: t.id, name: t.name })),
    [tenants],
  );

  // Super-admin tenant directory — same pattern as SchedulesClient.
  useEffect(() => {
    if (!isSuperAdmin || tenantsLoaded) return;
    let cancelled = false;
    void (async () => {
      try {
        const list = await listTenantsAction({ limit: 200, offset: 0 });
        if (cancelled) return;
        setTenants(list);
        setTenantsLoaded(true);
      } catch (err) {
        if (cancelled) return;
        setListError(webhookDlqActionErrorMessage(err));
        setTenantsLoaded(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [isSuperAdmin, tenantsLoaded, listTenantsAction]);

  type RefetchOverrides = {
    readonly tenantId?: string | null;
    readonly filters?: Partial<FilterState>;
  };

  const refetch = useCallback(
    (overrides: RefetchOverrides = {}) => {
      const tenantArg =
        overrides.tenantId !== undefined
          ? overrides.tenantId
          : selectedTenantId !== ""
            ? selectedTenantId
            : null;
      const merged: FilterState = { ...filters, ...overrides.filters };
      const myReqId = ++reqIdRef.current;
      setListError(null);
      setIsLoading(true);
      startTransition(async () => {
        try {
          const next = await listAction({
            tenantId: tenantArg,
            status: merged.status === "all" ? null : merged.status,
            adapterName: merged.adapter.trim() || null,
            createdAfter: merged.createdAfter.trim() || null,
            createdBefore: merged.createdBefore.trim() || null,
            limit: merged.limit,
            offset: merged.offset,
          });
          if (myReqId !== reqIdRef.current) return;
          setEntries(next.items);
          setTotal(next.total);
          setIsLoading(false);
        } catch (err) {
          if (myReqId !== reqIdRef.current) return;
          setListError(webhookDlqActionErrorMessage(err));
          setIsLoading(false);
        }
      });
    },
    [selectedTenantId, filters, listAction],
  );

  // Polling — silent background refresh on the active filter set.
  useEffect(() => {
    if (pollMs <= 0) return;
    const id = window.setInterval(() => {
      refetch();
    }, pollMs);
    return () => window.clearInterval(id);
  }, [pollMs, refetch]);

  // Debounced adapter filter — avoid hammering the API on every key.
  useEffect(() => {
    if (adapterDraft === filters.adapter) return;
    const id = window.setTimeout(() => {
      const nextFilters: Partial<FilterState> = {
        adapter: adapterDraft,
        offset: 0,
      };
      setFilters((prev) => ({ ...prev, ...nextFilters }));
      refetch({ filters: nextFilters });
    }, ADAPTER_INPUT_DEBOUNCE_MS);
    return () => window.clearTimeout(id);
  }, [adapterDraft, filters.adapter, refetch]);

  const applyFilterPatch = (patch: Partial<FilterState>): void => {
    const nextFilters: Partial<FilterState> = { ...patch, offset: 0 };
    setFilters((prev) => ({ ...prev, ...nextFilters }));
    setActionInfo(null);
    setActionError(null);
    refetch({ filters: nextFilters });
  };

  const handleStatusChange = (raw: string): void => {
    const next: WebhookDlqTriageStatus | "all" =
      raw === "all"
        ? "all"
        : (WEBHOOK_DLQ_TRIAGE_STATUSES as readonly string[]).includes(raw)
          ? (raw as WebhookDlqTriageStatus)
          : "all";
    applyFilterPatch({ status: next });
  };

  const handleAfterChange = (raw: string): void => {
    applyFilterPatch({ createdAfter: raw });
  };

  const handleBeforeChange = (raw: string): void => {
    applyFilterPatch({ createdBefore: raw });
  };

  const handleLimitChange = (raw: string): void => {
    const parsed = Number.parseInt(raw, 10);
    const next = PAGE_SIZE_OPTIONS.includes(parsed)
      ? parsed
      : WEBHOOK_DLQ_LIMIT_DEFAULT;
    applyFilterPatch({ limit: next });
  };

  const handlePrev = (): void => {
    if (filters.offset <= 0) return;
    const nextOffset = Math.max(0, filters.offset - filters.limit);
    const patch: Partial<FilterState> = { offset: nextOffset };
    setFilters((prev) => ({ ...prev, ...patch }));
    refetch({ filters: patch });
  };

  const handleNext = (): void => {
    if (filters.offset + filters.limit >= total) return;
    const patch: Partial<FilterState> = {
      offset: filters.offset + filters.limit,
    };
    setFilters((prev) => ({ ...prev, ...patch }));
    refetch({ filters: patch });
  };

  const handleTenantChange = (next: string): void => {
    setSelectedTenantId(next);
    setActionInfo(null);
    setActionError(null);
    const tenantArg = next === "" ? null : next;
    const offsetReset: Partial<FilterState> = { offset: 0 };
    setFilters((prev) => ({ ...prev, ...offsetReset }));
    refetch({ tenantId: tenantArg, filters: offsetReset });
  };

  const handleManualRefresh = (): void => {
    setActionInfo(null);
    setActionError(null);
    refetch();
  };

  const handleClearFilters = (): void => {
    setAdapterDraft("");
    setSelectedTenantId(session.tenantId ?? "");
    setFilters(INITIAL_FILTERS);
    setActionInfo(null);
    setActionError(null);
    refetch({
      tenantId: session.tenantId ?? null,
      filters: INITIAL_FILTERS,
    });
  };

  const handleReplaySuccess = (result: WebhookDlqReplayResponse): void => {
    setActionInfo(
      result.success
        ? `Webhook повторён успешно. Audit id: ${result.audit_id}.`
        : `Повтор не удался; попытка засчитана (всего ${result.attempt_count}).`,
    );
    setActionError(null);
    refetch();
  };

  const handleAbandonSuccess = (result: WebhookDlqAbandonResponse): void => {
    setActionInfo(`Запись отмечена как abandoned. Audit id: ${result.audit_id}.`);
    setActionError(null);
    refetch();
  };

  const auditTrailHref = useMemo(() => {
    const sp = new URLSearchParams();
    sp.set("event_type_prefix", "webhook_dlq.");
    if (selectedTenantId) sp.set("tenant_id", selectedTenantId);
    return `/admin/audit-logs?${sp.toString()}`;
  }, [selectedTenantId]);

  const pageStart = total === 0 ? 0 : filters.offset + 1;
  const pageEnd = Math.min(total, filters.offset + entries.length);
  const canPrev = filters.offset > 0;
  const canNext = filters.offset + filters.limit < total;

  return (
    <div className="space-y-4" data-testid="dlq-client">
      <header className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">
            Очередь dead-letter webhook&rsquo;ов
          </h1>
          <p className="text-sm text-[var(--text-secondary)]">
            Сообщения, не доставленные после автоматических ретраев.
            Повтор обходит in-process circuit-breaker и дедуп
            dispatcher&rsquo;а; abandon помечает запись как окончательно
            отброшенную (без новых попыток).
          </p>
        </div>
        <button
          type="button"
          onClick={handleManualRefresh}
          disabled={isLoading}
          aria-label="Обновить список DLQ"
          className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-1.5 text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
          data-testid="dlq-refresh-button"
        >
          {isLoading ? "Обновляем…" : "Обновить"}
        </button>
      </header>

      {listError ? (
        <div
          role="alert"
          className="rounded border border-red-900/40 bg-red-950/30 px-3 py-2 text-sm text-red-200"
          data-testid="dlq-list-error"
        >
          {listError}
        </div>
      ) : null}

      {actionError ? (
        <div
          role="alert"
          className="rounded border border-red-900/40 bg-red-950/30 px-3 py-2 text-sm text-red-200"
          data-testid="dlq-action-error"
        >
          {actionError}
        </div>
      ) : null}

      {actionInfo ? (
        <div
          className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)]"
          data-testid="dlq-action-info"
        >
          {actionInfo}
        </div>
      ) : null}

      <div
        className="flex flex-wrap items-end gap-3 rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2"
        data-testid="dlq-filters-row"
      >
        {isSuperAdmin ? (
          <div className="flex flex-col gap-1">
            <label
              className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]"
              htmlFor="dlq-tenant-select"
            >
              Tenant
            </label>
            <select
              id="dlq-tenant-select"
              data-testid="dlq-filter-tenant"
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
              value={selectedTenantId}
              onChange={(e) => handleTenantChange(e.target.value)}
              disabled={isLoading && !tenantsLoaded}
            >
              <option value="">Все tenants</option>
              {tenantOptions.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          </div>
        ) : null}

        <div className="flex flex-col gap-1">
          <label
            className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]"
            htmlFor="dlq-status-select"
          >
            Статус
          </label>
          <select
            id="dlq-status-select"
            data-testid="dlq-filter-status"
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
            value={filters.status}
            onChange={(e) => handleStatusChange(e.target.value)}
            disabled={isLoading}
          >
            <option value="all">Все</option>
            {WEBHOOK_DLQ_TRIAGE_STATUSES.map((s) => (
              <option key={s} value={s}>
                {s === "pending"
                  ? "В очереди"
                  : s === "replayed"
                    ? "Повторено"
                    : "Отброшено"}
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-col gap-1">
          <label
            className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]"
            htmlFor="dlq-adapter-input"
          >
            Adapter
          </label>
          <input
            id="dlq-adapter-input"
            type="text"
            value={adapterDraft}
            onChange={(e) => setAdapterDraft(e.target.value)}
            placeholder="slack / linear / jira"
            autoComplete="off"
            data-testid="dlq-filter-adapter"
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)]"
            disabled={isLoading}
          />
        </div>

        <div className="flex flex-col gap-1">
          <label
            className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]"
            htmlFor="dlq-after-input"
          >
            Создано после (UTC)
          </label>
          <input
            id="dlq-after-input"
            type="date"
            value={filters.createdAfter}
            onChange={(e) => handleAfterChange(e.target.value)}
            data-testid="dlq-filter-after"
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
            disabled={isLoading}
          />
        </div>

        <div className="flex flex-col gap-1">
          <label
            className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]"
            htmlFor="dlq-before-input"
          >
            Создано до (UTC)
          </label>
          <input
            id="dlq-before-input"
            type="date"
            value={filters.createdBefore}
            onChange={(e) => handleBeforeChange(e.target.value)}
            data-testid="dlq-filter-before"
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
            disabled={isLoading}
          />
        </div>

        <div className="flex flex-col gap-1">
          <label
            className="text-[11px] uppercase tracking-wide text-[var(--text-muted)]"
            htmlFor="dlq-limit-select"
          >
            На странице
          </label>
          <select
            id="dlq-limit-select"
            data-testid="dlq-filter-limit"
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
            value={String(filters.limit)}
            onChange={(e) => handleLimitChange(e.target.value)}
            disabled={isLoading}
          >
            {PAGE_SIZE_OPTIONS.map((n) => (
              <option key={n} value={String(n)}>
                {n}
              </option>
            ))}
          </select>
        </div>

        <button
          type="button"
          onClick={handleClearFilters}
          disabled={isLoading}
          aria-label="Сбросить фильтры"
          className="self-end rounded border border-[var(--border)] px-3 py-1.5 text-sm text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
          data-testid="dlq-filters-clear"
        >
          Сброс
        </button>
      </div>

      <DlqTable
        entries={entries}
        isLoading={isLoading}
        showTenantColumn={isSuperAdmin}
        canMutate={canMutate}
        onReplay={(entry) => {
          setActionInfo(null);
          setActionError(null);
          setReplayEntry(entry);
        }}
        onAbandon={(entry) => {
          setActionInfo(null);
          setActionError(null);
          setAbandonEntry(entry);
        }}
      />

      <nav
        className="flex flex-col gap-2 rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2 text-xs text-[var(--text-secondary)] sm:flex-row sm:items-center sm:justify-between"
        aria-label="Пагинация DLQ"
        data-testid="dlq-pagination"
      >
        <span data-testid="dlq-pagination-summary">
          {total === 0
            ? "Нет записей под текущие фильтры"
            : `Показано ${pageStart}\u2013${pageEnd} из ${total}`}
        </span>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={handlePrev}
            disabled={!canPrev || isLoading}
            aria-label="Предыдущая страница"
            className="rounded border border-[var(--border)] px-2 py-1 hover:bg-[var(--bg-tertiary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
            data-testid="dlq-pagination-prev"
          >
            ← Назад
          </button>
          <button
            type="button"
            onClick={handleNext}
            disabled={!canNext || isLoading}
            aria-label="Следующая страница"
            className="rounded border border-[var(--border)] px-2 py-1 hover:bg-[var(--bg-tertiary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
            data-testid="dlq-pagination-next"
          >
            Вперёд →
          </button>
        </div>
      </nav>

      <section
        className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-3 text-sm"
        aria-label="Audit trail webhook_dlq.* событий"
        data-testid="dlq-audit-trail-panel"
      >
        <a
          href={auditTrailHref}
          className="text-[var(--accent)] hover:underline"
          data-testid="dlq-audit-trail-link"
        >
          → Перейти к audit trail (webhook_dlq.*)
        </a>
      </section>

      {replayEntry !== null ? (
        <ReplayDialog
          open={replayEntry !== null}
          onOpenChange={(o) => !o && setReplayEntry(null)}
          entry={replayEntry}
          replayAction={replayAction}
          onComplete={(result) => {
            setReplayEntry(null);
            handleReplaySuccess(result);
          }}
        />
      ) : null}

      {abandonEntry !== null ? (
        <AbandonDialog
          open={abandonEntry !== null}
          onOpenChange={(o) => !o && setAbandonEntry(null)}
          entry={abandonEntry}
          abandonAction={abandonAction}
          onComplete={(result) => {
            setAbandonEntry(null);
            handleAbandonSuccess(result);
          }}
        />
      ) : null}
    </div>
  );
}
