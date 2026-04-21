"use client";

/**
 * `SchedulesClient` — operator-facing scheduled-scan dashboard
 * (T35, ARG-056).
 *
 * Layout:
 *   ┌─ Header (title, "Создать расписание", session/tenant chip) ───────┐
 *   │                                                                   │
 *   │  [Status / action banners]                                        │
 *   │                                                                   │
 *   │  [Tenant selector]   (super-admin only)                           │
 *   │                                                                   │
 *   │  ┌─ SchedulesTable ─────────────────────────────────────────────┐ │
 *   │  │  rows w/ inline enable toggle + Edit / Run now / Delete      │ │
 *   │  └──────────────────────────────────────────────────────────────┘ │
 *   │                                                                   │
 *   │  [Audit trail link → /admin/audit-logs?event_type=scan_schedule.*]│
 *   └───────────────────────────────────────────────────────────────────┘
 *
 * Polling:
 *   The list refreshes every 30 s by default (`pollMs`). The interval
 *   reuses the same `reqIdRef` monotonic-id pattern as
 *   `PerTenantThrottleClient` so a slow response can NEVER overwrite a
 *   newer snapshot triggered by an immediate refetch (e.g. after editor
 *   or run-now success). `vi.useFakeTimers()` wins for tests.
 *
 * Optimistic enable toggle:
 *   The row toggle calls `updateScheduleAction` directly without opening
 *   the editor — we pass the schedule id into `busyScheduleIds` to grey
 *   out the row, and refetch the list on success / error. We do NOT
 *   apply optimistic local mutation: the source of truth is the backend
 *   (RedBeat sync, last_run_at update), so a confirmed refetch is
 *   simpler than reasoning about partial state.
 *
 * RBAC:
 *   - `operator`: read-only (canMutate=false). The "Создать расписание"
 *     button is hidden, all row actions are disabled.
 *   - `admin`: read/write within session tenant. Tenant selector hidden;
 *     the tenant column on the table is hidden too.
 *   - `super-admin`: read/write any tenant. Selector visible, tenant
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

import { listTenants, type AdminTenant } from "@/app/admin/tenants/actions";
import {
  createScheduleAction,
  deleteScheduleAction,
  listSchedulesAction,
  runNowAction,
  updateScheduleAction,
} from "@/app/admin/schedules/actions";
import { DeleteScheduleDialog } from "@/components/admin/schedules/DeleteScheduleDialog";
import { RunNowDialog } from "@/components/admin/schedules/RunNowDialog";
import { ScheduleEditorDialog } from "@/components/admin/schedules/ScheduleEditorDialog";
import { SchedulesTable } from "@/components/admin/schedules/SchedulesTable";
import {
  scheduleActionErrorMessage,
  type Schedule,
  type SchedulesListResponse,
  type RunNowResponse,
} from "@/lib/adminSchedules";

export type SchedulesClientSession = {
  readonly role: "admin" | "super-admin" | "operator";
  readonly tenantId: string | null;
};

export type SchedulesClientProps = {
  readonly initialList: SchedulesListResponse | null;
  readonly session: SchedulesClientSession;
  readonly pollMs?: number;
  /** Test override — defaults to canonical `listSchedulesAction`. */
  readonly listAction?: typeof listSchedulesAction;
  /** Test override — defaults to canonical `createScheduleAction`. */
  readonly createAction?: typeof createScheduleAction;
  /** Test override — defaults to canonical `updateScheduleAction`. */
  readonly updateAction?: typeof updateScheduleAction;
  /** Test override — defaults to canonical `deleteScheduleAction`. */
  readonly deleteScheduleAct?: typeof deleteScheduleAction;
  /** Test override — defaults to canonical `runNowAction`. */
  readonly runAction?: typeof runNowAction;
  /** Test override — defaults to canonical tenant directory action. */
  readonly listTenantsAction?: typeof listTenants;
};

const DEFAULT_POLL_MS = 30_000;

export function SchedulesClient({
  initialList,
  session,
  pollMs = DEFAULT_POLL_MS,
  listAction = listSchedulesAction,
  createAction = createScheduleAction,
  updateAction = updateScheduleAction,
  deleteScheduleAct = deleteScheduleAction,
  runAction = runNowAction,
  listTenantsAction = listTenants,
}: SchedulesClientProps): React.ReactElement {
  const isSuperAdmin = session.role === "super-admin";
  const canMutate = session.role !== "operator";

  const [schedules, setSchedules] = useState<ReadonlyArray<Schedule>>(
    () => initialList?.items ?? [],
  );
  const [isLoading, setIsLoading] = useState<boolean>(initialList === null);
  const [listError, setListError] = useState<string | null>(null);
  const [actionInfo, setActionInfo] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const [tenants, setTenants] = useState<ReadonlyArray<AdminTenant>>([]);
  const [tenantsLoaded, setTenantsLoaded] = useState(false);
  const [selectedTenantId, setSelectedTenantId] = useState<string>(
    () => session.tenantId ?? "",
  );

  const [editorOpen, setEditorOpen] = useState(false);
  const [editorSchedule, setEditorSchedule] = useState<Schedule | null>(null);
  const [runNowSchedule, setRunNowSchedule] = useState<Schedule | null>(null);
  const [deleteSchedule, setDeleteSchedule] = useState<Schedule | null>(null);
  const [busyScheduleIds, setBusyScheduleIds] = useState<ReadonlyArray<string>>(
    [],
  );
  const [, startTransition] = useTransition();

  const reqIdRef = useRef(0);

  const tenantOptions = useMemo(
    () => tenants.map((t) => ({ id: t.id, name: t.name })),
    [tenants],
  );

  // Super-admin tenant directory load — same pattern as
  // PerTenantThrottleClient. Operator role is page-blocked so we don't
  // even enter the loop.
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
        setListError(scheduleActionErrorMessage(err));
        setTenantsLoaded(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [isSuperAdmin, tenantsLoaded, listTenantsAction]);

  const refetch = useCallback(
    (tenantOverride?: string | null) => {
      const tenantArg =
        tenantOverride !== undefined
          ? tenantOverride
          : selectedTenantId !== ""
            ? selectedTenantId
            : null;
      const myReqId = ++reqIdRef.current;
      setListError(null);
      setIsLoading(true);
      startTransition(async () => {
        try {
          const next = await listAction({ tenantId: tenantArg });
          if (myReqId !== reqIdRef.current) return;
          setSchedules(next.items);
          setIsLoading(false);
        } catch (err) {
          if (myReqId !== reqIdRef.current) return;
          setListError(scheduleActionErrorMessage(err));
          setIsLoading(false);
        }
      });
    },
    [selectedTenantId, listAction],
  );

  // Polling. Exponential backoff isn't necessary — admin operations
  // page already proves a 30 s loop is gentle on the backend, and a
  // schedule-edit window remains manually refreshable via the editor's
  // success path.
  useEffect(() => {
    if (pollMs <= 0) return;
    const id = window.setInterval(() => {
      refetch();
    }, pollMs);
    return () => window.clearInterval(id);
  }, [pollMs, refetch]);

  const handleTenantChange = (next: string) => {
    setSelectedTenantId(next);
    setActionInfo(null);
    setActionError(null);
    refetch(next === "" ? null : next);
  };

  const handleCreate = () => {
    setActionInfo(null);
    setActionError(null);
    setEditorSchedule(null);
    setEditorOpen(true);
  };

  const handleEdit = (schedule: Schedule) => {
    setActionInfo(null);
    setActionError(null);
    setEditorSchedule(schedule);
    setEditorOpen(true);
  };

  const handleEditorSuccess = (s: Schedule) => {
    const wasCreate = editorSchedule === null;
    setActionInfo(
      wasCreate
        ? `Расписание «${s.name}» создано.`
        : `Расписание «${s.name}» обновлено.`,
    );
    setActionError(null);
    refetch();
  };

  const handleRunNowSuccess = (result: RunNowResponse) => {
    setActionInfo(
      `Расписание запущено вне очереди. Task id: ${result.enqueued_task_id}.`,
    );
    setActionError(null);
    refetch();
  };

  const handleDeleteSuccess = () => {
    setActionInfo("Расписание удалено.");
    setActionError(null);
    refetch();
  };

  const handleToggleEnabled = (schedule: Schedule, next: boolean) => {
    if (!canMutate) return;
    setActionInfo(null);
    setActionError(null);
    setBusyScheduleIds((prev) =>
      prev.includes(schedule.id) ? prev : [...prev, schedule.id],
    );

    startTransition(async () => {
      try {
        await updateAction(schedule.id, { enabled: next });
        setActionInfo(
          next
            ? `Расписание «${schedule.name}» включено.`
            : `Расписание «${schedule.name}» отключено.`,
        );
        refetch();
      } catch (err) {
        setActionError(scheduleActionErrorMessage(err));
        // Refetch on any failure — the row may already be in a different
        // state on the backend; sync the UI back to the source of truth.
        refetch();
      } finally {
        setBusyScheduleIds((prev) => prev.filter((id) => id !== schedule.id));
      }
    });
  };

  const auditTrailHref = useMemo(() => {
    const sp = new URLSearchParams();
    sp.set("event_type_prefix", "scan_schedule.");
    if (selectedTenantId) sp.set("tenant_id", selectedTenantId);
    return `/admin/audit-logs?${sp.toString()}`;
  }, [selectedTenantId]);

  // For `admin` operators the editor is pinned to their tenant. For
  // `super-admin`, when EDITING we still pin to the schedule's owner
  // (you can't move a schedule across tenants); when CREATING we leave
  // `pinnedTenantId=null` so the dialog renders a tenant selector.
  const editorPinnedTenantId = useMemo<string | null>(() => {
    if (editorSchedule !== null) return editorSchedule.tenant_id;
    if (!isSuperAdmin) return session.tenantId;
    return null;
  }, [editorSchedule, isSuperAdmin, session.tenantId]);

  return (
    <div className="space-y-4" data-testid="schedules-client">
      <header className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">
            Operations · Scheduled scans
          </h1>
          <p className="text-sm text-[var(--text-secondary)]">
            Cron-расписания для автоматического запуска сканов. Перед
            каждым запуском проверяются global kill-switch, per-tenant
            throttle и maintenance window.
          </p>
        </div>
        {canMutate ? (
          <button
            type="button"
            onClick={handleCreate}
            className="rounded bg-[var(--accent)] px-3 py-1.5 text-sm font-medium text-white hover:opacity-90 focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
            disabled={
              !canMutate ||
              (isSuperAdmin && tenantOptions.length === 0 && !tenantsLoaded)
            }
            data-testid="schedules-create-button"
          >
            Создать расписание
          </button>
        ) : null}
      </header>

      {listError ? (
        <div
          role="alert"
          className="rounded border border-red-900/40 bg-red-950/30 px-3 py-2 text-sm text-red-200"
          data-testid="schedules-list-error"
        >
          {listError}
        </div>
      ) : null}

      {actionError ? (
        <div
          role="alert"
          className="rounded border border-red-900/40 bg-red-950/30 px-3 py-2 text-sm text-red-200"
          data-testid="schedules-action-error"
        >
          {actionError}
        </div>
      ) : null}

      {actionInfo ? (
        <div
          className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)]"
          data-testid="schedules-action-info"
        >
          {actionInfo}
        </div>
      ) : null}

      {isSuperAdmin ? (
        <div
          className="flex flex-wrap items-end gap-2"
          data-testid="schedules-tenant-selector-row"
        >
          <label
            className="text-xs text-[var(--text-muted)]"
            htmlFor="schedules-tenant-select"
          >
            Tenant
          </label>
          <select
            id="schedules-tenant-select"
            data-testid="schedules-tenant-select"
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

      <SchedulesTable
        schedules={schedules}
        isLoading={isLoading}
        showTenantColumn={isSuperAdmin}
        canMutate={canMutate}
        busyScheduleIds={busyScheduleIds}
        onEdit={handleEdit}
        onDelete={(s) => {
          setActionInfo(null);
          setActionError(null);
          setDeleteSchedule(s);
        }}
        onRunNow={(s) => {
          setActionInfo(null);
          setActionError(null);
          setRunNowSchedule(s);
        }}
        onToggleEnabled={handleToggleEnabled}
      />

      <section
        className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-3 text-sm"
        aria-label="Audit trail scan_schedule.* событий"
        data-testid="schedules-audit-trail-panel"
      >
        <a
          href={auditTrailHref}
          className="text-[var(--accent)] hover:underline"
          data-testid="schedules-audit-trail-link"
        >
          → Перейти к audit trail (scan_schedule.*)
        </a>
      </section>

      <ScheduleEditorDialog
        open={editorOpen}
        onOpenChange={setEditorOpen}
        mode={editorSchedule === null ? "create" : "edit"}
        pinnedTenantId={editorPinnedTenantId}
        initialSchedule={editorSchedule}
        availableTenants={
          isSuperAdmin
            ? tenantOptions
            : session.tenantId
              ? [
                  {
                    id: session.tenantId,
                    name: session.tenantId,
                  },
                ]
              : []
        }
        createAction={createAction}
        updateAction={updateAction}
        onSuccess={handleEditorSuccess}
      />

      {runNowSchedule !== null ? (
        <RunNowDialog
          open={runNowSchedule !== null}
          onOpenChange={(o) => !o && setRunNowSchedule(null)}
          schedule={runNowSchedule}
          runAction={runAction}
          onSuccess={handleRunNowSuccess}
        />
      ) : null}

      {deleteSchedule !== null ? (
        <DeleteScheduleDialog
          open={deleteSchedule !== null}
          onOpenChange={(o) => !o && setDeleteSchedule(null)}
          schedule={deleteSchedule}
          deleteAction={deleteScheduleAct}
          onSuccess={handleDeleteSuccess}
        />
      ) : null}
    </div>
  );
}
