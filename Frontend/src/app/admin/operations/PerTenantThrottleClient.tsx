"use client";

/**
 * `PerTenantThrottleClient` — operator-facing per-tenant throttle dashboard
 * (T29, ARG-052).
 *
 * Layout:
 *   ┌─ Status panel ─────────────────────────────┐
 *   │  Tenant: [select | pinned label]           │
 *   │  State : ACTIVE | NORMAL                   │
 *   │  Countdown (if active): MM:SS / HH:MM:SS   │
 *   │  Reason / activated_by_hash (if active)    │
 *   │                                            │
 *   │  [Throttle this tenant]   [Resume now*]    │
 *   └────────────────────────────────────────────┘
 *   ┌─ Audit trail link ─────────────────────────┐
 *   │  → /admin/audit-logs?event_type=...        │
 *   └────────────────────────────────────────────┘
 *
 * RBAC handling:
 *   - `admin` operators see ONLY their session-bound tenant; the tenant
 *     selector is hidden.
 *   - `super-admin` can pick any tenant from the dropdown (loaded once on
 *     mount via `listTenants`).
 *   - `operator` is filtered out by the page-level RouteGuard, but the
 *     server actions also independently refuse the operator role.
 *
 * Auto-resume on TTL expiry:
 *   The countdown timer fires `onExpire()` once when remaining time hits
 *   zero. The handler refetches the throttle status; the new snapshot will
 *   no longer contain the expired entry (Redis TTL has cleared it).
 *
 * Manual override:
 *   The "Resume now" button currently surfaces a `not_implemented` error
 *   because the backend does NOT expose `/throttle/resume` and the
 *   `EmergencyThrottleDurationMinutes` literal excludes 0 (see ISS-T29-001).
 *   The button is rendered DISABLED with a tooltip explaining the
 *   carry-over so operators know auto-resume is the supported path.
 */

import {
  useCallback,
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  useTransition,
} from "react";

import { listTenants, type AdminTenant } from "@/app/admin/tenants/actions";
import {
  getEmergencyStatusAction,
  resumeTenantAction,
} from "@/app/admin/operations/actions";
import { CountdownTimer } from "@/components/admin/operations/CountdownTimer";
import {
  PerTenantThrottleDialog,
  type ThrottleTenantOption,
} from "@/components/admin/operations/PerTenantThrottleDialog";
import { useFocusTrap } from "@/components/admin/operations/useFocusTrap";
import {
  findActiveThrottle,
  throttleActionErrorMessage,
  type ThrottleStatusResponse,
  type ThrottleResponse,
} from "@/lib/adminOperations";
import type { AdminRole } from "@/services/admin/adminRoles";

export type PerTenantThrottleSession = {
  readonly role: "admin" | "super-admin";
  readonly tenantId: string | null;
};

export type PerTenantThrottleClientProps = {
  readonly initialStatus: ThrottleStatusResponse | null;
  readonly session: PerTenantThrottleSession;
  /** Test override — defaults to the canonical `getEmergencyStatusAction`. */
  readonly statusAction?: typeof getEmergencyStatusAction;
  /** Test override — defaults to the canonical `resumeTenantAction`. */
  readonly resumeAction?: typeof resumeTenantAction;
  /** Test override — defaults to the canonical tenant directory action. */
  readonly listTenantsAction?: typeof listTenants;
};

function formatActivatedAt(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export function PerTenantThrottleClient({
  initialStatus,
  session,
  statusAction = getEmergencyStatusAction,
  resumeAction = resumeTenantAction,
  listTenantsAction = listTenants,
}: PerTenantThrottleClientProps): React.ReactElement {
  const isSuperAdmin = session.role === "super-admin";
  const [status, setStatus] = useState<ThrottleStatusResponse | null>(
    initialStatus,
  );
  const [statusError, setStatusError] = useState<string | null>(null);
  const [actionInfo, setActionInfo] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [resumeOpen, setResumeOpen] = useState(false);
  const [tenants, setTenants] = useState<ReadonlyArray<AdminTenant>>([]);
  const [tenantsLoaded, setTenantsLoaded] = useState(false);
  const [selectedTenantId, setSelectedTenantId] = useState<string>(
    () => session.tenantId ?? "",
  );
  const [isPending, startTransition] = useTransition();

  // Monotonic request id for `refetchStatus` so a slow response from a
  // previously selected tenant cannot overwrite the latest selection's
  // state. `useTransition` itself does NOT cancel in-flight async work
  // (super-admin tenant-switch race; T29 review S2 #1).
  const reqIdRef = useRef(0);

  const tenantOptions: ReadonlyArray<ThrottleTenantOption> = useMemo(
    () => tenants.map((t) => ({ id: t.id, name: t.name })),
    [tenants],
  );

  // Super-admin: load tenant directory once. Admin: skip — the selector
  // is pinned to session.tenantId and the dropdown never renders.
  useEffect(() => {
    if (!isSuperAdmin || tenantsLoaded) return;
    let cancelled = false;
    void (async () => {
      try {
        const list = await listTenantsAction({ limit: 200, offset: 0 });
        if (cancelled) return;
        setTenants(list);
        setTenantsLoaded(true);
        if (selectedTenantId === "" && list.length > 0) {
          setSelectedTenantId(list[0].id);
        }
      } catch (err) {
        if (cancelled) return;
        setStatusError(throttleActionErrorMessage(err));
        setTenantsLoaded(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [isSuperAdmin, tenantsLoaded, selectedTenantId, listTenantsAction]);

  const refetchStatus = useCallback(
    (tenantIdOverride?: string) => {
      const target = tenantIdOverride ?? selectedTenantId;
      if (!target && !isSuperAdmin) return;
      const myReqId = ++reqIdRef.current;
      setStatusError(null);
      startTransition(async () => {
        try {
          const next = await statusAction({
            tenantId: target ? target : null,
          });
          if (myReqId !== reqIdRef.current) return;
          setStatus(next);
        } catch (err) {
          if (myReqId !== reqIdRef.current) return;
          setStatusError(throttleActionErrorMessage(err));
        }
      });
    },
    [selectedTenantId, isSuperAdmin, statusAction],
  );

  const handleTenantChange = (next: string) => {
    setSelectedTenantId(next);
    setActionInfo(null);
    setActionError(null);
    refetchStatus(next);
  };

  const handleThrottleSuccess = (result: ThrottleResponse) => {
    setActionInfo(
      `Throttle применён. TTL до ${formatActivatedAt(result.expires_at)}.`,
    );
    setActionError(null);
    refetchStatus();
  };

  const handleResumeConfirm = () => {
    if (!selectedTenantId) return;
    setResumeOpen(false);
    setActionInfo(null);
    setActionError(null);
    startTransition(async () => {
      try {
        await resumeAction({ tenantId: selectedTenantId });
        setActionInfo("Throttle снят.");
        refetchStatus();
      } catch (err) {
        setActionError(throttleActionErrorMessage(err));
      }
    });
  };

  const activeThrottle = useMemo(
    () => findActiveThrottle(status, selectedTenantId || null),
    [status, selectedTenantId],
  );

  const auditTrailHref = useMemo(() => {
    const sp = new URLSearchParams();
    sp.set("event_type", "emergency.throttle");
    if (selectedTenantId) sp.set("tenant_id", selectedTenantId);
    return `/admin/audit-logs?${sp.toString()}`;
  }, [selectedTenantId]);

  return (
    <div className="space-y-4" data-testid="per-tenant-throttle-client">
      <header className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">
            Operations · Per-tenant throttle
          </h1>
          <p className="text-sm text-[var(--text-secondary)]">
            Точечный emergency-throttle: блокирует диспатч новых scan-инструментов
            для одного tenant на TTL 15 минут / 1 час / 4 часа / 24 часа.
            Auto-resume срабатывает по истечении TTL.
          </p>
        </div>
        <div className="text-xs text-[var(--text-muted)]">
          {isPending ? "загрузка…" : null}
        </div>
      </header>

      {statusError ? (
        <div
          role="alert"
          className="rounded border border-red-900/40 bg-red-950/30 px-3 py-2 text-sm text-red-200"
          data-testid="throttle-status-error"
        >
          {statusError}
        </div>
      ) : null}

      {actionError ? (
        <div
          role="alert"
          className="rounded border border-red-900/40 bg-red-950/30 px-3 py-2 text-sm text-red-200"
          data-testid="throttle-action-error"
        >
          {actionError}
        </div>
      ) : null}

      {actionInfo ? (
        <div
          className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-2 text-sm text-[var(--text-secondary)]"
          data-testid="throttle-action-info"
        >
          {actionInfo}
        </div>
      ) : null}

      {isSuperAdmin ? (
        <div
          className="flex flex-wrap items-end gap-2"
          data-testid="throttle-tenant-selector-row"
        >
          <label
            className="text-xs text-[var(--text-muted)]"
            htmlFor="throttle-tenant-select"
          >
            Tenant
          </label>
          <select
            id="throttle-tenant-select"
            data-testid="throttle-tenant-select"
            className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
            value={selectedTenantId}
            onChange={(e) => handleTenantChange(e.target.value)}
            disabled={isPending && !tenantsLoaded}
          >
            {tenantOptions.length === 0 ? (
              <option value="">—</option>
            ) : (
              tenantOptions.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))
            )}
          </select>
        </div>
      ) : null}

      <section
        className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-4"
        aria-label="Текущее состояние throttle"
        data-testid="throttle-status-panel"
      >
        {activeThrottle ? (
          <ActiveThrottleSummary
            throttle={activeThrottle}
            onExpire={() => refetchStatus()}
          />
        ) : (
          <InactiveSummary
            tenantId={selectedTenantId}
            isSuperAdmin={isSuperAdmin}
          />
        )}

        <div
          className="mt-4 flex flex-wrap gap-2"
          data-testid="throttle-actions-row"
        >
          <button
            type="button"
            data-testid="throttle-open-dialog"
            className="rounded bg-amber-600 px-3 py-1.5 text-sm font-medium text-white hover:opacity-90 focus-visible:ring-2 focus-visible:ring-amber-400 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
            onClick={() => {
              setActionError(null);
              setActionInfo(null);
              setDialogOpen(true);
            }}
            disabled={!selectedTenantId || isPending}
          >
            Throttle this tenant
          </button>

          {activeThrottle ? (
            <button
              type="button"
              data-testid="throttle-resume-now"
              className="rounded border border-amber-500 px-3 py-1.5 text-sm font-medium text-amber-200 hover:text-amber-100 focus-visible:ring-2 focus-visible:ring-amber-400 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
              onClick={() => {
                setActionError(null);
                setActionInfo(null);
                setResumeOpen(true);
              }}
              disabled={isPending}
              aria-describedby="throttle-resume-help"
            >
              Resume now
            </button>
          ) : null}
        </div>

        <p
          id="throttle-resume-help"
          className="mt-2 text-[11px] text-[var(--text-muted)]"
        >
          Auto-resume: TTL автоматически снимет throttle. Manual resume
          требует выделенного backend-маршрута (carry-over ISS-T29-001).
        </p>
      </section>

      <section
        className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-3 text-sm"
        aria-label="Audit trail emergency.* событий"
        data-testid="throttle-audit-trail-panel"
      >
        <a
          href={auditTrailHref}
          className="text-[var(--accent)] hover:underline"
          data-testid="throttle-audit-trail-link"
        >
          → Перейти к audit trail (emergency.throttle)
        </a>
      </section>

      <PerTenantThrottleDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        pinnedTenantId={isSuperAdmin ? null : session.tenantId}
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
        onSuccess={handleThrottleSuccess}
      />

      {resumeOpen ? (
        <ResumeConfirmDialog
          tenantLabel={
            tenantOptions.find((t) => t.id === selectedTenantId)?.name ??
            selectedTenantId
          }
          onCancel={() => setResumeOpen(false)}
          onConfirm={handleResumeConfirm}
        />
      ) : null}
    </div>
  );
}

function ActiveThrottleSummary({
  throttle,
  onExpire,
}: {
  throttle: NonNullable<ReturnType<typeof findActiveThrottle>>;
  onExpire: () => void;
}): React.ReactElement {
  return (
    <div className="grid grid-cols-1 gap-2 sm:grid-cols-[140px_1fr] sm:gap-x-4">
      <div className="text-xs text-[var(--text-muted)]">State</div>
      <div
        data-testid="throttle-status-badge"
        data-state="active"
        className="text-sm font-semibold text-amber-300"
      >
        ACTIVE — throttle in effect
      </div>

      <div className="text-xs text-[var(--text-muted)]">Time remaining</div>
      <div className="text-sm">
        <CountdownTimer
          expiresAt={throttle.expires_at}
          onExpire={onExpire}
          ariaLabel={`Time remaining for tenant throttle on ${throttle.tenant_id}`}
          className="font-mono text-amber-200"
        />
        <span className="ml-2 text-[11px] text-[var(--text-muted)]">
          (до {formatActivatedAt(throttle.expires_at)})
        </span>
      </div>

      <div className="text-xs text-[var(--text-muted)]">Reason</div>
      <div className="text-sm text-[var(--text-primary)]">
        {throttle.reason}
      </div>

      <div className="text-xs text-[var(--text-muted)]">Activated at</div>
      <div className="text-sm text-[var(--text-primary)]">
        {formatActivatedAt(throttle.activated_at)}
      </div>
    </div>
  );
}

function InactiveSummary({
  tenantId,
  isSuperAdmin,
}: {
  tenantId: string;
  isSuperAdmin: boolean;
}): React.ReactElement {
  if (!tenantId) {
    return (
      <p className="text-sm text-[var(--text-muted)]">
        {isSuperAdmin
          ? "Выберите tenant для просмотра состояния throttle."
          : "Не привязан tenant — обратитесь к super-admin."}
      </p>
    );
  }
  return (
    <div className="grid grid-cols-[140px_1fr] gap-x-4 gap-y-2">
      <div className="text-xs text-[var(--text-muted)]">State</div>
      <div
        data-testid="throttle-status-badge"
        data-state="inactive"
        className="text-sm font-semibold text-emerald-300"
      >
        NORMAL — no throttle in effect
      </div>
      <div className="text-xs text-[var(--text-muted)]">Tenant</div>
      <div className="font-mono text-xs text-[var(--text-primary)]">
        {tenantId}
      </div>
    </div>
  );
}

function ResumeConfirmDialog({
  tenantLabel,
  onCancel,
  onConfirm,
}: {
  tenantLabel: string;
  onCancel: () => void;
  onConfirm: () => void;
}): React.ReactElement {
  const titleId = useId();
  const descriptionId = useId();
  const dialogRef = useRef<HTMLDivElement | null>(null);

  // The dialog is mounted only while open — `enabled` is therefore
  // always true here. Esc + Tab cycling + focus restoration are
  // delegated to the shared hook so the throttle and resume modals
  // stay behaviourally identical for AT users (T29 review S2 #2).
  useFocusTrap({
    enabled: true,
    containerRef: dialogRef,
    onEscape: onCancel,
  });

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4"
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        className="flex w-full max-w-md flex-col gap-3 rounded-lg border border-amber-500/60 bg-[var(--bg-secondary)] p-4 text-[var(--text-primary)]"
        data-testid="throttle-resume-dialog"
      >
        <h2 id={titleId} className="text-base font-semibold">
          Resume throttle for {tenantLabel}?
        </h2>
        <p id={descriptionId} className="text-sm text-[var(--text-secondary)]">
          Manual resume требует выделенного backend-маршрута и пока не
          реализован (carry-over). Подтверждение покажет ожидаемое сообщение
          об ошибке; auto-resume по TTL продолжает работать без вмешательства.
        </p>
        <div className="flex justify-end gap-2">
          <button
            type="button"
            className="rounded border border-[var(--border)] px-3 py-1.5 text-xs"
            onClick={onCancel}
            data-testid="throttle-resume-cancel"
          >
            Отмена
          </button>
          <button
            type="button"
            className="rounded border border-amber-500 bg-amber-600 px-3 py-1.5 text-xs font-medium text-white"
            onClick={onConfirm}
            data-testid="throttle-resume-confirm"
          >
            Resume now
          </button>
        </div>
      </div>
    </div>
  );
}

// Re-export the AdminRole alias so consumers can wire the optional UI
// hint without importing from `services/admin/adminRoles.ts`. This keeps
// the public surface of this client minimal.
export type { AdminRole };
