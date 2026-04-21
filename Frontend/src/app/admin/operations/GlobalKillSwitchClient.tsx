"use client";

/**
 * `GlobalKillSwitchClient` — super-admin-facing global emergency stop
 * dashboard (T30, ARG-053).
 *
 * Layout (super-admin):
 *   ┌─ Banner ─────────────────────────────────────┐
 *   │  GREEN: "All systems normal"                 │
 *   │  -- OR --                                    │
 *   │  RED: "🚨 GLOBAL STOP ACTIVE since {ts}"     │
 *   │       reason: ...                            │
 *   └──────────────────────────────────────────────┘
 *   [STOP ALL SCANS] (red, full-width) — when GREEN
 *   [Resume all scans] (yellow) — when RED
 *   <EmergencyAuditTrail …/>
 *
 * Layout (admin): single notice card explaining super-admin only.
 *
 * Status polling:
 *   `setInterval(statusPollMs)` (default 10 s). Cleanup on unmount.
 *   `reqIdRef` prevents stale-overwrite races (T29 review S2 #1). Polling
 *   pauses while either confirmation dialog is open so the operator is
 *   not pulled out of the typed-phrase flow by an info banner re-render.
 *
 * No `useTransition` for polling — `useTransition` is for one-off
 *   action submissions (handled inside the dialogs). Polling is plain
 *   `useState` + `useEffect` + `useRef`, mirroring the pattern that
 *   PerTenantThrottleClient uses for `refetchStatus`.
 */

import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  getEmergencyStatusAction,
  listEmergencyAuditTrailAction,
  stopAllAction,
  resumeAllAction,
} from "@/app/admin/operations/actions";
import { EmergencyAuditTrail } from "@/components/admin/operations/EmergencyAuditTrail";
import { GlobalKillSwitchDialog } from "@/components/admin/operations/GlobalKillSwitchDialog";
import { ResumeAllDialog } from "@/components/admin/operations/ResumeAllDialog";
import {
  throttleActionErrorMessage,
  type EmergencyAuditListResponse,
  type StopAllResponse,
  type ThrottleStatusResponse,
} from "@/lib/adminOperations";

const DEFAULT_STATUS_POLL_MS = 10_000;
const INFO_BANNER_TIMEOUT_MS = 5_000;

export type GlobalKillSwitchSession = {
  readonly role: "admin" | "super-admin";
};

export type GlobalKillSwitchClientProps = {
  readonly session: GlobalKillSwitchSession;
  readonly initialStatus: ThrottleStatusResponse | null;
  readonly initialAuditTrail: EmergencyAuditListResponse | null;
  /** Test override — defaults to `getEmergencyStatusAction`. */
  readonly statusAction?: typeof getEmergencyStatusAction;
  /** Test override — defaults to `stopAllAction`. */
  readonly stopAction?: typeof stopAllAction;
  /** Test override — defaults to `resumeAllAction`. */
  readonly resumeAction?: typeof resumeAllAction;
  /** Test override — defaults to `listEmergencyAuditTrailAction`. */
  readonly auditAction?: typeof listEmergencyAuditTrailAction;
  /** Test override — defaults to 10_000 ms; tests pass 100 ms with fake timers. */
  readonly statusPollMs?: number;
  /** Test override — defaults to 30_000 ms; same idea. */
  readonly auditPollMs?: number;
};

function formatActivatedAt(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

export function GlobalKillSwitchClient({
  session,
  initialStatus,
  initialAuditTrail,
  statusAction = getEmergencyStatusAction,
  stopAction = stopAllAction,
  resumeAction = resumeAllAction,
  auditAction = listEmergencyAuditTrailAction,
  statusPollMs = DEFAULT_STATUS_POLL_MS,
  auditPollMs,
}: GlobalKillSwitchClientProps): React.ReactElement {
  const isSuperAdmin = session.role === "super-admin";

  const [status, setStatus] = useState<ThrottleStatusResponse | null>(
    initialStatus,
  );
  const [statusError, setStatusError] = useState<string | null>(null);
  const [stopOpen, setStopOpen] = useState(false);
  const [resumeOpen, setResumeOpen] = useState(false);
  const [actionInfo, setActionInfo] = useState<string | null>(null);

  // Bump on every successful action to force EmergencyAuditTrail to refetch
  // (it owns its own list state). Cheaper than threading a callback through
  // the child and avoids a re-render loop when the child is also polling.
  const [auditNonce, setAuditNonce] = useState(0);

  // Same monotonic-id pattern as PerTenantThrottleClient.refetchStatus.
  const reqIdRef = useRef(0);

  // Polling pause: while either confirmation dialog is open we skip
  // status pulls so the operator is not yanked between dialog renders.
  const dialogOpen = stopOpen || resumeOpen;
  const dialogOpenRef = useRef(dialogOpen);
  useEffect(() => {
    dialogOpenRef.current = dialogOpen;
  }, [dialogOpen]);

  const refetchStatus = useCallback(async () => {
    if (!isSuperAdmin) return;
    const myReqId = ++reqIdRef.current;
    try {
      const next = await statusAction({});
      if (myReqId !== reqIdRef.current) return;
      setStatus(next);
      setStatusError(null);
    } catch (err) {
      if (myReqId !== reqIdRef.current) return;
      setStatusError(throttleActionErrorMessage(err));
    }
  }, [isSuperAdmin, statusAction]);

  // Status polling — skip when the dialog is open. Cleared on unmount.
  useEffect(() => {
    if (!isSuperAdmin || statusPollMs <= 0) return;
    const id = window.setInterval(() => {
      if (dialogOpenRef.current) return;
      void refetchStatus();
    }, statusPollMs);
    return () => {
      window.clearInterval(id);
    };
  }, [isSuperAdmin, statusPollMs, refetchStatus]);

  // Auto-clear the success info banner after 5 s so an operator who
  // pulls up the page minutes later doesn't see a stale toast.
  useEffect(() => {
    if (!actionInfo) return;
    const id = window.setTimeout(() => setActionInfo(null), INFO_BANNER_TIMEOUT_MS);
    return () => window.clearTimeout(id);
  }, [actionInfo]);

  const handleStopSuccess = (result: StopAllResponse) => {
    setActionInfo(
      `Глобальный stop активен. Отменено scan: ${result.cancelled_count}, ` +
        `tenant затронуто: ${result.tenants_affected}.`,
    );
    setAuditNonce((n) => n + 1);
    void refetchStatus();
  };

  const handleResumeSuccess = () => {
    setActionInfo("Глобальный stop снят. Дисптач scan возобновлён.");
    setAuditNonce((n) => n + 1);
    void refetchStatus();
  };

  if (!isSuperAdmin) {
    return (
      <section
        className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-4"
        aria-labelledby="global-kill-switch-admin-notice-h"
        data-testid="global-kill-switch-admin-notice"
      >
        <h2
          id="global-kill-switch-admin-notice-h"
          className="text-base font-semibold text-[var(--text-primary)]"
        >
          Global emergency stop
        </h2>
        <p className="mt-2 text-sm text-[var(--text-secondary)]">
          Управление глобальным emergency-stop доступно только super-admin.
          Запросите доступ у владельца платформы при необходимости срочной
          остановки всех scan.
        </p>
      </section>
    );
  }

  const isActive = Boolean(status?.global_state.active);
  const reason = status?.global_state.reason ?? null;
  const activatedAt = status?.global_state.activated_at ?? null;

  return (
    <div className="space-y-4" data-testid="global-kill-switch-client">
      <header>
        <h2 className="text-lg font-semibold text-[var(--text-primary)]">
          Operations · Global emergency stop
        </h2>
        <p className="text-sm text-[var(--text-secondary)]">
          Cross-tenant kill-switch. Останавливает диспатч новых scan по
          всей платформе и отменяет все активные scan. Действие фиксируется
          в audit-логе.
        </p>
      </header>

      {statusError ? (
        <div
          role="alert"
          className="rounded border border-red-900/40 bg-red-950/30 px-3 py-2 text-sm text-red-200"
          data-testid="global-kill-switch-status-error"
        >
          {statusError}
        </div>
      ) : null}

      {actionInfo ? (
        <div
          className="rounded border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-200"
          data-testid="global-kill-switch-action-info"
        >
          {actionInfo}
        </div>
      ) : null}

      <section
        className={`rounded border p-4 ${isActive ? "border-red-500/60 bg-red-950/30" : "border-emerald-500/40 bg-emerald-950/20"}`}
        role="status"
        aria-label="Состояние глобального kill-switch"
        data-testid="global-kill-switch-banner"
        data-state={isActive ? "active" : "normal"}
      >
        {isActive ? (
          <div className="flex flex-col gap-2">
            <p className="text-base font-semibold text-red-200">
              🚨 GLOBAL STOP ACTIVE
            </p>
            <p className="text-sm text-[var(--text-secondary)]">
              Активен с{" "}
              <time
                dateTime={activatedAt ?? undefined}
                className="font-mono"
              >
                {formatActivatedAt(activatedAt)}
              </time>
            </p>
            {reason ? (
              <p className="text-sm text-[var(--text-primary)]">
                <span className="text-[var(--text-muted)]">Причина: </span>
                {reason}
              </p>
            ) : null}
          </div>
        ) : (
          <p className="text-base font-semibold text-emerald-200">
            ✅ All systems normal — диспатч scan работает в штатном режиме.
          </p>
        )}
      </section>

      <div data-testid="global-kill-switch-actions">
        {isActive ? (
          <button
            type="button"
            onClick={() => setResumeOpen(true)}
            className="w-full rounded border border-amber-500 bg-amber-600 px-3 py-2 text-sm font-semibold text-white hover:opacity-90 focus-visible:ring-2 focus-visible:ring-amber-400 focus-visible:outline-none sm:w-auto"
            data-testid="global-kill-switch-open-resume"
          >
            Resume all scans
          </button>
        ) : (
          <button
            type="button"
            onClick={() => setStopOpen(true)}
            className="w-full rounded border border-red-500 bg-red-700 px-3 py-2 text-sm font-semibold text-white hover:opacity-90 focus-visible:ring-2 focus-visible:ring-red-400 focus-visible:outline-none sm:w-auto"
            data-testid="global-kill-switch-open-stop"
          >
            STOP ALL SCANS
          </button>
        )}
      </div>

      <EmergencyAuditTrail
        key={auditNonce}
        initial={initialAuditTrail}
        auditAction={auditAction}
        tenantId={null}
        pollMs={auditPollMs}
      />

      <GlobalKillSwitchDialog
        open={stopOpen}
        onOpenChange={setStopOpen}
        onSuccess={handleStopSuccess}
        stopAction={stopAction}
      />
      <ResumeAllDialog
        open={resumeOpen}
        onOpenChange={setResumeOpen}
        onSuccess={handleResumeSuccess}
        resumeAction={resumeAction}
      />
    </div>
  );
}
