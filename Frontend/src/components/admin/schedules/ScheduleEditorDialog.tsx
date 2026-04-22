"use client";

/**
 * `ScheduleEditorDialog` — modal form for create/edit of a scan schedule
 * (T35, ARG-056).
 *
 * RBAC:
 *   The tenant selector is HIDDEN for `admin` operators — the dialog is
 *   pinned to the session-bound tenant the parent client passed in. The
 *   server action also pins to `session.tenantId` independently so a
 *   craftily mounted React tree cannot widen scope.
 *
 * A11y (zero axe-core findings target):
 *   - `role="dialog"` + `aria-modal="true"` + labelled by the visible h2.
 *   - First focusable input auto-focuses on open (via `useFocusTrap`);
 *     focus restored to triggering element on close.
 *   - Esc closes (when not submitting); Tab/Shift-Tab cycle within the
 *     dialog. Backdrop click closes.
 *   - Disabled submit carries `aria-disabled` + `aria-describedby` so AT
 *     users hear *why* it is unavailable.
 *
 * Wire safety:
 *   - On submit, the dialog calls the matching server action and surfaces
 *     ANY failure as a closed-taxonomy RU sentence (`scheduleActionErrorMessage`).
 *   - Specific 422 / 409 codes (`invalid_cron_expression`,
 *     `schedule_name_conflict`) DO highlight the offending field via
 *     `aria-invalid` so AT users get the same hint.
 *   - We deliberately do NOT echo backend `detail` strings — every error
 *     path renders a stable RU sentence instead.
 */

import {
  useCallback,
  useId,
  useMemo,
  useRef,
  useState,
  useTransition,
  type FormEvent,
} from "react";

import { useFocusTrap } from "@/components/admin/operations/useFocusTrap";
import {
  createScheduleAction,
  updateScheduleAction,
} from "@/app/admin/schedules/actions";
import {
  SCAN_MODES,
  SCAN_MODE_LABELS_RU,
  SCHEDULE_NAME_MAX,
  SCHEDULE_NAME_MIN,
  SCHEDULE_TARGET_MAX,
  ScheduleActionError,
  ScheduleCreateInputSchema,
  ScheduleUpdateInputSchema,
  extractScheduleActionCode,
  isUuid,
  scheduleActionErrorMessage,
  type ScanMode,
  type Schedule,
} from "@/lib/adminSchedules";
import { CronExpressionField } from "./CronExpressionField";

export type ScheduleEditorTenantOption = {
  readonly id: string;
  readonly name: string;
};

export type ScheduleEditorDialogProps = {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly mode: "create" | "edit";
  /** When set, the tenant selector is hidden (admin-pinned). */
  readonly pinnedTenantId: string | null;
  readonly availableTenants: ReadonlyArray<ScheduleEditorTenantOption>;
  /** Required for `mode="edit"`. */
  readonly initialSchedule?: Schedule | null;
  readonly onSuccess?: (next: Schedule) => void;
  /** Test override — defaults to the canonical create action. */
  readonly createAction?: typeof createScheduleAction;
  /** Test override — defaults to the canonical update action. */
  readonly updateAction?: typeof updateScheduleAction;
};

type FormState = {
  readonly tenantId: string;
  readonly name: string;
  readonly cron: string;
  readonly targetUrl: string;
  readonly scanMode: ScanMode;
  readonly enabled: boolean;
  readonly maintenanceCron: string;
};

function buildInitialForm(
  mode: "create" | "edit",
  initial: Schedule | null | undefined,
  pinnedTenantId: string | null,
  availableTenants: ReadonlyArray<ScheduleEditorTenantOption>,
): FormState {
  if (mode === "edit" && initial) {
    return {
      tenantId: initial.tenant_id,
      name: initial.name,
      cron: initial.cron_expression,
      targetUrl: initial.target_url,
      scanMode: (SCAN_MODES as ReadonlyArray<string>).includes(initial.scan_mode)
        ? (initial.scan_mode as ScanMode)
        : "standard",
      enabled: initial.enabled,
      maintenanceCron: initial.maintenance_window_cron ?? "",
    };
  }
  const defaultTenant = pinnedTenantId ?? availableTenants[0]?.id ?? "";
  return {
    tenantId: defaultTenant,
    name: "",
    cron: "0 * * * *",
    targetUrl: "https://example.com",
    scanMode: "standard",
    enabled: true,
    maintenanceCron: "",
  };
}

export function ScheduleEditorDialog({
  open,
  onOpenChange,
  mode,
  pinnedTenantId,
  availableTenants,
  initialSchedule,
  onSuccess,
  createAction = createScheduleAction,
  updateAction = updateScheduleAction,
}: ScheduleEditorDialogProps): React.ReactElement | null {
  const titleId = useId();
  const descriptionId = useId();
  const tenantId = useId();
  const nameId = useId();
  const cronId = useId();
  const targetId = useId();
  const scanModeId = useId();
  const enabledId = useId();
  const maintenanceId = useId();
  const submitHelpId = useId();

  const dialogRef = useRef<HTMLDivElement | null>(null);
  const firstFieldRef = useRef<HTMLElement | null>(null);

  const initial = useMemo(
    () => buildInitialForm(mode, initialSchedule, pinnedTenantId, availableTenants),
    [mode, initialSchedule, pinnedTenantId, availableTenants],
  );

  const [form, setForm] = useState<FormState>(initial);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  // React 19 derived-from-props reset pattern. Reset the form whenever
  // the dialog opens against a different schedule (or transitions
  // create ↔ edit) so stale state from a previous session never bleeds
  // into the new form.
  const identityKey = `${open ? "1" : "0"}:${mode}:${initialSchedule?.id ?? "new"}:${pinnedTenantId ?? "any"}`;
  const [lastIdentity, setLastIdentity] = useState<string>(identityKey);
  if (identityKey !== lastIdentity) {
    setLastIdentity(identityKey);
    setForm(initial);
    setErrorMessage(null);
    setErrorCode(null);
  }

  const handleEscape = useCallback(() => {
    if (isPending) return;
    onOpenChange(false);
  }, [isPending, onOpenChange]);

  useFocusTrap({
    enabled: open,
    containerRef: dialogRef,
    initialFocusRef: firstFieldRef,
    onEscape: handleEscape,
  });

  const handleBackdropMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    if (e.target === e.currentTarget && !isPending) {
      onOpenChange(false);
    }
  };

  const trimmedName = form.name.trim();
  const nameValid =
    trimmedName.length >= SCHEDULE_NAME_MIN &&
    trimmedName.length <= SCHEDULE_NAME_MAX;
  const tenantValid =
    pinnedTenantId !== null
      ? isUuid(pinnedTenantId)
      : isUuid(form.tenantId);

  const canSubmit = nameValid && tenantValid && !isPending;

  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!canSubmit) return;
    setErrorMessage(null);
    setErrorCode(null);

    if (mode === "create") {
      const parsed = ScheduleCreateInputSchema.safeParse({
        tenantId: pinnedTenantId ?? form.tenantId,
        name: form.name,
        cronExpression: form.cron,
        targetUrl: form.targetUrl,
        scanMode: form.scanMode,
        enabled: form.enabled,
        maintenanceWindowCron: form.maintenanceCron === "" ? null : form.maintenanceCron,
      });
      if (!parsed.success) {
        const next = new ScheduleActionError("validation_failed", 400);
        setErrorMessage(scheduleActionErrorMessage(next));
        setErrorCode(next.code);
        return;
      }
      startTransition(async () => {
        try {
          const created = await createAction(parsed.data);
          onOpenChange(false);
          if (onSuccess) onSuccess(created);
        } catch (err) {
          setErrorMessage(scheduleActionErrorMessage(err));
          setErrorCode(extractScheduleActionCode(err));
        }
      });
      return;
    }

    if (!initialSchedule) return;
    // PATCH semantic: send only the fields the operator changed. The
    // server treats `null` as "no change" (T33 deferred clear-via-null);
    // we therefore send nothing for `maintenanceWindowCron` when the user
    // hasn't touched it. To CLEAR it, the user must currently delete the
    // schedule and recreate it (documented carry-over).
    const partial: Record<string, unknown> = {};
    if (form.name !== initialSchedule.name) partial.name = form.name;
    if (form.cron !== initialSchedule.cron_expression)
      partial.cronExpression = form.cron;
    if (form.targetUrl !== initialSchedule.target_url)
      partial.targetUrl = form.targetUrl;
    if (form.scanMode !== initialSchedule.scan_mode)
      partial.scanMode = form.scanMode;
    if (form.enabled !== initialSchedule.enabled) partial.enabled = form.enabled;
    if (
      form.maintenanceCron !== "" &&
      form.maintenanceCron !== (initialSchedule.maintenance_window_cron ?? "")
    ) {
      partial.maintenanceWindowCron = form.maintenanceCron;
    }

    const parsed = ScheduleUpdateInputSchema.safeParse(partial);
    if (!parsed.success) {
      const next = new ScheduleActionError("validation_failed", 400);
      setErrorMessage(scheduleActionErrorMessage(next));
      setErrorCode(next.code);
      return;
    }
    startTransition(async () => {
      try {
        const updated = await updateAction(initialSchedule.id, parsed.data);
        onOpenChange(false);
        if (onSuccess) onSuccess(updated);
      } catch (err) {
        setErrorMessage(scheduleActionErrorMessage(err));
        setErrorCode(extractScheduleActionCode(err));
      }
    });
  };

  if (!open) return null;

  const tenantSelectorVisible = pinnedTenantId === null;
  const cronInvalid = errorCode === "invalid_cron_expression";
  const maintenanceInvalid = errorCode === "invalid_maintenance_window_cron";
  const nameInvalid = errorCode === "schedule_name_conflict";

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4"
      data-testid="schedule-editor-backdrop"
      onMouseDown={handleBackdropMouseDown}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        className="flex max-h-[90vh] w-full max-w-2xl flex-col gap-3 overflow-y-auto rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-5 text-[var(--text-primary)] shadow-2xl"
        data-testid="schedule-editor-dialog"
      >
        <header className="flex items-start justify-between gap-2">
          <h2 id={titleId} className="text-base font-semibold">
            {mode === "create"
              ? "Создать расписание"
              : `Редактировать ${initialSchedule?.name ?? "расписание"}`}
          </h2>
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            disabled={isPending}
            className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
            aria-label="Закрыть диалог"
            data-testid="schedule-editor-close"
          >
            ×
          </button>
        </header>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <p
            id={descriptionId}
            className="text-sm text-[var(--text-secondary)]"
          >
            Расписание периодически запускает scan для указанного target по
            cron-выражению. Maintenance window — опциональный интервал, в
            который запуски подавляются. URL очищается от query/fragment перед
            сохранением (PII safety).
          </p>

          {tenantSelectorVisible ? (
            <div className="flex flex-col gap-1">
              <label
                htmlFor={tenantId}
                className="text-xs font-medium text-[var(--text-muted)]"
              >
                Tenant
              </label>
              <select
                id={tenantId}
                ref={firstFieldRef as React.RefObject<HTMLSelectElement>}
                value={form.tenantId}
                onChange={(e) =>
                  setForm((f) => ({ ...f, tenantId: e.target.value }))
                }
                disabled={isPending || mode === "edit"}
                aria-required="true"
                className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
                data-testid="schedule-editor-tenant"
              >
                {availableTenants.length === 0 ? (
                  <option value="">—</option>
                ) : (
                  availableTenants.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))
                )}
              </select>
            </div>
          ) : (
            <input
              type="hidden"
              data-testid="schedule-editor-tenant-pinned"
              value={pinnedTenantId ?? ""}
              readOnly
            />
          )}

          <div className="flex flex-col gap-1">
            <label
              htmlFor={nameId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Имя расписания
            </label>
            <input
              id={nameId}
              ref={
                tenantSelectorVisible
                  ? undefined
                  : (firstFieldRef as React.RefObject<HTMLInputElement>)
              }
              type="text"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
              disabled={isPending}
              minLength={SCHEDULE_NAME_MIN}
              maxLength={SCHEDULE_NAME_MAX}
              aria-required="true"
              aria-invalid={nameInvalid || (form.name.length > 0 && !nameValid)}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
              data-testid="schedule-editor-name"
            />
          </div>

          <div className="flex flex-col gap-1">
            <label
              htmlFor={cronId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Cron-выражение
            </label>
            <CronExpressionField
              id={cronId}
              mode="primary"
              value={form.cron}
              onChange={(next) => setForm((f) => ({ ...f, cron: next }))}
              disabled={isPending}
              ariaInvalid={cronInvalid}
            />
          </div>

          <div className="flex flex-col gap-1">
            <label
              htmlFor={targetId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Target URL
            </label>
            <input
              id={targetId}
              type="url"
              value={form.targetUrl}
              onChange={(e) =>
                setForm((f) => ({ ...f, targetUrl: e.target.value }))
              }
              disabled={isPending}
              maxLength={SCHEDULE_TARGET_MAX}
              aria-required="true"
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 font-mono text-xs text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
              data-testid="schedule-editor-target"
              spellCheck={false}
            />
            <span className="text-[11px] text-[var(--text-muted)]">
              Query string и fragment будут удалены при сохранении.
            </span>
          </div>

          <div className="flex flex-wrap gap-4">
            <div className="flex flex-col gap-1">
              <label
                htmlFor={scanModeId}
                className="text-xs font-medium text-[var(--text-muted)]"
              >
                Режим сканирования
              </label>
              <select
                id={scanModeId}
                value={form.scanMode}
                onChange={(e) =>
                  setForm((f) => ({
                    ...f,
                    scanMode: e.target.value as ScanMode,
                  }))
                }
                disabled={isPending}
                aria-required="true"
                className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
                data-testid="schedule-editor-scan-mode"
              >
                {SCAN_MODES.map((m) => (
                  <option key={m} value={m}>
                    {SCAN_MODE_LABELS_RU[m]}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex items-end gap-2">
              <input
                id={enabledId}
                type="checkbox"
                checked={form.enabled}
                onChange={(e) =>
                  setForm((f) => ({ ...f, enabled: e.target.checked }))
                }
                disabled={isPending}
                className="h-4 w-4 rounded border border-[var(--border)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
                data-testid="schedule-editor-enabled"
              />
              <label
                htmlFor={enabledId}
                className="text-xs text-[var(--text-secondary)]"
              >
                Включено
              </label>
            </div>
          </div>

          <div className="flex flex-col gap-1">
            <label
              htmlFor={maintenanceId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Maintenance window cron (опционально)
            </label>
            <CronExpressionField
              id={maintenanceId}
              mode="maintenance"
              value={form.maintenanceCron}
              onChange={(next) =>
                setForm((f) => ({ ...f, maintenanceCron: next }))
              }
              disabled={isPending}
              ariaInvalid={maintenanceInvalid}
            />
          </div>

          {errorMessage ? (
            <div
              role="alert"
              className="rounded border border-red-500/60 bg-red-500/10 px-3 py-2 text-xs text-red-200"
              data-testid="schedule-editor-error"
            >
              {errorMessage}
            </div>
          ) : null}

          <span id={submitHelpId} className="sr-only">
            Кнопка станет активной после ввода имени и выбора tenant.
          </span>

          <footer className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => onOpenChange(false)}
              disabled={isPending}
              className="rounded border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
              data-testid="schedule-editor-cancel"
            >
              Отмена
            </button>
            <button
              type="submit"
              disabled={!canSubmit}
              aria-disabled={!canSubmit}
              aria-describedby={submitHelpId}
              className="rounded border border-[var(--accent-strong)] bg-[var(--accent-strong)] px-3 py-1.5 text-xs font-medium text-[var(--on-accent)] hover:opacity-90 focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
              data-testid="schedule-editor-submit"
            >
              {isPending
                ? "Сохраняем…"
                : mode === "create"
                  ? "Создать расписание"
                  : "Сохранить изменения"}
            </button>
          </footer>
        </form>
      </div>
    </div>
  );
}
