"use client";

/**
 * `PerScanKillSwitchDialog` — confirmation modal for the per-scan
 * kill-switch (T28, Cycle 6 Batch 4).
 *
 * Why so much UX friction:
 *   Cancelling a running scan is destructive and irreversible from the
 *   operator's POV (the worker may still be midway through a fingerprint
 *   pass). To prevent fat-finger misclicks the dialog requires the operator
 *   to **type the full scan id by hand** before the submit button becomes
 *   enabled. Pasting / dragging is blocked at the input level so a stale
 *   clipboard cannot complete the gesture.
 *
 * A11y (zero axe-core findings target — T36 audit):
 *   - `role="dialog"` + `aria-modal="true"` + labelled by the visible `<h2>`.
 *   - First focusable element auto-focuses on open; on close, focus is
 *     restored to the element that triggered the dialog (when it still
 *     exists in the DOM).
 *   - Esc closes (when not submitting).
 *   - Tab / Shift-Tab cycle within the dialog — light-weight focus trap
 *     (mirrors `BulkActionDialog` / `AuditLogsTable` drawer pattern).
 *   - The disabled submit button carries `aria-disabled` and an
 *     `aria-describedby` pointing at a help line so AT users hear *why*
 *     the action is unavailable (matches scan id exactly).
 *
 * Security:
 *   - Backend call is a server action (`cancelAdminScan`); the
 *     `X-Admin-Key` never reaches the browser.
 *   - We render `scan.id` and `scan.target_url` as plain text — never
 *     `dangerouslySetInnerHTML`, never `innerHTML`.
 *   - On error, the dialog renders a closed-taxonomy RU sentence; raw
 *     backend `detail` strings, stack traces and PII are filtered out by
 *     `scanActionErrorMessage` and `callAdminBackendJson`.
 *   - Logging in the browser uses a 12-char id prefix so the full scan
 *     UUID is never written to console.
 */

import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  useTransition,
  type ClipboardEvent,
  type DragEvent,
  type FormEvent,
} from "react";

import { cancelAdminScan } from "@/app/admin/scans/actions";
import {
  scanActionErrorMessage,
  type KillScanResult,
} from "@/lib/adminScans";

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

const DEFAULT_REASON = "manual operator stop via kill-switch";

export type ScanKillTarget = {
  readonly id: string;
  readonly target_url: string;
  readonly status: string;
  readonly tenant_id: string;
};

export type PerScanKillSwitchDialogProps = {
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly scan: ScanKillTarget;
  readonly onSuccess?: (result: KillScanResult) => void;
  /**
   * Override the server action — mainly used by unit tests so we don't need
   * to mock the `"use server"` module boundary at the dialog level.
   */
  readonly cancelAction?: typeof cancelAdminScan;
};

function shortId(id: string): string {
  return id.length <= 12 ? id : `${id.slice(0, 8)}…`;
}

export function PerScanKillSwitchDialog({
  open,
  onOpenChange,
  scan,
  onSuccess,
  cancelAction = cancelAdminScan,
}: PerScanKillSwitchDialogProps): React.ReactElement | null {
  const titleId = useId();
  const descriptionId = useId();
  const inputId = useId();
  const helpId = useId();

  const dialogRef = useRef<HTMLDivElement | null>(null);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const previouslyFocusedRef = useRef<HTMLElement | null>(null);

  const [typedId, setTypedId] = useState<string>("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  // React 19 "derived-from-props" reset pattern — calling setState during
  // render is the recommended way to reset state when an external prop
  // changes (vs. an effect, which triggers a redundant cascade and trips
  // the project's `react-hooks/set-state-in-effect` rule). See
  // https://react.dev/learn/you-might-need-an-effect#resetting-all-state-when-a-prop-changes
  const [lastIdentity, setLastIdentity] = useState<string>(
    () => `${open ? "1" : "0"}:${scan.id}`,
  );
  const currentIdentity = `${open ? "1" : "0"}:${scan.id}`;
  if (currentIdentity !== lastIdentity) {
    setLastIdentity(currentIdentity);
    setTypedId("");
    setErrorMessage(null);
  }

  const matches = useMemo(
    () => typedId === scan.id,
    [typedId, scan.id],
  );
  const canSubmit = matches && !isPending;

  // Focus management: capture the previously-focused element on open,
  // restore on close. Auto-focus the typed-id input so AT users land on
  // the action they have to take.
  useEffect(() => {
    if (!open) return;
    previouslyFocusedRef.current =
      typeof document !== "undefined"
        ? (document.activeElement as HTMLElement | null)
        : null;
    const id = window.setTimeout(() => {
      inputRef.current?.focus();
    }, 0);
    return () => {
      window.clearTimeout(id);
      const restoreTo = previouslyFocusedRef.current;
      previouslyFocusedRef.current = null;
      if (
        restoreTo &&
        typeof restoreTo.focus === "function" &&
        typeof document !== "undefined" &&
        document.contains(restoreTo)
      ) {
        restoreTo.focus();
      }
    };
  }, [open]);

  // Esc closes when not submitting; Tab cycles focus inside the dialog so
  // keyboard users cannot drift onto the page background while the modal
  // is up.
  useEffect(() => {
    if (!open) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && !isPending) {
        e.preventDefault();
        onOpenChange(false);
        return;
      }
      if (e.key !== "Tab") return;
      const container = dialogRef.current;
      if (!container) return;
      const focusables = Array.from(
        container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR),
      ).filter((el) => el.getAttribute("aria-hidden") !== "true");
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const active = document.activeElement as HTMLElement | null;
      if (e.shiftKey && (active === first || !container.contains(active))) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open, isPending, onOpenChange]);

  const handlePaste = (e: ClipboardEvent<HTMLInputElement>) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleDrop = (e: DragEvent<HTMLInputElement>) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleBackdropMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    if (e.target === e.currentTarget && !isPending) {
      onOpenChange(false);
    }
  };

  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!canSubmit) return;
    setErrorMessage(null);
    startTransition(async () => {
      try {
        const result = await cancelAction({
          scanId: scan.id,
          tenantId: scan.tenant_id,
          reason: DEFAULT_REASON,
        });
        onOpenChange(false);
        if (onSuccess) onSuccess(result);
      } catch (err) {
        setErrorMessage(scanActionErrorMessage(err));
      }
    });
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-40 flex items-center justify-center bg-black/60 p-4"
      data-testid="kill-scan-dialog-backdrop"
      onMouseDown={handleBackdropMouseDown}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
        className="flex w-full max-w-lg flex-col gap-4 rounded-lg border border-red-500/60 bg-[var(--bg-secondary)] p-5 text-[var(--text-primary)] shadow-2xl"
        data-testid="kill-scan-dialog"
      >
        <header className="flex items-start justify-between gap-2">
          <h2
            id={titleId}
            className="text-base font-semibold text-[var(--text-primary)]"
          >
            Kill scan {shortId(scan.id)}
          </h2>
          <button
            type="button"
            onClick={() => onOpenChange(false)}
            disabled={isPending}
            className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
            aria-label="Закрыть диалог"
            data-testid="kill-scan-dialog-close"
          >
            ×
          </button>
        </header>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-2 text-sm">
            <p
              id={descriptionId}
              className="text-[var(--text-secondary)]"
            >
              Это действие отменит активный скан и зафиксирует событие в
              audit-логе. Восстановить отменённый скан нельзя — потребуется
              перезапуск.
            </p>

            <dl className="grid grid-cols-[88px_1fr] gap-x-3 gap-y-1 rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-xs">
              <dt className="text-[var(--text-muted)]">Scan ID</dt>
              <dd
                className="break-all font-mono text-[var(--text-primary)]"
                data-testid="kill-scan-dialog-scan-id"
              >
                <code>{scan.id}</code>
              </dd>
              <dt className="text-[var(--text-muted)]">Target</dt>
              <dd
                className="break-all text-[var(--text-primary)]"
                data-testid="kill-scan-dialog-target"
              >
                {scan.target_url}
              </dd>
              <dt className="text-[var(--text-muted)]">Status</dt>
              <dd className="text-[var(--text-primary)]">{scan.status}</dd>
            </dl>
          </div>

          <div className="flex flex-col gap-1">
            <label
              htmlFor={inputId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Введите Scan ID для подтверждения
            </label>
            <input
              id={inputId}
              ref={inputRef}
              type="text"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              value={typedId}
              onChange={(e) => setTypedId(e.target.value)}
              onPaste={handlePaste}
              onDrop={handleDrop}
              onDragOver={handleDrop}
              aria-describedby={helpId}
              aria-invalid={typedId.length > 0 && !matches}
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 font-mono text-xs text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
              data-testid="kill-scan-dialog-input"
              disabled={isPending}
            />
            <span
              id={helpId}
              className="text-[11px] text-[var(--text-muted)]"
              data-testid="kill-scan-dialog-help"
            >
              Введите идентификатор скана дословно (paste отключён). Кнопка
              станет активной после точного совпадения.
            </span>
          </div>

          {errorMessage ? (
            <div
              role="alert"
              aria-live="polite"
              className="rounded border border-red-500/60 bg-red-500/10 px-3 py-2 text-xs text-red-200"
              data-testid="kill-scan-dialog-error"
            >
              {errorMessage}
            </div>
          ) : null}

          <footer className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={() => onOpenChange(false)}
              disabled={isPending}
              className="rounded border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
              data-testid="kill-scan-dialog-cancel"
            >
              Отмена
            </button>
            <button
              type="submit"
              disabled={!canSubmit}
              aria-disabled={!canSubmit}
              aria-describedby={helpId}
              className="rounded border border-red-500 bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:opacity-90 focus-visible:ring-2 focus-visible:ring-red-400 focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
              data-testid="kill-scan-dialog-confirm"
            >
              {isPending ? "Отменяем…" : "Kill scan"}
            </button>
          </footer>
        </form>
      </div>
    </div>
  );
}
