"use client";

/**
 * `BulkActionDialog` — modal that confirms bulk operations on the
 * findings list. Reused for all four bulk actions; the rendered body
 * branches on `kind`:
 *
 *   - "suppress"            → reason dropdown + optional comment textarea
 *   - "mark_false_positive" → confirm checkbox + selection summary
 *   - "escalate" / "attach_to_cve" → Phase-2 stub (cancel-only)
 *
 * A11y:
 *   - `role="dialog"` + `aria-modal="true"` + labelled by `<h2>`.
 *   - First focusable element auto-focuses on open (lightweight focus
 *     trap; mirrors the FindingsTable drawer pattern from T20).
 *   - Esc cancels (calls `onClose`); Enter inside the form submits.
 *   - The confirm button is disabled until the body considers the form
 *     valid (e.g. reason chosen + comment ≤ MAX_BULK_COMMENT_LENGTH).
 *
 * Submission contract:
 *   - The dialog NEVER calls the backend itself. It collects user
 *     intent and hands a typed payload to `onConfirm`. The parent
 *     (AdminFindingsClient) owns the server-action call and the
 *     resulting toast/banner — that keeps the component decoupled from
 *     React Query and from the action layer.
 */

import { useEffect, useId, useMemo, useRef, useState } from "react";

import {
  BULK_SUPPRESS_REASONS,
  BULK_SUPPRESS_REASON_LABEL_RU,
  MAX_BULK_COMMENT_LENGTH,
  type BulkSuppressReason,
} from "@/lib/adminFindings";

import type { BulkActionKind } from "./BulkActionsToolbar";

export type BulkActionPayload =
  | {
      readonly kind: "suppress";
      readonly reason: BulkSuppressReason;
      readonly comment: string;
    }
  | {
      readonly kind: "mark_false_positive";
      readonly comment: string;
    };

export type BulkActionDialogProps = {
  readonly kind: BulkActionKind;
  readonly selectedCount: number;
  readonly submitting: boolean;
  readonly errorMessage: string | null;
  readonly onConfirm: (payload: BulkActionPayload) => void;
  readonly onClose: () => void;
};

const DIALOG_TITLE: Readonly<Record<BulkActionKind, string>> = {
  suppress: "Подавить findings",
  mark_false_positive: "Пометить как false positive",
  escalate: "Escalate findings",
  attach_to_cve: "Привязать к CVE",
};

const PHASE_2_BODY_TEXT: Partial<Readonly<Record<BulkActionKind, string>>> = {
  escalate:
    "Backend API для bulk-escalate ещё не реализовано (ISS-T21-001). Эта операция станет доступна после поставки Phase 2.",
  attach_to_cve:
    "Backend API для bulk-attach-CVE ещё не реализовано (ISS-T21-002). Эта операция станет доступна после поставки Phase 2.",
};

export function BulkActionDialog({
  kind,
  selectedCount,
  submitting,
  errorMessage,
  onConfirm,
  onClose,
}: BulkActionDialogProps): React.ReactElement {
  const titleId = useId();
  const reasonSelectId = useId();
  const commentId = useId();
  const fpConfirmId = useId();

  const dialogRef = useRef<HTMLDivElement | null>(null);
  const firstFocusableRef = useRef<HTMLElement | null>(null);
  const previouslyFocusedRef = useRef<HTMLElement | null>(null);

  const [suppressReason, setSuppressReason] =
    useState<BulkSuppressReason | "">("");
  const [comment, setComment] = useState<string>("");
  const [fpConfirmed, setFpConfirmed] = useState<boolean>(false);

  const isPhase2 = kind === "escalate" || kind === "attach_to_cve";

  // Focus management: capture the previously-focused element on mount,
  // restore on unmount. Auto-focus the first focusable inside the
  // dialog so AT users land on a known anchor.
  useEffect(() => {
    previouslyFocusedRef.current =
      typeof document !== "undefined"
        ? (document.activeElement as HTMLElement | null)
        : null;
    const id = window.setTimeout(() => {
      firstFocusableRef.current?.focus();
    }, 0);
    return () => {
      window.clearTimeout(id);
      const restoreTo = previouslyFocusedRef.current;
      if (
        restoreTo &&
        typeof restoreTo.focus === "function" &&
        typeof document !== "undefined" &&
        document.contains(restoreTo)
      ) {
        restoreTo.focus();
      }
    };
  }, []);

  // Esc closes; Tab stays inside (light-weight focus trap mirroring
  // the FindingsTable drawer in T20). We don't pull a portal lib in to
  // keep the bundle lean — the modal mounts inline with the page.
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape" && !submitting) {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== "Tab") return;
      const container = dialogRef.current;
      if (!container) return;
      const focusables = Array.from(
        container.querySelectorAll<HTMLElement>(
          'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
        ),
      ).filter((el) => el.getAttribute("aria-hidden") !== "true");
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const active = document.activeElement as HTMLElement | null;
      if (e.shiftKey && active === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose, submitting]);

  const commentTooLong = comment.length > MAX_BULK_COMMENT_LENGTH;

  const canConfirm = useMemo(() => {
    if (submitting || isPhase2) return false;
    if (commentTooLong) return false;
    if (kind === "suppress") {
      return suppressReason !== "";
    }
    if (kind === "mark_false_positive") {
      return fpConfirmed;
    }
    return false;
  }, [submitting, isPhase2, commentTooLong, kind, suppressReason, fpConfirmed]);

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!canConfirm) return;
    if (kind === "suppress" && suppressReason !== "") {
      onConfirm({
        kind: "suppress",
        reason: suppressReason,
        comment: comment.trim(),
      });
      return;
    }
    if (kind === "mark_false_positive") {
      onConfirm({ kind: "mark_false_positive", comment: comment.trim() });
    }
  };

  const renderBody = () => {
    if (isPhase2) {
      return (
        <p className="text-sm text-[var(--text-muted)]">
          {PHASE_2_BODY_TEXT[kind] ??
            "Эта операция ещё не реализована в backend."}
        </p>
      );
    }
    if (kind === "suppress") {
      return (
        <div className="flex flex-col gap-3">
          <p className="text-sm text-[var(--text-secondary)]">
            Будет подавлено{" "}
            <span className="font-semibold text-[var(--text-primary)]">
              {selectedCount}
            </span>{" "}
            findings. Подавленные записи остаются в БД, но скрыты по умолчанию
            на дашбордах и в API.
          </p>
          <div className="flex flex-col gap-1">
            <label
              htmlFor={reasonSelectId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Причина подавления
            </label>
            <select
              id={reasonSelectId}
              ref={(el) => {
                if (firstFocusableRef.current == null) {
                  firstFocusableRef.current = el;
                }
              }}
              value={suppressReason}
              onChange={(e) =>
                setSuppressReason(e.target.value as BulkSuppressReason | "")
              }
              required
              className="rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
              data-testid="bulk-suppress-reason"
            >
              <option value="">— выберите —</option>
              {BULK_SUPPRESS_REASONS.map((r) => (
                <option key={r} value={r}>
                  {BULK_SUPPRESS_REASON_LABEL_RU[r]}
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <label
              htmlFor={commentId}
              className="text-xs font-medium text-[var(--text-muted)]"
            >
              Комментарий (необязательно, ≤ {MAX_BULK_COMMENT_LENGTH} символов)
            </label>
            <textarea
              id={commentId}
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              rows={3}
              maxLength={MAX_BULK_COMMENT_LENGTH + 16}
              className="resize-y rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
              data-testid="bulk-suppress-comment"
            />
            {commentTooLong ? (
              <span className="text-xs text-red-300">
                Комментарий длиннее {MAX_BULK_COMMENT_LENGTH} символов.
              </span>
            ) : null}
          </div>
        </div>
      );
    }
    // mark_false_positive
    return (
      <div className="flex flex-col gap-3">
        <p className="text-sm text-[var(--text-secondary)]">
          Будет помечено как false positive{" "}
          <span className="font-semibold text-[var(--text-primary)]">
            {selectedCount}
          </span>{" "}
          findings. Эти записи будут скрыты с дашбордов и не попадут в SLA-
          отчёты.
        </p>
        <label
          htmlFor={fpConfirmId}
          className="flex cursor-pointer items-start gap-2 text-sm text-[var(--text-secondary)]"
        >
          <input
            id={fpConfirmId}
            ref={(el) => {
              if (firstFocusableRef.current == null) {
                firstFocusableRef.current = el;
              }
            }}
            type="checkbox"
            checked={fpConfirmed}
            onChange={(e) => setFpConfirmed(e.target.checked)}
            className="mt-0.5 h-4 w-4 cursor-pointer accent-[var(--accent)]"
            data-testid="bulk-fp-confirm"
          />
          <span>
            Я подтверждаю, что эти findings — false positive (это действие
            фиксируется в audit-логе).
          </span>
        </label>
        <div className="flex flex-col gap-1">
          <label
            htmlFor={commentId}
            className="text-xs font-medium text-[var(--text-muted)]"
          >
            Комментарий (необязательно, ≤ {MAX_BULK_COMMENT_LENGTH} символов)
          </label>
          <textarea
            id={commentId}
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            rows={2}
            maxLength={MAX_BULK_COMMENT_LENGTH + 16}
            className="resize-y rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
            data-testid="bulk-fp-comment"
          />
          {commentTooLong ? (
            <span className="text-xs text-red-300">
              Комментарий длиннее {MAX_BULK_COMMENT_LENGTH} символов.
            </span>
          ) : null}
        </div>
      </div>
    );
  };

  return (
    <div
      className="fixed inset-0 z-30 flex items-center justify-center bg-black/60 p-4"
      data-testid="bulk-action-dialog-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget && !submitting) {
          onClose();
        }
      }}
    >
      <div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="flex w-full max-w-lg flex-col gap-4 rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-5 text-[var(--text-primary)] shadow-2xl"
        data-testid="bulk-action-dialog"
      >
        <header className="flex items-start justify-between gap-2">
          <h2
            id={titleId}
            className="text-base font-semibold text-[var(--text-primary)]"
          >
            {DIALOG_TITLE[kind]}
          </h2>
          <button
            type="button"
            onClick={onClose}
            disabled={submitting}
            className="rounded p-1 text-[var(--text-muted)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
            aria-label="Закрыть диалог"
            data-testid="bulk-action-dialog-close"
          >
            ×
          </button>
        </header>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {renderBody()}
          {errorMessage ? (
            <div
              role="alert"
              className="rounded border border-red-500/60 bg-red-500/10 px-3 py-2 text-xs text-red-200"
              data-testid="bulk-action-dialog-error"
            >
              {errorMessage}
            </div>
          ) : null}
          <footer className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              disabled={submitting}
              className="rounded border border-[var(--border)] px-3 py-1.5 text-xs text-[var(--text-secondary)] hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:opacity-50"
              data-testid="bulk-action-dialog-cancel"
            >
              Отмена
            </button>
            {!isPhase2 ? (
              <button
                type="submit"
                disabled={!canConfirm}
                className="rounded border border-[var(--accent)] bg-[var(--accent)] px-3 py-1.5 text-xs font-medium text-white hover:opacity-90 focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
                data-testid="bulk-action-dialog-confirm"
              >
                {submitting ? "Применяется…" : "Подтвердить"}
              </button>
            ) : null}
          </footer>
        </form>
      </div>
    </div>
  );
}
