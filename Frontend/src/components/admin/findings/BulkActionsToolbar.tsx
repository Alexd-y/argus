"use client";

/**
 * `BulkActionsToolbar` — sticky strip that surfaces above the findings
 * table when ≥1 row is selected. Lets the operator suppress, mark as
 * false-positive, escalate (Phase-2), or attach to a CVE (Phase-2) the
 * current selection.
 *
 * Backend availability today:
 *   - "suppress" + "mark_false_positive" → wired through
 *     `bulkSuppressFindingsAction` / `bulkMarkFalsePositiveFindingsAction`.
 *   - "escalate" + "attach_to_cve" → NO backend support yet; rendered as
 *     disabled buttons with a tooltip pointing at the deferred issues
 *     (ISS-T21-001 / ISS-T21-002). Disabled state is also marked with
 *     `aria-disabled` and a `title` attribute so AT users get the same
 *     reason a sighted user does.
 *
 * A11y:
 *   - The toolbar exposes `role="toolbar"` + `aria-label`.
 *   - Each action button has visible text (icon-only is forbidden).
 *   - Disabled buttons are not focusable via keyboard (`tabIndex={-1}`)
 *     but stay reachable via the tooltip text for screen readers.
 *   - Selection-count is announced via a `<span>` inside the live region
 *     of the page's polite container (parent owns the live region).
 */

import { useMemo } from "react";

export type BulkActionKind =
  | "suppress"
  | "mark_false_positive"
  | "escalate"
  | "attach_to_cve";

export type BulkActionAvailability = {
  /** Suppress is implemented (backed by `bulk-suppress`). */
  readonly suppress: boolean;
  /** Mark FP is implemented (backed by `bulk-suppress` with fixed reason). */
  readonly markFalsePositive: boolean;
  /** Escalate is NOT implemented yet — Phase 2. */
  readonly escalate: boolean;
  /** Attach to CVE is NOT implemented yet — Phase 2. */
  readonly attachToCve: boolean;
};

export const DEFAULT_BULK_AVAILABILITY: BulkActionAvailability = {
  suppress: true,
  markFalsePositive: true,
  escalate: false,
  attachToCve: false,
};

export type BulkActionsToolbarProps = {
  readonly selectedCount: number;
  readonly availability?: BulkActionAvailability;
  readonly disabled?: boolean;
  readonly onAction: (kind: BulkActionKind) => void;
  readonly onClearSelection: () => void;
  /**
   * Human-readable role label, used to switch the disabled-tooltip when
   * the operator role itself can't perform bulk actions (e.g. admin
   * without bound tenant). Optional — undefined keeps the default
   * "Phase 2" tooltip semantics.
   */
  readonly disabledReason?: string | null;
};

const PHASE_2_ESCALATE_TOOLTIP =
  "Phase 2 — backend в разработке (ISS-T21-001).";
const PHASE_2_ATTACH_CVE_TOOLTIP =
  "Phase 2 — backend в разработке (ISS-T21-002).";

const ACTION_LABEL: Readonly<Record<BulkActionKind, string>> = {
  suppress: "Подавить",
  mark_false_positive: "False positive",
  escalate: "Escalate",
  attach_to_cve: "Attach CVE",
};

const ACTION_ICON: Readonly<Record<BulkActionKind, string>> = {
  // Plain-text glyphs (no font icons) — keeps the bundle slim and
  // guarantees consistent rendering on any OS / theme. Glyphs are
  // marked aria-hidden so AT users only hear the label.
  suppress: "🛇",
  mark_false_positive: "✕",
  escalate: "↑",
  attach_to_cve: "🔗",
};

export function BulkActionsToolbar({
  selectedCount,
  availability = DEFAULT_BULK_AVAILABILITY,
  disabled = false,
  onAction,
  onClearSelection,
  disabledReason = null,
}: BulkActionsToolbarProps): React.ReactElement | null {
  const visible = selectedCount > 0;

  const buttonStates = useMemo(() => {
    return {
      suppress: {
        enabled: availability.suppress && !disabled,
        tooltip: disabledReason ?? "Подавить выбранные findings",
      },
      mark_false_positive: {
        enabled: availability.markFalsePositive && !disabled,
        tooltip: disabledReason ?? "Пометить выбранные как false positive",
      },
      escalate: {
        enabled: availability.escalate && !disabled,
        tooltip: availability.escalate
          ? (disabledReason ?? "Повысить severity выбранных findings")
          : PHASE_2_ESCALATE_TOOLTIP,
      },
      attach_to_cve: {
        enabled: availability.attachToCve && !disabled,
        tooltip: availability.attachToCve
          ? (disabledReason ?? "Привязать выбранные findings к CVE")
          : PHASE_2_ATTACH_CVE_TOOLTIP,
      },
    } as const;
  }, [availability, disabled, disabledReason]);

  if (!visible) return null;

  const renderButton = (kind: BulkActionKind) => {
    const state = buttonStates[kind];
    const baseClass =
      "inline-flex items-center gap-1.5 rounded border px-3 py-1.5 text-xs font-medium transition focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none";
    const enabledClass =
      "border-[var(--border)] bg-[var(--bg-primary)] text-[var(--text-primary)] hover:border-[var(--accent)]";
    const disabledClass =
      "cursor-not-allowed border-dashed border-[var(--border)] bg-[var(--bg-tertiary)] text-[var(--text-muted)]";
    return (
      <button
        key={kind}
        type="button"
        onClick={() => state.enabled && onAction(kind)}
        disabled={!state.enabled}
        aria-disabled={!state.enabled}
        title={state.tooltip}
        className={`${baseClass} ${state.enabled ? enabledClass : disabledClass}`}
        data-testid={`bulk-action-${kind}`}
      >
        <span aria-hidden>{ACTION_ICON[kind]}</span>
        <span>{ACTION_LABEL[kind]}</span>
      </button>
    );
  };

  return (
    <section
      role="toolbar"
      aria-label="Bulk actions for selected findings"
      data-testid="bulk-actions-toolbar"
      className="sticky top-0 z-20 flex flex-wrap items-center justify-between gap-2 rounded border border-[var(--accent)]/60 bg-[var(--accent)]/10 px-3 py-2 text-sm"
    >
      <div className="flex items-center gap-2">
        <span
          className="font-medium text-[var(--text-primary)]"
          data-testid="bulk-selection-count"
        >
          Выбрано {selectedCount} findings
        </span>
        {disabledReason ? (
          <span
            className="text-xs text-[var(--text-muted)]"
            data-testid="bulk-disabled-reason"
          >
            {disabledReason}
          </span>
        ) : null}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {renderButton("suppress")}
        {renderButton("mark_false_positive")}
        {renderButton("escalate")}
        {renderButton("attach_to_cve")}
        <button
          type="button"
          onClick={onClearSelection}
          className="inline-flex items-center gap-1.5 rounded border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-1.5 text-xs text-[var(--text-secondary)] transition hover:text-[var(--text-primary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
          data-testid="bulk-action-clear"
        >
          Снять выбор
        </button>
      </div>
    </section>
  );
}
