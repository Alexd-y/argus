"use client";

import { useEffect, useMemo, useState } from "react";
import {
  useMcpNotifications,
  type McpNotification,
  type McpNotificationKind,
  type McpNotificationStreamState,
} from "@/services/mcp/hooks/useMcpNotifications";

const KIND_LABELS: Record<McpNotificationKind, string> = {
  info: "Info",
  warning: "Warning",
  error: "Error",
  approval_pending: "Approval pending",
  scan_started: "Scan started",
  scan_completed: "Scan completed",
  report_ready: "Report ready",
  tool_run_completed: "Tool run completed",
  policy_decision: "Policy decision",
  rate_limit_warning: "Rate limit warning",
};

const KIND_TONES: Record<McpNotificationKind, string> = {
  info: "border-l-[var(--accent)] text-[var(--text-secondary)]",
  warning: "border-l-[var(--warning)] text-[var(--text-primary)]",
  error: "border-l-[var(--error)] text-[var(--text-primary)]",
  approval_pending: "border-l-[var(--warning)] text-[var(--text-primary)]",
  scan_started: "border-l-[var(--accent-dim)] text-[var(--text-secondary)]",
  scan_completed: "border-l-[var(--success)] text-[var(--text-primary)]",
  report_ready: "border-l-[var(--success)] text-[var(--text-primary)]",
  tool_run_completed: "border-l-[var(--accent)] text-[var(--text-primary)]",
  policy_decision: "border-l-[var(--secondary)] text-[var(--text-primary)]",
  rate_limit_warning: "border-l-[var(--warning)] text-[var(--text-primary)]",
};

const STATE_LABELS: Record<McpNotificationStreamState, string> = {
  idle: "Idle",
  connecting: "Connecting…",
  open: "Live",
  reconnecting: "Reconnecting…",
  closed: "Closed",
  error: "Error",
};

export interface NotificationsDrawerProps {
  /** Optional override for the SSE endpoint. */
  streamUrl?: string;
  /** Limit how many notifications are kept (defaults to 50). */
  bufferSize?: number;
  /** Initial open / closed state (uncontrolled). */
  defaultOpen?: boolean;
}

/**
 * Slide-out notifications panel anchored to the viewport's right edge.
 *
 * Shows the most recent N (default 50) MCP notifications received over
 * SSE. Includes a connection state indicator, a reconnect button when
 * the stream errors, and a clear-buffer affordance.
 */
export function NotificationsDrawer({
  streamUrl,
  bufferSize = 50,
  defaultOpen = false,
}: NotificationsDrawerProps) {
  const [open, setOpen] = useState(defaultOpen);
  const { notifications, state, error, clear, reconnect, count } =
    useMcpNotifications({ streamUrl, bufferSize });

  const unread = useMemo(
    () => (open ? 0 : Math.min(count, 99)),
    [count, open],
  );

  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && open) {
        setOpen(false);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open]);

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen((prev) => !prev)}
        aria-expanded={open}
        aria-controls="mcp-notifications-drawer"
        data-testid="mcp-notifications-toggle"
        className="relative inline-flex items-center gap-2 rounded-md border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-1.5 text-sm text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--accent)]"
      >
        <StreamStateDot state={state} />
        <span>Notifications</span>
        {unread > 0 ? (
          <span
            data-testid="mcp-notifications-unread"
            className="ml-1 inline-flex min-w-[1.25rem] items-center justify-center rounded-full bg-[var(--accent)] px-1.5 py-0.5 text-[0.6875rem] font-semibold text-white"
          >
            {unread}
          </span>
        ) : null}
      </button>

      <aside
        id="mcp-notifications-drawer"
        role="dialog"
        aria-label="MCP notifications"
        data-testid="mcp-notifications-drawer"
        data-open={open ? "true" : "false"}
        className={`fixed inset-y-0 right-0 z-50 flex w-full max-w-md transform flex-col border-l border-[var(--border)] bg-[var(--bg-secondary)] text-sm shadow-2xl transition-transform duration-200 ${
          open ? "translate-x-0" : "translate-x-full"
        }`}
      >
        <header className="flex items-center justify-between border-b border-[var(--border)] px-4 py-3">
          <div>
            <h2 className="text-base font-semibold text-[var(--text-primary)]">
              Notifications
            </h2>
            <p className="text-xs text-[var(--text-muted)]">
              Last {bufferSize} events · {STATE_LABELS[state]}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={reconnect}
              data-testid="mcp-notifications-reconnect"
              className="rounded border border-[var(--border-light)] px-2 py-1 text-xs text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--accent)]"
            >
              Reconnect
            </button>
            <button
              type="button"
              onClick={clear}
              data-testid="mcp-notifications-clear"
              className="rounded border border-[var(--border-light)] px-2 py-1 text-xs text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--accent)]"
            >
              Clear
            </button>
            <button
              type="button"
              onClick={() => setOpen(false)}
              data-testid="mcp-notifications-close"
              aria-label="Close notifications"
              className="rounded border border-[var(--border-light)] px-2 py-1 text-xs text-[var(--text-secondary)] transition hover:border-[var(--accent)] hover:text-[var(--accent)]"
            >
              Close
            </button>
          </div>
        </header>

        {error !== null ? (
          <p
            role="alert"
            data-testid="mcp-notifications-error"
            className="border-b border-[var(--border)] bg-[var(--bg-tertiary)] px-4 py-2 text-xs text-[var(--warning)]"
          >
            {error}
          </p>
        ) : null}

        <div className="flex-1 overflow-y-auto" data-testid="mcp-notifications-list">
          {notifications.length === 0 ? (
            <p
              data-testid="mcp-notifications-empty"
              className="px-4 py-8 text-center text-sm italic text-[var(--text-muted)]"
            >
              No notifications yet.
            </p>
          ) : (
            <ul className="divide-y divide-[var(--border)]">
              {notifications.map((notification) => (
                <NotificationRow
                  key={notification.id}
                  notification={notification}
                />
              ))}
            </ul>
          )}
        </div>
      </aside>

      {open ? (
        <button
          type="button"
          aria-label="Close notifications backdrop"
          data-testid="mcp-notifications-backdrop"
          onClick={() => setOpen(false)}
          className="fixed inset-0 z-40 bg-black/40"
        />
      ) : null}
    </>
  );
}

function NotificationRow({ notification }: { notification: McpNotification }) {
  const tone =
    KIND_TONES[notification.kind] ??
    "border-l-[var(--border-light)] text-[var(--text-secondary)]";
  return (
    <li
      data-testid="mcp-notification-item"
      data-notification-kind={notification.kind}
      className={`border-l-4 px-4 py-3 ${tone}`}
    >
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)]">
          {KIND_LABELS[notification.kind] ?? notification.kind}
        </span>
        <time
          dateTime={notification.occurred_at}
          className="text-xs text-[var(--text-muted)]"
        >
          {formatTimestamp(notification.occurred_at)}
        </time>
      </div>
      <p className="mt-1 text-sm font-medium text-[var(--text-primary)]">
        {notification.title}
      </p>
      {notification.body ? (
        <p className="mt-1 text-xs text-[var(--text-secondary)]">{notification.body}</p>
      ) : null}
    </li>
  );
}

function StreamStateDot({ state }: { state: McpNotificationStreamState }) {
  const colour =
    state === "open"
      ? "bg-[var(--success)]"
      : state === "reconnecting" || state === "connecting"
        ? "bg-[var(--warning)]"
        : state === "error"
          ? "bg-[var(--error)]"
          : "bg-[var(--text-muted)]";
  return (
    <span
      aria-hidden="true"
      data-testid="mcp-notifications-state-dot"
      data-state={state}
      className={`inline-block h-2 w-2 rounded-full ${colour}`}
    />
  );
}

function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  return date.toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}
