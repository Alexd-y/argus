"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { configureMcpClient } from "../index";
import { resolveMcpHeaders } from "../auth";

const DEFAULT_STREAM_PATH = "/api/mcp/notifications/stream";
const DEFAULT_BUFFER_SIZE = 50;
const INITIAL_BACKOFF_MS = 1_000;
const MAX_BACKOFF_MS = 30_000;
const BACKOFF_MULTIPLIER = 2;
const RECONNECT_JITTER_MS = 250;

/** Closed taxonomy mirroring the backend `NotificationKind` enum. */
export type McpNotificationKind =
  | "info"
  | "warning"
  | "error"
  | "approval_pending"
  | "scan_started"
  | "scan_completed"
  | "report_ready"
  | "tool_run_completed"
  | "policy_decision"
  | "rate_limit_warning";

export interface McpNotification {
  /** Stable id assigned by the server. Falls back to a synthetic uuid-ish key. */
  id: string;
  kind: McpNotificationKind;
  /** ISO-8601 timestamp. */
  occurred_at: string;
  /** Short, user-facing title. */
  title: string;
  /** Optional longer body. */
  body?: string;
  /** Free-form structured payload (already redacted server-side). */
  metadata?: Record<string, unknown>;
}

export type McpNotificationStreamState =
  | "idle"
  | "connecting"
  | "open"
  | "reconnecting"
  | "closed"
  | "error";

export interface UseMcpNotificationsOptions {
  /** SSE endpoint. Defaults to the Next.js API route at `/api/mcp/notifications/stream`. */
  streamUrl?: string;
  /** Max notifications kept in memory (FIFO eviction). Defaults to 50. */
  bufferSize?: number;
  /** Disable auto-connect (useful for tests / opt-in widgets). */
  enabled?: boolean;
  /** Override the initial backoff in milliseconds (defaults to 1s). */
  initialBackoffMs?: number;
  /** Cap the backoff at this value (defaults to 30s). */
  maxBackoffMs?: number;
}

export interface UseMcpNotificationsResult {
  notifications: ReadonlyArray<McpNotification>;
  state: McpNotificationStreamState;
  error: string | null;
  /** Number of notifications currently held in memory. */
  count: number;
  /** Force a reconnect (resets backoff). */
  reconnect: () => void;
  /** Drop the in-memory buffer (does NOT close the stream). */
  clear: () => void;
  /** Close the stream and stop reconnect attempts. */
  disconnect: () => void;
}

/**
 * SSE subscription to MCP notifications with exponential-backoff reconnect.
 *
 * Reconnect strategy: 1s → 2s → 4s → 8s → 16s → 30s (capped) with up to
 * `RECONNECT_JITTER_MS` random jitter to spread reconnection storms across
 * clients. The backoff is reset every time we successfully receive an
 * `open` event from the EventSource (i.e. handshake succeeded).
 *
 * The hook is SSR-safe: it never reads `window` outside an effect and it
 * gracefully no-ops when `EventSource` is missing (e.g. older runtimes).
 */
export function useMcpNotifications(
  options: UseMcpNotificationsOptions = {},
): UseMcpNotificationsResult {
  configureMcpClient();
  const {
    streamUrl = DEFAULT_STREAM_PATH,
    bufferSize = DEFAULT_BUFFER_SIZE,
    enabled = true,
    initialBackoffMs = INITIAL_BACKOFF_MS,
    maxBackoffMs = MAX_BACKOFF_MS,
  } = options;

  const [notifications, setNotifications] = useState<ReadonlyArray<McpNotification>>([]);
  const [state, setState] = useState<McpNotificationStreamState>("idle");
  const [error, setError] = useState<string | null>(null);

  const sourceRef = useRef<EventSource | null>(null);
  const backoffRef = useRef(initialBackoffMs);
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const stoppedRef = useRef(false);
  const generationRef = useRef(0);
  // Refs that hold the latest closure version of connect / scheduleReconnect.
  // Using refs breaks the natural cyclic dependency between the two functions
  // (connect schedules a reconnect on error; scheduleReconnect calls connect)
  // while keeping each callback's identity stable across renders.
  const connectRef = useRef<() => Promise<void>>(async () => {});
  const scheduleReconnectRef = useRef<() => void>(() => {});

  const closeSource = useCallback(() => {
    if (sourceRef.current !== null) {
      sourceRef.current.close();
      sourceRef.current = null;
    }
    if (reconnectTimerRef.current !== null) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
  }, []);

  const appendNotification = useCallback(
    (next: McpNotification) => {
      setNotifications((prev) => {
        const merged = [next, ...prev];
        if (merged.length <= bufferSize) {
          return merged;
        }
        return merged.slice(0, bufferSize);
      });
    },
    [bufferSize],
  );

  const connect = useCallback(async () => {
    if (typeof window === "undefined") {
      return;
    }
    if (typeof EventSource === "undefined") {
      setState("error");
      setError("EventSource is not supported in this runtime.");
      return;
    }

    closeSource();
    setState("connecting");
    setError(null);

    const generation = ++generationRef.current;

    let url = streamUrl;
    try {
      const extraHeaders = await resolveMcpHeaders();
      const tenantId = extraHeaders["X-Tenant-Id"];
      if (tenantId !== undefined) {
        const separator = url.includes("?") ? "&" : "?";
        url = `${url}${separator}tenant_id=${encodeURIComponent(tenantId)}`;
      }
    } catch {
      // Tenant header is best-effort; the server still validates auth.
    }

    if (generation !== generationRef.current) {
      return;
    }

    let source: EventSource;
    try {
      source = new EventSource(url, { withCredentials: true });
    } catch (err) {
      setState("error");
      setError(toErrorMessage(err, "Failed to open notifications stream."));
      scheduleReconnectRef.current();
      return;
    }

    sourceRef.current = source;

    source.onopen = () => {
      backoffRef.current = initialBackoffMs;
      setState("open");
      setError(null);
    };

    source.onmessage = (event: MessageEvent<string>) => {
      const parsed = parseNotification(event.data);
      if (parsed !== null) {
        appendNotification(parsed);
      }
    };

    source.onerror = () => {
      if (stoppedRef.current) {
        return;
      }
      setState("reconnecting");
      setError("Notifications stream disconnected — retrying.");
      closeSource();
      scheduleReconnectRef.current();
    };
  }, [appendNotification, closeSource, initialBackoffMs, streamUrl]);

  const scheduleReconnect = useCallback(() => {
    if (stoppedRef.current) {
      return;
    }
    if (reconnectTimerRef.current !== null) {
      return;
    }
    const baseDelay = Math.min(backoffRef.current, maxBackoffMs);
    const jitter = Math.floor(Math.random() * RECONNECT_JITTER_MS);
    const delay = baseDelay + jitter;
    backoffRef.current = Math.min(
      backoffRef.current * BACKOFF_MULTIPLIER,
      maxBackoffMs,
    );
    reconnectTimerRef.current = setTimeout(() => {
      reconnectTimerRef.current = null;
      void connectRef.current();
    }, delay);
  }, [maxBackoffMs]);

  // Keep the refs pointing at the latest closures so onerror/onopen can
  // call them without needing to be re-created when the deps change.
  useEffect(() => {
    connectRef.current = connect;
    scheduleReconnectRef.current = scheduleReconnect;
  }, [connect, scheduleReconnect]);

  const reconnect = useCallback(() => {
    stoppedRef.current = false;
    backoffRef.current = initialBackoffMs;
    void connect();
  }, [connect, initialBackoffMs]);

  const disconnect = useCallback(() => {
    stoppedRef.current = true;
    closeSource();
    setState("closed");
  }, [closeSource]);

  const clear = useCallback(() => {
    setNotifications([]);
  }, []);

  useEffect(() => {
    if (!enabled) {
      return;
    }
    stoppedRef.current = false;
    // Defer the initial connect to a microtask so the React 19 effect-rule
    // is satisfied (no synchronous setState inside an effect body).
    const kickoff = setTimeout(() => {
      void connect();
    }, 0);
    return () => {
      clearTimeout(kickoff);
      stoppedRef.current = true;
      closeSource();
    };
  }, [enabled, connect, closeSource]);

  return {
    notifications,
    state,
    error,
    count: notifications.length,
    reconnect,
    clear,
    disconnect,
  };
}

function parseNotification(raw: string): McpNotification | null {
  if (!raw || raw.length === 0) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as Partial<McpNotification>;
    if (
      typeof parsed.id !== "string" ||
      typeof parsed.kind !== "string" ||
      typeof parsed.occurred_at !== "string" ||
      typeof parsed.title !== "string"
    ) {
      return null;
    }
    return {
      id: parsed.id,
      kind: parsed.kind as McpNotificationKind,
      occurred_at: parsed.occurred_at,
      title: parsed.title,
      body: typeof parsed.body === "string" ? parsed.body : undefined,
      metadata:
        parsed.metadata && typeof parsed.metadata === "object"
          ? parsed.metadata
          : undefined,
    };
  } catch {
    return null;
  }
}

function toErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof Error) {
    return err.message || fallback;
  }
  return fallback;
}
