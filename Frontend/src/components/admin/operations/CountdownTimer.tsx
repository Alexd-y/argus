"use client";

/**
 * `CountdownTimer` — reusable wall-clock countdown widget (T29).
 *
 * Why "wall-clock" instead of "tick-and-decrement":
 *   On every interval we re-derive the remaining duration from
 *   `Math.max(0, expiresAt - Date.now())` instead of mutating internal
 *   state. This makes the component:
 *     - DST/leap-second tolerant (the underlying Date arithmetic stays
 *       monotonic even if the wall clock skips a second);
 *     - resilient to dropped frames / paused tabs (when the browser
 *       rate-limits the timer in a backgrounded tab and resumes, the next
 *       tick lands on the correct value);
 *     - safe under React 19 strict-mode double-invoke (the effect's setup
 *       does not capture the previous remaining value).
 *
 * Lifecycle:
 *   - `setInterval(tick, 1000)` schedules a re-render once per second.
 *     The first tick runs synchronously inside the effect to avoid a
 *     1-second blank frame on mount.
 *   - The interval is cleared on unmount and on `expiresAt` change.
 *   - `onExpire()` is invoked AT MOST ONCE per `expiresAt` value. Parent
 *     callers typically use it to refetch the throttle status and remove
 *     the timer from the panel.
 *
 * A11y:
 *   - The text node carries `aria-live="polite"` so AT users hear the
 *     final "00:00" announcement without being interrupted every second.
 *   - `role="timer"` is intentionally NOT applied on the wrapper because
 *     it conflicts with `aria-live` polite semantics in NVDA; the
 *     `aria-label` prop lets callers pass a contextual label such as
 *     "Time remaining for tenant Acme throttle".
 */

import { useEffect, useRef, useState } from "react";

export type CountdownTimerProps = {
  /** ISO-8601 instant when the throttle expires. */
  readonly expiresAt: string;
  /** Called exactly once when the remaining time first hits zero. */
  readonly onExpire?: () => void;
  readonly className?: string;
  readonly ariaLabel?: string;
  /**
   * Override `Date.now` for deterministic tests. Production code should
   * leave this `undefined`.
   */
  readonly nowFn?: () => number;
};

const ONE_HOUR_MS = 60 * 60 * 1000;
const ONE_SECOND_MS = 1000;

function parseExpiresAt(expiresAt: string): number {
  const t = Date.parse(expiresAt);
  if (Number.isNaN(t)) return 0;
  return t;
}

function format(remainingMs: number): string {
  const totalSeconds = Math.max(0, Math.floor(remainingMs / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  const mm = String(minutes).padStart(2, "0");
  const ss = String(seconds).padStart(2, "0");
  if (hours > 0) {
    const hh = String(hours).padStart(2, "0");
    return `${hh}:${mm}:${ss}`;
  }
  return `${mm}:${ss}`;
}

export function CountdownTimer({
  expiresAt,
  onExpire,
  className,
  ariaLabel,
  nowFn,
}: CountdownTimerProps): React.ReactElement {
  const expiresAtMs = parseExpiresAt(expiresAt);
  const onExpireRef = useRef(onExpire);
  const expiredFiredForRef = useRef<string | null>(null);
  // Wall-clock snapshot kept in state so render stays pure (no `Date.now()`
  // in the render body — the linter rule `react-hooks/purity` treats that
  // as a non-idempotent read). The state is refreshed once per second from
  // inside the effect; the initialiser captures the wall clock once on
  // mount which is also pure-by-rule because it only runs during the
  // initial state setup.
  const nowFnRef = useRef(nowFn);
  const [nowMs, setNowMs] = useState<number>(() =>
    nowFn ? nowFn() : Date.now(),
  );

  useEffect(() => {
    onExpireRef.current = onExpire;
  }, [onExpire]);

  useEffect(() => {
    nowFnRef.current = nowFn;
  }, [nowFn]);

  useEffect(() => {
    const readNow = () => {
      const fn = nowFnRef.current;
      return fn ? fn() : Date.now();
    };
    // Re-snapshot the wall clock immediately so a remount with an updated
    // `expiresAt` doesn't show a stale value for the first second.
    const initialNow = readNow();
    setNowMs(initialNow);
    const initialRemaining = Math.max(0, expiresAtMs - initialNow);

    // Already expired on mount: fire `onExpire` once and skip the
    // interval entirely.
    if (initialRemaining === 0) {
      if (expiredFiredForRef.current !== expiresAt) {
        expiredFiredForRef.current = expiresAt;
        onExpireRef.current?.();
      }
      return;
    }

    // Reset the "have we fired onExpire?" guard for the new instant so the
    // same widget can be reused across consecutive throttles.
    expiredFiredForRef.current = null;

    const id = window.setInterval(() => {
      const tickNow = readNow();
      setNowMs(tickNow);
      const remaining = Math.max(0, expiresAtMs - tickNow);
      if (remaining === 0 && expiredFiredForRef.current !== expiresAt) {
        expiredFiredForRef.current = expiresAt;
        onExpireRef.current?.();
        window.clearInterval(id);
      }
    }, ONE_SECOND_MS);

    return () => {
      window.clearInterval(id);
    };
  }, [expiresAt, expiresAtMs]);

  const remainingMs = Math.max(0, expiresAtMs - nowMs);
  const display = format(remainingMs);

  // Choose the right format hint for assistive tech depending on whether
  // the duration crosses the 1-hour boundary.
  const isLong = remainingMs >= ONE_HOUR_MS;

  return (
    <span
      className={className}
      data-testid="countdown-timer"
      data-remaining-ms={remainingMs}
      data-format={isLong ? "HH:MM:SS" : "MM:SS"}
      aria-live="polite"
      aria-atomic="true"
      aria-label={ariaLabel}
    >
      {display}
    </span>
  );
}
