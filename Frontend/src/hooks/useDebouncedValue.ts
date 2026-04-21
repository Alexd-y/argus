"use client";

import { useEffect, useState } from "react";

/**
 * Returns a debounced copy of `value` that only updates after `delayMs` of
 * inactivity. Useful for free-text and date inputs feeding a network query
 * — without it, every keystroke triggers a refetch (and a new server-action
 * round-trip).
 *
 * The hook is intentionally minimal — it relies on `useEffect` cleanup
 * rather than scheduling work outside the React tree, so it composes with
 * `useTransition` / `useDeferredValue` when callers want both behaviours.
 *
 * @param value Source value to debounce. Must be a primitive or a stable
 *              reference; passing a fresh array/object on every render will
 *              defeat the debounce.
 * @param delayMs Inactivity window in milliseconds. Defaults to 300 ms,
 *                which matches the task acceptance criteria for the admin
 *                findings filter bar (T20). Pass `0` to disable debouncing
 *                entirely (the source value is returned synchronously).
 */
export function useDebouncedValue<T>(value: T, delayMs = 300): T {
  const [debounced, setDebounced] = useState(value);

  useEffect(() => {
    if (delayMs <= 0) return undefined;
    const id = window.setTimeout(() => {
      setDebounced(value);
    }, delayMs);
    return () => {
      window.clearTimeout(id);
    };
  }, [value, delayMs]);

  // delayMs <= 0 disables debouncing — return the source synchronously without
  // scheduling a state update inside the effect (which the React-hooks ESLint
  // rule rightly flags as a cascading render).
  return delayMs <= 0 ? value : debounced;
}
