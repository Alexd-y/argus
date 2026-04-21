"use client";

/**
 * `useFocusTrap` — modal-dialog focus mechanics shared between the
 * per-tenant throttle dialog and the resume-confirm dialog (T29 follow-up).
 *
 * Responsibilities:
 *   1. Auto-focus the first interactive element when `enabled` becomes
 *      true. Callers may pin a specific target via `initialFocusRef`;
 *      otherwise the first DOM-tabbable child of `containerRef` wins.
 *   2. Restore focus to whatever was active *before* the trap engaged
 *      when the trap disengages (cleanup of the same effect).
 *   3. Cycle Tab / Shift-Tab inside `containerRef` so AT users cannot
 *      accidentally tab into the page behind the modal.
 *   4. Forward Escape to `onEscape` so each dialog can decide whether
 *      to close (e.g. ignore Escape while a request is in-flight).
 *
 * The focusable selector matches the in-house `FOCUSABLE_SELECTOR`
 * previously inlined in `PerTenantThrottleDialog`. It excludes any
 * element with `aria-hidden="true"` so visually hidden helper text
 * (`<span class="sr-only">`) does not steal focus.
 *
 * Design notes:
 *   - All callbacks are read through a ref so the keydown handler does
 *     not have to be re-bound on every render.
 *   - `previouslyFocused` is captured once when the effect runs (i.e.
 *     when `enabled` flips to `true`) and restored on cleanup; the
 *     consumer does not need to thread that state.
 *   - The hook is SSR-safe — every DOM access is guarded with a
 *     `typeof document !== "undefined"` check or only runs inside an
 *     effect (which never executes on the server).
 */

import { useEffect, useRef, type RefObject } from "react";

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

export type UseFocusTrapOptions = {
  /**
   * When `false`, the hook is inert (no focus shift, no keydown
   * listener). Flip to `true` when the modal becomes visible.
   */
  readonly enabled: boolean;
  /** Ref pointing at the modal's outermost focusable container. */
  readonly containerRef: RefObject<HTMLElement | null>;
  /**
   * Optional ref pinning the initial focus target. Falls back to the
   * first focusable inside `containerRef` when omitted or null.
   */
  readonly initialFocusRef?: RefObject<HTMLElement | null>;
  /**
   * Invoked when Escape is pressed. Receivers typically call their
   * `onOpenChange(false)` / `onCancel()` here. When omitted, Escape
   * is left for the consumer to handle elsewhere.
   */
  readonly onEscape?: () => void;
};

export function useFocusTrap({
  enabled,
  containerRef,
  initialFocusRef,
  onEscape,
}: UseFocusTrapOptions): void {
  const onEscapeRef = useRef(onEscape);
  useEffect(() => {
    onEscapeRef.current = onEscape;
  }, [onEscape]);

  // Initial focus + restoration.
  useEffect(() => {
    if (!enabled) return;
    const previouslyFocused: HTMLElement | null =
      typeof document !== "undefined"
        ? (document.activeElement as HTMLElement | null)
        : null;

    const timeoutId = window.setTimeout(() => {
      const explicit = initialFocusRef?.current ?? null;
      if (explicit && typeof explicit.focus === "function") {
        explicit.focus();
        return;
      }
      const container = containerRef.current;
      if (!container) return;
      const firstFocusable =
        container.querySelector<HTMLElement>(FOCUSABLE_SELECTOR);
      firstFocusable?.focus();
    }, 0);

    return () => {
      window.clearTimeout(timeoutId);
      if (
        previouslyFocused &&
        typeof previouslyFocused.focus === "function" &&
        typeof document !== "undefined" &&
        document.contains(previouslyFocused)
      ) {
        previouslyFocused.focus();
      }
    };
  }, [enabled, containerRef, initialFocusRef]);

  // Esc + Tab cycling.
  useEffect(() => {
    if (!enabled) return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") {
        const cb = onEscapeRef.current;
        if (cb) {
          e.preventDefault();
          cb();
        }
        return;
      }
      if (e.key !== "Tab") return;
      const container = containerRef.current;
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
  }, [enabled, containerRef]);
}

export { FOCUSABLE_SELECTOR };
