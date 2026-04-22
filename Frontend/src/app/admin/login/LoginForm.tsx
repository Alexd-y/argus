"use client";

import { useActionState, useSyncExternalStore } from "react";
import { useFormStatus } from "react-dom";

import {
  AUTH_ERROR_MESSAGES_EN,
  AUTH_ERROR_MESSAGES_RU,
} from "@/lib/adminAuth";

import {
  INITIAL_LOGIN_STATE,
  loginAction,
  type LoginActionState,
} from "./actions";

/**
 * Admin login form (B6-T09 / ISS-T20-003 Phase 1 frontend).
 *
 * Accessibility
 * -------------
 * * Each input has an associated `<label htmlFor=...>`.
 * * Errors are announced via `role="alert"` + `aria-live="assertive"`
 *   and bound to the inputs through `aria-describedby`.
 * * The submit button is the sole `<button type="submit">`; pressing
 *   Enter inside either input triggers the same action.
 *
 * Security UX
 * -----------
 * * Pre-flight, invalid-credentials, validation, and 5xx errors all
 *   render the SAME generic copy ("Invalid credentials" / "Неверные
 *   учётные данные"). No enumeration, no leaking of why login failed.
 *   The only distinct UI state is rate-limit (we owe the user a
 *   countdown so they don't spam-click against a closed door).
 * * The form locks for `retryAfterSeconds` after a 429 response.
 *
 * Localisation
 * ------------
 * * No i18n framework is wired up in `Frontend/`; the project's
 *   convention is "Russian primary, English fallback" inline. Both
 *   languages render in the same DOM node so a screen reader emits
 *   both — fine for the bilingual ops team this console targets.
 */

const COPY = {
  title: "Вход администратора",
  subtitle: "Admin sign-in",
  subjectLabel: "Имя пользователя / Username",
  passwordLabel: "Пароль / Password",
  submit: "Войти / Sign in",
  submitting: "Проверка… / Signing in…",
  retrySuffix: "сек / s",
} as const;

const ERROR_RU = AUTH_ERROR_MESSAGES_RU;
const ERROR_EN = AUTH_ERROR_MESSAGES_EN;

function describeError(state: LoginActionState): string | null {
  if (state.status !== "error") return null;
  // Render BOTH copies so the bilingual UX is consistent regardless of
  // which language the operator reads first. Code is one of the closed
  // taxonomy values — TypeScript catches drift at compile time.
  return `${ERROR_RU[state.code]} / ${ERROR_EN[state.code]}`;
}

function describeRateLimited(): string {
  // Same bilingual structure as describeError; trailing seconds count
  // is rendered separately by the caller so the announcement updates
  // every tick without re-emitting the prose.
  return `${ERROR_RU.rate_limited} / ${ERROR_EN.rate_limited}`.replace(
    /\.$/,
    "",
  );
}

function SubmitButton({
  locked,
  countdownSeconds,
}: {
  locked: boolean;
  countdownSeconds: number | null;
}) {
  const { pending } = useFormStatus();
  const isDisabled = locked || pending;
  let label: string;
  if (locked && countdownSeconds !== null && countdownSeconds > 0) {
    label = `${countdownSeconds} ${COPY.retrySuffix}`;
  } else if (pending) {
    label = COPY.submitting;
  } else {
    label = COPY.submit;
  }
  return (
    <button
      type="submit"
      disabled={isDisabled}
      aria-busy={pending || undefined}
      data-testid="admin-login-submit"
      className="inline-flex w-full items-center justify-center rounded-md bg-[var(--accent-strong)] px-4 py-2 text-sm font-semibold text-[var(--on-accent)] shadow-sm transition hover:bg-[var(--accent-hover)] disabled:cursor-not-allowed disabled:opacity-60"
    >
      {label}
    </button>
  );
}

/**
 * Subscribe to a once-per-second tick of `Date.now()` via React's
 * external-store API. We use this instead of `useEffect` + `setState`
 * because:
 *   * `Date.now()` is an impure function and React 19's purity rules
 *     forbid calling it directly during render.
 *   * Driving the countdown from `useState` synced inside an effect
 *     trips the `react-hooks/set-state-in-effect` rule (cascading
 *     renders).
 *   * `useSyncExternalStore` is the canonical React way to read an
 *     external, mutable value (here, the wall clock) safely.
 *
 * The store is a singleton: every mounted form shares the same 1 s
 * interval, which is fine — there is at most one login form on screen
 * at any time. SSR returns `0` so the server-rendered markup is stable
 * and React reconciles to the real value on hydration.
 */
const wallClockListeners = new Set<() => void>();
let wallClockInterval: ReturnType<typeof setInterval> | null = null;
let wallClockSnapshot = 0;

function subscribeWallClock(notify: () => void): () => void {
  wallClockListeners.add(notify);
  if (wallClockInterval === null) {
    wallClockInterval = setInterval(() => {
      wallClockSnapshot = Date.now();
      for (const fn of wallClockListeners) fn();
    }, 1000);
  }
  return () => {
    wallClockListeners.delete(notify);
    if (wallClockListeners.size === 0 && wallClockInterval !== null) {
      clearInterval(wallClockInterval);
      wallClockInterval = null;
    }
  };
}

function getWallClockSnapshot(): number {
  if (wallClockSnapshot === 0) wallClockSnapshot = Date.now();
  return wallClockSnapshot;
}

function getServerSnapshot(): number {
  // SSR: anchor the snapshot to 0 so the server-rendered countdown is
  // deterministic. The hook is only ever consumed from a `"use client"`
  // component, so this branch is purely belt-and-braces hydration
  // safety.
  return 0;
}

/**
 * Compute the visible rate-limit countdown from the action state's
 * `expiresAtMs` (a stable backend-anchored timestamp). Returns `null`
 * when the form is not rate-limited, otherwise the integer seconds
 * remaining (clamped to 0).
 */
function useRateLimitCountdown(state: LoginActionState): number | null {
  const now = useSyncExternalStore(
    subscribeWallClock,
    getWallClockSnapshot,
    getServerSnapshot,
  );
  if (state.status !== "rate_limited") return null;
  if (now === 0) return state.retryAfterSeconds; // SSR / first paint
  return Math.max(0, Math.ceil((state.expiresAtMs - now) / 1000));
}

export function LoginForm() {
  const [state, formAction] = useActionState<LoginActionState, FormData>(
    loginAction,
    INITIAL_LOGIN_STATE,
  );

  const countdown = useRateLimitCountdown(state);
  const errorMessage = describeError(state);
  const isLockedOut = countdown !== null && countdown > 0;
  const rateLimitedMessage =
    state.status === "rate_limited" ? describeRateLimited() : null;

  return (
    <form
      action={formAction}
      noValidate
      aria-labelledby="admin-login-title"
      className="space-y-5"
      data-testid="admin-login-form"
    >
      <div>
        <h1
          id="admin-login-title"
          className="text-xl font-semibold text-[var(--text-primary)]"
        >
          {COPY.title}
        </h1>
        <p className="mt-1 text-sm text-[var(--text-muted)]">
          {COPY.subtitle}
        </p>
      </div>

      <div className="space-y-1">
        <label
          htmlFor="admin-login-subject"
          className="block text-sm font-medium text-[var(--text-secondary)]"
        >
          {COPY.subjectLabel}
        </label>
        <input
          id="admin-login-subject"
          name="subject"
          type="text"
          autoComplete="username"
          required
          maxLength={255}
          aria-describedby={errorMessage ? "admin-login-error" : undefined}
          className="block w-full rounded-md border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)] shadow-sm focus:border-[var(--accent)] focus:outline-none focus:ring-1 focus:ring-[var(--accent)]"
          data-testid="admin-login-subject"
        />
      </div>

      <div className="space-y-1">
        <label
          htmlFor="admin-login-password"
          className="block text-sm font-medium text-[var(--text-secondary)]"
        >
          {COPY.passwordLabel}
        </label>
        <input
          id="admin-login-password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          maxLength={1024}
          aria-describedby={errorMessage ? "admin-login-error" : undefined}
          className="block w-full rounded-md border border-[var(--border)] bg-[var(--bg-primary)] px-3 py-2 text-sm text-[var(--text-primary)] shadow-sm focus:border-[var(--accent)] focus:outline-none focus:ring-1 focus:ring-[var(--accent)]"
          data-testid="admin-login-password"
        />
      </div>

      {errorMessage !== null ? (
        <div
          id="admin-login-error"
          role="alert"
          aria-live="assertive"
          data-testid="admin-login-error"
          className="rounded-md border border-rose-300/60 bg-rose-500/10 px-3 py-2 text-sm text-rose-700 dark:text-rose-300"
        >
          {errorMessage}
        </div>
      ) : null}

      {rateLimitedMessage !== null ? (
        <div
          role="status"
          aria-live="polite"
          data-testid="admin-login-rate-limited"
          // keep: rate-limited notice is `role="status"` (informational
          // throttle countdown), not a warning action. The amber-500 tint
          // is a soft attention cue. `--warning-strong` is reserved for
          // text-on-fill confirm CTAs only — see design-tokens.md §3.5.
          className="rounded-md border border-amber-300/60 bg-amber-500/10 px-3 py-2 text-sm text-amber-800 dark:text-amber-300"
        >
          {rateLimitedMessage}
          {countdown !== null && countdown > 0 ? (
            <>
              {" "}
              <span data-testid="admin-login-countdown">{countdown}</span>{" "}
              {COPY.retrySuffix}
            </>
          ) : null}
        </div>
      ) : null}

      <SubmitButton locked={isLockedOut} countdownSeconds={countdown} />
    </form>
  );
}
