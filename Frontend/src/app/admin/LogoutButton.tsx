"use client";

import { useTransition } from "react";

import { logoutAction } from "./login/actions";

/**
 * Compact "Sign out" control for the admin chrome header.
 *
 * Why a client component invoking a server action:
 *   We can't use a plain `<form action={logoutAction}>` because the
 *   button must communicate `pending` state for accessibility (`aria-busy`,
 *   disabled). `useTransition` gives us that without dragging in the
 *   form-action API. The action is server-side — the browser never
 *   touches the backend session-cookie path itself.
 *
 * Visibility:
 *   The parent (`AdminLayoutClient`) is responsible for hiding this when
 *   the auth mode is `cookie` (the legacy dev shim has nothing to log
 *   out of). This component does not read env directly so it can be
 *   driven by a single source of truth at the parent level.
 */

export function LogoutButton() {
  const [pending, startTransition] = useTransition();

  const onClick = () => {
    startTransition(async () => {
      try {
        await logoutAction();
      } catch {
        // The action `redirect()`s on success; Next.js throws a special
        // error that is propagated through the transition. We swallow
        // any other failure mode so the button is never wedged in a
        // pending-forever state — the form's source of truth is the
        // session cookie, not the button's React state.
      }
    });
  };

  return (
    <button
      type="button"
      onClick={onClick}
      disabled={pending}
      aria-busy={pending || undefined}
      data-testid="admin-logout-button"
      className="inline-flex items-center gap-1.5 rounded border border-[var(--border)] bg-[var(--bg-tertiary)] px-2.5 py-1 text-xs text-[var(--text-secondary)] transition hover:bg-[var(--bg-primary)] hover:text-[var(--text-primary)] disabled:cursor-not-allowed disabled:opacity-60"
    >
      {pending ? "Выход… / Signing out…" : "Выход / Sign out"}
    </button>
  );
}
