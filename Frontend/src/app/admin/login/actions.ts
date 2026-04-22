"use server";

/**
 * Server actions backing the admin auth surface (B6-T09 / ISS-T20-003
 * Phase 1 frontend). The browser NEVER calls FastAPI directly; every
 * mutation goes through one of these actions so:
 *
 *   * `ADMIN_API_KEY` (server-only env) never reaches the browser,
 *   * the backend's `argus.admin.session` HttpOnly + Secure cookie is
 *     forwarded verbatim via {@link forwardSetCookieHeaders} — the
 *     frontend NEVER recreates the cookie, preserving the security flags,
 *   * the rate-limit decision lives at the backend; we forward
 *     `X-Forwarded-For` so the per-IP token-bucket keys on the actual
 *     client IP rather than the Next.js loopback,
 *   * every backend status maps to a single closed-taxonomy
 *     {@link AuthActionCode} so the form NEVER renders raw `detail`
 *     strings (no enumeration, no stack-trace leak).
 */

import { cookies } from "next/headers";
import { redirect } from "next/navigation";

import {
  ADMIN_AUTH_PATHS,
  ADMIN_SESSION_COOKIE,
  buildAuthBackendUrl,
  parseRetryAfterSeconds,
  statusToAuthActionCode,
  validateLoginCredentials,
  type AuthActionCode,
} from "@/lib/adminAuth";
import {
  forwardSetCookieHeaders,
  getForwardedFor,
  readSessionCookie,
} from "@/lib/adminAuthServer";
import {
  ADMIN_ROLE_COOKIE,
  ADMIN_SUBJECT_COOKIE,
  ADMIN_TENANT_COOKIE,
} from "@/services/admin/serverSession";

/**
 * Discriminated union returned by `loginAction` — the React form layer
 * pattern-matches on `status` so all three failure modes (validation,
 * invalid creds, rate-limited) render through the same channel without
 * leaking which one occurred to the user.
 */
export type LoginActionState =
  | { readonly status: "idle" }
  | { readonly status: "error"; readonly code: AuthActionCode }
  | {
      readonly status: "rate_limited";
      readonly retryAfterSeconds: number;
      /**
       * Epoch ms at which the lockout expires. Stored alongside the
       * `Retry-After` value so the client can derive the visible
       * countdown from `Date.now()` instead of syncing local state from
       * the action result inside an effect (which trips the
       * `react-hooks/set-state-in-effect` rule and causes cascading
       * renders).
       */
      readonly expiresAtMs: number;
    };

export const INITIAL_LOGIN_STATE: LoginActionState = { status: "idle" };

/**
 * TTL for the dev-mirror cookies we keep populating in `auto`/`session`
 * mode so the legacy `AdminAuthContext` (client) and the cookie-shim
 * resolver (server) keep working without a full whoami round-trip on
 * every render. These cookies are NOT trusted in `session` mode — they
 * exist purely as a UX accelerator.
 */
const ROLE_COOKIE_MAX_AGE_S = 60 * 60 * 24;

type LoginResponseBody = {
  readonly role?: unknown;
  readonly tenant_id?: unknown;
  readonly expires_at?: unknown;
};

type WritableCookieJar = Awaited<ReturnType<typeof cookies>>;

/**
 * Mirror the backend-confirmed role / tenant onto the non-HttpOnly UX
 * cookies the legacy resolver and `AdminAuthContext` already understand.
 *
 * Why we still write these in `session` mode:
 *   The client `AdminAuthContext` reads `argus.admin.role` from the
 *   cookie to render the sidebar without a round-trip. In `session`
 *   mode the source of truth is still the backend's whoami, but we
 *   pre-populate the UX cookie so the very first paint after login
 *   shows the right chrome. The middleware never trusts these cookies
 *   for access control.
 */
function mirrorLoginResponseToCookies(
  jar: WritableCookieJar,
  body: LoginResponseBody,
  fallbackSubject: string,
): void {
  const isHttpsHint = process.env.NODE_ENV === "production";

  const role = typeof body.role === "string" ? body.role.trim() : "";
  if (role !== "") {
    jar.set({
      name: ADMIN_ROLE_COOKIE,
      value: role,
      path: "/",
      maxAge: ROLE_COOKIE_MAX_AGE_S,
      sameSite: "strict",
      secure: isHttpsHint,
    });
  }

  const tenantId =
    typeof body.tenant_id === "string" ? body.tenant_id.trim() : "";
  if (tenantId !== "") {
    jar.set({
      name: ADMIN_TENANT_COOKIE,
      value: tenantId,
      path: "/",
      maxAge: ROLE_COOKIE_MAX_AGE_S,
      sameSite: "strict",
      secure: isHttpsHint,
    });
  } else {
    // Cross-tenant super-admin: drop any stale tenant cookie.
    jar.delete(ADMIN_TENANT_COOKIE);
  }

  jar.set({
    name: ADMIN_SUBJECT_COOKIE,
    value: fallbackSubject,
    path: "/",
    maxAge: ROLE_COOKIE_MAX_AGE_S,
    sameSite: "strict",
    secure: isHttpsHint,
  });
}

function clearAuthMirrorCookies(jar: WritableCookieJar): void {
  jar.delete(ADMIN_ROLE_COOKIE);
  jar.delete(ADMIN_TENANT_COOKIE);
  jar.delete(ADMIN_SUBJECT_COOKIE);
}

// ---------------------------------------------------------------------------
// loginAction — POST /api/v1/auth/admin/login
// ---------------------------------------------------------------------------

/**
 * Server action invoked by `<form action={loginAction}>` in `LoginForm`.
 *
 * Failure modes (all surface as the same UI copy via `AUTH_ERROR_MESSAGES_*`):
 *   * Pre-flight validation failure   → `error` / `invalid_credentials`
 *   * Backend 401 / 403 / 422        → `error` / `invalid_credentials`
 *   * Backend 429                    → `rate_limited` (with `retryAfterSeconds`)
 *   * Network failure / 5xx          → `error` / `service_unavailable`
 *
 * Success path: forwards the backend's `Set-Cookie` headers to the
 * browser, mirrors role/tenant onto the UX cookies, then redirects to
 * `/admin`. `redirect()` throws so this function never returns on
 * success — the React form action API treats the throw as the redirect
 * signal.
 */
export async function loginAction(
  _previous: LoginActionState,
  formData: FormData,
): Promise<LoginActionState> {
  const validated = validateLoginCredentials(
    formData.get("subject"),
    formData.get("password"),
  );
  if (!validated.ok) {
    return { status: "error", code: "invalid_credentials" };
  }
  const { subject, password } = validated;

  const url = buildAuthBackendUrl(ADMIN_AUTH_PATHS.login);
  const xff = await getForwardedFor();

  const requestHeaders: Record<string, string> = {
    "Content-Type": "application/json",
    Accept: "application/json",
  };
  if (xff) requestHeaders["X-Forwarded-For"] = xff;

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: requestHeaders,
      body: JSON.stringify({ subject, password }),
      cache: "no-store",
      redirect: "manual",
    });
  } catch {
    return { status: "error", code: "service_unavailable" };
  }

  if (response.status === 429) {
    const retryAfterSeconds = parseRetryAfterSeconds(
      response.headers.get("retry-after"),
    );
    return {
      status: "rate_limited",
      retryAfterSeconds,
      expiresAtMs: Date.now() + retryAfterSeconds * 1000,
    };
  }

  if (!response.ok) {
    return { status: "error", code: statusToAuthActionCode(response.status) };
  }

  let body: LoginResponseBody;
  try {
    body = (await response.json()) as LoginResponseBody;
  } catch {
    return { status: "error", code: "service_unavailable" };
  }

  // Forward the HttpOnly session cookie FIRST so a parsing failure on
  // the mirror cookies still yields a working session.
  await forwardSetCookieHeaders(response);
  const jar = await cookies();
  mirrorLoginResponseToCookies(jar, body, subject);

  redirect("/admin");
}

// ---------------------------------------------------------------------------
// logoutAction — POST /api/v1/auth/admin/logout
// ---------------------------------------------------------------------------

/**
 * Server action: revoke the backend session and clear cookies.
 *
 * Idempotent: a missing or already-revoked cookie still wipes the local
 * UX cookies and redirects to `/admin/login`. We always end on a
 * redirect so the operator sees the login page even when the backend
 * call failed (defence in depth — if the session cookie didn't get
 * cleared, the server-side resolver will still 401 on the next request
 * and bounce them back here).
 */
export async function logoutAction(): Promise<void> {
  const sessionId = await readSessionCookie();

  if (sessionId) {
    const url = buildAuthBackendUrl(ADMIN_AUTH_PATHS.logout);
    const xff = await getForwardedFor();
    const requestHeaders: Record<string, string> = {
      Accept: "application/json",
      Cookie: `${ADMIN_SESSION_COOKIE}=${sessionId}`,
    };
    if (xff) requestHeaders["X-Forwarded-For"] = xff;

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: requestHeaders,
        cache: "no-store",
        redirect: "manual",
      });
      // Honour the backend's Set-Cookie (Max-Age=0) so the client
      // immediately drops the cookie even if the local delete below
      // races with a stale header.
      await forwardSetCookieHeaders(response);
    } catch {
      // Best-effort — proceed with local cleanup regardless.
    }
  }

  // Defensive cleanup: explicitly delete on our side too in case the
  // backend response was lost (network blip) or carried no Set-Cookie.
  const jar = await cookies();
  jar.delete(ADMIN_SESSION_COOKIE);
  clearAuthMirrorCookies(jar);

  redirect("/admin/login");
}
