/**
 * Server-only helpers for the admin-auth surface.
 *
 * These functions touch `next/headers` (cookies + headers from the
 * current request) and therefore CANNOT be imported from middleware
 * (Edge runtime), client components, or pure-utility modules. The split
 * with {@link ./adminAuth.ts} keeps the import graph honest:
 *
 *   * `adminAuth.ts`        — pure constants, types, parsers (Edge-safe)
 *   * `adminAuthServer.ts`  — runtime helpers using next/headers (Node only)
 *
 * Security boundary
 * -----------------
 * These helpers are the ONLY place the front-end emits cookies on behalf
 * of the backend (login / logout `Set-Cookie`). They never invent flags;
 * they re-emit exactly what the backend sent, preserving HttpOnly / Secure
 * / SameSite. The browser is therefore strictly downstream of the backend
 * for the session cookie's lifecycle.
 */

import { cookies, headers } from "next/headers";

import {
  ADMIN_SESSION_COOKIE,
  isExpiredSetCookie,
  parseSetCookie,
  splitSetCookies,
} from "./adminAuth";

/**
 * Best-effort source IP for the backend's per-IP rate-limiter. We forward
 * the value the proxy gave us (Next.js sets `x-forwarded-for` when running
 * behind a trusted proxy) without parsing — the backend already trims to
 * the first hop. Returning `null` is safe; the backend then falls back to
 * the raw socket address.
 */
export async function getForwardedFor(): Promise<string | null> {
  const h = await headers();
  const forwarded = h.get("x-forwarded-for");
  if (forwarded && forwarded.trim()) return forwarded.trim();
  const realIp = h.get("x-real-ip");
  if (realIp && realIp.trim()) return realIp.trim();
  return null;
}

/**
 * Read the current request's `argus.admin.session` cookie value (if any).
 * Returns `null` when the cookie is missing OR present-but-empty so callers
 * never accidentally forward a blank string to the backend.
 */
export async function readSessionCookie(): Promise<string | null> {
  const store = await cookies();
  const v = store.get(ADMIN_SESSION_COOKIE)?.value;
  return v && v.length > 0 ? v : null;
}

/**
 * Forward every `Set-Cookie` header from a backend response to the browser.
 *
 * Why this exists:
 *   The login / logout endpoints set `argus.admin.session` with `HttpOnly`,
 *   `Secure`, `SameSite=Strict`, `Path=/`. The frontend MUST NOT recreate
 *   those flags by hand (drift risk + `HttpOnly` cannot be set from JS).
 *   We re-emit each cookie verbatim through `next/headers` so the browser
 *   stores exactly what the backend wrote.
 *
 * Limitations:
 *   `next/headers` does NOT expose a generic "set raw Set-Cookie string"
 *   API. We parse each cookie just enough to call `cookies().set()` with
 *   the canonical attributes, preserving the safety flags.
 */
export async function forwardSetCookieHeaders(response: Response): Promise<void> {
  const setCookieHeaders = collectSetCookies(response);
  if (setCookieHeaders.length === 0) return;
  const store = await cookies();
  for (const raw of setCookieHeaders) {
    const parsed = parseSetCookie(raw);
    if (!parsed) continue;
    if (isExpiredSetCookie(parsed)) {
      store.delete(parsed.name);
      continue;
    }
    store.set({
      name: parsed.name,
      value: parsed.value,
      path: parsed.path ?? "/",
      httpOnly: parsed.httpOnly,
      secure: parsed.secure,
      sameSite: parsed.sameSite,
      maxAge: parsed.maxAge,
      expires: parsed.expires,
    });
  }
}

/**
 * `Headers#getSetCookie()` returns one entry per `Set-Cookie` line. Older
 * Node runtimes only expose `headers.get("set-cookie")` (concatenated by
 * commas), so we fall back to parsing that when needed.
 */
function collectSetCookies(response: Response): string[] {
  const h = response.headers as Headers & {
    getSetCookie?: () => string[];
  };
  if (typeof h.getSetCookie === "function") {
    return h.getSetCookie();
  }
  const single = h.get("set-cookie");
  return single ? splitSetCookies(single) : [];
}
