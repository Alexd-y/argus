import { NextResponse, type NextRequest } from "next/server";

/**
 * Edge middleware (B6-T09 / ISS-T20-003 Phase 1 frontend).
 *
 * Sole responsibility: in `session` mode, redirect any anonymous
 * `/admin/*` request (no `argus.admin.session` cookie) to
 * `/admin/login`. Everything else passes through untouched.
 *
 * What we explicitly DO NOT do here:
 *   - Validate the session token: that requires a backend round-trip
 *     and Edge runtime cannot be trusted to share the SSR fetch
 *     pool. `serverSession.ts` performs the canonical validation.
 *   - Touch `cookie` or `auto` modes: legacy dev loops keep working,
 *     and `auto` deliberately falls through to the cookie shim when
 *     the backend rejects the session, which only the SSR layer can
 *     decide.
 *   - Run on `/admin/login`, static assets, or APIs.
 *
 * The `NEXT_PUBLIC_ADMIN_AUTH_MODE` env value is inlined at build
 * time, so the gate is a static branch — no per-request env lookup.
 */

const ADMIN_AUTH_MODE = (process.env.NEXT_PUBLIC_ADMIN_AUTH_MODE ?? "auto")
  .trim()
  .toLowerCase();

const ADMIN_SESSION_COOKIE = "argus.admin.session";

export function middleware(request: NextRequest): NextResponse {
  if (ADMIN_AUTH_MODE !== "session") {
    return NextResponse.next();
  }

  const pathname = request.nextUrl.pathname;
  if (!pathname.startsWith("/admin")) {
    return NextResponse.next();
  }
  if (pathname === "/admin/login" || pathname.startsWith("/admin/login/")) {
    return NextResponse.next();
  }

  const sessionCookie = request.cookies.get(ADMIN_SESSION_COOKIE)?.value;
  if (sessionCookie && sessionCookie.trim() !== "") {
    return NextResponse.next();
  }

  const loginUrl = request.nextUrl.clone();
  loginUrl.pathname = "/admin/login";
  loginUrl.search = "";
  return NextResponse.redirect(loginUrl);
}

export const config = {
  matcher: [
    // Run only on /admin/* — no static assets, no API routes, no
    // public pages. The Edge runtime startup cost is paid only when
    // it actually matters.
    "/admin/:path*",
  ],
};
