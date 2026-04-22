import { redirect } from "next/navigation";

import { getAdminAuthMode } from "@/lib/adminAuth";

import { LoginForm } from "./LoginForm";

/**
 * Admin login screen (B6-T09 / ISS-T20-003 Phase 1 frontend).
 *
 * Mode-aware:
 *   - `cookie` mode auto-resolves identity from `NEXT_PUBLIC_ADMIN_DEV_*`
 *     so the login UI is meaningless. Redirect straight to `/admin`.
 *   - `session` and `auto` modes render the form. In `auto` mode a
 *     successful login pins the operator to a real backend session
 *     while the legacy cookie shim keeps working for unauthenticated
 *     dev surfaces.
 *
 * Rendering:
 *   - This route is intentionally OUTSIDE the protected layout chrome:
 *     `AdminLayoutClient` short-circuits on `/admin/login` so the
 *     route guard never bounces the user to `/admin/forbidden` before
 *     they can authenticate.
 *
 * Caching:
 *   - `force-dynamic` because the response depends on the active auth
 *     mode AND the presence of the session cookie (we redirect away
 *     from the form when cookie-mode is active).
 */

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

export const metadata = {
  title: "Admin sign-in / Вход администратора",
  robots: { index: false, follow: false },
};

export default function AdminLoginPage() {
  if (getAdminAuthMode() === "cookie") {
    redirect("/admin");
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-100 px-4 py-12">
      <div className="w-full max-w-sm rounded-lg border border-slate-200 bg-white p-6 shadow-sm">
        <LoginForm />
      </div>
    </main>
  );
}
