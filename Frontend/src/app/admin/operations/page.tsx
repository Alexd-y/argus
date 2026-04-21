/**
 * Admin operations surface (T29, ARG-052) — server entry-point that
 * pre-fetches the throttle status snapshot so the client doesn't render
 * an empty flash on first paint.
 *
 * SSR strategy:
 *   - We resolve the admin session synchronously here. `operator` is sent
 *     to `/admin/forbidden` by `AdminRouteGuard` on the client; the
 *     server pre-fetch is skipped instead of throwing so the SSR pass
 *     never crashes the route.
 *   - Errors during the initial fetch are intentionally swallowed: the
 *     client already renders a status-error banner and will retry on its
 *     own (`refetchStatus`) once mounted. Bubbling errors here would
 *     replace the chrome with a Next.js error boundary which leaks
 *     internals.
 */

import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import { PerTenantThrottleClient } from "@/app/admin/operations/PerTenantThrottleClient";
import { getEmergencyStatusAction } from "@/app/admin/operations/actions";
import { getServerAdminSession } from "@/services/admin/serverSession";
import type { ThrottleStatusResponse } from "@/lib/adminOperations";

export const dynamic = "force-dynamic";

export default async function AdminOperationsPage() {
  const session = await getServerAdminSession();
  // The client guard does the redirect for `null` / `operator`; bail out
  // here without hitting the backend so the SSR pass stays cheap.
  if (session.role === null || session.role === "operator") {
    return (
      <AdminRouteGuard minimumRole="admin">
        <FallbackChrome />
      </AdminRouteGuard>
    );
  }

  let initialStatus: ThrottleStatusResponse | null = null;
  if (session.role === "super-admin" || session.tenantId !== null) {
    try {
      initialStatus = await getEmergencyStatusAction({
        tenantId: session.tenantId ?? null,
      });
    } catch {
      // Silent fallback: client will retry on mount.
      initialStatus = null;
    }
  }

  return (
    <AdminRouteGuard minimumRole="admin">
      <PerTenantThrottleClient
        initialStatus={initialStatus}
        session={{
          role: session.role,
          tenantId: session.tenantId,
        }}
      />
    </AdminRouteGuard>
  );
}

function FallbackChrome() {
  return (
    <div className="space-y-3">
      <h1 className="text-lg font-semibold text-[var(--text-primary)]">
        Operations
      </h1>
      <p className="text-sm text-[var(--text-secondary)]">
        Перенаправление…
      </p>
    </div>
  );
}
