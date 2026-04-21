/**
 * Admin scan-schedules surface (T35, ARG-056) — server entry-point that
 * pre-fetches the first page so the client doesn't render a "loading…"
 * flash on the very first paint.
 *
 * SSR strategy mirrors `/admin/operations/page.tsx`:
 *   - `RouteGuard minimumRole="operator"` on the client AND we bail out
 *     early server-side for `null` / unknown roles to keep the SSR pass
 *     cheap.
 *   - Initial fetch errors are silently swallowed and rendered as
 *     `initialList=null`. The client re-renders + retries; bubbling here
 *     would replace the chrome with a Next.js error boundary that leaks
 *     internals.
 */

import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import { SchedulesClient } from "@/app/admin/schedules/SchedulesClient";
import { listSchedulesAction } from "@/app/admin/schedules/actions";
import { getServerAdminSession } from "@/services/admin/serverSession";
import type { SchedulesListResponse } from "@/lib/adminSchedules";

export const dynamic = "force-dynamic";

export default async function AdminSchedulesPage() {
  const session = await getServerAdminSession();

  // Operator can READ but not mutate (handled by SchedulesClient via
  // `canMutate`). Anything below operator → bail out to the guard.
  if (session.role === null) {
    return (
      <AdminRouteGuard minimumRole="operator">
        <FallbackChrome />
      </AdminRouteGuard>
    );
  }

  let initialList: SchedulesListResponse | null = null;
  try {
    initialList = await listSchedulesAction({
      tenantId: session.tenantId ?? null,
      limit: 50,
    });
  } catch {
    initialList = null;
  }

  return (
    <AdminRouteGuard minimumRole="operator">
      <SchedulesClient
        initialList={initialList}
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
        Scheduled scans
      </h1>
      <p className="text-sm text-[var(--text-secondary)]">
        Перенаправление…
      </p>
    </div>
  );
}
