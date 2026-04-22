/**
 * Admin webhook DLQ surface (T41, ARG-053) — server entry-point that
 * pre-fetches the first page so the client doesn't render a "loading…"
 * flash on the very first paint.
 *
 * RBAC strategy:
 *   The backend (T39) hard-rejects `operator` callers with 403 on every
 *   DLQ endpoint (list / replay / abandon) — so unlike the schedules
 *   surface (operator can read), this page MUST be admin-or-super.
 *   Letting operators reach the page would render an immediately-failing
 *   list with a `forbidden` banner — bad UX. We bail out via
 *   `<AdminRouteGuard minimumRole="admin">` so the redirect happens
 *   before any data fetch.
 *
 * SSR strategy mirrors `/admin/schedules/page.tsx`:
 *   - Server-side bail out for `null` / unknown roles to keep the SSR
 *     pass cheap.
 *   - Initial fetch errors are silently swallowed and rendered as
 *     `initialList=null`. The client re-renders + retries; bubbling
 *     here would replace the chrome with a Next.js error boundary that
 *     leaks internals.
 */

import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import { listWebhookDlqAction } from "@/app/admin/webhooks/dlq/actions";
import { WebhookDlqClient } from "@/app/admin/webhooks/dlq/WebhookDlqClient";
import { getServerAdminSession } from "@/services/admin/serverSession";
import {
  WEBHOOK_DLQ_LIMIT_DEFAULT,
  type WebhookDlqListResponse,
} from "@/lib/adminWebhookDlq";

export const dynamic = "force-dynamic";

export default async function AdminWebhookDlqPage() {
  const session = await getServerAdminSession();

  if (session.role === null || session.role === "operator") {
    return (
      <AdminRouteGuard minimumRole="admin">
        <FallbackChrome />
      </AdminRouteGuard>
    );
  }

  let initialList: WebhookDlqListResponse | null = null;
  try {
    initialList = await listWebhookDlqAction({
      tenantId: session.tenantId ?? null,
      limit: WEBHOOK_DLQ_LIMIT_DEFAULT,
      offset: 0,
    });
  } catch {
    initialList = null;
  }

  return (
    <AdminRouteGuard minimumRole="admin">
      <WebhookDlqClient
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
        Очередь dead-letter webhook&rsquo;ов
      </h1>
      <p className="text-sm text-[var(--text-secondary)]">
        Перенаправление…
      </p>
    </div>
  );
}
