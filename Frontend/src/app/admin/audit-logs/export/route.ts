import { NextResponse } from "next/server";

import { getBackendBaseUrl, getServerAdminApiKey } from "@/lib/adminProxy";
import { getServerAdminSession } from "@/services/admin/serverSession";

/**
 * Server-side proxy for `GET /api/v1/admin/audit-logs/export` (T22).
 *
 * Why a route handler and not a server action: the backend returns
 * `text/csv` or `application/json` with `Content-Disposition: attachment`,
 * which is awkward to thread through a server action's JSON-only return
 * channel. A route handler lets us stream the bytes straight to the browser
 * while still keeping `X-Admin-Key` server-only.
 *
 * Same security rules as the read action:
 *   - `X-Admin-Key` is read from `ADMIN_API_KEY` server-side; never reaches
 *     the client.
 *   - Identity headers (`X-Admin-Role`, `X-Admin-Tenant`,
 *     `X-Operator-Subject`) are derived from `getServerAdminSession()`.
 *   - For `admin` role, the session tenant overrides any URL-supplied
 *     `tenant_id` so the operator cannot widen scope by editing the URL.
 *   - `operator` role is refused outright (audit log is admin-only).
 *
 * Forwarded query params (closed allow-list): `since`, `until`, `q`,
 * `event_type`, `format`, `limit`. Anything else is dropped on the floor.
 */

const ALLOWED_FORWARD_PARAMS = new Set([
  "since",
  "until",
  "q",
  "event_type",
  "format",
  "limit",
]);

const ALLOWED_FORMATS = new Set(["csv", "json"]);

export async function GET(req: Request): Promise<Response> {
  const session = await getServerAdminSession();
  if (session.role === null) {
    return NextResponse.json(
      { detail: "Unauthorized" },
      { status: 401 },
    );
  }
  if (session.role === "operator") {
    return NextResponse.json({ detail: "Forbidden" }, { status: 403 });
  }

  const key = getServerAdminApiKey();
  if (!key) {
    return NextResponse.json(
      { detail: "Admin service is temporarily unavailable." },
      { status: 503 },
    );
  }

  const incoming = new URL(req.url);
  const sp = new URLSearchParams();

  for (const [name, value] of incoming.searchParams.entries()) {
    if (!ALLOWED_FORWARD_PARAMS.has(name)) continue;
    if (value === "") continue;
    if (name === "format" && !ALLOWED_FORMATS.has(value)) continue;
    sp.set(name, value);
  }

  // Resolve effective tenant: admin always uses session tenant; super-admin
  // honours the URL-supplied value (or omits it for cross-tenant view).
  let effectiveTenant: string | null = null;
  if (session.role === "admin") {
    effectiveTenant = session.tenantId;
  } else {
    const fromUrl = incoming.searchParams.get("tenant_id");
    effectiveTenant = fromUrl && fromUrl.trim() ? fromUrl.trim() : null;
  }
  if (effectiveTenant) {
    sp.set("tenant_id", effectiveTenant);
  }

  if (session.role === "admin" && effectiveTenant === null) {
    return NextResponse.json(
      { detail: "Tenant binding required." },
      { status: 403 },
    );
  }

  const qs = sp.toString();
  const url = `${getBackendBaseUrl()}/api/v1/admin/audit-logs/export${qs ? `?${qs}` : ""}`;

  let upstream: Response;
  try {
    upstream = await fetch(url, {
      method: "GET",
      headers: {
        "X-Admin-Key": key,
        "X-Admin-Role": session.role,
        ...(effectiveTenant ? { "X-Admin-Tenant": effectiveTenant } : {}),
        "X-Operator-Subject": session.subject,
      },
      cache: "no-store",
    });
  } catch {
    return NextResponse.json(
      { detail: "Admin service is temporarily unavailable." },
      { status: 503 },
    );
  }

  if (!upstream.ok) {
    // Echo the status code but use a generic message to avoid leaking the
    // backend's `detail` payload (closed-taxonomy contract).
    return NextResponse.json(
      { detail: "Audit-log export failed." },
      { status: upstream.status },
    );
  }

  const contentType =
    upstream.headers.get("content-type") ?? "application/octet-stream";
  const disposition =
    upstream.headers.get("content-disposition") ??
    'attachment; filename="audit_logs"';

  return new Response(upstream.body, {
    status: 200,
    headers: {
      "Content-Type": contentType,
      "Content-Disposition": disposition,
      "Cache-Control": "no-store",
    },
  });
}
