import { NextResponse } from "next/server";

/**
 * @deprecated See `app/api/admin/tenants/route.ts` — use server actions instead.
 */
function gone(): NextResponse {
  return NextResponse.json(
    {
      error:
        "This endpoint was removed. Tenant administration uses server-side actions only.",
    },
    { status: 410 },
  );
}

export const GET = gone;
export const PATCH = gone;
export const DELETE = gone;
