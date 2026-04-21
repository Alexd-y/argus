import { NextResponse } from "next/server";

/**
 * @deprecated Public admin BFF routes were removed (security): they forwarded any
 * caller to FastAPI with the server `ADMIN_API_KEY`. Use server actions in
 * `app/admin/tenants/actions.ts` instead.
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
export const POST = gone;
