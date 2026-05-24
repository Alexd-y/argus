"use server";

import { callAdminBackendJson } from "@/lib/serverAdminBackend";

export async function requestPasswordReset(
  subject: string,
): Promise<{ requested: boolean }> {
  const result = await callAdminBackendJson<{ requested: boolean }>(
    "/auth/admin/request-reset",
    {
      method: "POST",
      body: JSON.stringify({ subject }),
    },
  );
  if (!result.ok) throw new Error(result.error);
  return result.data;
}