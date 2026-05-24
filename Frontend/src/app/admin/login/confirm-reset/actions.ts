"use server";

import { callAdminBackendJson } from "@/lib/serverAdminBackend";

export async function confirmPasswordReset(
  token: string,
  otpCode: string,
  newPassword: string,
): Promise<{ reset: boolean }> {
  const result = await callAdminBackendJson<{ reset: boolean }>(
    "/auth/admin/confirm-reset",
    {
      method: "POST",
      body: JSON.stringify({ token, otp_code: otpCode, new_password: newPassword }),
    },
  );
  if (!result.ok) throw new Error(result.error);
  return result.data;
}