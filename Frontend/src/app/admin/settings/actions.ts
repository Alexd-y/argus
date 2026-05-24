"use server";

import { callAdminBackendJson } from "@/lib/serverAdminBackend";
import { getServerAdminSession } from "@/services/admin/serverSession";

export async function changeAdminPassword(
  currentPassword: string,
  newPassword: string,
): Promise<{ changed: boolean }> {
  const session = await getServerAdminSession();
  if (!session.role) throw new Error("Not authenticated");

  const result = await callAdminBackendJson<{ changed: boolean }>(
    "/auth/admin/change-password",
    {
      method: "POST",
      headers: {
        "X-Admin-Role": session.role,
        "X-Operator-Subject": session.subject,
      },
      body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    },
  );
  if (!result.ok) throw new Error(result.error);
  return result.data;
}

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

export async function adminResetPassword(
  subject: string,
  newPassword: string,
): Promise<{ subject: string; reset: boolean }> {
  const session = await getServerAdminSession();
  if (!session.role || session.role !== "super-admin") {
    throw new Error("Only super-admin can reset passwords");
  }

  const result = await callAdminBackendJson<{ subject: string; reset: boolean }>(
    `/auth/admin/${encodeURIComponent(subject)}/reset-password`,
    {
      method: "PATCH",
      headers: {
        "X-Admin-Role": session.role,
        "X-Operator-Subject": session.subject,
      },
      body: JSON.stringify({ new_password: newPassword }),
    },
  );
  if (!result.ok) throw new Error(result.error);
  return result.data;
}