"use server";

import { getServerAdminSession } from "@/services/admin/serverSession";

// Server-side only: prefer the internal backend URL (docker DNS). The public
// NEXT_PUBLIC_* value is a last-resort fallback and must never be required for
// server→backend calls (keeps admin actions working after IP/domain changes).
const BACKEND_URL =
  process.env.BACKEND_URL?.trim() ||
  process.env.ARGUS_BACKEND_URL?.trim() ||
  process.env.NEXT_PUBLIC_BACKEND_URL?.trim() ||
  "http://backend:8000";

function apiUrl(path: string): string {
  return `${BACKEND_URL.replace(/\/$/, "")}/api/v1${path}`;
}

function adminHeaders(session: { role: string | null; subject: string }, apiKey: string | null): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) h["X-Admin-Key"] = apiKey;
  h["X-Admin-Role"] = session.role ?? "";
  h["X-Operator-Subject"] = session.subject;
  return h;
}

function getApiKey(): string | null {
  const k = process.env.ADMIN_API_KEY?.trim();
  return k && k.length > 0 ? k : null;
}

export async function changeAdminPassword(
  currentPassword: string,
  newPassword: string,
): Promise<{ changed: boolean }> {
  const session = await getServerAdminSession();
  if (!session.role) throw new Error("Not authenticated");

  const apiKey = getApiKey();
  if (!apiKey) throw new Error("Service temporarily unavailable");

  const res = await fetch(apiUrl("/auth/admin/change-password"), {
    method: "POST",
    headers: { ...adminHeaders(session, apiKey), "Content-Type": "application/json" },
    body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
    cache: "no-store",
  });

  if (!res.ok) {
    const body = await res.json().catch(() => null);
    const detail = body && typeof body === "object" && "detail" in body ? String(body.detail) : `Error ${res.status}`;
    throw new Error(detail);
  }
  return res.json();
}

export async function requestPasswordReset(
  subject: string,
): Promise<{ requested: boolean }> {
  const apiKey = getApiKey();
  if (!apiKey) throw new Error("Service temporarily unavailable");

  const res = await fetch(apiUrl("/auth/admin/request-reset"), {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Admin-Key": apiKey },
    body: JSON.stringify({ subject }),
    cache: "no-store",
  });

  if (!res.ok) {
    const body = await res.json().catch(() => null);
    const detail = body && typeof body === "object" && "detail" in body ? String(body.detail) : `Error ${res.status}`;
    throw new Error(detail);
  }
  return res.json();
}

export async function confirmPasswordReset(
  token: string,
  otpCode: string,
  newPassword: string,
): Promise<{ reset: boolean }> {
  const apiKey = getApiKey();
  if (!apiKey) throw new Error("Service temporarily unavailable");

  const res = await fetch(apiUrl("/auth/admin/confirm-reset"), {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Admin-Key": apiKey },
    body: JSON.stringify({ token, otp_code: otpCode, new_password: newPassword }),
    cache: "no-store",
  });

  if (!res.ok) {
    const body = await res.json().catch(() => null);
    const detail = body && typeof body === "object" && "detail" in body ? String(body.detail) : `Error ${res.status}`;
    throw new Error(detail);
  }
  return res.json();
}

export async function adminResetPassword(
  subject: string,
  newPassword: string,
): Promise<{ subject: string; reset: boolean }> {
  const session = await getServerAdminSession();
  if (!session.role || session.role !== "super-admin") {
    throw new Error("Only super-admin can reset passwords");
  }

  const apiKey = getApiKey();
  if (!apiKey) throw new Error("Service temporarily unavailable");

  const res = await fetch(apiUrl(`/auth/admin/${encodeURIComponent(subject)}/reset-password`), {
    method: "PATCH",
    headers: { ...adminHeaders(session, apiKey), "Content-Type": "application/json" },
    body: JSON.stringify({ new_password: newPassword }),
    cache: "no-store",
  });

  if (!res.ok) {
    const body = await res.json().catch(() => null);
    const detail = body && typeof body === "object" && "detail" in body ? String(body.detail) : `Error ${res.status}`;
    throw new Error(detail);
  }
  return res.json();
}

export async function getAdminProfile(): Promise<{
  subject: string;
  role: string;
  tenant_id: string | null;
  mfa_enabled: boolean;
  created_at: string | null;
  disabled_at: string | null;
}> {
  const session = await getServerAdminSession();
  if (!session.role) throw new Error("Not authenticated");

  const apiKey = getApiKey();
  if (!apiKey) throw new Error("Service temporarily unavailable");

  const res = await fetch(apiUrl("/auth/admin/me"), {
    method: "GET",
    headers: adminHeaders(session, apiKey),
    cache: "no-store",
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || `Failed to fetch profile (${res.status})`);
  }
  return res.json();
}

export async function getAdminSessions(): Promise<{
  sessions: Array<{
    session_hash_prefix: string;
    created_at: string;
    last_used_at: string;
    expires_at: string;
    is_current: boolean;
  }>;
}> {
  const session = await getServerAdminSession();
  if (!session.role) throw new Error("Not authenticated");

  const apiKey = getApiKey();
  if (!apiKey) throw new Error("Service temporarily unavailable");

  const res = await fetch(apiUrl("/auth/admin/sessions"), {
    method: "GET",
    headers: adminHeaders(session, apiKey),
    cache: "no-store",
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(text || `Failed to fetch sessions (${res.status})`);
  }
  return res.json();
}

export async function revokeAdminSession(
  sessionHashPrefix: string,
): Promise<{ revoked: boolean }> {
  const session = await getServerAdminSession();
  if (!session.role) throw new Error("Not authenticated");

  const apiKey = getApiKey();
  if (!apiKey) throw new Error("Service temporarily unavailable");

  const res = await fetch(apiUrl(`/auth/admin/sessions/${encodeURIComponent(sessionHashPrefix)}`), {
    method: "DELETE",
    headers: adminHeaders(session, apiKey),
    cache: "no-store",
  });

  if (!res.ok) {
    const body = await res.json().catch(() => null);
    const detail = body && typeof body === "object" && "detail" in body ? String(body.detail) : `Failed to revoke (${res.status})`;
    throw new Error(detail);
  }
  return res.json();
}

export async function getMfaStatus(): Promise<{
  enrolled: boolean;
  verified: boolean;
}> {
  const session = await getServerAdminSession();
  if (!session.role) throw new Error("Not authenticated");

  const apiKey = getApiKey();
  if (!apiKey) throw new Error("Service temporarily unavailable");

  const res = await fetch(apiUrl("/auth/admin/mfa/status"), {
    method: "GET",
    headers: adminHeaders(session, apiKey),
    cache: "no-store",
  });

  if (!res.ok) {
    return { enrolled: false, verified: false };
  }
  return res.json();
}