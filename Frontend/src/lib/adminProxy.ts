export function getBackendBaseUrl(): string {
  const raw =
    process.env.BACKEND_URL?.trim() ||
    process.env.NEXT_PUBLIC_BACKEND_URL?.trim() ||
    "http://localhost:8000";
  return raw.replace(/\/$/, "");
}

export function getServerAdminApiKey(): string | null {
  const k = process.env.ADMIN_API_KEY?.trim();
  return k && k.length > 0 ? k : null;
}
