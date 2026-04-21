/**
 * Maps FastAPI-style `detail` payloads to a short user-visible string.
 * Rejects messages that look like stack traces or internal errors.
 */

const INTERNALISH = /stack|trace|internal|exception|file\.py|line \d/i;

export function normalizeAdminDetailError(detail: unknown): string | null {
  if (typeof detail === "string") {
    const t = detail.trim();
    if (!t || t.length > 240) return null;
    if (INTERNALISH.test(t)) return null;
    return t;
  }
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0];
    if (typeof first === "object" && first !== null && "msg" in first) {
      return normalizeAdminDetailError((first as { msg: unknown }).msg);
    }
  }
  return null;
}
