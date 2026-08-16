import type { ExecutionMode, LabLeaseResponse } from "@/lib/scanApi";

/** True when lease is active, kill-switch cleared, and not expired. */
export function isValidLabLease(
  lease: LabLeaseResponse | null | undefined,
  now: Date = new Date()
): boolean {
  if (!lease) return false;
  if (lease.status !== "active") return false;
  if (!lease.kill_switch_cleared) return false;
  const expires = new Date(lease.expires_at);
  if (Number.isNaN(expires.getTime())) return false;
  return expires.getTime() > now.getTime();
}

/**
 * LAB unrestricted + valid lease → skip approval UI (master §17 / CONT-006).
 * Production risk labels must never force an approval dialog when this is true.
 */
export function shouldSkipApprovalDialog(
  executionMode: ExecutionMode,
  lease: LabLeaseResponse | null | undefined
): boolean {
  switch (executionMode) {
    case "lab_unrestricted":
      return isValidLabLease(lease);
    case "production":
    case "quick":
      return false;
    default: {
      const _exhaustive: never = executionMode;
      return _exhaustive;
    }
  }
}
