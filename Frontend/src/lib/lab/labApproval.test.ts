import { describe, expect, it } from "vitest";

import {
  addPlanStep,
  emptyLabPlan,
  isValidLabLease,
  normalizeLabPlan,
  removePlanStep,
  shouldSkipApprovalDialog,
} from "./labApproval";
import type { LabLeaseResponse, LabScanPlan } from "./types";

function lease(over: Partial<LabLeaseResponse> = {}): LabLeaseResponse {
  return {
    lease_id: "lease-1",
    tenant_id: "t-1",
    engagement_id: "e-1",
    manifest_id: "m-1",
    mode: "lab_unrestricted",
    status: "active",
    issued_at: "2026-08-16T00:00:00.000Z",
    expires_at: "2026-08-17T00:00:00.000Z",
    kill_switch_cleared: true,
    ...over,
  };
}

describe("labApproval", () => {
  it("accepts an active unexpired lease with kill switch cleared", () => {
    const now = new Date("2026-08-16T12:00:00.000Z");
    expect(isValidLabLease(lease(), now)).toBe(true);
  });

  it("rejects expired, revoked, or kill-switched leases", () => {
    const now = new Date("2026-08-16T12:00:00.000Z");
    expect(isValidLabLease(null, now)).toBe(false);
    expect(isValidLabLease(lease({ status: "expired" }), now)).toBe(false);
    expect(isValidLabLease(lease({ kill_switch_cleared: false }), now)).toBe(false);
    expect(
      isValidLabLease(lease({ expires_at: "2026-08-16T11:00:00.000Z" }), now),
    ).toBe(false);
  });

  it("skips approval dialogs only for LAB with a usable lease", () => {
    const valid = lease();
    expect(shouldSkipApprovalDialog("lab_unrestricted", valid)).toBe(true);
    expect(shouldSkipApprovalDialog("production", valid)).toBe(false);
    expect(shouldSkipApprovalDialog("lab_unrestricted", null)).toBe(false);
  });

  it("locks requires_approval false for LAB plans", () => {
    const dirty: LabScanPlan = {
      mode: "lab_unrestricted",
      requires_approval: true,
      steps: [],
    };
    expect(emptyLabPlan("lab_unrestricted").requires_approval).toBe(false);
    expect(normalizeLabPlan(dirty).requires_approval).toBe(false);
    expect(emptyLabPlan("production").requires_approval).toBe(true);
  });

  it("adds and removes plan steps without mutating argv arrays", () => {
    const started = addPlanStep(emptyLabPlan("lab_unrestricted"), "template", "unsigned");
    expect(started.steps).toHaveLength(1);
    expect(started.steps[0]?.name).toBe("unsigned");
    expect(started.requires_approval).toBe(false);
    const removed = removePlanStep(started, started.steps[0]!.id);
    expect(removed.steps).toHaveLength(0);
  });
});
