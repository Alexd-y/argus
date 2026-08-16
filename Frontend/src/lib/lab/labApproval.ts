import type { ExecutionMode, LabLeaseResponse, LabScanPlan, LabPlanStep, PlanStepKind } from "./types";

export function isValidLabLease(
  lease: LabLeaseResponse | null | undefined,
  now: Date = new Date(),
): boolean {
  if (!lease) return false;
  if (lease.status !== "active") return false;
  if (!lease.kill_switch_cleared) return false;
  const expires = new Date(lease.expires_at);
  if (Number.isNaN(expires.getTime())) return false;
  return expires.getTime() > now.getTime();
}

export function shouldSkipApprovalDialog(
  executionMode: ExecutionMode,
  lease: LabLeaseResponse | null | undefined,
): boolean {
  return executionMode === "lab_unrestricted" && isValidLabLease(lease);
}

export function emptyLabPlan(mode: ExecutionMode = "lab_unrestricted"): LabScanPlan {
  return {
    mode,
    requires_approval: mode === "lab_unrestricted" ? false : true,
    steps: [],
  };
}

export function normalizeLabPlan(plan: LabScanPlan): LabScanPlan {
  const lab = plan.mode === "lab_unrestricted";
  return {
    mode: plan.mode,
    requires_approval: lab ? false : plan.requires_approval,
    steps: plan.steps.map((step) => ({
      ...step,
      argv: [...step.argv],
    })),
  };
}

export function addPlanStep(
  plan: LabScanPlan,
  kind: PlanStepKind,
  name: string,
): LabScanPlan {
  const trimmed = name.trim();
  if (!trimmed) return plan;
  const step: LabPlanStep = {
    id: `${kind}-${trimmed}-${plan.steps.length + 1}`,
    kind,
    name: trimmed,
    argv: [],
  };
  return normalizeLabPlan({ ...plan, steps: [...plan.steps, step] });
}

export function removePlanStep(plan: LabScanPlan, stepId: string): LabScanPlan {
  return normalizeLabPlan({
    ...plan,
    steps: plan.steps.filter((step) => step.id !== stepId),
  });
}

export const LAB_DEFAULT_TOOLS: readonly string[] = [
  "nuclei",
  "sqlmap",
  "dalfox",
  "ffuf",
  "custom_script",
];

export const LAB_DEFAULT_TEMPLATES: readonly string[] = [
  "unsigned",
  "code",
  "headless",
  "javascript",
];
