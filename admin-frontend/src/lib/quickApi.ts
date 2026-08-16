/** Quick execution-mode API — GET /quick/profiles and GET /scans/{id}/plan. */

import { fetchV1 } from "@/lib/scanApi";

export type QuickProfileName = "compact" | "balanced" | "extended";

export type QuickSeverityFloor = "critical" | "high" | "medium" | "low" | "info";

export interface QuickBudgetView {
  wall_clock_budget_seconds: number;
  discovery_budget_seconds?: number;
  fingerprint_budget_seconds?: number;
  verification_budget_seconds?: number;
  ai_budget_seconds?: number;
  report_budget_seconds?: number;
  request_budget?: number;
  per_host_budget?: number;
  concurrency_budget?: number;
  reserve_for_validation_percent?: number;
}

export interface QuickProfileCatalogItem {
  name: QuickProfileName;
  wall_clock_budget_seconds: number;
  ai_budget_seconds: number;
  reserve_for_validation_percent: number;
  max_targets: number;
  max_urls_per_host: number;
  crawl_depth: number;
  severity_floor: string;
  enable_ai: boolean;
  enable_oast: boolean;
  enable_headless_on_signal: boolean;
  request_budget: number;
  per_host_budget: number;
  concurrency_budget: number;
}

export interface QuickCoverageIntent {
  capability_id: string;
  reason_code: string;
  state?: string;
}

export interface QuickPlanTask {
  tool_id?: string;
  capability_id?: string;
  status?: string;
  stage?: string;
  target_ref?: string;
}

export interface QuickScanPlanView {
  scan_id: string;
  mode: "quick";
  profile: QuickProfileName;
  plan_version: number;
  deadline_at: string;
  budget: QuickBudgetView;
  stages: string[];
  tasks: QuickPlanTask[];
  fallbacks: string[];
  coverage_intent: QuickCoverageIntent[];
  assumptions: string[];
  prompt_version?: string;
  model_route?: string;
  revision_reason?: string | null;
}

export interface QuickProfilesResponse {
  profiles: QuickProfileCatalogItem[];
}

export function formatDurationSeconds(total: number): string {
  const seconds = Math.max(0, Math.floor(total));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${rest}s`;
  return `${rest}s`;
}

function asObject(value: unknown): Record<string, unknown> | null {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return null;
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string");
}

function parseBudget(raw: unknown): QuickBudgetView {
  const obj = asObject(raw) ?? {};
  return {
    wall_clock_budget_seconds: asNumber(obj.wall_clock_budget_seconds) ?? 1,
    discovery_budget_seconds: asNumber(obj.discovery_budget_seconds),
    fingerprint_budget_seconds: asNumber(obj.fingerprint_budget_seconds),
    verification_budget_seconds: asNumber(obj.verification_budget_seconds),
    ai_budget_seconds: asNumber(obj.ai_budget_seconds),
    report_budget_seconds: asNumber(obj.report_budget_seconds),
    request_budget: asNumber(obj.request_budget),
    per_host_budget: asNumber(obj.per_host_budget),
    concurrency_budget: asNumber(obj.concurrency_budget),
    reserve_for_validation_percent: asNumber(obj.reserve_for_validation_percent),
  };
}

function parseProfileName(raw: unknown): QuickProfileName {
  if (raw === "compact" || raw === "balanced" || raw === "extended") {
    return raw;
  }
  return "balanced";
}

function parseTask(raw: unknown): QuickPlanTask {
  const obj = asObject(raw) ?? {};
  return {
    tool_id: asString(obj.tool_id),
    capability_id: asString(obj.capability_id),
    status: asString(obj.status),
    stage: asString(obj.stage),
    target_ref: asString(obj.target_ref),
  };
}

function parseCoverageIntent(raw: unknown): QuickCoverageIntent | null {
  const obj = asObject(raw);
  if (!obj) return null;
  const capabilityId = asString(obj.capability_id);
  const reasonCode = asString(obj.reason_code);
  if (!capabilityId || !reasonCode) return null;
  return {
    capability_id: capabilityId,
    reason_code: reasonCode,
    state: asString(obj.state),
  };
}

function parsePlan(raw: unknown, scanId: string): QuickScanPlanView {
  const obj = asObject(raw) ?? {};
  const tasksRaw = Array.isArray(obj.tasks) ? obj.tasks : [];
  const intentRaw = Array.isArray(obj.coverage_intent) ? obj.coverage_intent : [];
  const stagesRaw = Array.isArray(obj.stages) ? obj.stages : [];
  const fallbacksRaw = Array.isArray(obj.fallbacks) ? obj.fallbacks : [];
  const assumptionsRaw = Array.isArray(obj.assumptions) ? obj.assumptions : [];
  return {
    scan_id: asString(obj.scan_id) ?? scanId,
    mode: "quick",
    profile: parseProfileName(obj.profile),
    plan_version: asNumber(obj.plan_version) ?? 0,
    deadline_at: asString(obj.deadline_at) ?? "",
    budget: parseBudget(obj.budget),
    stages: stagesRaw.map((item) => (typeof item === "string" ? item : JSON.stringify(item))),
    tasks: tasksRaw.map(parseTask),
    fallbacks: asStringArray(fallbacksRaw),
    coverage_intent: intentRaw
      .map(parseCoverageIntent)
      .filter((item): item is QuickCoverageIntent => item !== null),
    assumptions: asStringArray(assumptionsRaw),
    prompt_version: asString(obj.prompt_version),
    model_route: asString(obj.model_route),
    revision_reason: asString(obj.revision_reason) ?? null,
  };
}

export async function fetchQuickProfiles(): Promise<QuickProfileCatalogItem[]> {
  const response = await fetchV1<QuickProfilesResponse>("/quick/profiles");
  const items = Array.isArray(response.profiles) ? response.profiles : [];
  return items.filter(
    (item): item is QuickProfileCatalogItem =>
      item.name === "compact" || item.name === "balanced" || item.name === "extended"
  );
}

export async function fetchScanPlan(scanId: string): Promise<QuickScanPlanView> {
  const raw = await fetchV1<unknown>(`/scans/${encodeURIComponent(scanId)}/plan`);
  return parsePlan(raw, scanId);
}
