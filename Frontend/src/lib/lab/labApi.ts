/**
 * LAB / unified-AI client — /api/v1/* via Next rewrites.
 */

import { apiFetch } from "@/lib/api";

import type {
  ExecutionMode,
  ExecutionModeResponse,
  LabExecutionRecord,
  LabLeaseResponse,
  LabScopeManifestResponse,
  LlmRoutingHealth,
  NucleiReleaseRecord,
  NucleiReleasesResponse,
  OastTraceResponse,
  RagTraceResponse,
  ScanCoverageResponse,
  ScanDiffResponse,
  ScanOccurrencesResponse,
} from "./types";

function getTenantId(): string {
  if (typeof window !== "undefined") {
    const stored = window.localStorage.getItem("tenant_id");
    if (stored) return stored;
  }
  return process.env.NEXT_PUBLIC_TENANT_ID || "default";
}

async function labFetch<T>(path: string, options: RequestInit = {}): Promise<T> {
  return apiFetch<T>(path, {
    ...options,
    headers: {
      "X-Tenant-Id": getTenantId(),
      ...(options.headers as Record<string, string> | undefined),
    },
  });
}

export const labApi = {
  getExecutionMode: (engagementId: string) =>
    labFetch<ExecutionModeResponse>(
      `/engagements/${encodeURIComponent(engagementId)}/execution-mode`,
    ),

  setExecutionMode: (engagementId: string, mode: ExecutionMode) =>
    labFetch<ExecutionModeResponse>(
      `/engagements/${encodeURIComponent(engagementId)}/execution-mode`,
      { method: "POST", body: JSON.stringify({ mode }) },
    ),

  createLabScope: (
    engagementId: string,
    body: {
      cidrs?: string[];
      dns_suffixes?: string[];
      k8s_namespace?: string;
      vm_network_ids?: string[];
      internet_attached?: boolean;
      capture_full?: boolean;
      expires_in_hours?: number;
    },
  ) =>
    labFetch<LabScopeManifestResponse>(
      `/engagements/${encodeURIComponent(engagementId)}/lab-scope`,
      { method: "POST", body: JSON.stringify(body) },
    ),

  createLabLease: (
    engagementId: string,
    body: { target: string; kill_switch_cleared?: boolean },
  ) =>
    labFetch<LabLeaseResponse>(
      `/engagements/${encodeURIComponent(engagementId)}/lab-lease`,
      { method: "POST", body: JSON.stringify(body) },
    ),

  getCoverage: (scanId: string) =>
    labFetch<ScanCoverageResponse>(`/scans/${encodeURIComponent(scanId)}/coverage`),

  getDiff: (scanId: string, baselineId: string) =>
    labFetch<ScanDiffResponse>(
      `/scans/${encodeURIComponent(scanId)}/diff/${encodeURIComponent(baselineId)}`,
    ),

  getOccurrences: (scanId: string) =>
    labFetch<ScanOccurrencesResponse>(
      `/scans/${encodeURIComponent(scanId)}/occurrences`,
    ),

  retestFinding: (findingKey: string, scanId: string, outcome: string) =>
    labFetch<{ job: Record<string, unknown>; finding: Record<string, unknown> }>(
      `/findings/${encodeURIComponent(findingKey)}/retest?scan_id=${encodeURIComponent(scanId)}&outcome=${encodeURIComponent(outcome)}`,
      { method: "POST" },
    ),

  listNucleiProfiles: () =>
    labFetch<{ profiles: Array<Record<string, unknown>> }>("/nuclei/profiles"),

  listNucleiTemplates: () =>
    labFetch<{ templates: Array<Record<string, unknown>> }>("/nuclei/templates"),

  listNucleiReleases: () => labFetch<NucleiReleasesResponse>("/nuclei/releases"),

  registerNucleiRelease: (body: {
    version: string;
    digest_sha256: string;
    provenance?: Record<string, unknown>;
  }) =>
    labFetch<NucleiReleaseRecord>("/nuclei/releases", {
      method: "POST",
      body: JSON.stringify(body),
    }),

  activateNucleiRelease: (releaseId: string) =>
    labFetch<NucleiReleaseRecord>(
      `/nuclei/releases/${encodeURIComponent(releaseId)}/activate`,
      { method: "POST" },
    ),

  rollbackNucleiRelease: (releaseId: string) =>
    labFetch<NucleiReleaseRecord>(
      `/nuclei/releases/${encodeURIComponent(releaseId)}/rollback`,
      { method: "POST" },
    ),

  getRagTrace: (scanId: string) =>
    labFetch<RagTraceResponse>(`/rag/traces/${encodeURIComponent(scanId)}`),

  getOastTrace: (scanId: string) =>
    labFetch<OastTraceResponse>(`/oast/traces/${encodeURIComponent(scanId)}`),

  getLabExecution: (executionId: string) =>
    labFetch<LabExecutionRecord>(
      `/lab/executions/${encodeURIComponent(executionId)}`,
    ),

  getLlmRoutingHealth: () => labFetch<LlmRoutingHealth>("/llm/health/all"),
};
