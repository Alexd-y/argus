/**
 * LAB / unified-AI API types (docs/api-contracts.md §4.1).
 */

export type ExecutionMode = "production" | "lab_unrestricted" | "quick";

export type CoverageStatus =
  | "planned"
  | "running"
  | "covered_no_finding"
  | "covered_with_finding"
  | "partial"
  | "blocked"
  | "not_applicable"
  | "not_tested";

export type DiffStatus =
  | "new"
  | "unchanged"
  | "changed"
  | "resolved_candidate"
  | "resolved"
  | "regressed"
  | "not_tested";

export type NucleiReleaseStatus = "pending" | "active" | "rolled_back";

export type PlanStepKind = "tool" | "template" | "script";

export interface ExecutionModeResponse {
  engagement_id: string;
  tenant_id: string;
  mode: ExecutionMode;
  first_execution_at: string | null;
}

export interface LabScopeManifestResponse {
  manifest_id: string;
  tenant_id: string;
  engagement_id: string;
  mode: ExecutionMode;
  asset_ids?: string[];
  cidrs?: string[];
  dns_suffixes?: string[];
  k8s_namespace?: string | null;
  vm_network_ids?: string[];
  internet_attached?: boolean;
  capture_full?: boolean;
  expires_at: string;
  created_by?: string;
  created_at?: string;
  signature?: string | null;
}

export interface LabLeaseResponse {
  lease_id: string;
  tenant_id: string;
  engagement_id: string;
  manifest_id: string;
  mode: ExecutionMode;
  status: "active" | "expired" | "revoked" | "kill_switched";
  issued_at: string;
  expires_at: string;
  kill_switch_cleared: boolean;
  boundary_proof?: string;
  capture_full?: boolean;
  k8s_namespace?: string | null;
  policy?: {
    requires_approval?: boolean;
    outcome?: string;
    allowed_tools?: string | string[];
    allowed_actions?: string | string[];
    reason?: string;
  };
}

export interface CoverageResult {
  requirement_id: string;
  tenant_id: string;
  scan_id: string;
  asset_id: string;
  capability_id: string;
  status: CoverageStatus;
  execution_evidence_id?: string | null;
  blocked_reason?: string | null;
  finding_id?: string | null;
  recorded_at?: string | null;
}

export interface CoverageRequirement {
  id: string;
  tenant_id: string;
  scan_id: string;
  asset_id: string;
  capability_id: string;
  required_evidence_types?: string[];
}

export interface ScanCoverageResponse {
  scan_id: string;
  requirements: CoverageRequirement[];
  results: CoverageResult[];
}

export interface ScanDiffEntry {
  finding_key: string;
  status: DiffStatus;
  baseline_state?: string | null;
  current_state?: string | null;
}

export interface ScanDiffResponse {
  scan_id: string;
  baseline_id: string;
  entries: ScanDiffEntry[];
}

export interface FindingOccurrence {
  occurrence_key: string;
  finding_key: string;
  tenant_id: string;
  scan_id: string;
  scanner: string;
  detector_id: string;
  detector_version: string;
  evidence_refs: string[];
  first_seen_at: string;
  last_seen_at: string;
}

export interface ScanOccurrencesResponse {
  scan_id: string;
  occurrences: FindingOccurrence[];
}

export interface NucleiReleaseRecord {
  release_id: string;
  version: string;
  digest_sha256: string;
  provenance: Record<string, unknown>;
  provenance_hash: string;
  status: NucleiReleaseStatus;
  activated_at?: string | null;
  previous_release_id?: string | null;
}

export interface NucleiReleasesResponse {
  releases: NucleiReleaseRecord[];
  active_release_id: string | null;
}

export interface LabExecutionRecord {
  execution_id: string;
  lease_id: string;
  status: string;
  return_code: number | null;
  stdout: string;
  stderr: string;
  runner: string;
  argv: string[];
  error_code: string | null;
  requires_approval: boolean;
  capture_full: boolean;
  execution_time_sec?: number;
  script_id?: string;
  artifact_id?: string;
}

export interface LlmRoutingHealth {
  whiteRabbitNeo: { status: string; model?: string; local?: boolean };
  cloud: { status: string; note?: string };
  routing_mode: string;
}

export interface LabPlanStep {
  id: string;
  kind: PlanStepKind;
  name: string;
  argv: string[];
}

export interface LabScanPlan {
  mode: ExecutionMode;
  requires_approval: boolean;
  steps: LabPlanStep[];
}

export interface RagTraceResponse {
  scan_id: string;
  query: string;
  citations: Array<Record<string, unknown>>;
  collection: string;
}

export interface OastTraceResponse {
  scan_id: string;
  interactions: Array<{
    scan_id: string;
    protocol: string;
    correlation_status: string;
    token_id?: string | null;
    payload_hash?: string | null;
  }>;
}
