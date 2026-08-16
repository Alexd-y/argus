import type { ScanTier } from "@/lib/scan-tiers";
import type { ScanResults } from "@/lib/scan-results";

export type ScanStatus = "pending" | "running" | "complete" | "failed";

export interface ScanData {
  id: string;
  target: string;
  email: string;
  tier: ScanTier;
  status: ScanStatus;
  stage: string;
  stageIndex: number;
  progress: number;
  error: string | null;
  results: ScanResults | null;
  parentScanId: string | null;
  darkWebMonitoring: boolean;
  paid: boolean;
  createdAt: string;
  completedAt: string | null;
}
