import { randomUUID } from "crypto";
import type { ScanTier } from "./scan-tiers";
import { SCAN_STAGES } from "./scan-tiers";
import { getResultsForTier } from "./scan-results";

export type ScanStatus = "pending" | "running" | "complete" | "failed";

export interface ScanRecord {
  id: string;
  target: string;
  email: string;
  tier: ScanTier;
  status: ScanStatus;
  stage: string;
  stageIndex: number;
  progress: number;
  error: string | null;
  results: ReturnType<typeof getResultsForTier> | null;
  parentScanId: string | null;
  darkWebMonitoring: boolean;
  paid: boolean;
  createdAt: string;
  completedAt: string | null;
}

export interface CreateScanInput {
  target: string;
  email: string;
  tier: ScanTier;
  parentScanId?: string;
  darkWebMonitoring?: boolean;
}

const TIER_STAGE_MS: Record<ScanTier, number> = {
  free: 8000,
  standard: 12000,
  premium: 16000,
};

const globalForScans = globalThis as unknown as {
  scanStore?: Map<string, ScanRecord>;
  activeRunners?: Set<string>;
};

function getStore(): Map<string, ScanRecord> {
  if (!globalForScans.scanStore) {
    globalForScans.scanStore = new Map();
  }
  return globalForScans.scanStore;
}

function getActiveRunners(): Set<string> {
  if (!globalForScans.activeRunners) {
    globalForScans.activeRunners = new Set();
  }
  return globalForScans.activeRunners;
}

function shouldSimulateFailure(target: string): boolean {
  return target.toLowerCase().includes("fail-scan");
}

export function createScan(input: CreateScanInput): ScanRecord {
  const id = randomUUID();
  const scan: ScanRecord = {
    id,
    target: input.target,
    email: input.email,
    tier: input.tier,
    status: "pending",
    stage: SCAN_STAGES[0],
    stageIndex: 0,
    progress: 0,
    error: null,
    results: null,
    parentScanId: input.parentScanId ?? null,
    darkWebMonitoring: input.darkWebMonitoring ?? false,
    paid: input.tier === "free",
    createdAt: new Date().toISOString(),
    completedAt: null,
  };

  getStore().set(id, scan);
  startMockScanner(id);
  return scan;
}

export function getScan(id: string): ScanRecord | null {
  return getStore().get(id) ?? null;
}

export function updateScan(id: string, updates: Partial<ScanRecord>): ScanRecord | null {
  const scan = getStore().get(id);
  if (!scan) return null;
  const updated = { ...scan, ...updates };
  getStore().set(id, updated);
  return updated;
}

function startMockScanner(id: string): void {
  const runners = getActiveRunners();
  if (runners.has(id)) return;
  runners.add(id);

  const scan = getScan(id);
  if (!scan) {
    runners.delete(id);
    return;
  }

  if (shouldSimulateFailure(scan.target)) {
    setTimeout(() => {
      updateScan(id, {
        status: "failed",
        error: "Scanner encountered an error while assessing the target. Please retry or contact support.",
        completedAt: new Date().toISOString(),
      });
      runners.delete(id);
    }, 3000);
    return;
  }

  const stageMs = TIER_STAGE_MS[scan.tier];
  let stageIndex = 0;

  const advance = () => {
    const current = getScan(id);
    if (!current || current.status === "failed" || current.status === "complete") {
      runners.delete(id);
      return;
    }

    if (stageIndex === 0) {
      updateScan(id, { status: "running" });
    }

    if (stageIndex >= SCAN_STAGES.length) {
      updateScan(id, {
        status: "complete",
        stage: SCAN_STAGES[SCAN_STAGES.length - 1],
        stageIndex: SCAN_STAGES.length - 1,
        progress: 100,
        results: getResultsForTier(current.tier),
        completedAt: new Date().toISOString(),
      });
      runners.delete(id);
      return;
    }

    const progress = Math.round(((stageIndex + 0.5) / SCAN_STAGES.length) * 100);
    updateScan(id, {
      stage: SCAN_STAGES[stageIndex],
      stageIndex,
      progress: Math.min(progress, 99),
    });

    stageIndex += 1;
    setTimeout(advance, stageMs);
  };

  setTimeout(advance, 500);
}

export function markScanPaid(id: string): ScanRecord | null {
  return updateScan(id, { paid: true });
}

/** Whether full report content is available (free tier or subscription paid). */
export function isScanUnlocked(scan: Pick<ScanRecord, "tier" | "paid">): boolean {
  return scan.tier === "free" || scan.paid;
}

function sanitizeResultsForResponse(scan: ScanRecord) {
  if (!scan.results) return null;
  if (isScanUnlocked(scan)) return scan.results;

  // Locked paid tier: expose severity counts only — no detailed findings
  return {
    critical: scan.results.critical,
    high: scan.results.high,
    medium: scan.results.medium,
    low: scan.results.low,
    info: scan.results.info,
    technologies: [],
    sslIssues: null,
    headerIssues: null,
    leaksFound: false,
  };
}

export function toScanResponse(scan: ScanRecord) {
  return {
    id: scan.id,
    target: scan.target,
    email: scan.email,
    tier: scan.tier,
    status: scan.status,
    stage: scan.stage,
    stageIndex: scan.stageIndex,
    progress: scan.progress,
    error: scan.error,
    results: sanitizeResultsForResponse(scan),
    parentScanId: scan.parentScanId,
    darkWebMonitoring: scan.darkWebMonitoring,
    paid: scan.paid,
    createdAt: scan.createdAt,
    completedAt: scan.completedAt,
  };
}
