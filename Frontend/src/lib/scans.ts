import { randomUUID } from "crypto";
import type { ScanTier } from "./scan-tiers";
import { SCAN_STAGES, includesDarkWebMonitoring, isPaidTier, isScanUnlocked } from "./scan-tiers";
import { getResultsForTier, lockFindings, localizeResults } from "./scan-results";
import { fetchDemoFindings, isLiveFindingsTarget, resultsFromCanonical } from "./live-findings";
import {
  activateSubscription,
  getScanQuota,
  refundCredit,
  type QuotaSource,
} from "./scan-quota";

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
  quotaCharged: boolean;
  quotaSource: QuotaSource | null;
  createdAt: string;
  completedAt: string | null;
}

export interface CreateScanInput {
  target: string;
  email: string;
  tier: ScanTier;
  parentScanId?: string;
  darkWebMonitoring?: boolean;
  paid?: boolean;
  quotaCharged?: boolean;
  quotaSource?: QuotaSource | null;
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
    darkWebMonitoring: includesDarkWebMonitoring(input.tier, input.darkWebMonitoring),
    paid: input.paid ?? input.tier === "free",
    quotaCharged: input.quotaCharged ?? false,
    quotaSource: input.quotaSource ?? null,
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
      const current = getScan(id);
      if (current?.quotaCharged) {
        refundCredit(current);
      }
      updateScan(id, {
        status: "failed",
        error: "Scanner encountered an error while assessing the target. Please retry or contact support.",
        completedAt: new Date().toISOString(),
        quotaCharged: false,
        quotaSource: null,
      });
      runners.delete(id);
    }, 3000);
    return;
  }

  const stageMs = TIER_STAGE_MS[scan.tier];
  let stageIndex = 0;
  const liveFindings = isLiveFindingsTarget(scan.target)
    ? fetchDemoFindings()
    : Promise.resolve(null);

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
      void finalizeScan(id, liveFindings);
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

async function finalizeScan(
  id: string,
  liveFindings: Promise<Awaited<ReturnType<typeof fetchDemoFindings>> | null>
): Promise<void> {
  const current = getScan(id);
  if (!current || current.status === "failed" || current.status === "complete") {
    getActiveRunners().delete(id);
    return;
  }

  try {
    const payload = await liveFindings;
    const results = payload
      ? resultsFromCanonical(payload, current.tier, current.target)
      : localizeResults(getResultsForTier(current.tier), current.target);

    updateScan(id, {
      status: "complete",
      stage: SCAN_STAGES[SCAN_STAGES.length - 1],
      stageIndex: SCAN_STAGES.length - 1,
      progress: 100,
      results,
      completedAt: new Date().toISOString(),
    });
  } catch (error) {
    console.error("Failed to load scan findings:", error);
    const failed = getScan(id);
    if (failed?.quotaCharged) {
      refundCredit(failed);
    }
    updateScan(id, {
      status: "failed",
      error: "Could not load scan findings for this target. Please retry.",
      completedAt: new Date().toISOString(),
      quotaCharged: false,
      quotaSource: null,
    });
  } finally {
    getActiveRunners().delete(id);
  }
}

export function markScanPaid(id: string, stripeSubscriptionId?: string | null): ScanRecord | null {
  const scan = getScan(id);
  if (!scan) return null;
  if (scan.paid && isPaidTier(scan.tier)) {
    activateSubscription({ ...scan, stripeSubscriptionId });
    return scan;
  }
  const updated = updateScan(id, { paid: true, quotaCharged: true, quotaSource: "included" });
  if (updated && isPaidTier(updated.tier)) {
    activateSubscription({ ...updated, stripeSubscriptionId });
  }
  return updated;
}

export { isScanUnlocked } from "./scan-tiers";

function sanitizeResultsForResponse(scan: ScanRecord) {
  if (!scan.results) return null;
  if (isScanUnlocked(scan)) return scan.results;
  return lockFindings(scan.results);
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
    quota: getScanQuota(scan),
    createdAt: scan.createdAt,
    completedAt: scan.completedAt,
  };
}
