"use client";

import { ScanSuccess } from "@/components/scan/ScanSuccess";
import type { ScanData } from "@/lib/scan-types";
import { getResultsForTier, localizeResults } from "@/lib/scan-results";

const SAMPLE_TARGET = "example.com";

const SAMPLE_SCAN: ScanData = {
  id: "sample",
  target: SAMPLE_TARGET,
  email: "owner@example.com",
  tier: "premium",
  status: "complete",
  stage: "Generating report",
  stageIndex: 4,
  progress: 100,
  error: null,
  results: localizeResults(getResultsForTier("premium"), SAMPLE_TARGET),
  parentScanId: null,
  darkWebMonitoring: true,
  paid: true,
  quota: {
    included: 6,
    extra: 0,
    extraCap: 3,
    used: 1,
    remaining: 5,
    capacity: 6,
    periodEnd: "2026-09-01T12:00:00.000Z",
    canRetest: true,
    canBuyExtra: false,
  },
  createdAt: "2026-08-01T12:00:00.000Z",
  completedAt: "2026-08-01T12:00:00.000Z",
};

export function SampleReport() {
  return <ScanSuccess scan={SAMPLE_SCAN} sample />;
}
