"use client";

import { useCallback, useEffect, useState } from "react";

import { CaptureFullArtifactViewer } from "@/components/lab/CaptureFullArtifactViewer";
import { CoverageHeatmap } from "@/components/lab/CoverageHeatmap";
import { CoverageStatusView } from "@/components/lab/CoverageStatusView";
import { ExecutionModeSelector } from "@/components/lab/ExecutionModeSelector";
import { LabKillSwitchControl } from "@/components/lab/LabKillSwitchControl";
import { LabLeaseStatusBanner } from "@/components/lab/LabLeaseStatusBanner";
import { LabUnrestrictedBadge } from "@/components/lab/LabUnrestrictedBadge";
import { NucleiReleasePanel } from "@/components/lab/NucleiReleasePanel";
import { OccurrenceTimeline } from "@/components/lab/OccurrenceTimeline";
import { PlanEditor } from "@/components/lab/PlanEditor";
import { RoutingHealthView } from "@/components/lab/RoutingHealthView";
import { ScanDiffView } from "@/components/lab/ScanDiffView";
import { emptyLabPlan } from "@/lib/lab/labApproval";
import { labApi } from "@/lib/lab/labApi";
import type {
  ExecutionMode,
  LabLeaseResponse,
  LabScanPlan,
  LabScopeManifestResponse,
} from "@/lib/lab/types";

interface LabWorkspaceProps {
  title: string;
  initialScanId?: string;
  showNuclei?: boolean;
}

export function LabWorkspace({
  title,
  initialScanId = "scan-1",
  showNuclei = true,
}: LabWorkspaceProps) {
  const [scanId, setScanId] = useState(initialScanId);
  const [baselineId, setBaselineId] = useState("");
  const [executionId, setExecutionId] = useState("");
  const [engagementId, setEngagementId] = useState("default-engagement");
  const [mode, setMode] = useState<ExecutionMode>("lab_unrestricted");
  const [modeLocked, setModeLocked] = useState(false);
  const [lease, setLease] = useState<LabLeaseResponse | null>(null);
  const [manifest, setManifest] = useState<LabScopeManifestResponse | null>(null);
  const [plan, setPlan] = useState<LabScanPlan>(emptyLabPlan("lab_unrestricted"));
  const [citations, setCitations] = useState<Array<Record<string, unknown>>>([]);
  const [oast, setOast] = useState<Array<Record<string, unknown>>>([]);
  const [error, setError] = useState<string | null>(null);

  const loadTraces = useCallback(() => {
    Promise.all([labApi.getRagTrace(scanId), labApi.getOastTrace(scanId)])
      .then(([rag, oastTrace]) => {
        setCitations(rag.citations);
        setOast(oastTrace.interactions);
        setError(null);
      })
      .catch((err: unknown) => {
        setError(err instanceof Error ? err.message : "trace_failed");
      });
  }, [scanId]);

  useEffect(() => {
    loadTraces();
  }, [loadTraces]);

  useEffect(() => {
    void labApi
      .getExecutionMode(engagementId)
      .then((payload) => {
        setMode(payload.mode);
        setModeLocked(Boolean(payload.first_execution_at));
        setPlan((current) => ({ ...current, mode: payload.mode }));
      })
      .catch(() => {
        /* engagement may not exist yet */
      });
  }, [engagementId]);

  const lab = mode === "lab_unrestricted";

  return (
    <div className="mx-auto max-w-6xl space-y-6 px-4 py-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold text-white">{title}</h1>
        {lab ? <LabUnrestrictedBadge /> : null}
      </div>
      <p className="text-sm text-neutral-400">
        LAB capabilities are not filtered by production risk labels. Approval dialogs are
        skipped when a usable lease is active.
      </p>
      <LabKillSwitchControl enabled={lab} />
      <LabLeaseStatusBanner lease={lease} manifest={manifest} />
      <ExecutionModeSelector
        value={mode}
        disabled={modeLocked}
        lockedReason={modeLocked ? "Mode is immutable after first execution" : null}
        onChange={(next) => {
          setMode(next);
          setPlan((current) => ({ ...current, mode: next }));
          void labApi.setExecutionMode(engagementId, next).catch((err: unknown) => {
            setError(err instanceof Error ? err.message : "mode_failed");
          });
        }}
      />

      <div className="grid gap-3 sm:grid-cols-2">
        <label className="block text-sm text-neutral-300">
          Engagement ID
          <input
            className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 px-3 py-2"
            value={engagementId}
            onChange={(event) => setEngagementId(event.target.value)}
          />
        </label>
        <label className="block text-sm text-neutral-300">
          Scan ID
          <input
            className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 px-3 py-2"
            value={scanId}
            onChange={(event) => setScanId(event.target.value)}
            data-testid="lab-scan-id"
          />
        </label>
      </div>

      <div className="flex flex-wrap gap-2">
        <button
          type="button"
          className="rounded border border-neutral-600 px-3 py-1 text-sm text-neutral-200"
          onClick={() => {
            void labApi
              .createLabScope(engagementId, {
                cidrs: ["10.90.0.0/16"],
                dns_suffixes: ["lab.argus"],
                k8s_namespace: "argus-lab",
                capture_full: true,
              })
              .then(setManifest)
              .catch((err: unknown) => {
                setError(err instanceof Error ? err.message : "scope_failed");
              });
          }}
        >
          Create lab scope
        </button>
        <button
          type="button"
          className="rounded border border-neutral-600 px-3 py-1 text-sm text-neutral-200"
          onClick={() => {
            void labApi
              .createLabLease(engagementId, {
                target: "https://lab.argus",
                kill_switch_cleared: true,
              })
              .then(setLease)
              .catch((err: unknown) => {
                setError(err instanceof Error ? err.message : "lease_failed");
              });
          }}
        >
          Issue lab lease
        </button>
      </div>

      {error ? (
        <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">
          {error}
        </div>
      ) : null}

      <PlanEditor plan={plan} onChange={setPlan} />
      <RoutingHealthView />
      {showNuclei ? <NucleiReleasePanel /> : null}

      <section className="rounded border border-neutral-800 p-4">
        <h2 className="mb-2 font-medium text-white">Coverage heatmap</h2>
        <CoverageHeatmap scanId={scanId} />
        <div className="mt-4">
          <CoverageStatusView scanId={scanId} />
        </div>
      </section>

      <section className="rounded border border-neutral-800 p-4">
        <h2 className="mb-2 font-medium text-white">Finding occurrence timeline</h2>
        <OccurrenceTimeline scanId={scanId} />
      </section>

      <section className="rounded border border-neutral-800 p-4">
        <h2 className="mb-2 font-medium text-white">Scan diff / retest</h2>
        <label className="mb-2 block text-sm text-neutral-300">
          Baseline scan ID
          <input
            className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 px-3 py-2"
            value={baselineId}
            onChange={(event) => setBaselineId(event.target.value)}
          />
        </label>
        <ScanDiffView scanId={scanId} baselineId={baselineId} />
      </section>

      <section className="rounded border border-neutral-800 p-4">
        <h2 className="mb-2 font-medium text-white">capture_full artifact</h2>
        <label className="mb-2 block text-sm text-neutral-300">
          Lab execution ID
          <input
            className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 px-3 py-2"
            value={executionId}
            onChange={(event) => setExecutionId(event.target.value)}
            data-testid="lab-execution-id"
          />
        </label>
        <CaptureFullArtifactViewer executionId={executionId} />
      </section>

      <section className="rounded border border-neutral-800 p-4">
        <h2 className="mb-2 font-medium text-white">RAG citation trace</h2>
        <pre className="overflow-auto text-xs text-neutral-300">
          {JSON.stringify(citations, null, 2)}
        </pre>
      </section>

      <section className="rounded border border-neutral-800 p-4">
        <h2 className="mb-2 font-medium text-white">OAST interactions</h2>
        <pre className="overflow-auto text-xs text-neutral-300" data-testid="oast-trace">
          {JSON.stringify(oast, null, 2)}
        </pre>
      </section>
    </div>
  );
}
