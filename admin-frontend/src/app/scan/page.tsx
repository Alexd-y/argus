"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { CoverageHeatmap } from "@/components/CoverageHeatmap";
import { CoverageStatusView } from "@/components/CoverageStatusView";
import { ExecutionModeSelector } from "@/components/ExecutionModeSelector";
import { ExploitationApprovalDialog } from "@/components/ExploitationApprovalDialog";
import { LabKillSwitchControl } from "@/components/LabKillSwitchControl";
import { LabLeaseStatusBanner } from "@/components/LabLeaseStatusBanner";
import { LabUnrestrictedBadge } from "@/components/LabUnrestrictedBadge";
import { QuickLiveStatus, type QuickBudgetSnapshot } from "@/components/QuickLiveStatus";
import { QuickModeCard, type QuickModeCardValue } from "@/components/QuickModeCard";
import { ScanDiffView } from "@/components/ScanDiffView";
import { DataTable } from "@/components/DataTable";
import { shouldSkipApprovalDialog } from "@/lib/labApproval";
import type { QuickCreateOptions } from "@/lib/scanApi";
import type {
  ExecutionMode,
  LabLeaseResponse,
  LabScopeManifestResponse,
  ScanFinding,
} from "@/lib/scanApi";
import {
  isLabExecution,
  isQuickExecution,
  scanApi,
  scanModeForExecution,
} from "@/lib/scanApi";

const getBaseUrl = () =>
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface ScanEvent {
  event: string;
  phase?: string;
  progress?: number;
  message?: string;
  data?: Record<string, unknown>;
  error?: string;
  code?: string;
  approval_id?: string;
}

const PHASE_LABELS: Record<string, string> = {
  init: "Initialising",
  recon: "Reconnaissance",
  threat_modeling: "Threat Modeling",
  vuln_analysis: "Vulnerability Analysis",
  exploitation: "Exploitation",
  post_exploitation: "Post-Exploitation",
  reporting: "Reporting",
  complete: "Completed",
};

const PHASE_ORDER = [
  "init",
  "recon",
  "threat_modeling",
  "vuln_analysis",
  "exploitation",
  "post_exploitation",
  "reporting",
  "complete",
];

const QUICK_PHASES = ["recon", "threat_modeling", "vuln_analysis", "reporting"];

const DEFAULT_QUICK: QuickModeCardValue = {
  profile: "balanced",
  severityFloor: "medium",
  enableOast: true,
  enableAi: true,
  cloudLlmAllowed: false,
  authenticatedContextId: "",
};

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return null;
}

function parseSsePayload(raw: string): ScanEvent | null {
  try {
    return JSON.parse(raw) as ScanEvent;
  } catch {
    return null;
  }
}

function parseQuickBudget(payload: ScanEvent): QuickBudgetSnapshot {
  const data = asRecord(payload.data) ?? asRecord(payload);
  const used =
    typeof data?.used_seconds === "number"
      ? data.used_seconds
      : typeof data?.consumed_seconds === "number"
        ? data.consumed_seconds
        : undefined;
  const remaining =
    typeof data?.remaining_seconds === "number" ? data.remaining_seconds : undefined;
  const wall =
    typeof data?.wall_clock_budget_seconds === "number"
      ? data.wall_clock_budget_seconds
      : typeof data?.wall_clock_seconds === "number"
        ? data.wall_clock_seconds
        : undefined;
  const ratio =
    typeof data?.used_ratio === "number"
      ? data.used_ratio
      : typeof data?.budget_used_ratio === "number"
        ? data.budget_used_ratio
        : undefined;
  return {
    usedSeconds: used,
    remainingSeconds: remaining,
    wallClockSeconds: wall,
    usedRatio: ratio,
  };
}

function parsePlanVersion(payload: ScanEvent): number | null {
  const data = asRecord(payload.data) ?? asRecord(payload);
  const version = data?.plan_version ?? data?.revision ?? data?.version;
  return typeof version === "number" ? version : null;
}

function parseDegraded(payload: ScanEvent): string[] {
  const data = asRecord(payload.data) ?? asRecord(payload);
  if (!data) return payload.message ? [payload.message] : [];
  const list = data.components ?? data.degraded ?? data.names;
  if (Array.isArray(list)) {
    return list.filter((item): item is string => typeof item === "string");
  }
  if (typeof data.component === "string") return [data.component];
  if (payload.message) return [payload.message];
  return [];
}

function parseFindingsCount(payload: ScanEvent): number | null {
  const data = asRecord(payload.data);
  if (typeof data?.findings_count === "number") return data.findings_count;
  return null;
}

function useScanSSE(scanId: string | null, skipApproval: boolean) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [phase, setPhase] = useState<string>("init");
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState<
    "running" | "completed" | "failed" | "awaiting_approval" | "cancelled"
  >("running");
  const [error, setError] = useState<string | null>(null);
  const [pendingApprovalId, setPendingApprovalId] = useState<string | null>(
    null
  );
  const [quickBudget, setQuickBudget] = useState<QuickBudgetSnapshot | null>(null);
  const [quickPlanRevision, setQuickPlanRevision] = useState<number | null>(null);
  const [quickDegraded, setQuickDegraded] = useState<string[]>([]);
  const [sseFindingsCount, setSseFindingsCount] = useState<number | null>(null);
  const reconnectRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const retriesRef = useRef(0);

  const connect = useCallback(() => {
    if (!scanId) return;

    const baseUrl = getBaseUrl();
    const url = `${baseUrl}/api/v1/scans/${scanId}/events`;
    const eventSource = new EventSource(url);

    eventSource.onopen = () => {
      retriesRef.current = 0;
    };

    const pushEvent = (data: ScanEvent) => {
      setEvents((prev) => [...prev, data]);
    };

    eventSource.addEventListener("init", (e) => {
      const data = parseSsePayload(e.data);
      if (data) pushEvent(data);
    });

    eventSource.addEventListener("phase_start", (e) => {
      const data = parseSsePayload(e.data);
      if (!data) return;
      setPhase(data.phase || "");
      setProgress(data.progress || 0);
      pushEvent(data);
    });

    eventSource.addEventListener("phase_complete", (e) => {
      const data = parseSsePayload(e.data);
      if (!data) return;
      setPhase(data.phase || "");
      setProgress(data.progress || 0);
      const findingsCount = parseFindingsCount(data);
      if (findingsCount != null) setSseFindingsCount(findingsCount);
      pushEvent(data);
    });

    eventSource.addEventListener("progress", (e) => {
      const data = parseSsePayload(e.data);
      if (!data) return;
      setProgress(data.progress || 0);
      pushEvent(data);
    });

    eventSource.addEventListener("quick_budget", (e) => {
      const data = parseSsePayload(e.data);
      if (!data) return;
      setQuickBudget(parseQuickBudget(data));
      pushEvent(data);
    });

    eventSource.addEventListener("quick_plan_revision", (e) => {
      const data = parseSsePayload(e.data);
      if (!data) return;
      const version = parsePlanVersion(data);
      if (version != null) setQuickPlanRevision(version);
      pushEvent(data);
    });

    eventSource.addEventListener("quick_degraded", (e) => {
      const data = parseSsePayload(e.data);
      if (!data) return;
      setQuickDegraded(parseDegraded(data));
      pushEvent(data);
    });

    eventSource.addEventListener("complete", (e) => {
      try {
        const data = JSON.parse(e.data);
        setStatus("completed");
        setProgress(100);
        setPhase("complete");
        pushEvent(data);
        eventSource.close();
      } catch {
        /* ignore malformed */
      }
    });

    eventSource.addEventListener("error", (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data) as ScanEvent;
        if (data.error === "Event stream timeout") {
          return;
        }
        if (data.code === "approval_required") {
          // LAB + valid lease: never surface approval UI (CONT-006 / master §17).
          if (skipApproval) {
            pushEvent({
              ...data,
              event: "approval_skipped",
              message: "Approval skipped — LAB unrestricted lease active",
            });
            return;
          }
          const approvalId =
            data.approval_id ||
            (typeof data.data?.approval_id === "string"
              ? data.data.approval_id
              : null);
          setPendingApprovalId(approvalId);
          setStatus("awaiting_approval");
          setError(data.message || "Exploitation requires approval");
          eventSource.close();
          return;
        }
        pushEvent(data);
      } catch {
        /* ignore malformed */
      }
    });

    eventSource.onerror = () => {
      eventSource.close();
      const retries = retriesRef.current;
      if (retries < 10) {
        retriesRef.current = retries + 1;
        const delay = Math.min(1000 * Math.pow(2, retries), 30000);
        reconnectRef.current = setTimeout(connect, delay);
      } else {
        setError(
          "Lost connection to scan. The scan continues in the background."
        );
      }
    };

    eventSource.addEventListener("keepalive", () => {
      /* connection alive */
    });

    return () => {
      eventSource.close();
      if (reconnectRef.current) {
        clearTimeout(reconnectRef.current);
      }
    };
  }, [scanId, skipApproval]);

  useEffect(() => {
    const cleanup = connect();
    return () => cleanup?.();
  }, [connect]);

  const clearApproval = useCallback(() => {
    setPendingApprovalId(null);
    setStatus("running");
    setError(null);
  }, []);

  const rejectApproval = useCallback(() => {
    setPendingApprovalId(null);
    setStatus("failed");
    setError("Exploitation approval rejected");
  }, []);

  return {
    events,
    phase,
    progress,
    status,
    error,
    pendingApprovalId,
    clearApproval,
    rejectApproval,
    quickBudget,
    quickPlanRevision,
    quickDegraded,
    sseFindingsCount,
  };
}

function newEngagementId(): string {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return `eng-${Date.now()}`;
}

export default function ScanPage() {
  const [engagementId] = useState(() => newEngagementId());
  const [tenantId, setTenantId] = useState("default");
  const [executionMode, setExecutionMode] =
    useState<ExecutionMode>("production");
  const [quickOptions, setQuickOptions] =
    useState<QuickModeCardValue>(DEFAULT_QUICK);
  const [modeLocked, setModeLocked] = useState(false);
  const [modeLockReason, setModeLockReason] = useState<string | null>(null);
  const [labLease, setLabLease] = useState<LabLeaseResponse | null>(null);
  const [labManifest, setLabManifest] =
    useState<LabScopeManifestResponse | null>(null);

  const [scanId, setScanId] = useState("");
  const [inputValue, setInputValue] = useState("https://");
  const [email, setEmail] = useState("");
  const [baselineId, setBaselineId] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const [approvalNote, setApprovalNote] = useState<string | null>(null);

  const skipApproval = useMemo(
    () => shouldSkipApprovalDialog(executionMode, labLease),
    [executionMode, labLease]
  );

  const {
    events,
    phase,
    progress,
    status,
    error,
    pendingApprovalId,
    clearApproval,
    rejectApproval,
    quickBudget,
    quickPlanRevision,
    quickDegraded,
    sseFindingsCount,
  } = useScanSSE(scanId || null, skipApproval);

  useEffect(() => {
    const stored = localStorage.getItem("tenant_id");
    if (stored) setTenantId(stored);
  }, []);

  useEffect(() => {
    localStorage.setItem("tenant_id", tenantId);
  }, [tenantId]);

  useEffect(() => {
    let cancelled = false;

    const loadMode = async () => {
      try {
        const row = await scanApi.getExecutionMode(engagementId, tenantId);
        if (cancelled) return;
        setExecutionMode(row.mode);
        if (row.first_execution_at) {
          setModeLocked(true);
          setModeLockReason(
            `Locked after first execution at ${new Date(row.first_execution_at).toLocaleString()}`
          );
        }
      } catch {
        /* engagement may not exist yet */
      }
    };

    void loadMode();
    return () => {
      cancelled = true;
    };
  }, [engagementId, tenantId]);

  const startScan = async () => {
    setSubmitting(true);
    setStartError(null);
    setApprovalNote(null);
    try {
      await scanApi.setExecutionMode(engagementId, executionMode, tenantId);

      let lease: LabLeaseResponse | null = null;
      let manifest: LabScopeManifestResponse | null = null;
      if (isLabExecution(executionMode)) {
        manifest = await scanApi.createLabScope(
          engagementId,
          {
            cidrs: [
              "10.0.0.0/8",
              "172.16.0.0/12",
              "192.168.0.0/16",
              "127.0.0.0/8",
            ],
            dns_suffixes: ["lab.local", "localhost"],
            capture_full: true,
            expires_in_hours: 8,
          },
          tenantId
        );
        setLabManifest(manifest);
        lease = await scanApi.createLabLease(
          engagementId,
          { target: inputValue, kill_switch_cleared: true },
          tenantId
        );
        setLabLease(lease);
      } else {
        setLabManifest(null);
        setLabLease(null);
      }

      const scanOptions: Record<string, unknown> = {
        execution_mode: executionMode,
        engagement_id: engagementId,
      };
      if (lease) {
        scanOptions.lab_lease_id = lease.lease_id;
      }
      if (manifest) {
        scanOptions.lab_manifest_id = manifest.manifest_id;
      }

      let quickPayload: QuickCreateOptions | undefined;
      if (isQuickExecution(executionMode)) {
        quickPayload = {
          profile: quickOptions.profile,
          severity_floor: quickOptions.severityFloor,
          enable_ai: quickOptions.enableAi,
          enable_oast: quickOptions.enableOast,
        };
        const authRef = quickOptions.authenticatedContextId.trim();
        if (authRef) {
          quickPayload.authenticated_context_id = authRef;
        }
        if (quickOptions.cloudLlmAllowed) {
          quickPayload.cloud_llm_allowed = true;
        }
      }

      const data = await scanApi.createScan({
        target: inputValue,
        email: email || "unknown@argus.local",
        execution_mode: executionMode,
        scan_mode: scanModeForExecution(executionMode),
        quick: quickPayload,
        options: scanOptions,
      });

      setScanId(data.scan_id);
      setModeLocked(true);
      setModeLockReason("Execution mode is immutable after scan start");
    } catch (e) {
      setStartError(e instanceof Error ? e.message : "Failed");
    } finally {
      setSubmitting(false);
    }
  };

  const showApprovalDialog =
    status === "awaiting_approval" && !skipApproval;

  const handleApprove = () => {
    setApprovalNote(
      pendingApprovalId
        ? `Approval recorded for ${pendingApprovalId} (operator acknowledged).`
        : "Approval acknowledged by operator."
    );
    clearApproval();
  };

  const handleReject = () => {
    setApprovalNote(null);
    rejectApproval();
  };

  const phaseIndex = PHASE_ORDER.indexOf(phase);
  const lastEvent = events[events.length - 1];
  // Always show LAB chrome when mode is lab_unrestricted — never hide by risk labels.
  const showLabChrome = isLabExecution(executionMode);
  const showQuickChrome = isQuickExecution(executionMode);
  const visiblePhases = showQuickChrome
    ? QUICK_PHASES
    : PHASE_ORDER.filter((p) => p !== "init" && p !== "complete");

  return (
    <div className="mx-auto max-w-3xl">
      {!skipApproval && (
        <ExploitationApprovalDialog
          open={showApprovalDialog}
          message={error}
          approvalId={pendingApprovalId}
          onApprove={handleApprove}
          onReject={handleReject}
        />
      )}

      {!scanId ? (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <h1 className="text-xl font-semibold">New Pentest Scan</h1>
            {showLabChrome && <LabUnrestrictedBadge />}
            {showQuickChrome && (
              <span
                className="rounded border border-cyan-700 bg-cyan-950/40 px-2 py-0.5 text-xs uppercase tracking-wide text-cyan-300"
                data-testid="quick-mode-badge"
              >
                Quick
              </span>
            )}
          </div>

          <div className="mb-4 flex flex-col gap-2">
            <label className="text-xs text-neutral-500">
              Tenant ID
              <input
                type="text"
                value={tenantId}
                onChange={(e) => setTenantId(e.target.value)}
                className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 px-3 py-2 text-white"
                disabled={submitting || modeLocked}
              />
            </label>
            <label className="text-xs text-neutral-500">
              Engagement ID
              <input
                type="text"
                value={engagementId}
                readOnly
                className="mt-1 w-full rounded border border-neutral-800 bg-neutral-950 px-3 py-2 font-mono text-xs text-neutral-400"
              />
            </label>
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="https://example.com"
              className="rounded border border-neutral-700 bg-neutral-900 px-3 py-2 text-white"
              disabled={submitting}
            />
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="your@email.com (optional)"
              className="rounded border border-neutral-700 bg-neutral-900 px-3 py-2 text-white"
              disabled={submitting}
            />
          </div>

          <div className="mb-4">
            <ExecutionModeSelector
              value={executionMode}
              onChange={setExecutionMode}
              disabled={submitting || modeLocked}
              lockedReason={modeLockReason}
            />
          </div>

          {showQuickChrome && (
            <div className="mb-4">
              <QuickModeCard
                value={quickOptions}
                onChange={setQuickOptions}
                disabled={submitting || modeLocked}
                targetCount={1}
              />
            </div>
          )}

          {showLabChrome && (
            <div className="mb-4 space-y-3">
              <LabLeaseStatusBanner lease={labLease} manifest={labManifest} />
              <LabKillSwitchControl enabled />
            </div>
          )}

          <div className="mb-4 flex gap-2">
            <button
              onClick={() => void startScan()}
              disabled={submitting || !inputValue.startsWith("http")}
              className="rounded bg-indigo-600 px-4 py-2 text-white hover:bg-indigo-700 disabled:opacity-50"
            >
              {submitting ? "Starting..." : "Start Scan"}
            </button>
          </div>
          {startError && (
            <div className="rounded border border-red-900/50 bg-red-950/30 p-4 text-red-400">
              {startError}
            </div>
          )}
        </>
      ) : (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <h1 className="text-xl font-semibold">Scan Progress</h1>
            {showLabChrome && <LabUnrestrictedBadge />}
            {showQuickChrome && (
              <span
                className="rounded border border-cyan-700 bg-cyan-950/40 px-2 py-0.5 text-xs uppercase tracking-wide text-cyan-300"
                data-testid="quick-mode-badge"
              >
                Quick
              </span>
            )}
            {skipApproval && (
              <span className="text-xs text-neutral-500">
                Approval gates bypassed
              </span>
            )}
          </div>

          <div className="mb-4">
            <ExecutionModeSelector
              value={executionMode}
              onChange={setExecutionMode}
              disabled
              lockedReason={modeLockReason ?? "Execution mode is immutable after scan start"}
            />
          </div>

          {showQuickChrome && (
            <div className="mb-4">
              <QuickLiveStatus
                scanId={scanId}
                stage={phase}
                sseBudget={quickBudget}
                ssePlanVersion={quickPlanRevision}
                sseDegraded={quickDegraded}
                sseFindingsCount={sseFindingsCount}
              />
            </div>
          )}

          {showLabChrome && (
            <div className="mb-4 space-y-3">
              <LabLeaseStatusBanner lease={labLease} manifest={labManifest} />
              <LabKillSwitchControl enabled />
            </div>
          )}

          <div className="mb-4 rounded border border-neutral-800 bg-neutral-900 p-4">
            <div className="mb-2 flex items-center justify-between text-sm text-neutral-400">
              <span>Status</span>
              <span className="text-xs font-mono text-neutral-500">
                {scanId.slice(0, 8)}...
              </span>
            </div>

            <div className="mb-3 h-2 w-full rounded-full bg-neutral-800">
              <div
                className={`h-2 rounded-full transition-all duration-500 ${
                  status === "completed"
                    ? "bg-green-500"
                    : status === "failed" || status === "cancelled"
                      ? "bg-red-500"
                      : status === "awaiting_approval"
                        ? "bg-amber-500"
                        : "bg-indigo-500"
                }`}
                style={{ width: `${progress}%` }}
              />
            </div>

            <div className="mb-3 flex flex-wrap gap-1">
              {visiblePhases.map((p) => {
                const idx = PHASE_ORDER.indexOf(p);
                const isPast = idx <= phaseIndex;
                const isCurrent = p === phase;
                return (
                  <span
                    key={p}
                    className={`rounded px-2 py-0.5 text-xs ${
                      isCurrent
                        ? "bg-indigo-600 text-white"
                        : isPast
                          ? "bg-green-900/50 text-green-400"
                          : "bg-neutral-800 text-neutral-600"
                    }`}
                  >
                    {PHASE_LABELS[p] || p}
                  </span>
                );
              })}
            </div>

            <div className="text-sm">
              <span className="text-neutral-400">Current: </span>
              <span
                className={
                  status === "completed"
                    ? "text-green-400"
                    : status === "failed" || status === "cancelled"
                      ? "text-red-400"
                      : "text-white"
                }
              >
                {status === "completed"
                  ? "Scan Complete"
                  : status === "awaiting_approval"
                    ? "Awaiting Exploitation Approval"
                    : status === "failed"
                      ? "Scan Failed"
                      : status === "cancelled"
                        ? "Scan Cancelled"
                        : `${PHASE_LABELS[phase] || phase} (${progress}%)`}
              </span>
            </div>

            {error && !showApprovalDialog && (
              <div className="mt-2 text-sm text-amber-400">{error}</div>
            )}
            {approvalNote && (
              <div className="mt-2 text-sm text-neutral-400">{approvalNote}</div>
            )}
            {lastEvent?.message && (
              <div className="mt-2 text-xs text-neutral-500">
                {lastEvent.message}
              </div>
            )}
          </div>

          <div className="mb-4 space-y-4">
            <div className="grid gap-4 lg:grid-cols-2">
              <ScanFindingsPanel scanId={scanId} />
              <CoverageHeatmap scanId={scanId} />
            </div>
            <CoverageStatusView scanId={scanId} />
            <div>
              <label className="mb-2 block text-xs text-neutral-500">
                Baseline scan ID (for diff / retest)
                <input
                  type="text"
                  value={baselineId}
                  onChange={(e) => setBaselineId(e.target.value)}
                  placeholder="Previous scan UUID"
                  className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 px-3 py-2 font-mono text-xs text-white"
                />
              </label>
              <ScanDiffView scanId={scanId} baselineId={baselineId} />
            </div>
          </div>

          <div className="rounded border border-neutral-800 bg-neutral-950 p-4">
            <h2 className="mb-2 text-sm font-medium text-neutral-400">
              Event Log
            </h2>
            <div className="max-h-64 space-y-1 overflow-y-auto font-mono text-xs">
              {events.length === 0 && (
                <div className="text-neutral-600">Waiting for events...</div>
              )}
              {events.map((ev, i) => (
                <div key={i} className="flex gap-2">
                  <span className="w-16 shrink-0 text-neutral-600">
                    {(ev.event || "event").replace("_", " ")}
                  </span>
                  <span className="truncate text-neutral-400">
                    {ev.message || ev.phase || ""}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

interface FindingRow extends Record<string, unknown> {
  title: string;
  severity: string;
  confidence: string;
  cwe: string;
}

function ScanFindingsPanel({ scanId }: { scanId: string }) {
  const [findings, setFindings] = useState<ScanFinding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const rows = await scanApi.getFindings(scanId);
        if (!cancelled) {
          setFindings(rows);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Failed to load findings");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void load();
    const interval = setInterval(() => void load(), 10000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [scanId]);

  const rows: FindingRow[] = findings.map((finding) => ({
    title: finding.title,
    severity: finding.severity,
    confidence: finding.confidence ?? "—",
    cwe: finding.cwe ?? "—",
  }));

  return (
    <div
      className="rounded border border-neutral-800 bg-neutral-950 p-4"
      data-testid="scan-findings-panel"
    >
      <h2 className="mb-2 text-sm font-medium text-neutral-300">Findings</h2>
      <p className="mb-3 text-xs text-neutral-500">
        Shown next to coverage so untested cells are not read as safe.
      </p>
      {loading && findings.length === 0 && (
        <p className="text-xs text-neutral-600">Loading findings...</p>
      )}
      {error && <p className="text-xs text-red-400">{error}</p>}
      {!loading && !error && rows.length === 0 && (
        <p className="text-xs text-neutral-600">No findings yet.</p>
      )}
      {rows.length > 0 && (
        <DataTable<FindingRow>
          columns={[
            { key: "severity", label: "Sev" },
            { key: "title", label: "Title" },
            { key: "confidence", label: "Confidence" },
            { key: "cwe", label: "CWE" },
          ]}
          data={rows}
          emptyMessage="No findings"
        />
      )}
    </div>
  );
}
