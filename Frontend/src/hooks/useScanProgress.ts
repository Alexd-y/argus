"use client";

import { useCallback, useRef, useState } from "react";
import {
  createScan,
  getScanStatus,
  subscribeScanEvents,
} from "@/lib/scans";
import { getSafeErrorMessage } from "@/lib/api";
import type { CreateScanRequest, SSEEventPayload } from "@/lib/types";

const POLL_INTERVAL_MS = 3000;

export interface ScanProgressState {
  progress: number;
  phase: string;
  status: "idle" | "starting" | "running" | "complete" | "error";
  error: string | null;
}

export function useScanProgress() {
  const [state, setState] = useState<ScanProgressState>({
    progress: 0,
    phase: "",
    status: "idle",
    error: null,
  });

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const unsubscribeRef = useRef<(() => void) | null>(null);

  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    unsubscribeRef.current?.();
    unsubscribeRef.current = null;
  }, []);

  const startScan = useCallback(
    async (request: CreateScanRequest) => {
      setState({ progress: 0, phase: "", status: "starting", error: null });
      stopPolling();

      try {
        const res = await createScan(request);
        const scanId = res.scan_id;

        setState((s) => ({ ...s, status: "running", phase: "Initializing" }));

        const startPolling = () => {
          if (pollRef.current) return;
          pollRef.current = setInterval(async () => {
            try {
              const status = await getScanStatus(scanId);
              setState((s) => ({
                ...s,
                progress: status.progress,
                phase: status.phase,
                status: status.status === "completed" ? "complete" : "running",
              }));
              if (status.status === "completed" || status.status === "failed") {
                stopPolling();
                if (status.status === "failed") {
                  setState((s) => ({ ...s, status: "error", error: "Scan failed" }));
                }
              }
            } catch {
              // keep polling on transient errors
            }
          }, POLL_INTERVAL_MS);
        };

        const cleanup = subscribeScanEvents(
          scanId,
          (payload: SSEEventPayload) => {
            setState((s) => {
              const next = { ...s };
              if (payload.progress !== undefined) next.progress = payload.progress;
              if (payload.phase) next.phase = payload.phase;
              if (payload.message) next.phase = payload.message;
              if (payload.event === "complete") {
                next.status = "complete";
                next.progress = 100;
              }
              if (payload.event === "error") {
                next.status = "error";
                next.error = getSafeErrorMessage(
                  (payload as { error?: string }).error ?? "Scan failed",
                  "Scan failed"
                );
              }
              return next;
            });
          },
          () => {
            startPolling();
          }
        );

        unsubscribeRef.current = cleanup;
      } catch (err) {
        setState({
          progress: 0,
          phase: "",
          status: "error",
          error: getSafeErrorMessage(err, "Failed to start scan"),
        });
      }
    },
    [stopPolling]
  );

  const reset = useCallback(() => {
    stopPolling();
    setState({ progress: 0, phase: "", status: "idle", error: null });
  }, [stopPolling]);

  return { state, startScan, reset, stopPolling };
}
