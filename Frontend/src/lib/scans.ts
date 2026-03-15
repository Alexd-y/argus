/**
 * ARGUS Scans API - POST /scans, GET /scans/:id, GET /scans/:id/events (SSE).
 */

import { apiFetch, getApiBaseUrl } from "./api";
import type {
  CreateScanRequest,
  CreateScanResponse,
  ScanStatus,
  SSEEventPayload,
} from "./types";

export async function createScan(
  request: CreateScanRequest
): Promise<CreateScanResponse> {
  return apiFetch<CreateScanResponse>("/scans", {
    method: "POST",
    body: JSON.stringify(request),
  });
}

export async function getScanStatus(scanId: string): Promise<ScanStatus> {
  return apiFetch<ScanStatus>(`/scans/${encodeURIComponent(scanId)}`);
}

export type ScanEventCallback = (payload: SSEEventPayload) => void;

/**
 * Subscribe to scan events via SSE. Returns cleanup function.
 * Falls back to no-op if EventSource is unavailable.
 */
export function subscribeScanEvents(
  scanId: string,
  onEvent: ScanEventCallback,
  onError?: (err: unknown) => void
): () => void {
  const base = getApiBaseUrl();
  const url = `${base}/scans/${encodeURIComponent(scanId)}/events`;

  if (typeof EventSource === "undefined") {
    onError?.(new Error("EventSource not supported"));
    return () => {};
  }

  const es = new EventSource(url);

  es.onmessage = (e) => {
    try {
      const payload = JSON.parse(e.data) as SSEEventPayload;
      onEvent(payload);
    } catch {
      // ignore malformed events
    }
  };

  es.onerror = () => {
    es.close();
    onError?.(new Error("SSE connection failed"));
  };

  return () => es.close();
}
