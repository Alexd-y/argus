"use client";

import { useCallback, useEffect, useRef, useState } from "react";

const getBaseUrl = () =>
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface ScanEvent {
  event: string;
  phase?: string;
  progress?: number;
  message?: string;
  data?: Record<string, unknown>;
  error?: string;
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

function useScanSSE(scanId: string | null) {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [phase, setPhase] = useState<string>("init");
  const [progress, setProgress] = useState(0);
  const [status, setStatus] = useState<"running" | "completed" | "failed" | "awaiting_approval">("running");
  const [error, setError] = useState<string | null>(null);
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

    eventSource.addEventListener("init", (e) => {
      try {
        const data = JSON.parse(e.data);
        setEvents((prev) => [...prev, data]);
      } catch {}
    });

    eventSource.addEventListener("phase_start", (e) => {
      try {
        const data = JSON.parse(e.data);
        setPhase(data.phase || "");
        setProgress(data.progress || 0);
        setEvents((prev) => [...prev, data]);
      } catch {}
    });

    eventSource.addEventListener("phase_complete", (e) => {
      try {
        const data = JSON.parse(e.data);
        setPhase(data.phase || "");
        setProgress(data.progress || 0);
        setEvents((prev) => [...prev, data]);
      } catch {}
    });

    eventSource.addEventListener("progress", (e) => {
      try {
        const data = JSON.parse(e.data);
        setProgress(data.progress || 0);
        setEvents((prev) => [...prev, data]);
      } catch {}
    });

    eventSource.addEventListener("complete", (e) => {
      try {
        const data = JSON.parse(e.data);
        setStatus("completed");
        setProgress(100);
        setPhase("complete");
        setEvents((prev) => [...prev, data]);
        eventSource.close();
      } catch {}
    });

    eventSource.addEventListener("error", (e: MessageEvent) => {
      try {
        const data = JSON.parse(e.data);
        // "Event stream timeout" is not a real error — the scan continues, don't fail
        if (data.error === "Event stream timeout") {
          return;
        }
        if (data.code === "approval_required") {
          setStatus("awaiting_approval");
          setError("Exploitation requires approval");
          eventSource.close();
          return;
        }
        setEvents((prev) => [...prev, data]);
      } catch {}
    });

    eventSource.onerror = () => {
      eventSource.close();
      const retries = retriesRef.current;
      if (retries < 10) {
        retriesRef.current = retries + 1;
        const delay = Math.min(1000 * Math.pow(2, retries), 30000);
        reconnectRef.current = setTimeout(connect, delay);
      } else {
        setError("Lost connection to scan. The scan continues in the background.");
      }
    };

    eventSource.addEventListener("keepalive", () => {
      // Keepalive ping received — connection is alive
    });

    return () => {
      eventSource.close();
      if (reconnectRef.current) {
        clearTimeout(reconnectRef.current);
      }
    };
  }, [scanId]);

  useEffect(() => {
    const cleanup = connect();
    return () => cleanup?.();
  }, [connect]);

  return { events, phase, progress, status, error };
}

export default function ScanPage() {
  const [scanId, setScanId] = useState("");
  const [inputValue, setInputValue] = useState("https://");
  const [submitting, setSubmitting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const { events, phase, progress, status, error } = useScanSSE(scanId || null);

  const startScan = async () => {
    setSubmitting(true);
    setStartError(null);
    try {
      const baseUrl = getBaseUrl();
      const res = await fetch(`${baseUrl}/api/v1/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_url: inputValue, options: {} }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: res.statusText }));
        throw new Error((err as { detail?: string }).detail ?? "Failed to start scan");
      }
      const data = await res.json();
      setScanId(data.scan_id || data.id);
    } catch (e) {
      setStartError(e instanceof Error ? e.message : "Failed");
    } finally {
      setSubmitting(false);
    }
  };

  const phaseIndex = PHASE_ORDER.indexOf(phase);
  const lastEvent = events[events.length - 1];

  return (
    <div className="mx-auto max-w-2xl">
      {!scanId ? (
        <>
          <h1 className="mb-4 text-xl font-semibold">New Pentest Scan</h1>
          <div className="flex gap-2 mb-4">
            <input
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              placeholder="https://example.com"
              className="flex-1 rounded border border-neutral-700 bg-neutral-900 px-3 py-2 text-white"
              disabled={submitting}
            />
            <button
              onClick={startScan}
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
          <h1 className="mb-4 text-xl font-semibold">Scan Progress</h1>
          <div className="mb-4 rounded border border-neutral-800 bg-neutral-900 p-4">
            <div className="mb-2 flex items-center justify-between text-sm text-neutral-400">
              <span>Status</span>
              <span className="text-xs font-mono text-neutral-500">{scanId.slice(0, 8)}...</span>
            </div>

            {/* Progress bar */}
            <div className="mb-3 h-2 w-full rounded-full bg-neutral-800">
              <div
                className={`h-2 rounded-full transition-all duration-500 ${
                  status === "completed"
                    ? "bg-green-500"
                    : status === "failed"
                    ? "bg-red-500"
                    : status === "awaiting_approval"
                    ? "bg-amber-500"
                    : "bg-indigo-500"
                }`}
                style={{ width: `${progress}%` }}
              />
            </div>

            {/* Phase tracker */}
            <div className="mb-3 flex flex-wrap gap-1">
              {PHASE_ORDER.filter((p) => p !== "init" && p !== "complete").map((p) => {
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
              <span className={
                status === "completed" ? "text-green-400" :
                status === "failed" ? "text-red-400" :
                "text-white"
              }>
                {status === "completed" ? "Scan Complete" :
                 status === "awaiting_approval" ? "Awaiting Exploitation Approval" :
                 status === "failed" ? "Scan Failed" :
                 `${PHASE_LABELS[phase] || phase} (${progress}%)`}
              </span>
            </div>

            {error && (
              <div className="mt-2 text-sm text-amber-400">{error}</div>
            )}
            {lastEvent?.message && (
              <div className="mt-2 text-xs text-neutral-500">{lastEvent.message}</div>
            )}
          </div>

          {/* Event log */}
          <div className="rounded border border-neutral-800 bg-neutral-950 p-4">
            <h2 className="mb-2 text-sm font-medium text-neutral-400">Event Log</h2>
            <div className="max-h-64 overflow-y-auto space-y-1 font-mono text-xs">
              {events.length === 0 && (
                <div className="text-neutral-600">Waiting for events...</div>
              )}
              {events.map((ev, i) => (
                <div key={i} className="flex gap-2">
                  <span className="text-neutral-600 w-16 shrink-0">
                    {ev.event.replace("_", " ")}
                  </span>
                  <span className="text-neutral-400 truncate">
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
