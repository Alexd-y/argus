"use client";

import { useCallback, useState } from "react";

import { adminApi } from "@/lib/api";

const STOP_PHRASE = "STOP ALL SCANS";

interface LabKillSwitchControlProps {
  enabled: boolean;
}

/** Global kill switch — uses existing admin emergency API. Disabled in production mode. */
export function LabKillSwitchControl({ enabled }: LabKillSwitchControlProps) {
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const trip = useCallback(async () => {
    if (!enabled) return;
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const result = await adminApi.emergency.stopAll({
        reason: "LAB operator kill switch from scan UI",
        confirmation_phrase: STOP_PHRASE,
      });
      setMessage(`Kill switch active. Cancelled ${result.cancelled_count} scans.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "kill_switch_failed");
    } finally {
      setBusy(false);
    }
  }, [enabled]);

  return (
    <div
      className="rounded border border-red-900/40 bg-red-950/20 p-3"
      data-testid="lab-kill-switch"
    >
      <div className="mb-2 flex items-center justify-between gap-2">
        <p className="text-xs font-medium text-red-200">Global kill switch</p>
        <button
          type="button"
          data-testid="lab-kill-switch-button"
          disabled={!enabled || busy}
          onClick={() => void trip()}
          className="rounded bg-red-700 px-3 py-1 text-xs text-white hover:bg-red-600 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {busy ? "Stopping…" : "STOP ALL SCANS"}
        </button>
      </div>
      {!enabled && (
        <p className="text-xs text-neutral-500" data-testid="lab-kill-switch-disabled">
          Available only in LAB UNRESTRICTED mode.
        </p>
      )}
      {message && <p className="text-xs text-red-200">{message}</p>}
      {error && <p className="text-xs text-red-400">{error}</p>}
    </div>
  );
}
