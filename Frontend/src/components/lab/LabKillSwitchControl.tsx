"use client";

import { useState } from "react";

import { GlobalKillSwitchDialog } from "@/components/admin/operations/GlobalKillSwitchDialog";

interface LabKillSwitchControlProps {
  enabled: boolean;
}

/** Global kill switch — real emergency stop dialog, LAB-only on this surface. */
export function LabKillSwitchControl({ enabled }: LabKillSwitchControlProps) {
  const [open, setOpen] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

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
          disabled={!enabled}
          onClick={() => setOpen(true)}
          className="rounded bg-red-700 px-3 py-1 text-xs text-white hover:bg-red-600 disabled:cursor-not-allowed disabled:opacity-40"
        >
          STOP ALL SCANS
        </button>
      </div>
      {!enabled ? (
        <p className="text-xs text-neutral-500" data-testid="lab-kill-switch-disabled">
          Available only in LAB UNRESTRICTED mode.
        </p>
      ) : null}
      {message ? (
        <p className="text-xs text-red-200" data-testid="lab-kill-switch-result">
          {message}
        </p>
      ) : null}
      <GlobalKillSwitchDialog
        open={open && enabled}
        onOpenChange={setOpen}
        onSuccess={(result) => {
          setMessage(`Kill switch active. Cancelled ${result.cancelled_count} scans.`);
          setOpen(false);
        }}
      />
    </div>
  );
}
