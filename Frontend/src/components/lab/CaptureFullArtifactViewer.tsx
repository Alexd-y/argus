"use client";

import { useEffect, useState } from "react";

import { labApi } from "@/lib/lab/labApi";
import type { LabExecutionRecord } from "@/lib/lab/types";

interface CaptureFullArtifactViewerProps {
  executionId: string;
  execution?: LabExecutionRecord;
}

function downloadText(filename: string, body: string) {
  const blob = new Blob([body], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function CaptureFullArtifactViewer({
  executionId,
  execution,
}: CaptureFullArtifactViewerProps) {
  const [row, setRow] = useState<LabExecutionRecord | null>(execution ?? null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (execution) {
      setRow(execution);
      return;
    }
    if (!executionId.trim()) {
      setRow(null);
      return;
    }
    let cancelled = false;
    void labApi
      .getLabExecution(executionId.trim())
      .then((payload) => {
        if (!cancelled) setRow(payload);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "execution_failed");
      });
    return () => {
      cancelled = true;
    };
  }, [executionId, execution]);

  if (error) {
    return (
      <p className="text-xs text-red-400" data-testid="artifact-viewer-error">
        {error}
      </p>
    );
  }
  if (!executionId.trim()) {
    return (
      <p className="text-xs text-neutral-600" data-testid="artifact-viewer-empty">
        Enter a lab execution id
      </p>
    );
  }
  if (!row) {
    return <p className="text-xs text-neutral-500">Loading artifact…</p>;
  }
  if (!row.capture_full) {
    return (
      <div
        className="rounded border border-neutral-800 bg-neutral-950 p-3 text-xs text-neutral-400"
        data-testid="artifact-viewer-redacted"
      >
        Raw stdout/stderr are redacted because capture_full is false.
      </div>
    );
  }

  const bundle = [
    `execution_id=${row.execution_id}`,
    `status=${row.status}`,
    `return_code=${row.return_code}`,
    `runner=${row.runner}`,
    `argv=${row.argv.join(" ")}`,
    "--- stdout ---",
    row.stdout,
    "--- stderr ---",
    row.stderr,
  ].join("\n");

  return (
    <div className="space-y-2" data-testid="artifact-viewer">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-white">Raw artifact (capture_full)</h3>
        <button
          type="button"
          className="rounded border border-neutral-600 px-2 py-0.5 text-xs text-neutral-200"
          data-testid="artifact-viewer-download"
          onClick={() => downloadText(`${row.execution_id}.txt`, bundle)}
        >
          Download
        </button>
      </div>
      <pre className="max-h-80 overflow-auto rounded border border-neutral-800 bg-neutral-950 p-3 font-mono text-xs text-neutral-200 whitespace-pre-wrap">
        {bundle}
      </pre>
    </div>
  );
}
