"use client";

import { useCallback, useEffect, useState, useTransition } from "react";

import { AdminRouteGuard } from "@/components/admin/AdminRouteGuard";
import {
  getWrbDashboard,
  wrbTestPrompt,
  type WrbDashboardData,
  type WrbTestPromptResult,
} from "./wrbActions";

const STATUS_COLORS: Record<string, string> = {
  available: "bg-emerald-500",
  unavailable: "bg-red-500",
  unconfigured: "bg-yellow-500",
  unknown: "bg-gray-500",
};

const STATUS_LABELS: Record<string, string> = {
  available: "Available",
  unavailable: "Unavailable",
  unconfigured: "Not configured",
  unknown: "Unknown",
};

function StatusDot({ status }: { status: string }) {
  const color = STATUS_COLORS[status] ?? "bg-gray-500";
  return <span className={`inline-block h-2.5 w-2.5 rounded-full ${color}`} />;
}

function StatCard({
  label,
  value,
  sub,
}: {
  label: string;
  value: string | number;
  sub?: string;
}) {
  return (
    <div className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-3">
      <div className="text-xs text-[var(--text-muted)] uppercase tracking-wider">
        {label}
      </div>
      <div className="mt-1 text-lg font-semibold text-[var(--text-primary)]">
        {value}
      </div>
      {sub ? (
        <div className="text-xs text-[var(--text-muted)]">{sub}</div>
      ) : null}
    </div>
  );
}

function WrbDashboardBody() {
  const [isPending, startTransition] = useTransition();
  const [dashboard, setDashboard] = useState<WrbDashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [testPrompt, setTestPrompt] = useState("");
  const [testSystemPrompt, setTestSystemPrompt] = useState("");
  const [testResult, setTestResult] = useState<WrbTestPromptResult | null>(
    null,
  );
  const [testError, setTestError] = useState<string | null>(null);
  const [testing, setTesting] = useState(false);

  const refresh = useCallback(() => {
    startTransition(async () => {
      try {
        setDashboard(await getWrbDashboard());
        setError(null);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Failed to load dashboard");
      }
    });
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleTest = () => {
    if (!testPrompt.trim()) return;
    setTestError(null);
    setTestResult(null);
    setTesting(true);
    startTransition(async () => {
      try {
        setTestResult(await wrbTestPrompt(testPrompt, testSystemPrompt || undefined));
      } catch (e) {
        setTestError(e instanceof Error ? e.message : "Test prompt failed");
      } finally {
        setTesting(false);
      }
    });
  };

  if (error && !dashboard) {
    return (
      <div className="rounded border border-red-900/40 bg-red-950/20 px-3 py-2 text-sm text-red-200">
        {error}
      </div>
    );
  }

  if (!dashboard) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[var(--border)] border-t-[var(--accent)]" />
      </div>
    );
  }

  const st = dashboard.status;

  return (
    <div className="space-y-6">
      {/* Health status banner */}
      <div className="flex items-center gap-3 rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-4 py-3">
        <StatusDot status={st} />
        <div>
          <div className="text-sm font-semibold text-[var(--text-primary)]">
            WhiteRabbitNeo — {STATUS_LABELS[st] ?? st}
          </div>
          {dashboard.error ? (
            <div className="text-xs text-red-400">{dashboard.error}</div>
          ) : null}
        </div>
        <div className="ml-auto">
          <button
            type="button"
            className="rounded border border-[var(--border)] px-2 py-1 text-xs text-[var(--text-secondary)] hover:bg-[var(--bg-tertiary)] disabled:opacity-50"
            disabled={isPending}
            onClick={refresh}
          >
            Refresh
          </button>
        </div>
      </div>

      {/* Metrics grid */}
      <div className="grid gap-3 sm:grid-cols-2 md:grid-cols-4">
        <StatCard label="Status" value={STATUS_LABELS[st] ?? st} />
        <StatCard
          label="Models loaded"
          value={dashboard.models_count}
          sub={dashboard.model || undefined}
        />
        <StatCard label="Mode" value={dashboard.gpu_mode || "cpu"} />
        <StatCard
          label="Timeout"
          value={`${dashboard.timeout_seconds}s`}
          sub={`Concurrency limit: ${dashboard.concurrency_limit}`}
        />
      </div>

      {/* Configuration table */}
      <div>
        <h2 className="mb-2 text-sm font-semibold text-[var(--text-primary)]">
          Configuration
        </h2>
        <div className="overflow-x-auto rounded border border-[var(--border)]">
          <table className="w-full border-collapse text-left text-sm">
            <thead className="border-b border-[var(--border)] bg-[var(--bg-secondary)] text-xs text-[var(--text-muted)]">
              <tr>
                <th className="px-3 py-2 font-medium">Parameter</th>
                <th className="px-3 py-2 font-medium">Value</th>
                <th className="px-3 py-2 font-medium">Source</th>
              </tr>
            </thead>
            <tbody>
              <ConfigRow
                label="Base URL"
                value={dashboard.base_url || "—"}
                source="WHITERABBITNEO_URL"
              />
              <ConfigRow
                label="API Key"
                value={dashboard.api_key_configured ? "••••••••" : "Not set"}
                source="WHITERABBITNEO_API_KEY"
              />
              <ConfigRow
                label="Default Model"
                value="taico-ai/WhiteRabbitNeo-v3-7B"
                source="Code default"
              />
              <ConfigRow
                label="Temperature"
                value={String(dashboard.default_temperature)}
                source="Code default"
              />
              <ConfigRow
                label="Max Tokens"
                value={String(dashboard.default_max_tokens)}
                source="Code default"
              />
              <ConfigRow
                label="Max Prompt Bytes"
                value={dashboard.max_prompt_bytes.toLocaleString()}
                source="WRB_MAX_PROMPT_BYTES"
              />
              <ConfigRow
                label="GPU Mode"
                value={dashboard.gpu_mode || "cpu"}
                source="WRB_GPU_MODE"
              />
            </tbody>
          </table>
        </div>
        <p className="mt-2 text-xs text-[var(--text-muted)]">
          Configuration is read-only. Changes require updating environment variables
          and restarting the container.
        </p>
      </div>

      {/* Test prompt */}
      <div>
        <h2 className="mb-2 text-sm font-semibold text-[var(--text-primary)]">
          Test Prompt
        </h2>
        <div className="space-y-3 rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
          <div>
            <label className="mb-1 block text-xs text-[var(--text-muted)]">
              System prompt (optional)
            </label>
            <input
              className="w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
              placeholder="You are a cybersecurity assistant…"
              value={testSystemPrompt}
              onChange={(e) => setTestSystemPrompt(e.target.value)}
              disabled={st !== "available" || testing}
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-[var(--text-muted)]">
              Prompt
            </label>
            <textarea
              className="w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)]"
              rows={3}
              placeholder="What are common XSS vectors in web applications?"
              value={testPrompt}
              onChange={(e) => setTestPrompt(e.target.value)}
              disabled={st !== "available" || testing}
            />
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              className="rounded bg-[var(--accent-strong)] px-3 py-1.5 text-sm font-medium text-[var(--on-accent)] disabled:opacity-50"
              disabled={st !== "available" || !testPrompt.trim() || testing}
              onClick={handleTest}
            >
              {testing ? "Running…" : "Send test prompt"}
            </button>
            {testResult ? (
              <span className="text-xs text-[var(--text-muted)]">
                {testResult.elapsed_ms}ms · {testResult.total_tokens} tokens
                ({testResult.prompt_tokens}↑ {testResult.completion_tokens}↓)
              </span>
            ) : null}
          </div>
          {testError ? (
            <div className="rounded border border-red-900/40 bg-red-950/20 px-3 py-2 text-sm text-red-200">
              {testError}
            </div>
          ) : null}
          {testResult ? (
            <div className="rounded border border-[var(--border)] bg-[var(--bg-primary)] p-3">
              <div className="mb-1 text-xs text-[var(--text-muted)]">Response</div>
              <pre className="whitespace-pre-wrap text-sm text-[var(--text-primary)]">
                {testResult.response}
              </pre>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}

function ConfigRow({
  label,
  value,
  source,
}: {
  label: string;
  value: string;
  source: string;
}) {
  return (
    <tr className="border-b border-[var(--border)]">
      <td className="px-3 py-2 font-medium text-[var(--text-primary)]">{label}</td>
      <td className="px-3 py-2 font-mono text-xs text-[var(--text-secondary)]">
        {value}
      </td>
      <td className="px-3 py-2 text-xs text-[var(--text-muted)]">{source}</td>
    </tr>
  );
}

export function WrbDashboardClient() {
  return (
    <AdminRouteGuard minimumRole="admin">
      <WrbDashboardBody />
    </AdminRouteGuard>
  );
}