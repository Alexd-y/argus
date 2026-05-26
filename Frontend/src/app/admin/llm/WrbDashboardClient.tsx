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
  available: "bg-emerald-400",
  unavailable: "bg-red-400",
  unconfigured: "bg-amber-400",
  unknown: "bg-zinc-500",
};

const STATUS_LABELS: Record<string, string> = {
  available: "Available",
  unavailable: "Unavailable",
  unconfigured: "Not configured",
  unknown: "Unknown",
};

const STATUS_BORDER_COLORS: Record<string, string> = {
  available: "border-l-emerald-500",
  unavailable: "border-l-red-500",
  unconfigured: "border-l-amber-500",
  unknown: "border-l-zinc-500",
};

const STATUS_BADGE: Record<string, string> = {
  available: "border border-emerald-500/30 bg-emerald-500/10 text-emerald-200",
  unavailable: "border border-red-500/30 bg-red-500/10 text-red-200",
  unconfigured: "border border-amber-500/30 bg-amber-500/10 text-amber-200",
  unknown: "border border-zinc-500/30 bg-zinc-500/10 text-zinc-300",
};

function WrbStatCard({
  label,
  value,
  sub,
  accent,
  isLoading,
}: {
  label: string;
  value: string | number;
  sub?: string;
  accent: string;
  isLoading: boolean;
}) {
  return (
    <div className={`rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-4 ${accent}`}>
      <div className="text-xs font-medium uppercase tracking-wide text-[var(--text-muted)]">{label}</div>
      {isLoading ? (
        <div className="mt-2 h-8 w-16 animate-pulse rounded bg-[var(--bg-tertiary)]" />
      ) : (
        <div className="mt-2 text-2xl font-bold text-[var(--text-primary)]">{value}</div>
      )}
      {sub ? (
        <div className="mt-1 text-xs text-[var(--text-secondary)]">
          {isLoading ? <span className="inline-block h-3 w-24 animate-pulse rounded bg-[var(--bg-tertiary)]" /> : sub}
        </div>
      ) : null}
    </div>
  );
}

type CapRow = {
  label: string;
  value: string;
  source: string;
  enhancable: boolean;
  note: string;
};

function WrbDashboardBody() {
  const [isPending, startTransition] = useTransition();
  const [dashboard, setDashboard] = useState<WrbDashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [testPrompt, setTestPrompt] = useState("");
  const [testSystemPrompt, setTestSystemPrompt] = useState("");
  const [testResult, setTestResult] = useState<WrbTestPromptResult | null>(null);
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

  const isLoading = !dashboard && !error;

  if (error && !dashboard) {
    return (
      <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-[var(--border)] bg-[var(--bg-secondary)] px-6 py-12 text-center">
        <div className="flex size-12 items-center justify-center rounded-full bg-red-500/10">
          <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="text-red-400">
            <circle cx="12" cy="12" r="10" /><path d="M15 9l-6 6M9 9l6 6" />
          </svg>
        </div>
        <h3 className="text-sm font-medium text-[var(--text-primary)]">Failed to load dashboard</h3>
        <p className="max-w-sm text-xs text-[var(--text-muted)]">{error}</p>
        <button
          type="button"
          className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-1.5 text-sm text-[var(--text-secondary)] transition-colors hover:bg-[var(--bg-tertiary)]"
          onClick={refresh}
        >
          Retry
        </button>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-3">
          <div className="h-5 w-40 animate-pulse rounded bg-[var(--bg-tertiary)]" />
        </div>
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-4">
              <div className="h-3 w-16 animate-pulse rounded bg-[var(--bg-tertiary)]" />
              <div className="mt-2 h-8 w-12 animate-pulse rounded bg-[var(--bg-tertiary)]" />
            </div>
          ))}
        </div>
      </div>
    );
  }

  const d = dashboard!;
  const st = d.status;
  const borderAccent = STATUS_BORDER_COLORS[st] ?? "border-l-zinc-500";

  const capRows: CapRow[] = [
    { label: "Base URL", value: d.base_url || "\u2014", source: "WHITERABBITNEO_URL", enhancable: true, note: "Set the WRB inference server URL. Required for all WRB operations." },
    { label: "API Key", value: d.api_key_configured ? "\u2022\u2022\u2022\u2022\u2022\u2022\u2022\u2022" : "Not set", source: "WHITERABBITNEO_API_KEY", enhancable: true, note: "API key for the WRB server. Required for authenticated inference." },
    { label: "Default Model", value: d.model || "taico-ai/WhiteRabbitNeo-v3-7B", source: "Code default", enhancable: false, note: "The primary model used for all WRB prompts. Can be overridden per-request." },
    { label: "GPU Mode", value: d.gpu_mode || "cpu", source: "WRB_GPU_MODE", enhancable: true, note: "Set to \u201cgpu\u201d to enable GPU acceleration. Significant speed improvement for inference." },
    { label: "Temperature", value: String(d.default_temperature), source: "WRB_DEFAULT_TEMPERATURE", enhancable: true, note: "Controls randomness (0.0 = deterministic, 1.0 = creative). Lower values recommended for security analysis." },
    { label: "Max Tokens", value: String(d.default_max_tokens), source: "WRB_DEFAULT_MAX_TOKENS", enhancable: true, note: "Maximum output tokens per response. Increase for longer detailed analysis reports." },
    { label: "Timeout", value: `${d.timeout_seconds}s`, source: "WHITERABBITNEO_TIMEOUT_SEC", enhancable: true, note: "Maximum wait time for inference. Increase for complex multi-step reasoning tasks." },
    { label: "Concurrency Limit", value: String(d.concurrency_limit), source: "Code default (3)", enhancable: false, note: "Max simultaneous WRB inference requests. Increase for higher throughput." },
    { label: "Max Prompt Bytes", value: d.max_prompt_bytes.toLocaleString(), source: "WRB_MAX_PROMPT_BYTES", enhancable: true, note: "Maximum input prompt size in bytes. Larger prompts allow more context for complex pentest analysis." },
    { label: "Models Available", value: String(d.models_count), source: "Runtime", enhancable: false, note: "Number of models loaded on the WRB server. Depends on server configuration." },
    { label: "Provider", value: d.provider, source: "Runtime", enhancable: false, note: "The inference provider identifier. Always \u201cwhiterabbitneo\u201d for built-in WRB." },
  ];

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-1 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h1 className="text-lg font-semibold text-[var(--text-primary)]">WhiteRabbitNeo</h1>
          <p className="mt-0.5 text-sm text-[var(--text-secondary)]">
            Built-in cybersecurity AI model. Configure, test, and tune all parameters for pentest operations.
          </p>
        </div>
        <button
          type="button"
          className="rounded border border-[var(--border)] bg-[var(--bg-secondary)] px-3 py-1.5 text-sm text-[var(--text-secondary)] transition-colors hover:bg-[var(--bg-tertiary)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none disabled:cursor-not-allowed disabled:opacity-50"
          disabled={isPending}
          onClick={refresh}
        >
          {isPending ? "Refreshing\u2026" : "Refresh"}
        </button>
      </header>

      <div className={`flex items-center gap-3 rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)] p-4 ${borderAccent} border-l-4`}>
        <span className={`inline-block size-3 rounded-full ${STATUS_COLORS[st] ?? "bg-zinc-500"}`} />
        <div className="flex-1">
          <div className="text-sm font-semibold text-[var(--text-primary)]">
            WhiteRabbitNeo — {STATUS_LABELS[st] ?? st}
          </div>
          {d.error ? (
            <div className="mt-0.5 text-xs text-red-400">{d.error}</div>
          ) : null}
        </div>
        <span className={`inline-flex items-center rounded px-2 py-0.5 text-[11px] font-medium ${STATUS_BADGE[st] ?? STATUS_BADGE.unknown}`}>
          {STATUS_LABELS[st] ?? st}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <WrbStatCard label="Status" value={STATUS_LABELS[st] ?? st} accent={borderAccent} isLoading={false} />
        <WrbStatCard label="Models" value={d.models_count} sub={d.model || undefined} accent="border-l-4 border-l-[var(--accent)]" isLoading={false} />
        <WrbStatCard label="Mode" value={d.gpu_mode || "cpu"} accent="border-l-4 border-l-[var(--accent)]" isLoading={false} />
        <WrbStatCard label="Timeout" value={`${d.timeout_seconds}s`} sub={`Concurrency: ${d.concurrency_limit}`} accent="border-l-4 border-l-[var(--accent)]" isLoading={false} />
      </div>

      <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)]">
        <div className="border-b border-[var(--border)] px-4 py-3">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">Configuration & Capabilities</h2>
          <p className="mt-0.5 text-xs text-[var(--text-muted)]">
            All available parameters. Items marked with <span className="inline-flex items-center gap-0.5 rounded bg-emerald-500/10 px-1 py-0.5 text-[10px] font-medium text-emerald-300 border border-emerald-500/30">Configurable</span> can be changed via environment variables.
          </p>
        </div>
        <div className="divide-y divide-[var(--border)]">
          {capRows.map((row) => (
            <div key={row.label} className="flex items-start justify-between px-4 py-3">
              <div className="flex flex-col gap-0.5 min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-[var(--text-primary)]">{row.label}</span>
                  {row.enhancable ? (
                    <span className="inline-flex items-center rounded bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-medium text-emerald-300 border border-emerald-500/30">
                      Configurable
                    </span>
                  ) : (
                    <span className="inline-flex items-center rounded bg-zinc-500/10 px-1.5 py-0.5 text-[10px] font-medium text-zinc-400 border border-zinc-500/30">
                      Read-only
                    </span>
                  )}
                </div>
                <p className="text-[11px] text-[var(--text-muted)]">{row.note}</p>
              </div>
              <div className="flex flex-col items-end gap-0.5 shrink-0 ml-4">
                <span className="font-mono text-sm text-[var(--text-secondary)]">{row.value}</span>
                <span className="text-[10px] text-[var(--text-muted)]">{row.source}</span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {d.api_key_configured && d.base_url ? (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 px-4 py-3 text-sm text-[var(--text-secondary)]">
          <span className="font-medium text-emerald-300">Ready for inference.</span> WRB is configured with an API key and base URL. You can send test prompts below.
        </div>
      ) : (
        <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-3 text-sm text-[var(--text-secondary)]">
          <span className="font-medium text-amber-300">Not fully configured.</span> Set <code className="rounded bg-[var(--bg-tertiary)] px-1 py-0.5 text-xs font-mono">WHITERABBITNEO_URL</code> and <code className="rounded bg-[var(--bg-tertiary)] px-1 py-0.5 text-xs font-mono">WHITERABBITNEO_API_KEY</code> environment variables to enable inference.
        </div>
      )}

      <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)]">
        <div className="border-b border-[var(--border)] px-4 py-3">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">Enhancement Guide</h2>
          <p className="mt-0.5 text-xs text-[var(--text-muted)]">
            How to improve WRB capabilities for pentest operations
          </p>
        </div>
        <div className="space-y-4 p-4">
          <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-3">
            <h3 className="text-xs font-medium text-[var(--text-primary)]">GPU Acceleration</h3>
            <p className="mt-1 text-[11px] text-[var(--text-muted)]">
              Set <code className="rounded bg-[var(--bg-tertiary)] px-1 py-0.5 text-[10px] font-mono">WRB_GPU_MODE=gpu</code> to enable GPU inference. Reduces response time from minutes to seconds. Requires NVIDIA GPU with CUDA support.
            </p>
          </div>
          <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-3">
            <h3 className="text-xs font-medium text-[var(--text-primary)]">Temperature Tuning</h3>
            <p className="mt-1 text-[11px] text-[var(--text-muted)]">
              Default <code className="rounded bg-[var(--bg-tertiary)] px-1 py-0.5 text-[10px] font-mono">0.3</code> (low randomness). For creative vulnerability exploration, try 0.5-0.7. For precise exploit analysis, keep at 0.1-0.3. Set via <code className="rounded bg-[var(--bg-tertiary)] px-1 py-0.5 text-[10px] font-mono">WRB_DEFAULT_TEMPERATURE</code>.
            </p>
          </div>
          <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-3">
            <h3 className="text-xs font-medium text-[var(--text-primary)]">Max Tokens & Prompt Size</h3>
            <p className="mt-1 text-[11px] text-[var(--text-muted)]">
              Default <code className="rounded bg-[var(--bg-tertiary)] px-1 py-0.5 text-[10px] font-mono">4096</code> tokens output, <code className="rounded bg-[var(--bg-tertiary)] px-1 py-0.5 text-[10px] font-mono">8192</code> bytes max input. Increase <code className="rounded bg-[var(--bg-tertiary)] px-1 py-0.5 text-[10px] font-mono">WRB_DEFAULT_MAX_TOKENS</code> for detailed reports, and <code className="rounded bg-[var(--bg-tertiary)] px-1 py-0.5 text-[10px] font-mono">WRB_MAX_PROMPT_BYTES</code> for longer context inputs. Test prompts are limited to 256 tokens.
            </p>
          </div>
          <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-3">
            <h3 className="text-xs font-medium text-[var(--text-primary)]">Cloud Provider Fallback</h3>
            <p className="mt-1 text-[11px] text-[var(--text-muted)]">
              WRB operates independently from cloud providers. If WRB is unavailable, the system falls back to configured cloud providers (OpenAI, DeepSeek, etc.) based on the routing priority. Configure cloud providers on the <a href="/admin/llm" className="text-[var(--accent)] hover:underline">Cloud Providers</a> tab.
            </p>
          </div>
        </div>
      </div>

      <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-secondary)]">
        <div className="border-b border-[var(--border)] px-4 py-3">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">Test Prompt</h2>
          <p className="mt-0.5 text-xs text-[var(--text-muted)]">
            Send a test prompt to WhiteRabbitNeo to verify connectivity and inference quality.
          </p>
        </div>
        <div className="space-y-3 p-4">
          <div>
            <label className="mb-1 block text-xs text-[var(--text-muted)]">
              System prompt (optional)
            </label>
            <input
              className="w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
              placeholder="You are a cybersecurity assistant specialized in penetration testing\u2026"
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
              className="w-full rounded border border-[var(--border)] bg-[var(--bg-primary)] px-2 py-1.5 text-sm text-[var(--text-primary)] placeholder:text-[var(--text-muted)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
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
              className="rounded bg-[var(--accent)] px-3 py-1.5 text-sm font-medium text-[var(--on-accent)] transition-colors hover:bg-[var(--accent-hover)] disabled:cursor-not-allowed disabled:opacity-50"
              disabled={st !== "available" || !testPrompt.trim() || testing}
              onClick={handleTest}
            >
              {testing ? "Running\u2026" : "Send test prompt"}
            </button>
            {testResult ? (
              <span className="text-xs text-[var(--text-muted)]">
                {testResult.elapsed_ms}ms &middot; {testResult.total_tokens} tokens
                ({testResult.prompt_tokens}&uarr; {testResult.completion_tokens}&darr;)
              </span>
            ) : null}
          </div>
          {testError ? (
            <div className="rounded-lg border border-red-500/30 bg-red-950/30 px-4 py-2 text-sm text-red-200" role="alert">
              {testError}
            </div>
          ) : null}
          {testResult ? (
            <div className="rounded-lg border border-[var(--border)] bg-[var(--bg-primary)] p-4">
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

export function WrbDashboardClient() {
  return (
    <AdminRouteGuard minimumRole="admin">
      <WrbDashboardBody />
    </AdminRouteGuard>
  );
}