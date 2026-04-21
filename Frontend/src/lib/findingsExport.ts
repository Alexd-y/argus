/**
 * Findings export — closed taxonomy of output formats, persistence helpers,
 * URL builder and a browser-side orchestrator that triggers a file download.
 *
 * Backend contract (no changes in T23):
 *   GET /api/v1/scans/{scanId}/findings/export?format=sarif|junit
 * See `backend/src/api/routers/scans.py::export_scan_findings`.
 *
 * Why two formats:
 *   - SARIF 2.1.0  → DevSecOps SAST integration (GitHub, SonarQube, Snyk, …)
 *   - JUnit XML    → CI/CD test reporting (Jenkins, GitLab, Allure, …)
 *
 * Why client-side persistence:
 *   The operator typically picks a single format that matches their pipeline.
 *   Persisting the choice in `localStorage` survives refresh and avoids
 *   surprising the next-most-used format. The key is whitelisted on read so
 *   a tampered value can never widen the surface.
 */

export const EXPORT_FORMATS = ["sarif", "junit"] as const;
export type ExportFormat = (typeof EXPORT_FORMATS)[number];

export const DEFAULT_EXPORT_FORMAT: ExportFormat = "sarif";
export const EXPORT_FORMAT_STORAGE_KEY = "argus.export.format";

const EXPORT_FORMAT_SET: ReadonlySet<string> = new Set(EXPORT_FORMATS);

export function isExportFormat(value: unknown): value is ExportFormat {
  return typeof value === "string" && EXPORT_FORMAT_SET.has(value);
}

/**
 * Whitelist parser. Returns `null` for any input outside the closed set —
 * callers MUST fall back to {@link DEFAULT_EXPORT_FORMAT} explicitly.
 */
export function parseExportFormat(
  value: string | null | undefined,
): ExportFormat | null {
  if (value == null) return null;
  const trimmed = value.trim().toLowerCase();
  if (trimmed === "") return null;
  return isExportFormat(trimmed) ? trimmed : null;
}

/**
 * Read the persisted format from `localStorage`. Falls back to SARIF when
 * the key is missing, the value is invalid, or `localStorage` is unavailable
 * (private mode, SSR pre-hydration, quota errors).
 */
export function readPersistedExportFormat(): ExportFormat {
  if (typeof window === "undefined") return DEFAULT_EXPORT_FORMAT;
  try {
    const raw = window.localStorage.getItem(EXPORT_FORMAT_STORAGE_KEY);
    return parseExportFormat(raw) ?? DEFAULT_EXPORT_FORMAT;
  } catch {
    return DEFAULT_EXPORT_FORMAT;
  }
}

/**
 * Persist the format. No-op (silent) when `localStorage` is unavailable or
 * when the value falls outside the closed set, which keeps the call site
 * compact and never throws into the React render tree.
 */
export function persistExportFormat(format: ExportFormat): void {
  if (typeof window === "undefined") return;
  if (!isExportFormat(format)) return;
  try {
    window.localStorage.setItem(EXPORT_FORMAT_STORAGE_KEY, format);
  } catch {
    // localStorage may throw QuotaExceeded or SecurityError — silently no-op.
  }
}

/**
 * Build the same-origin export URL. The browser hits the Next.js rewrite
 * (`/api/v1/* → BACKEND_URL/api/v1/*`) so no CORS is required.
 *
 * @throws when {@link scanId} is empty or {@link format} is not whitelisted.
 */
export function buildFindingsExportUrl(
  scanId: string,
  format: ExportFormat,
): string {
  if (!scanId || scanId.trim() === "") {
    throw new Error("scanId is required");
  }
  if (!isExportFormat(format)) {
    throw new Error("format must be 'sarif' or 'junit'");
  }
  const enc = encodeURIComponent(scanId);
  return `/api/v1/scans/${enc}/findings/export?format=${format}`;
}

/**
 * Suggested filename for the downloaded artefact. Keeps the extension aligned
 * with what the backend's `Content-Disposition` would set, so power users who
 * curl + redirect get the same name as the click flow.
 */
export function suggestExportFilename(
  scanId: string,
  format: ExportFormat,
): string {
  const safe = scanId.replace(/[^a-zA-Z0-9._-]/g, "-");
  return format === "sarif"
    ? `findings-${safe}.sarif`
    : `findings-${safe}.junit.xml`;
}

export type DownloadFindingsExportOptions = {
  /** Optional `X-Tenant-ID` value for multi-tenant deployments. */
  readonly tenantId?: string;
  /** Optional abort signal for cancellation. */
  readonly signal?: AbortSignal;
  /** Override fetch (for tests / instrumentation). Defaults to `globalThis.fetch`. */
  readonly fetchImpl?: typeof fetch;
};

/**
 * Browser-only: fetch the SARIF/JUnit document and trigger a file download.
 * Throws a closed-taxonomy `Error` (no internal details) on transport failure
 * so callers can surface a stack-trace-free message to the user.
 */
export async function downloadFindingsExport(
  scanId: string,
  format: ExportFormat,
  opts: DownloadFindingsExportOptions = {},
): Promise<void> {
  if (typeof window === "undefined" || typeof document === "undefined") {
    throw new Error("Findings export is only available in the browser");
  }
  const url = buildFindingsExportUrl(scanId, format);
  const headers: Record<string, string> = {};
  if (opts.tenantId && opts.tenantId.trim() !== "") {
    headers["X-Tenant-ID"] = opts.tenantId.trim();
  }

  const fetchFn = opts.fetchImpl ?? globalThis.fetch;
  const res = await fetchFn(url, {
    method: "GET",
    headers,
    signal: opts.signal,
    cache: "no-store",
  });

  if (!res.ok) {
    throw new Error(
      res.status === 404
        ? "Findings export is not available for this scan."
        : "Findings export failed.",
    );
  }

  const blob = await res.blob();
  const objectUrl = URL.createObjectURL(blob);
  try {
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = suggestExportFilename(scanId, format);
    anchor.rel = "noopener";
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
  } finally {
    URL.revokeObjectURL(objectUrl);
  }
}
