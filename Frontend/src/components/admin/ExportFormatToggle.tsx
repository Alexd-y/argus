"use client";

/**
 * `ExportFormatToggle` — accessible SARIF/JUnit format picker + download
 * trigger for the admin findings export flow (T23, ARGUS Cycle 6 Batch 3).
 *
 * Why not shadcn-Tabs / RadioGroup: the project ships no design-system deps;
 * we use native `<input type="radio">` so screen readers and keyboard users
 * get arrow-key navigation, focus management and `aria-checked` for free.
 *
 * Strings are in Russian to match the surrounding admin UI; if/when an i18n
 * layer lands, lift them into the dictionary file unchanged.
 */

import { useCallback, useEffect, useId, useState } from "react";

import {
  DEFAULT_EXPORT_FORMAT,
  EXPORT_FORMATS,
  type ExportFormat,
  persistExportFormat,
  readPersistedExportFormat,
} from "@/lib/findingsExport";

type FormatPresentation = {
  readonly label: string;
  readonly aria: string;
  readonly tooltip: string;
};

const FORMAT_PRESENTATION: Readonly<Record<ExportFormat, FormatPresentation>> = {
  sarif: {
    label: "SARIF",
    aria: "Скачать как SARIF",
    tooltip:
      "Static Analysis Results Interchange Format \u2014 \u0434\u043b\u044f DevSecOps \u0438\u043d\u0442\u0435\u0433\u0440\u0430\u0446\u0438\u0438 (GitHub, SonarQube, Snyk).",
  },
  junit: {
    label: "JUnit XML",
    aria: "Скачать как JUnit XML",
    tooltip:
      "JUnit-\u0441\u043e\u0432\u043c\u0435\u0441\u0442\u0438\u043c\u044b\u0439 \u043e\u0442\u0447\u0451\u0442 \u2014 \u0434\u043b\u044f CI/CD \u0438 Allure-\u0440\u0435\u043f\u043e\u0440\u0442\u043e\u0432.",
  },
};

export type ExportFormatToggleProps = {
  /** Scan id whose findings will be exported (used for the disabled state). */
  readonly scanId: string;
  /**
   * Called with the currently selected format when the user clicks Download.
   * Should `await` the underlying transport so the busy state is honoured.
   */
  readonly onDownload: (format: ExportFormat) => void | Promise<void>;
  /** Override the initial format (mostly for tests / Storybook). */
  readonly defaultFormat?: ExportFormat;
  /** Optional callback fired when the operator picks a different format. */
  readonly onFormatChange?: (format: ExportFormat) => void;
  /** Disable the download button externally (e.g. while the panel is loading). */
  readonly disabled?: boolean;
  readonly className?: string;
};

export function ExportFormatToggle({
  scanId,
  onDownload,
  defaultFormat,
  onFormatChange,
  disabled = false,
  className,
}: ExportFormatToggleProps): React.ReactElement {
  const groupId = useId();
  const radioName = `${groupId}-format`;

  const [format, setFormat] = useState<ExportFormat>(
    defaultFormat ?? DEFAULT_EXPORT_FORMAT,
  );
  const [hydrated, setHydrated] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Read the persisted preference *after* mount to avoid a hydration mismatch
  // (server render has no `localStorage`). When `defaultFormat` is supplied
  // (test / story) we still respect it on first paint and only sync from
  // storage if the operator never explicitly overrode it via prop.
  useEffect(() => {
    if (defaultFormat !== undefined) {
      setHydrated(true);
      return;
    }
    setFormat(readPersistedExportFormat());
    setHydrated(true);
  }, [defaultFormat]);

  const handleSelect = useCallback(
    (next: ExportFormat) => {
      setFormat(next);
      persistExportFormat(next);
      onFormatChange?.(next);
    },
    [onFormatChange],
  );

  const handleDownload = useCallback(async () => {
    if (busy) return;
    if (!scanId || scanId.trim() === "") return;
    setError(null);
    setBusy(true);
    try {
      await onDownload(format);
    } catch {
      // Closed-taxonomy message; never leak the underlying error string.
      setError("\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0441\u043a\u0430\u0447\u0430\u0442\u044c \u044d\u043a\u0441\u043f\u043e\u0440\u0442. \u041f\u043e\u043f\u0440\u043e\u0431\u0443\u0439\u0442\u0435 \u0435\u0449\u0451 \u0440\u0430\u0437.");
    } finally {
      setBusy(false);
    }
  }, [busy, format, onDownload, scanId]);

  const downloadDisabled =
    disabled || busy || !hydrated || !scanId || scanId.trim() === "";

  return (
    <fieldset
      data-testid="export-format-toggle"
      data-format={format}
      className={[
        "rounded border border-[var(--border)] bg-[var(--bg-secondary)] p-3 text-sm",
        className ?? "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      <legend className="px-1 text-xs font-medium uppercase tracking-wider text-[var(--text-muted)]">
        Findings export
      </legend>

      <div
        role="radiogroup"
        aria-label="Формат экспорта findings"
        className="mt-1 flex flex-col gap-2"
      >
        {EXPORT_FORMATS.map((value) => {
          const presentation = FORMAT_PRESENTATION[value];
          const radioId = `${groupId}-${value}`;
          const tipId = `${groupId}-${value}-tip`;
          const checked = format === value;
          return (
            <div key={value} className="flex flex-col gap-0.5">
              <label
                htmlFor={radioId}
                className="inline-flex cursor-pointer items-center gap-2 text-[var(--text-primary)]"
              >
                <input
                  id={radioId}
                  type="radio"
                  name={radioName}
                  value={value}
                  checked={checked}
                  aria-checked={checked}
                  aria-describedby={tipId}
                  onChange={() => handleSelect(value)}
                  data-testid={`export-format-${value}`}
                  className="h-4 w-4 cursor-pointer accent-[var(--accent)] focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
                />
                <span className="font-medium">{presentation.label}</span>
              </label>
              <p
                id={tipId}
                className="ml-6 text-xs text-[var(--text-muted)]"
                data-testid={`export-format-${value}-tip`}
              >
                {presentation.tooltip}
              </p>
            </div>
          );
        })}
      </div>

      <div className="mt-3 flex items-center justify-between gap-2">
        <button
          type="button"
          onClick={handleDownload}
          disabled={downloadDisabled}
          aria-label={FORMAT_PRESENTATION[format].aria}
          data-testid="export-format-download"
          className="rounded bg-[var(--accent)] px-3 py-1.5 text-sm font-medium text-[var(--bg-primary)] transition hover:opacity-90 disabled:opacity-50 focus-visible:ring-2 focus-visible:ring-[var(--accent)] focus-visible:outline-none"
        >
          {busy ? "Скачивание…" : `Скачать ${FORMAT_PRESENTATION[format].label}`}
        </button>
        {error ? (
          <span
            role="alert"
            className="text-xs text-red-500"
            data-testid="export-format-error"
          >
            {error}
          </span>
        ) : null}
      </div>
    </fieldset>
  );
}

export default ExportFormatToggle;
