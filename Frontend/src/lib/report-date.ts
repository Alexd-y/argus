// Report dates are server-rendered, so the locale and time zone must be pinned.
// With the runtime defaults, Node formats in en-US/UTC while the browser uses
// its own resolution — Firefox reads the app locale and OS regional prefs,
// Chrome reads its UI language — and the two disagree, breaking hydration.
const REPORT_LOCALE = "en-US";
const REPORT_TIME_ZONE = "UTC";

const fullDate = new Intl.DateTimeFormat(REPORT_LOCALE, {
  month: "short",
  day: "numeric",
  year: "numeric",
  timeZone: REPORT_TIME_ZONE,
});

const dayAndMonth = new Intl.DateTimeFormat(REPORT_LOCALE, {
  month: "short",
  day: "numeric",
  timeZone: REPORT_TIME_ZONE,
});

export function formatReportDate(iso: string | null, fallback = "Pending"): string {
  if (!iso) return fallback;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return fallback;
  return fullDate.format(date);
}

export function formatReportDayAndMonth(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return dayAndMonth.format(date);
}
