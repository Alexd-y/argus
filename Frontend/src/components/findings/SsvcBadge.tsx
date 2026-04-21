"use client";

/**
 * ARG-044 — CISA SSVC v2.1 outcome badge.
 *
 * Renders one of the four SSVC stakeholder-specific decisions
 * (`Act` / `Attend` / `Track*` / `Track`) as a colour-coded chip with
 * a hover tooltip that explains the operational meaning. Designed to
 * sit inline next to a finding title in the report / dashboard tables.
 *
 * The component is **purely presentational**: no data fetching, no
 * state. SSVC is computed server-side by the FindingPrioritizer
 * pipeline and shipped to the frontend through the `Finding.ssvc_decision`
 * field of the API contract.
 */

import * as React from "react";

export type SsvcDecision = "Act" | "Attend" | "Track*" | "Track";

const DECISIONS: ReadonlyArray<SsvcDecision> = ["Act", "Attend", "Track*", "Track"] as const;

export function isSsvcDecision(value: unknown): value is SsvcDecision {
  return typeof value === "string" && (DECISIONS as readonly string[]).includes(value);
}

interface SsvcStyle {
  readonly bg: string;
  readonly text: string;
  readonly border: string;
  readonly tooltip: string;
}

const SSVC_STYLES: Readonly<Record<SsvcDecision, SsvcStyle>> = {
  Act: {
    bg: "bg-red-600",
    text: "text-white",
    border: "border-red-400",
    tooltip:
      "Act — Highest priority. Active exploitation or imminent threat with significant impact. Mobilise immediately, even outside change windows.",
  },
  Attend: {
    bg: "bg-orange-600",
    text: "text-white",
    border: "border-orange-400",
    tooltip:
      "Attend — Senior leadership should be notified. Schedule remediation within the next change window.",
  },
  "Track*": {
    bg: "bg-blue-700",
    text: "text-white",
    border: "border-blue-500",
    tooltip:
      "Track* — Track and reassess; warrants closer monitoring than baseline (mission-impact context elevates priority).",
  },
  Track: {
    bg: "bg-slate-600",
    text: "text-slate-100",
    border: "border-slate-400",
    tooltip:
      "Track — Routine handling. Manage via the normal vulnerability management cadence.",
  },
};

const FALLBACK_STYLE: SsvcStyle = {
  bg: "bg-neutral-700",
  text: "text-neutral-200",
  border: "border-neutral-500",
  tooltip: "SSVC decision not available for this finding.",
};

export interface SsvcBadgeProps {
  /** SSVC v2.1 decision string. Unknown values render an "—" placeholder. */
  readonly decision: SsvcDecision | string | null | undefined;
  /** Optional aria-label override for callers that need extra context. */
  readonly ariaLabel?: string;
  /** Tailwind classes appended to the chip wrapper. */
  readonly className?: string;
  /** Optional `data-testid` (defaults to `"ssvc-badge"`). */
  readonly testId?: string;
}

/**
 * Render a colour-coded SSVC badge with hover tooltip.
 *
 * Accessibility
 * -------------
 * The chip exposes ``role="status"`` plus an ``aria-label`` that
 * combines the decision string and the tooltip text — screen readers
 * therefore receive the same operational meaning sighted users get
 * from the visual tooltip.
 */
export function SsvcBadge(props: SsvcBadgeProps): React.ReactElement {
  const { decision, ariaLabel, className, testId = "ssvc-badge" } = props;

  if (decision === null || decision === undefined || decision === "") {
    return (
      <span
        data-testid={testId}
        data-decision=""
        role="status"
        aria-label={ariaLabel ?? "SSVC decision not available"}
        title={FALLBACK_STYLE.tooltip}
        className={[
          "inline-flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border",
          FALLBACK_STYLE.bg,
          FALLBACK_STYLE.text,
          FALLBACK_STYLE.border,
          className ?? "",
        ]
          .filter(Boolean)
          .join(" ")}
      >
        —
      </span>
    );
  }

  const known = isSsvcDecision(decision) ? (decision as SsvcDecision) : null;
  const style = known ? SSVC_STYLES[known] : FALLBACK_STYLE;
  const label = known ?? String(decision);

  return (
    <span
      data-testid={testId}
      data-decision={label}
      role="status"
      aria-label={ariaLabel ?? `SSVC: ${label}. ${style.tooltip}`}
      title={style.tooltip}
      className={[
        "inline-flex items-center gap-1 rounded px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border",
        style.bg,
        style.text,
        style.border,
        className ?? "",
      ]
        .filter(Boolean)
        .join(" ")}
    >
      {label}
    </span>
  );
}

export const SSVC_DECISIONS: ReadonlyArray<SsvcDecision> = DECISIONS;

export default SsvcBadge;
