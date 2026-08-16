import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { FindingOccurrence } from "@/lib/lab/types";

import { OccurrenceTimeline } from "./OccurrenceTimeline";

const KEY_A = "a".repeat(64);
const KEY_B = "b".repeat(64);

const occurrences: FindingOccurrence[] = [
  {
    occurrence_key: KEY_A,
    finding_key: KEY_B,
    tenant_id: "t-1",
    scan_id: "scan-1",
    scanner: "nuclei",
    detector_id: "xss-reflected",
    detector_version: "1.0.0",
    evidence_refs: ["ev-1"],
    first_seen_at: "2026-08-16T10:00:00.000Z",
    last_seen_at: "2026-08-16T11:00:00.000Z",
  },
];

describe("OccurrenceTimeline", () => {
  it("renders injected occurrences without fetching", () => {
    render(<OccurrenceTimeline scanId="scan-1" occurrences={occurrences} />);
    expect(screen.getByTestId("occurrence-timeline")).toHaveTextContent(
      "xss-reflected",
    );
    expect(screen.getByRole("button", { name: "Retest" })).toBeInTheDocument();
  });
});
