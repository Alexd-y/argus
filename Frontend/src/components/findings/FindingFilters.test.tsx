import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import {
  applyFindingFilters,
  EMPTY_FINDING_FILTERS,
  FindingFilters,
  FINDING_SEVERITIES,
  type FindingFiltersValue,
  type FindingSeverity,
} from "./FindingFilters";
import { SSVC_DECISIONS, type SsvcDecision } from "./SsvcBadge";

interface FindingRow {
  readonly id: string;
  readonly severity: FindingSeverity;
  readonly ssvc_decision: SsvcDecision | null;
  readonly kev_listed: boolean;
  readonly title: string;
  readonly description?: string;
  readonly cwe?: string;
}

const SAMPLE: ReadonlyArray<FindingRow> = [
  {
    id: "f1",
    severity: "critical",
    ssvc_decision: "Act",
    kev_listed: true,
    title: "Remote Code Execution in foo",
    cwe: "CWE-78",
  },
  {
    id: "f2",
    severity: "high",
    ssvc_decision: "Attend",
    kev_listed: false,
    title: "SQL Injection in bar",
    cwe: "CWE-89",
  },
  {
    id: "f3",
    severity: "medium",
    ssvc_decision: "Track*",
    kev_listed: false,
    title: "XSS in admin panel",
    cwe: "CWE-79",
  },
  {
    id: "f4",
    severity: "low",
    ssvc_decision: "Track",
    kev_listed: false,
    title: "Verbose error pages",
    cwe: "CWE-209",
  },
  {
    id: "f5",
    severity: "info",
    ssvc_decision: null,
    kev_listed: false,
    title: "Deprecated TLS cipher offered",
    cwe: "CWE-326",
  },
];

describe("FindingFilters - presentation", () => {
  it("renders one button per severity and one per SSVC outcome", () => {
    const onChange = vi.fn();
    render(<FindingFilters value={EMPTY_FINDING_FILTERS} onChange={onChange} />);

    for (const sev of FINDING_SEVERITIES) {
      expect(screen.getByTestId(`severity-${sev}`)).toBeInTheDocument();
    }
    for (const decision of SSVC_DECISIONS) {
      expect(screen.getByTestId(`ssvc-${decision}`)).toBeInTheDocument();
    }
    expect(screen.getByTestId("finding-filters-kev-only")).toBeInTheDocument();
  });

  it("marks the active severity with aria-pressed=true", () => {
    const value: FindingFiltersValue = {
      ...EMPTY_FINDING_FILTERS,
      severities: new Set<FindingSeverity>(["critical"]),
    };
    render(<FindingFilters value={value} onChange={() => undefined} />);
    expect(screen.getByTestId("severity-critical")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByTestId("severity-high")).toHaveAttribute("aria-pressed", "false");
  });

  it("marks the active SSVC outcome with aria-pressed=true", () => {
    const value: FindingFiltersValue = {
      ...EMPTY_FINDING_FILTERS,
      ssvcOutcomes: new Set<SsvcDecision>(["Act"]),
    };
    render(<FindingFilters value={value} onChange={() => undefined} />);
    expect(screen.getByTestId("ssvc-Act")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByTestId("ssvc-Track")).toHaveAttribute("aria-pressed", "false");
  });
});

describe("FindingFilters - interactions", () => {
  it("toggles severity selection on click", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<FindingFilters value={EMPTY_FINDING_FILTERS} onChange={onChange} />);
    await user.click(screen.getByTestId("severity-critical"));
    expect(onChange).toHaveBeenCalledOnce();
    const next = onChange.mock.calls[0][0] as FindingFiltersValue;
    expect(next.severities.has("critical")).toBe(true);
  });

  it("toggles SSVC outcome selection on click", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<FindingFilters value={EMPTY_FINDING_FILTERS} onChange={onChange} />);
    await user.click(screen.getByTestId("ssvc-Attend"));
    expect(onChange).toHaveBeenCalledOnce();
    const next = onChange.mock.calls[0][0] as FindingFiltersValue;
    expect(next.ssvcOutcomes.has("Attend")).toBe(true);
  });

  it("toggles SSVC outcome OFF when already selected", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    const value: FindingFiltersValue = {
      ...EMPTY_FINDING_FILTERS,
      ssvcOutcomes: new Set<SsvcDecision>(["Act", "Attend"]),
    };
    render(<FindingFilters value={value} onChange={onChange} />);
    await user.click(screen.getByTestId("ssvc-Act"));
    const next = onChange.mock.calls[0][0] as FindingFiltersValue;
    expect(next.ssvcOutcomes.has("Act")).toBe(false);
    expect(next.ssvcOutcomes.has("Attend")).toBe(true);
  });

  it("toggles KEV-only flag", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<FindingFilters value={EMPTY_FINDING_FILTERS} onChange={onChange} />);
    await user.click(screen.getByTestId("finding-filters-kev-only"));
    const next = onChange.mock.calls[0][0] as FindingFiltersValue;
    expect(next.kevOnly).toBe(true);
  });

  it("emits a fresh empty filter when reset is clicked", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    const value: FindingFiltersValue = {
      severities: new Set<FindingSeverity>(["high"]),
      ssvcOutcomes: new Set<SsvcDecision>(["Act"]),
      kevOnly: true,
      query: "rce",
    };
    render(<FindingFilters value={value} onChange={onChange} />);
    await user.click(screen.getByTestId("finding-filters-reset"));
    const next = onChange.mock.calls[0][0] as FindingFiltersValue;
    expect(next.severities.size).toBe(0);
    expect(next.ssvcOutcomes.size).toBe(0);
    expect(next.kevOnly).toBe(false);
    expect(next.query).toBe("");
  });

  it("propagates query changes through onChange", async () => {
    const user = userEvent.setup();
    const onChange = vi.fn();
    render(<FindingFilters value={EMPTY_FINDING_FILTERS} onChange={onChange} />);
    const input = screen.getByLabelText("Search findings");
    await user.type(input, "x");
    expect(onChange).toHaveBeenCalled();
    const next = onChange.mock.calls.at(-1)![0] as FindingFiltersValue;
    expect(next.query).toBe("x");
  });

  it("exposes accessible roles for screen readers", () => {
    render(<FindingFilters value={EMPTY_FINDING_FILTERS} onChange={() => undefined} />);
    const region = screen.getByRole("region", { name: /finding filters/i });
    expect(region).toBeInTheDocument();
    const groups = within(region).getAllByRole("group");
    expect(groups.length).toBeGreaterThanOrEqual(2);
  });
});

describe("applyFindingFilters - pure helper", () => {
  it("returns the full list when filters are empty", () => {
    const out = applyFindingFilters(SAMPLE, EMPTY_FINDING_FILTERS);
    expect(out).toHaveLength(SAMPLE.length);
  });

  it("filters by severity (whitelist semantics)", () => {
    const out = applyFindingFilters(SAMPLE, {
      ...EMPTY_FINDING_FILTERS,
      severities: new Set<FindingSeverity>(["critical", "high"]),
    });
    expect(out.map((r) => r.id)).toEqual(["f1", "f2"]);
  });

  it("filters by SSVC outcome", () => {
    const out = applyFindingFilters(SAMPLE, {
      ...EMPTY_FINDING_FILTERS,
      ssvcOutcomes: new Set<SsvcDecision>(["Act", "Attend"]),
    });
    expect(out.map((r) => r.id)).toEqual(["f1", "f2"]);
  });

  it("excludes findings with null SSVC decision when SSVC filter active", () => {
    const out = applyFindingFilters(SAMPLE, {
      ...EMPTY_FINDING_FILTERS,
      ssvcOutcomes: new Set<SsvcDecision>(["Track"]),
    });
    expect(out.map((r) => r.id)).toEqual(["f4"]);
  });

  it("filters by KEV-only flag", () => {
    const out = applyFindingFilters(SAMPLE, {
      ...EMPTY_FINDING_FILTERS,
      kevOnly: true,
    });
    expect(out.map((r) => r.id)).toEqual(["f1"]);
  });

  it("filters by free-text query (case-insensitive across title/description/cwe)", () => {
    const out = applyFindingFilters(SAMPLE, {
      ...EMPTY_FINDING_FILTERS,
      query: "RCE in",
    });
    expect(out.map((r) => r.id)).toEqual([]);
    const out2 = applyFindingFilters(SAMPLE, {
      ...EMPTY_FINDING_FILTERS,
      query: "rce",
    });
    expect(out2.map((r) => r.id)).toEqual([]);
    const out3 = applyFindingFilters(SAMPLE, {
      ...EMPTY_FINDING_FILTERS,
      query: "execution",
    });
    expect(out3.map((r) => r.id)).toEqual(["f1"]);
    const out4 = applyFindingFilters(SAMPLE, {
      ...EMPTY_FINDING_FILTERS,
      query: "cwe-89",
    });
    expect(out4.map((r) => r.id)).toEqual(["f2"]);
  });

  it("combines all filter dimensions with AND semantics", () => {
    const out = applyFindingFilters(SAMPLE, {
      severities: new Set<FindingSeverity>(["critical"]),
      ssvcOutcomes: new Set<SsvcDecision>(["Act"]),
      kevOnly: true,
      query: "execution",
    });
    expect(out.map((r) => r.id)).toEqual(["f1"]);
  });
});
