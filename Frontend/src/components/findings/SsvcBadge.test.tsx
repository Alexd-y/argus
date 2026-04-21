import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { SsvcBadge, SSVC_DECISIONS, isSsvcDecision } from "./SsvcBadge";

describe("SsvcBadge", () => {
  it("renders all four CISA SSVC v2.1 decisions with the canonical label", () => {
    for (const decision of SSVC_DECISIONS) {
      const { unmount } = render(<SsvcBadge decision={decision} testId={`badge-${decision}`} />);
      const badge = screen.getByTestId(`badge-${decision}`);
      expect(badge).toBeInTheDocument();
      expect(badge).toHaveAttribute("data-decision", decision);
      expect(badge).toHaveTextContent(decision);
      unmount();
    }
  });

  it("uses distinct colour classes per decision so colour cannot collapse to one bucket", () => {
    const colourTokens = SSVC_DECISIONS.map((d) => {
      const { unmount } = render(<SsvcBadge decision={d} testId={`badge-${d}`} />);
      const cls = screen.getByTestId(`badge-${d}`).className;
      unmount();
      return cls.match(/bg-[a-z]+-\d{3}/)?.[0] ?? "";
    });
    const unique = new Set(colourTokens);
    expect(unique.size).toBe(SSVC_DECISIONS.length);
  });

  it("attaches the explanatory tooltip and accessible label for the highest-severity decision", () => {
    render(<SsvcBadge decision="Act" />);
    const badge = screen.getByTestId("ssvc-badge");
    const tooltip = badge.getAttribute("title") ?? "";
    expect(tooltip.toLowerCase()).toContain("act");
    expect(tooltip.toLowerCase()).toContain("highest priority");
    expect(badge.getAttribute("aria-label")).toContain("SSVC: Act");
  });

  it("renders an em-dash placeholder when the decision is null / undefined / empty string", () => {
    for (const value of [null, undefined, ""]) {
      const { unmount } = render(<SsvcBadge decision={value} testId={`badge-empty`} />);
      const badge = screen.getByTestId("badge-empty");
      expect(badge).toHaveTextContent("—");
      expect(badge).toHaveAttribute("data-decision", "");
      expect(badge.getAttribute("aria-label")).toMatch(/not available/i);
      unmount();
    }
  });

  it("falls back to the fallback style for an unknown decision string but still renders the literal label", () => {
    render(<SsvcBadge decision="Defer" testId="badge-unknown" />);
    const badge = screen.getByTestId("badge-unknown");
    expect(badge).toHaveTextContent("Defer");
    expect(badge.getAttribute("title")).toMatch(/not available/i);
  });

  it("respects the className override and exposes the decision via data-* for downstream filters", () => {
    render(
      <SsvcBadge
        decision="Track*"
        className="custom-extra-class"
        ariaLabel="Custom label"
        testId="badge-custom"
      />,
    );
    const badge = screen.getByTestId("badge-custom");
    expect(badge.className).toContain("custom-extra-class");
    expect(badge.getAttribute("aria-label")).toBe("Custom label");
    expect(badge).toHaveAttribute("data-decision", "Track*");
  });

  it("isSsvcDecision narrows correctly for known values and rejects unknown ones", () => {
    expect(isSsvcDecision("Act")).toBe(true);
    expect(isSsvcDecision("Attend")).toBe(true);
    expect(isSsvcDecision("Track*")).toBe(true);
    expect(isSsvcDecision("Track")).toBe(true);
    expect(isSsvcDecision("Defer")).toBe(false);
    expect(isSsvcDecision(null)).toBe(false);
    expect(isSsvcDecision(undefined)).toBe(false);
    expect(isSsvcDecision(42)).toBe(false);
  });
});
