import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { ScanCoverageResponse } from "@/lib/lab/types";

import { CoverageHeatmap } from "./CoverageHeatmap";

const coverage: ScanCoverageResponse = {
  scan_id: "scan-1",
  requirements: [],
  results: [
    {
      requirement_id: "r-ok",
      tenant_id: "t-1",
      scan_id: "scan-1",
      asset_id: "asset-a",
      capability_id: "web.xss",
      status: "covered_no_finding",
    },
    {
      requirement_id: "r-nt",
      tenant_id: "t-1",
      scan_id: "scan-1",
      asset_id: "asset-a",
      capability_id: "web.sqli",
      status: "not_tested",
    },
  ],
};

describe("CoverageHeatmap", () => {
  it("keeps not_tested visually distinct from covered_no_finding", () => {
    render(<CoverageHeatmap scanId="scan-1" coverage={coverage} />);
    const ok = screen.getByTitle("asset-a / web.xss: covered_no_finding");
    const nt = screen.getByTitle("asset-a / web.sqli: not_tested");
    expect(ok).toHaveAttribute("data-status", "covered_no_finding");
    expect(nt).toHaveAttribute("data-status", "not_tested");
    expect(ok.className).not.toBe(nt.className);
  });
});
